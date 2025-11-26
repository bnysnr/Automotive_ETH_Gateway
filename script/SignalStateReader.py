import socket
import struct
import sys
import time
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from SignalStateGUI import MyWindow, apply_font_to_table

sensor_ips = {"192.168.16.15", "192.168.16.12", "192.168.16.13", "192.168.16.14"}

MCAST_GRP = '239.22.0.3'
UDP_PORT = 40000
INTERFACE_IP = '192.168.16.5'

SENSOR_TIMEOUT = 1  # Sekunden ohne Daten = Fehler


class UDPThread(QThread):
    new_values = pyqtSignal(list)
    sensor_error = pyqtSignal(str)
    sensor_ok = pyqtSignal()  # Signal, wenn wieder Daten kommen

    def __init__(self):
        super().__init__()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', UDP_PORT))

        mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(INTERFACE_IP))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        self.last_any_data = time.time()
        self.no_data_sent_flag = False  # True, wenn Fehler bereits angezeigt wird

        self.check_timer = QTimer()
        self.check_timer.setInterval(500)
        self.check_timer.timeout.connect(self.check_sensor_is_alive)
        self.check_timer.start()

    def check_sensor_is_alive(self):
        now = time.time()

        if now - self.last_any_data > SENSOR_TIMEOUT:
            # Statuswerte auf '02' setzen
            self.new_values.emit(['02'] * 7)

            # Fehlermeldung anzeigen, falls noch nicht sichtbar
            if not self.no_data_sent_flag:
                self.sensor_error.emit("No sensor data received")
                self.no_data_sent_flag = True

            # Falls MessageBox vom Nutzer geschlossen wurde, erneut anzeigen
            else:
                self.sensor_error.emit("No sensor data received")

        else:
            # Sobald wieder Daten kommen, Fehlermeldung schließen
            if self.no_data_sent_flag:
                self.sensor_ok.emit()  # Signal an GUI, um MessageBox zu schließen
                self.no_data_sent_flag = False

                

    def run(self):
        print(f"Listening on multicast {MCAST_GRP}:{UDP_PORT} ...")
        try:
            while True:
                data, addr = self.sock.recvfrom(4096)

                if addr[0] not in sensor_ips:
                    continue

                self.last_any_data = time.time()

                raw = data.hex()
                if not raw.startswith("0007"):
                    continue

                extracted = raw[322:336]
                values = self.decode_values(extracted)
                self.new_values.emit(values)

        except Exception as e:
            print(f"Fehler im UDP Thread: {e}")

    def decode_values(self, hexstring):
        return [hexstring[i:i+2] for i in range(0, len(hexstring), 2)]


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MyWindow()
    window.show()

    gui_font = window.gui_font
    apply_font_to_table(window.table_ego, gui_font)
    apply_font_to_table(window.table_cfg, gui_font)

    udp_thread = UDPThread()
    udp_thread.new_values.connect(window.update_values)

    # Fehlermeldung anzeigen
    msg_box = QMessageBox(window)
    msg_box.setWindowTitle("Error")
    msg_box.setIcon(QMessageBox.Critical)

    def show_error(msg):
        msg_box.setText(msg)
        msg_box.show()

    def close_error():
        if msg_box.isVisible():
            msg_box.close()

    udp_thread.sensor_error.connect(show_error)
    udp_thread.sensor_ok.connect(close_error)

    udp_thread.start()

    sys.exit(app.exec_())
