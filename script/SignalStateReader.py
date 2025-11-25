import socket
import struct
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QThread, pyqtSignal
from SignalStateGUI import MyWindow, apply_font_to_table
from PyQt5.QtGui import QFont

sensor_ips = {"192.168.16.15", "192.168.16.12", "192.168.16.13", "192.168.16.14"}

MCAST_GRP = '239.22.0.3'
UDP_PORT = 40000
INTERFACE_IP = '192.168.16.5'


class UDPThread(QThread):
    new_values = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', UDP_PORT))
        mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(INTERFACE_IP))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def run(self):
        print(f"Listening on multicast {MCAST_GRP}:{UDP_PORT} ...")
        while True:
            data, addr = self.sock.recvfrom(4096)
            if addr[0] not in sensor_ips:
                continue
            raw = data.hex()
            if not raw.startswith("0007"):
                continue
            extracted = raw[322:336]
            values = self.decode_values(extracted)
            self.new_values.emit(values)

    def decode_values(self, hexstring):
        return [hexstring[i:i+2] for i in range(0, len(hexstring), 2)]


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Fenster erstellen (Font wird automatisch geladen)
    window = MyWindow()
    window.show()

    # Tabellen Font nochmal sicherstellen
    gui_font = window.gui_font
    apply_font_to_table(window.table_ego, gui_font)
    apply_font_to_table(window.table_cfg, gui_font)


    # UDP-Thread starten
    udp_thread = UDPThread()
    udp_thread.new_values.connect(window.update_values)
    udp_thread.start()

    sys.exit(app.exec_())
