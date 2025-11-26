import cantools
import can
import socket
import struct
import time
import threading
import pyshark


class Automotive_ETH_Gateway():

    def __init__(self):
        super().__init__()

        # -------------------- Konstanten --------------------
        self.SOURCE_IP = "192.168.16.5"
        self.SOURCE_PORT = 2001
        self.DEST_PORT = 60000
        self.INTERFACE = b"eth0.34\0"  # VLAN 34

        self.SERVICE_ID_EGOMOTION = 0x0002
        self.SERVICE_ID_SENSOR_CONFIG_MSG_STATUS = 0x0007
        self.METHOD_ID = 0x1000
        self.CLIENT_ID = 0x0000
        self.SESSION_ID = 0x0000
        self.PROTOCOL_VERSION = 0x01
        self.INTERFACE_VERSION = 0x01
        self.MESSAGE_TYPE = 0x02
        self.RETURN_CODE = 0x00
        self.DATA_ID = 0x03E8
        self.E2E_PAYLOAD_LENGTH = 73

        self.DBC_PATH = '/home/admin/Praxissemester/dbc/J1939_MAN_1.dbc'
        self.SIGNALS_FILE = '/home/admin/Praxissemester/script/required_signals.txt'
        self.CAN_CHANNEL = 'can0'

    # CRC16 Algorithmus
    def calc_crc16(self, data: bytes) -> int:
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc


    def float_to_uint32_le(self, value: float) -> int:
        """Float -> 4 Byte Little Endian (uint32)"""
        return struct.unpack("<I", struct.pack("<f", value))[0]

    def capture_eth0(self):
        ip_addr_arr = []
        print("Start radar IP sniffing - Waiting for 5 seconds")
        try:
            capture = pyshark.LiveCapture(interface='eth0')

            start_time = time.time()
            while True:
                capture.sniff(packet_count=1)
                for packet in capture:
                    if 'IP' in packet:
                        src_ip = packet.ip.src
                        if src_ip not in ip_addr_arr:
                            ip_addr_arr.append(src_ip)

                if time.time() - start_time >= 5:
                    break

            print(f"Found IP addresses: {ip_addr_arr}")
            return ip_addr_arr

        except KeyboardInterrupt:
            print("\nCapture finished")
        except Exception as e:
            print(f"Ein Fehler ist aufgetreten: {e}")


    


    # -------------------- Initialisierung --------------------
    def load_dbc_and_signals(self):
        """Lädt DBC und ermittelt relevante CAN-IDs"""
        db = cantools.database.load_file(self.DBC_PATH)
        print(f"DBC geladen: {len(db.messages)} Messages\n")

        with open(self.SIGNALS_FILE, 'r') as f:
            required_signals = [line.strip() for line in f if line.strip()]

        print(f"Required Signals: {required_signals}\n")

        relevant_message_ids = set()
        signal_info = {}

        for signal_name in required_signals:
            for message in db.messages:
                for signal in message.signals:
                    if signal.name == signal_name:
                        relevant_message_ids.add(message.frame_id)
                        signal_info[signal_name] = {
                            'message_id': message.frame_id,
                            'message_name': message.name,
                            'unit': signal.unit or ''
                        }
                        print(f"{signal_name} -> {message.name} ({hex(message.frame_id)})")
                        break

        print(f"\nÜberwache {len(relevant_message_ids)} Messages")
        print("=" * 70)
        print("Warte auf CAN-Daten...\n")

        # Rückgabe der dynamischen Signalliste
        return db, relevant_message_ids, signal_info, required_signals


    def init_can_bus(self):
        """Initialisiert die CAN-Schnittstelle"""
        return can.interface.Bus(channel=self.CAN_CHANNEL, interface='socketcan')


    def init_udp_socket(self):
        """Erzeugt und bindet den UDP-Socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, 25, self.INTERFACE)
        sock.bind((self.SOURCE_IP, self.SOURCE_PORT))
        return sock


    # -------------------- SOME/IP Aufbau --------------------
    def build_someip_payload(self, signal_names, vdy_signal_parameters, qf_signals_list, sqc):
        """Erstellt SOME/IP Payload dynamisch basierend auf signal_names"""
        float_signals_list = [self.float_to_uint32_le(v) for v in vdy_signal_parameters]
        E2E_PAYLOAD_RAW = b''.join(struct.pack("<I", v) for v in float_signals_list)
        E2E_PAYLOAD_RAW += b''.join(struct.pack("B", qf) for qf in qf_signals_list)

        if len(E2E_PAYLOAD_RAW) < self.E2E_PAYLOAD_LENGTH:
            E2E_PAYLOAD_RAW += bytes(self.E2E_PAYLOAD_LENGTH - len(E2E_PAYLOAD_RAW))
        elif len(E2E_PAYLOAD_RAW) > self.E2E_PAYLOAD_LENGTH:
            print(f"[WARN] E2E payload länger ({len(E2E_PAYLOAD_RAW)}) als erwartet ({self.E2E_PAYLOAD_LENGTH})")

        header_part2 = struct.pack("!HHBBBB",
                                self.CLIENT_ID, self.SESSION_ID,
                                self.PROTOCOL_VERSION, self.INTERFACE_VERSION,
                                self.MESSAGE_TYPE, self.RETURN_CODE)

        crc_input = (
            header_part2 +
            struct.pack("<H", len(E2E_PAYLOAD_RAW)) +
            struct.pack("B", sqc) +
            E2E_PAYLOAD_RAW +
            struct.pack("<H", self.DATA_ID)
        )

        crc = self.calc_crc16(crc_input)
        e2e_header = struct.pack(">HHB", crc, self.E2E_PAYLOAD_LENGTH, sqc)
        someip_payload = e2e_header + E2E_PAYLOAD_RAW

        message_id = (self.SERVICE_ID_EGOMOTION << 16) | self.METHOD_ID
        someip_length = len(header_part2) + len(someip_payload)
        header_part1 = struct.pack("!II", message_id, someip_length)

        # Debug-Ausgabe dynamisch
        print("\n[SOME/IP Payload Debug]")
        for name, val in zip(signal_names, vdy_signal_parameters):
            print(f"  {name:30s}: {val:10.3f}")
        print("-" * 60)

        return header_part1 + header_part2 + someip_payload


    # -------------------- Sender --------------------
    def send_udp_to_all(self, sock, radar_ips, payload):
        """Sendet Payload in Threads an alle Radar-IPs"""
        threads = []
        for radar_ip in radar_ips:
            t = threading.Thread(target=sock.sendto, args=(payload, (radar_ip, self.DEST_PORT)))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()


    # -------------------- Hauptverarbeitung --------------------
    def process_can_messages(self, db, bus, sock, relevant_message_ids, signal_info, radar_ips, signal_names):
        """Liest CAN, verarbeitet Signale und sendet an Radar-IPs"""
        vdy_signal_parameters = [0.0] * len(signal_names)
        qf_signals_list = [0x00] * len(signal_names)
        sqc = 0

        try:
            while True:
                msg = bus.recv(timeout=1.0)
                if msg is None:
                    continue

                if msg.arbitration_id not in relevant_message_ids:
                    continue

                decoded = db.decode_message(msg.arbitration_id, msg.data)
                updated = False
                signal_name_arr = []

                # Dynamisch über alle Signale iterieren
                for idx, signal_name in enumerate(signal_names):
                    if signal_name in decoded:
                        value = decoded[signal_name]
                        vdy_signal_parameters[idx] = value
                        updated = True
                        signal_name_arr.append(signal_name)
                        print(f"{signal_name}: {value:12.6f} {signal_info[signal_name]['unit']}")

                if not updated:
                    continue

                print(f"Gefundene Signale: {signal_name_arr}")
                print("-" * 70)

                # SOME/IP Nachricht aufbauen und senden
                udp_payload = self.build_someip_payload(signal_names, vdy_signal_parameters, qf_signals_list, sqc)
                print(f"VDY Signal Parameter Debug: {vdy_signal_parameters}")

                self.send_udp_to_all(sock, radar_ips, udp_payload)
                time.sleep(0.02)
                sqc = (sqc + 1) % 256
        

        except KeyboardInterrupt:
            print("\n\nBeendet")
        finally:
            bus.shutdown()
            sock.close()


    def start_radar_sender(self, radar_ips):
        db, relevant_message_ids, signal_info, signal_names = self.load_dbc_and_signals()
        bus = self.init_can_bus()
        sock = self.init_udp_socket()
        self.process_can_messages(db, bus, sock, relevant_message_ids, signal_info, radar_ips, signal_names)


if __name__ == "__main__":
    obj = Automotive_ETH_Gateway()
    sensor_ip_addresses = obj.capture_eth0()
    obj.start_radar_sender(sensor_ip_addresses)
