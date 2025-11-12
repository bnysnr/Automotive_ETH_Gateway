import cantools
import can
import socket
import struct
import time
import threading
import numpy as np
import pyshark


# -------------------- Hilfsfunktionen --------------------
def calc_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def float_to_uint32_le(value: float) -> int:
    """Float -> 4 Byte Little Endian (uint32)"""
    return struct.unpack("<I", struct.pack("<f", value))[0]


def hex_to_float32(hex_val: int) -> float:
    """Zur Kontrolle: int wieder zurück in float"""
    return struct.unpack("<f", struct.pack("<I", hex_val))[0]


def set_wertebereich(value, min_val, max_val):
    """Begrenzt den Wert auf den angegebenen Bereich"""
    if value < min_val:
        print(f"[CLAMP] {value:.3f} < min {min_val}, setze auf {min_val}")
        return min_val
    elif value > max_val:
        print(f"[CLAMP] {value:.3f} > max {max_val}, setze auf {max_val}")
        return max_val
    return value

def capture_eth0():
    ip_addr_arr = []
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

            # 5 Sekunden Timer
            if time.time() - start_time >= 5:
                break 

        print(f"Founded IP-Adresses: {ip_addr_arr}")
        return ip_addr_arr

    except KeyboardInterrupt:
        print("\nCapture finished")
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")


# -------------------- Konstanten --------------------
SOURCE_IP = "192.168.16.5"
SOURCE_PORT = 2001
DEST_PORT = 60000
INTERFACE = b"eth0.34\0"  # VLAN 34

SERVICE_ID = 0x0002
METHOD_ID = 0x1000
CLIENT_ID = 0x0000
SESSION_ID = 0x0000
PROTOCOL_VERSION = 0x01
INTERFACE_VERSION = 0x01
MESSAGE_TYPE = 0x02
RETURN_CODE = 0x00
DATA_ID = 0x03E8
E2E_PAYLOAD_LENGTH = 73

DBC_PATH = '/home/admin/Praxissemester/dbc/J1939_MAN_1.dbc'
SIGNALS_FILE = '/home/admin/Praxissemester/script/required_signals.txt'
CAN_CHANNEL = 'can0'

SIGNAL_ORDER = [
    "VDC2_YawRate_3E",
    "VDC2_SteerWhlAngle_3E",
    "VDC2_LatAccel_3E",
    "VDC2_LongAccel_3E",
    "EBC2_RelWhlSpdFL_0B",
    "EBC2_RelWhlSpdFR_0B",
    "EBC2_RelWhlSpdRL_0B",
    "EBC2_RelWhlSpdRR_0B",
    "TCO1_VehSpd_EE"
]

qf_signals_list = [0x00] * len(SIGNAL_ORDER)

# Wertebereiche
YAW_RATE_MIN, YAW_RATE_MAX = -2.6, 2.6
ST_WHEEL_ANGLE_MIN, ST_WHEEL_ANGLE_MAX = -14.5, 14.5
LAT_ACCEL_MIN, LAT_ACCEL_MAX = -15, 15
WHL_VEL_MIN, WHL_VEL_MAX = 0, 115
VEH_VEL_MIN, VEH_VEL_MAX = 0, 115
VEH_LONG_ACCEL_MIN, VEH_LONG_ACCEL_MAX = -15, 15


# -------------------- Initialisierung --------------------
def load_dbc_and_signals():
    """Lädt DBC und ermittelt relevante CAN-IDs"""
    db = cantools.database.load_file(DBC_PATH)
    print(f"DBC geladen: {len(db.messages)} Messages\n")

    with open(SIGNALS_FILE, 'r') as f:
        required_signals = [line.strip() for line in f if line.strip()]

    print(f"Suche nach {len(required_signals)} Signalen:")
    for sig in required_signals:
        print(f"  - {sig}")
    print()

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

    return db, relevant_message_ids, signal_info


def init_can_bus():
    """Initialisiert die CAN-Schnittstelle"""
    return can.interface.Bus(channel=CAN_CHANNEL, interface='socketcan')


def init_udp_socket():
    """Erzeugt und bindet den UDP-Socket"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, 25, INTERFACE)
    sock.bind((SOURCE_IP, SOURCE_PORT))
    return sock


# -------------------- SOME/IP Aufbau --------------------
def build_someip_payload(vdy_signal_parameters, qf_signals_list, sqc):
    float_signals_list = [float_to_uint32_le(v) for v in vdy_signal_parameters]
    E2E_PAYLOAD_RAW = b''.join(struct.pack("<I", v) for v in float_signals_list)
    E2E_PAYLOAD_RAW += b''.join(struct.pack("B", qf) for qf in qf_signals_list)

    if len(E2E_PAYLOAD_RAW) < E2E_PAYLOAD_LENGTH:
        E2E_PAYLOAD_RAW += bytes(E2E_PAYLOAD_LENGTH - len(E2E_PAYLOAD_RAW))
    elif len(E2E_PAYLOAD_RAW) > E2E_PAYLOAD_LENGTH:
        print(f"[WARN] E2E payload länger ({len(E2E_PAYLOAD_RAW)}) als erwartet ({E2E_PAYLOAD_LENGTH})")

    header_part2 = struct.pack("!HHBBBB",
                               CLIENT_ID, SESSION_ID,
                               PROTOCOL_VERSION, INTERFACE_VERSION,
                               MESSAGE_TYPE, RETURN_CODE)

    crc_input = (
        header_part2 +
        struct.pack("<H", len(E2E_PAYLOAD_RAW)) +
        struct.pack("B", sqc) +
        E2E_PAYLOAD_RAW +
        struct.pack("<H", DATA_ID)
    )

    crc = calc_crc16(crc_input)
    e2e_header = struct.pack(">HHB", crc, E2E_PAYLOAD_LENGTH, sqc)
    someip_payload = e2e_header + E2E_PAYLOAD_RAW

    message_id = (SERVICE_ID << 16) | METHOD_ID
    someip_length = len(header_part2) + len(someip_payload)
    header_part1 = struct.pack("!II", message_id, someip_length)

    udp_payload = header_part1 + header_part2 + someip_payload
    return udp_payload


# -------------------- Sender --------------------
def send_udp_to_all(sock, radar_ips, payload):
    """Sendet Payload in Threads an alle Radar-IPs"""
    threads = []
    for radar_ip in radar_ips:
        t = threading.Thread(target=sock.sendto, args=(payload, (radar_ip, DEST_PORT)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


# -------------------- Hauptverarbeitung --------------------
def process_can_messages(db, bus, sock, relevant_message_ids, signal_info, radar_ips):
    """Liest CAN, verarbeitet Signale und sendet an Radar-IPs"""
    vdy_signal_parameters = [0.0] * len(SIGNAL_ORDER)
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
            for idx, signal_name in enumerate(SIGNAL_ORDER):
                if signal_name in decoded:
                    value = decoded[signal_name]
                    vdy_signal_parameters[idx] = value
                    updated = True
                    print(f"{signal_name}: {value:12.6f} {signal_info[signal_name]['unit']}")

            if not updated:
                continue

            print("-" * 70)

            # Wertebereich begrenzen
            vdy_signal_parameters[0] = set_wertebereich(vdy_signal_parameters[0], YAW_RATE_MIN, YAW_RATE_MAX)
            vdy_signal_parameters[1] = set_wertebereich(vdy_signal_parameters[1], ST_WHEEL_ANGLE_MIN, ST_WHEEL_ANGLE_MAX)
            vdy_signal_parameters[2] = set_wertebereich(vdy_signal_parameters[2], LAT_ACCEL_MIN, LAT_ACCEL_MAX)
            vdy_signal_parameters[3] = set_wertebereich(vdy_signal_parameters[3], VEH_LONG_ACCEL_MIN, VEH_LONG_ACCEL_MAX)
            vdy_signal_parameters[4] = set_wertebereich(vdy_signal_parameters[4], WHL_VEL_MIN, WHL_VEL_MAX)
            vdy_signal_parameters[5] = set_wertebereich(vdy_signal_parameters[5], WHL_VEL_MIN, WHL_VEL_MAX)
            vdy_signal_parameters[6] = set_wertebereich(vdy_signal_parameters[6], WHL_VEL_MIN, WHL_VEL_MAX)
            vdy_signal_parameters[7] = set_wertebereich(vdy_signal_parameters[7], WHL_VEL_MIN, WHL_VEL_MAX)
            vdy_signal_parameters[8] = set_wertebereich(vdy_signal_parameters[8], VEH_VEL_MIN, VEH_VEL_MAX)

            long_acceleration_arr = [vdy_signal_parameters[3]]
            print(f"Longitudinal Acceleration Arr: {long_acceleration_arr}")

            # SOME/IP Nachricht aufbauen
            udp_payload = build_someip_payload(vdy_signal_parameters, qf_signals_list, sqc)

            # An alle Radar-IPs senden
            send_udp_to_all(sock, radar_ips, udp_payload)

            sqc = (sqc + 1) % 256
            time.sleep(0.02)

    except KeyboardInterrupt:
        print("\n\nBeendet")
    finally:
        bus.shutdown()
        sock.close()


def start_radar_sender(radar_ips):
    db, relevant_message_ids, signal_info = load_dbc_and_signals()
    bus = init_can_bus()
    sock = init_udp_socket()
    process_can_messages(db, bus, sock, relevant_message_ids, signal_info, radar_ips)



if __name__ == "__main__":
    sensor_ip_addresses = capture_eth0()
    start_radar_sender(sensor_ip_addresses)
