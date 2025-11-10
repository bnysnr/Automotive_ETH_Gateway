import cantools
import can
import socket
import struct
import time
import numpy as np
import threading

# ============================================================================
# KONFIGURATION
# ============================================================================
DBC_PATH = '/home/admin/Praxissemester/dbc/J1939_MAN_1.dbc'
SIGNALS_FILE = '/home/admin/Praxissemester/script/required_signals.txt'
CAN_CHANNEL = 'can0'

SOURCE_IP = "192.168.16.5"
RADAR_IP = "192.168.16.15"
SOURCE_PORT = 2001
DEST_PORT = 60000
INTERFACE = b"eth0.34\0"

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

# ============================================================================
# GLOBALE VARIABLEN
# ============================================================================
current_signal_values = [0.0] * 9
signal_lock = threading.Lock()
longitudinal_accel_history = []  # Array zum Tracken der Längsbeschleunigung

# ============================================================================
# HILFSFUNKTIONEN
# ============================================================================
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

def float32_to_uint32_be_int(value: float) -> int:
    value32 = np.float32(value)
    bytes_le = struct.pack('<f', value32)
    bytes_be = bytes_le[::-1]
    uint32 = int.from_bytes(bytes_be, byteorder='big', signed=False)
    return uint32

# ============================================================================
# CAN THREAD - Liest CAN-Daten
# ============================================================================
def read_can_continuously():
    global current_signal_values, longitudinal_accel_history
    
    # Lade DBC
    db = cantools.database.load_file(DBC_PATH)
    print(f"[CAN] DBC geladen: {len(db.messages)} Messages")
    
    # Lade gewünschte Signale
    with open(SIGNALS_FILE, 'r') as f:
        required_signals = [line.strip() for line in f if line.strip()]
    
    print(f"[CAN] Suche nach {len(required_signals)} Signalen:")
    for sig in required_signals:
        print(f"  - {sig}")
    
    # Finde Messages die diese Signale enthalten
    relevant_message_ids = set()
    
    for signal_name in required_signals:
        found = False
        for message in db.messages:
            for signal in message.signals:
                if signal.name == signal_name:
                    relevant_message_ids.add(message.frame_id)
                    found = True
                    break
            if found:
                break
    
    # Starte CAN-Bus
    bus = can.interface.Bus(channel=CAN_CHANNEL, interface='socketcan')
    message_count = 0
    
    while True:
        msg = bus.recv(timeout=1.0)
        
        if msg is None:
            continue
        
        if msg.arbitration_id not in relevant_message_ids:
            continue
        
        message_count += 1
        
        # Dekodiere Message
        decoded = db.decode_message(msg.arbitration_id, msg.data)
        
        # Extrahiere Signale in Reihenfolge
        signal_values = []
        for signal_name in required_signals:
            if signal_name in decoded:
                signal_values.append(decoded[signal_name])
                print(f"Signalname: {signal_name} - Wert: {decoded}")
            else:
                signal_values.append(0.0)
        
        # Speichere Werte
        with signal_lock:
            current_signal_values = signal_values
            
            # Tracke LongitudinalAcceleration (Index 3 in required_signals.txt)
            if len(signal_values) > 8:
                longitudinal_accel_history.append(signal_values[3])
                # Behalte nur letzte 100 Werte
                if len(longitudinal_accel_history) > 100:
                    longitudinal_accel_history.pop(0)
            for i in range (len(signal_values)):
                print(f"Signalnamen: {signal.name}")
            print(f"[CAN] {message_count} Messages - LongitudinalAccel = {signal_values[8]:.6f} m/s²")

# ============================================================================
# UDP THREAD - Sendet UDP-Nachrichten
# ============================================================================
def send_udp_continuously():
    global current_signal_values, longitudinal_accel_history
    
    qf_signals_list = [0x00] * 9
    SQC = 0x00
    
    # Socket aufbauen
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, 25, INTERFACE)
    sock.bind((SOURCE_IP, SOURCE_PORT))
    
    print(f"[UDP] Socket: {SOURCE_IP}:{SOURCE_PORT} -> {RADAR_IP}:{DEST_PORT}\n")
    
    send_count = 0
    
    while True:
        # Hole aktuelle Werte
        with signal_lock:
            physical_values = current_signal_values.copy()
            accel_history = longitudinal_accel_history.copy()
        
        # Konvertiere zu Uint32
        float_signals_list = [float32_to_uint32_be_int(val) for val in physical_values[:9]]
        
        # E2E Payload bauen
        E2E_PAYLOAD_RAW = b''
        for val in float_signals_list:
            E2E_PAYLOAD_RAW += struct.pack("<I", val)
        for qf in qf_signals_list:
            E2E_PAYLOAD_RAW += struct.pack("B", qf)
        
        # Padding auf 73 Bytes
        if len(E2E_PAYLOAD_RAW) < E2E_PAYLOAD_LENGTH:
            E2E_PAYLOAD_RAW += bytes(E2E_PAYLOAD_LENGTH - len(E2E_PAYLOAD_RAW))
        
        # SOME/IP Header Part 2
        header_part2 = struct.pack("!HHBBBB", CLIENT_ID, SESSION_ID, 
                                   PROTOCOL_VERSION, INTERFACE_VERSION, 
                                   MESSAGE_TYPE, RETURN_CODE)
        
        # CRC berechnen
        crc_input = b""
        crc_input += header_part2
        crc_input += struct.pack("<H", len(E2E_PAYLOAD_RAW))
        crc_input += struct.pack("B", SQC)
        crc_input += E2E_PAYLOAD_RAW
        crc_input += struct.pack("<H", DATA_ID)
        crc = calc_crc16(crc_input)
        
        # E2E Header
        e2e_header = struct.pack(">HHB", crc, E2E_PAYLOAD_LENGTH, SQC)
        someip_payload = e2e_header + E2E_PAYLOAD_RAW
        
        # SOME/IP Header Part 1
        message_id = (SERVICE_ID << 16) | METHOD_ID
        someip_length = len(header_part2) + len(someip_payload)
        header_part1 = struct.pack("!II", message_id, someip_length)
        
        # UDP Frame senden
        udp_payload = header_part1 + header_part2 + someip_payload
        sock.sendto(udp_payload, (RADAR_IP, DEST_PORT))
        
        send_count += 1
        
        # Ausgabe alle 50 Nachrichten
        if send_count % 50 == 0:
            print(f"[UDP] Nachricht #{send_count} (SQC={SQC}, CRC=0x{crc:04X})")
            print(f"      YawRate = {physical_values[0]:.6f}")
            print(f"      LongitudinalAccel = {physical_values[8]:.6f} m/s²")
            
            # Zeige Tracking-Statistik
            if len(accel_history) > 0:
                
                print(f"      LongAccel History ({len(accel_history)} Werte):")
                print(f"        Letzte 5: {accel_history[-5:]}")
        
        SQC = (SQC + 1) % 256
        time.sleep(0.02)

# ============================================================================
# HAUPTPROGRAMM
# ============================================================================
if __name__ == "__main__":
    print("="*70)
    print("CAN TO UDP BRIDGE")
    print("="*70)
    print()
    
    can_thread = threading.Thread(target=read_can_continuously, daemon=True)
    udp_thread = threading.Thread(target=send_udp_continuously, daemon=True)
    
    can_thread.start()
    time.sleep(1.0)
    udp_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nProgramm beendet")