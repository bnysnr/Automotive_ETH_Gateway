import cantools
import can
import numpy as np
import struct
import socket
import time
import threading


def float32_to_uint32_be_int(value: float) -> int:
    value32 = np.float32(value)
    bytes_le = struct.pack('<f', value32)
    bytes_be = bytes_le[::-1]
    uint32 = int.from_bytes(bytes_be, byteorder='big', signed=False)
    return uint32


def read_signals_from_file(filepath):
    """Liest Signalnamen aus einer Textdatei"""
    signal_names = []
    with open(filepath, 'r') as file:
        for line in file:
            signal = line.strip()
            if signal:
                signal_names.append(signal)
    return signal_names   


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


def extract_signal_value(data_bytes, signal):
    """
    Extrahiert den Signalwert korrekt aus CAN-Daten unter Berücksichtigung
    von Start-Bit, Länge und Byte-Order.
    """
    data_int = int.from_bytes(data_bytes, byteorder='little', signed=False)
    mask = (1 << signal.length) - 1
    raw_value = (data_int >> signal.start) & mask
    
    if signal.is_signed:
        if raw_value & (1 << (signal.length - 1)):
            raw_value -= (1 << signal.length)
    
    return raw_value


# Globale Variable für die aktuellen Signalwerte
current_signal_values = None
signal_lock = threading.Lock()


def read_can_continuously():
    """Thread-Funktion: Liest kontinuierlich CAN-Daten"""
    global current_signal_values
    
    try:
        db = cantools.database.load_file('/home/admin/Praxissemester/dbc/J1939_MAN_1.dbc')
    except Exception as e:
        print(f"Fehler bei der Datenbank: {e}")
        return
    
    target_id = 0x18F0093E
    required_signals_arr = read_signals_from_file('/home/admin/Praxissemester/script/required_signals.txt')
    
    try:
        message = db.get_message_by_frame_id(target_id)
    except KeyError:
        print(f"Fehler: Target ID: {hex(target_id)} nicht in der DBC gefunden")
        return
    
    print(f"[CAN] Starte CAN-Bus für Nachricht: {message.name} (ID: {hex(message.frame_id)})")
    print(f"[CAN] Gesuchte Signale: {required_signals_arr}\n")
    
    bus = can.interface.Bus(channel='can0', interface='socketcan')
    message_count = 0
    
    try:
        while True:
            received_msg = bus.recv(timeout=2.0)
            
            if received_msg is None:
                print("[CAN] Timeout - keine Nachricht empfangen")
                continue
            
            if received_msg.arbitration_id != target_id:
                continue
            
            message_count += 1
            
            # Daten extrahieren
            physical_calc_val_arr = []
            data_hex = ' '.join(format(byte, '02X') for byte in received_msg.data)
            
            # Dekodiere mit cantools (zuverlässigste Methode)
            try:
                decoded = db.decode_message(target_id, received_msg.data)
                
                # Durchlaufe die gewünschten Signale in der richtigen Reihenfolge
                for signal_name in required_signals_arr:
                    if signal_name in decoded:
                        physical_value = decoded[signal_name]
                        physical_calc_val_arr.append(physical_value)
                    else:
                        print(f"[CAN] Warnung: Signal {signal_name} nicht gefunden, verwende 0.0")
                        physical_calc_val_arr.append(0.0)
                
                # Thread-sicher aktualisieren
                with signal_lock:
                    current_signal_values = physical_calc_val_arr
                """
                if message_count % 50 == 0:  # Jede 50. Nachricht ausgeben
                    print(f"[CAN] Nachricht #{message_count} - Hex: {data_hex}")
                    for i, sig_name in enumerate(required_signals_arr):
                        if i < len(physical_calc_val_arr):
                            print(f"  {sig_name}: {physical_calc_val_arr[i]:.6f}")
                """
                            
            except Exception as e:
                print(f"[CAN] Fehler beim Dekodieren: {e}")
                continue
            
            time.sleep(0.001)  # Kurze Pause um CPU zu schonen
            
    except KeyboardInterrupt:
        print("\n[CAN] Thread beendet durch Benutzer")
    except Exception as e:
        print(f"[CAN] Fehler im CAN-Thread: {e}")
    finally:
        bus.shutdown()
        print("[CAN] CAN-Bus geschlossen")


def send_udp_continuously():
    """Thread-Funktion: Sendet kontinuierlich UDP-Nachrichten"""
    global current_signal_values
    
    # Netzwerk / SOME/IP Konfig
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
    SQC = 0x00

    qf_signals_list = [0x00] * 9  # 9 Quality Flags

    print("[UDP] Starte UDP-Sender\n")

    # Socket aufbauen
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, 25, INTERFACE)  
    sock.bind((SOURCE_IP, SOURCE_PORT))

    send_count = 0

    try:
        while True:
            # Hole aktuelle Werte thread-sicher
            with signal_lock:
                if current_signal_values is None:
                    print("[UDP] Warte auf CAN-Daten...")
                    time.sleep(0.1)
                    continue
                physical_values = current_signal_values.copy()
            
            # Prüfe ob wir genug Werte haben
            if len(physical_values) < 9:
                print(f"[UDP] Warnung: Nur {len(physical_values)} von 9 Signalen verfügbar")
                # Fülle fehlende Werte mit 0.0 auf
                while len(physical_values) < 9:
                    physical_values.append(0.0)
            
            # Konvertiere zu Float32 -> Uint32
            float_signals_list = [float32_to_uint32_be_int(val) for val in physical_values[:9]]
            
            # E2E Payload aufbauen
            E2E_PAYLOAD_RAW = b''
            for val in float_signals_list:
                E2E_PAYLOAD_RAW += struct.pack("<I", val)  # Little Endian uint32

            for qf in qf_signals_list:
                E2E_PAYLOAD_RAW += struct.pack("B", qf)

            # Padding
            if len(E2E_PAYLOAD_RAW) < E2E_PAYLOAD_LENGTH:
                E2E_PAYLOAD_RAW += bytes(E2E_PAYLOAD_LENGTH - len(E2E_PAYLOAD_RAW))
            elif len(E2E_PAYLOAD_RAW) > E2E_PAYLOAD_LENGTH:
                print(f"[UDP] WARNUNG: Payload zu lang ({len(E2E_PAYLOAD_RAW)} > {E2E_PAYLOAD_LENGTH})")
                E2E_PAYLOAD_RAW = E2E_PAYLOAD_RAW[:E2E_PAYLOAD_LENGTH]

            # SOME/IP Header Part 2
            header_part2 = struct.pack(
                "!HHBBBB",
                CLIENT_ID,
                SESSION_ID,
                PROTOCOL_VERSION,
                INTERFACE_VERSION,
                MESSAGE_TYPE,
                RETURN_CODE
            )

            # CRC berechnen
            crc_input = b""
            crc_input += header_part2
            crc_input += struct.pack("<H", len(E2E_PAYLOAD_RAW))
            crc_input += struct.pack("B", SQC)
            crc_input += E2E_PAYLOAD_RAW
            crc_input += struct.pack("<H", DATA_ID)

            crc = calc_crc16(crc_input)
            e2e_header = struct.pack(">HHB", crc, E2E_PAYLOAD_LENGTH, SQC)
            someip_payload = e2e_header + E2E_PAYLOAD_RAW

            # Header Part 1
            message_id = (SERVICE_ID << 16) | METHOD_ID
            someip_length = len(header_part2) + len(someip_payload)
            header_part1 = struct.pack("!II", message_id, someip_length)

            # Gesamter UDP-Frame
            udp_payload = header_part1 + header_part2 + someip_payload
            sock.sendto(udp_payload, (RADAR_IP, DEST_PORT))

            send_count += 1
            
            if send_count % 50 == 0:  # Jede 50. Nachricht
                print(f"[UDP] Nachricht #{send_count} gesendet (SQC={SQC}, CRC=0x{crc:04X}, Länge={len(udp_payload)})")
                print(f"  Beispiel: Signal[1] = {physical_values[1]:.6f} -> 0x{float_signals_list[1]:08X}")

            SQC = (SQC + 1) % 256
            time.sleep(0.02)  # 50 Hz Senderate

    except KeyboardInterrupt:
        print("\n[UDP] Thread beendet durch Benutzer")
    except Exception as e:
        print(f"[UDP] Fehler im UDP-Thread: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()
        print("[UDP] Socket geschlossen")


if __name__ == "__main__":
    print("="*70)
    print("CAN to UDP Bridge")
    print("="*70)
    print("Drücke Strg+C zum Beenden\n")
    
    # Erstelle zwei Threads
    can_thread = threading.Thread(target=read_can_continuously, daemon=True)
    udp_thread = threading.Thread(target=send_udp_continuously, daemon=True)
    
    # Starte Threads
    can_thread.start()
    time.sleep(0.5)  # Gib CAN-Thread Zeit zum Starten
    udp_thread.start()
    
    try:
        # Hauptthread wartet
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nProgramm wird beendet...")
        time.sleep(1)  # Gib Threads Zeit zum Aufräumen