import sqlite3
import datetime
import can
import cantools
import pyreaddbc
import socket
import struct
import time
import threading
import binascii
import numpy as np

DB_PATH = "signals.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS signals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        can_frame_id TEXT,
        signal_name TEXT,
        start_bit INTEGER,
        length_bit INTEGER,
        initial_value FLOAT,
        endianness TEXT,
        unit TEXT,
        factor REAL,
        offset REAL,
        hex_value TEXT,
        updated_at TEXT
    )
    """)
    conn.commit()
    conn.close()


def write_replace_signal(can_frame_id, signal_name, start_bit, length_bit, initial_value, endianness, unit, factor, offset, hex_value, updated_at):
    if signal_name is None:
        signal_name = ""
    signal_name = str(signal_name).strip()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("""
        REPLACE INTO signals (
            id, can_frame_id, signal_name, start_bit, length_bit, initial_value,
            endianness, unit, factor, offset, hex_value, updated_at
        ) VALUES (
            (SELECT id FROM signals WHERE signal_name = ?),
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """, (signal_name, can_frame_id, signal_name, start_bit, length_bit, initial_value,
              endianness, unit, factor, offset, hex_value, updated_at))
        conn.commit()

        c.execute("""
            SELECT signal_name, start_bit, length_bit, initial_value, endianness,
                   unit, factor, offset, hex_value, updated_at
            FROM signals
            WHERE signal_name = ?
        """, (signal_name,))
        row = c.fetchone()
        if row:
            print(f"[DB] Aktualisiert: {row}")
        else:
            print(f"[WARNUNG] Kein Eintrag für {signal_name} gefunden!")
    except Exception as e:
        print(f"[DB-FEHLER] Beim Schreiben von '{signal_name}': {e}")
    finally:
        conn.close()


def get_signal_data_from_dbc(target_id, bus_message):
    try:
        db = cantools.database.load_file('/home/admin/Praxissemester/dbc/J1939_MAN_1.dbc')
    except Exception as e:
        print(f"[Fehler] DBC konnte nicht geladen werden: {e}")
        return []

    can_data_arr = []

    try:
        message = db.get_message_by_frame_id(int(target_id, 16))
        can_frame_id = hex(message.frame_id)[2:].upper()
        print(f"Message CAN ID: {can_frame_id}")
    except KeyError:
        print(f"[Fehler] Target ID {target_id} nicht in der DBC gefunden.")
        return []

    for signal in message.signals:
        endianness = "Little Endian" if signal.byte_order == 'little_endian' else "Big Endian"
        data_hex = ' '.join(format(byte, '02X') for byte in bus_message.data)
        data_hex_formatted = data_hex.replace(" ", "")
        
        start_nibble = signal.start // 4
        length_nibbles = signal.length // 4
        final_result = data_hex_formatted[start_nibble: start_nibble + length_nibbles]
        
        byte_paare = [final_result[i:i+2] for i in range(0, len(final_result), 2)]
        
        if endianness == "Little Endian":
            byte_paare = list(reversed(byte_paare))
        
        endergebnis = "".join(byte_paare)
        
        can_data_arr.append((
            can_frame_id,
            signal.name,
            signal.start,
            signal.length,
            signal.initial if signal.initial is not None else 0.0,
            endianness,
            signal.unit if signal.unit is not None else '',
            signal.scale if signal.scale is not None else 1.0,
            signal.offset if signal.offset is not None else 0.0,
            endergebnis,
            datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
        ))

    return can_data_arr


def get_data_from_canoe(stop_event):
    """Thread 1: Liest CAN-Daten und schreibt in DB"""
    try:
        bus = can.interface.Bus(channel='can0', interface='socketcan')
    except Exception as e:
        print(f"[Fehler] CAN-Bus konnte nicht geöffnet werden: {e}")
        return

    print("[INFO] CAN-Bus gestartet. Warte auf Nachrichten...")

    try:
        while not stop_event.is_set():
            bus_message = bus.recv(timeout=1.0)
            
            if bus_message is None or not bus_message.data:
                continue

            data_hex = ' '.join(format(byte, '02X') for byte in bus_message.data)
            message_buffer = hex(bus_message.arbitration_id)[2:].upper()
            print(f"Ausgabe message_buffer: {message_buffer} - {data_hex}")

            signal_data_list = get_signal_data_from_dbc(message_buffer, bus_message)
            if signal_data_list:
                for signal_data in signal_data_list:
                    write_replace_signal(*signal_data)

    except (KeyboardInterrupt, SystemExit):
        print("\n[INFO] CAN-Thread beendet.")
    except Exception as e:
        print(f"[Fehler] Laufzeitfehler im CAN-Thread: {e}")
    finally:
        bus.shutdown()


def read_signals_from_file(filepath):
    """Liest Signalnamen aus einer Textdatei"""
    signal_names = []
    with open(filepath, 'r') as file:
        for line in file:
            signal = line.strip()
            if signal:
                signal_names.append(signal)
    return signal_names        


def get_data_from_db(signal_names):
    """Liest HEX-Werte aus der DB für gegebene Signalnamen"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    hex_value_arr = []
    try:
        for signal_name in signal_names:
            c.execute("""
            SELECT hex_value FROM signals WHERE signal_name = ?
            """, (signal_name,))
            ergebnisse = c.fetchall()
            
            if ergebnisse:
                hex_value_arr.append(ergebnisse[0][0])
            else:
                # Fallback: wenn Signal noch nicht in DB, nutze default-Wert
                hex_value_arr.append("00")  # Default-Wert
                print(f"[WARNUNG] Signal '{signal_name}' nicht in DB gefunden, nutze Default")
            
    finally:
        conn.close()
    
    return hex_value_arr

def get_signal_factor_from_db(signal_names):
    """Liest die zugehörigen Faktor Werte aus der DB für gegebene Signalnamen"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    factor_value_arr = []
    try:
        for signal_name in signal_names:
            c.execute("""
            SELECT factor FROM signals WHERE signal_name = ?
            """, (signal_name,))
            ergebnisse = c.fetchall()
            
            if ergebnisse:
                factor_value_arr.append(ergebnisse[0][0])
            else:
                # Fallback: wenn Signal noch nicht in DB, nutze default-Wert
                #hex_value_arr.append("00")  # Default-Wert
                print(f"[WARNUNG] Signal '{signal_name}' nicht in DB gefunden, nutze Default")
            
    finally:
        conn.close()
    
    return factor_value_arr

def get_signal_offset_from_db(signal_names):
    """Liest die zugehörigen Faktor Werte aus der DB für gegebene Signalnamen"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    offset_value_arr = []
    try:
        for signal_name in signal_names:
            c.execute("""
            SELECT offset FROM signals WHERE signal_name = ?
            """, (signal_name,))
            ergebnisse = c.fetchall()
            
            if ergebnisse:
                offset_value_arr.append(ergebnisse[0][0])
            else:
                # Fallback: wenn Signal noch nicht in DB, nutze default-Wert
                #hex_value_arr.append("00")  # Default-Wert
                print(f"[WARNUNG] Signal '{signal_name}' nicht in DB gefunden, nutze Default")
            
    finally:
        conn.close()
    
    return offset_value_arr

"""
def hex_to_float32(hex_string):
    #Konvertiert Hex-String zu Float32 (unterstützt variable Längen)
    try:
        # Entferne Leerzeichen und mache uppercase
        hex_string = hex_string.replace(" ", "").upper()
        
        # IMMER auf 8 Zeichen (4 Bytes) auffüllen mit führenden Nullen
        hex_string = hex_string.zfill(8)
        
        # Wenn länger als 8, schneide ab
        if len(hex_string) > 8:
            hex_string = hex_string[:8]
        
        print(f"[DEBUG] Hex-String nach Padding: {hex_string}")
        
        # Teile in Byte-Paare und kehre um (Little Endian -> Big Endian)
        bytes_list = [hex_string[i:i+2] for i in range(0, 8, 2)]
        big_endian_hex = "".join(reversed(bytes_list))
        
        # Konvertiere zu Bytes und dann zu Float
        bytes_data = binascii.unhexlify(big_endian_hex)
        float_value = struct.unpack('>f', bytes_data)[0]
        
        return float_value
    except Exception as e:
        print(f"[Fehler] Konvertierung von '{hex_string}': {e}")
        return 0.0
"""

def calc_crc16(data: bytes) -> int:
    """CRC16-CCITT (0x1021)"""
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
    bytes_le = struct.pack('<f', value32)   # little-endian bytes
    bytes_be = bytes_le[::-1]
    uint32 = int.from_bytes(bytes_be, byteorder='big', signed=False)            # Konvertiere big-endian bytes zu Integer
    return uint32

def calc_hex_to_physical_val(hex_value, factor, offset):
    calculated_int = int(hex_value, 16)
    result = (calculated_int * factor) + offset
    return result



def send_msg_continuously(signal_names, stop_event):
    """Thread 2: Liest kontinuierlich aus DB und sendet Daten"""
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

    qf_signals_list = [0x00] * 9

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, 25, INTERFACE)
    sock.bind((SOURCE_IP, SOURCE_PORT))


    while not stop_event.is_set():
        try:
            # Lese aktuelle Hex-Werte aus DB
            signal_hex_values = get_data_from_db(signal_names)
            signal_factor_val_arr = get_signal_factor_from_db(signal_names)
            signal_offset_val_arr = get_signal_offset_from_db(signal_names)
            
            print(f"[DEBUG] Hex-Werte aus DB: {signal_hex_values}")
           # print(f"Testausgabe: {calc_hex_to_physical_val(signal_hex_values[0], 0.00012207, -3.92)}")
            
            # Konvertiere jeden Hex-Wert zu Float32
            signal_float_values = []
            for i, hex_val in enumerate(signal_hex_values):
                float_val = calc_hex_to_physical_val(hex_val, signal_factor_val_arr[i], signal_offset_val_arr[i])
                signal_float_values.append(float_val)
                #print(f"[DEBUG] Signal {i} ({signal_names[i]}): '{hex_val}' -> {float_val:.6f}")
                #float32_to_uint32_be_int(-0.0002)
                print(f"Testausgabe: {signal_names[i]}  Faktor: {signal_factor_val_arr[i]} - Offset: {signal_factor_val_arr[i]} - Result: {signal_float_values[i]}")
            
            # E2E Payload aufbauen mit Float-Werten
            E2E_PAYLOAD_RAW = b''
            for float_val in signal_float_values:
                # Float32 als Little Endian packen
                E2E_PAYLOAD_RAW += struct.pack("<f", float_val)
            
            # Quality Flags hinzufügen
            for qf in qf_signals_list:
                E2E_PAYLOAD_RAW += struct.pack("B", qf)

            # Padding auf E2E_PAYLOAD_LENGTH
            if len(E2E_PAYLOAD_RAW) < E2E_PAYLOAD_LENGTH:
                E2E_PAYLOAD_RAW += bytes(E2E_PAYLOAD_LENGTH - len(E2E_PAYLOAD_RAW))

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

            # Komplettes UDP-Paket zusammenbauen
            udp_payload = header_part1 + header_part2 + someip_payload
            
            # Senden
            sock.sendto(udp_payload, (RADAR_IP, DEST_PORT))

            print(f"[SEND] SOME/IP Nachricht gesendet (SQC={SQC}, CRC=0x{crc:04X}, Länge={len(udp_payload)} Bytes)")
            #if len(signal_float_values) > 1:
                #print(f"[SEND] Beispiel - Signal 1: {signal_float_values[1]:.6f}")

            SQC = (SQC + 1) % 256
            time.sleep(0.02) 

        except Exception as e:
            print(f"[Fehler] im Sende-Thread: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(1)

    sock.close()


if __name__ == "__main__":
    # Initialisierung
    init_db()
    
    # Signalnamen laden
    signals = read_signals_from_file('/home/admin/Praxissemester/script/required_signals.txt')
    
    # Stop-Event für sauberes Beenden
    stop_event = threading.Event()
    
    # Thread 1: CAN-Daten lesen und in DB schreiben
    can_thread = threading.Thread(target=get_data_from_canoe, args=(stop_event,))
    can_thread.daemon = True
    
    # Thread 2: DB auslesen und senden
    send_thread = threading.Thread(target=send_msg_continuously, args=(signals, stop_event))
    send_thread.daemon = True
    
    # Threads starten
    can_thread.start()
    send_thread.start()
    

    
    try:
        # Hauptthread wartet
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        can_thread.join(timeout=2)
        send_thread.join(timeout=2)
        print("Programm beendet.")