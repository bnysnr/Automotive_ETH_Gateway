import socket
import struct
import time

def calc_crc16(data: bytes):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# --- Konfigurationen ---
SOURCE_IP = '192.168.16.99'
RADAR_IP = '192.168.16.15'
RADAR_PORT = 60000
SOURCE_PORT = 2001

# SOME/IP Header Konstanten (Big Endian - Network Byte Order: !)
SERVICE_ID = 0x0002
METHOD_ID = 0x1000
CLIENT_ID = 0x0000 
SESSION_ID = 0x03C4 
PROTOCOL_VERSION = 0x01
INTERFACE_VERSION = 0x01
MESSAGE_TYPE = 0x02
RETURN_CODE = 0x00


SQC = 0x01
DATA_ID = 0x03E8
E2E_PAYLOAD_LEN_EXPECTED = 78 # 78 Byte

# EgoMotion Daten 
float_signals_list = [0xCDCC4C3E, 0xCDCC8CBF, 0x713D0A3F, 0xCDCC4C3F, 0xCDCC4C3F, 0xCDCC4C3F, 0xCDCC4C3F, 0x3333333F, 0x9A9999BF]
qf_signals_list = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02]



while True:
    try:
        SQC = (SQC + 1) % 256

        # E2E Payload (Little Endian Signale)
        E2E_PAYLOAD = b''
        for hex_value in float_signals_list:
            E2E_PAYLOAD += struct.pack("<I", hex_value)
        for qf_value in qf_signals_list:
            E2E_PAYLOAD += struct.pack("B", qf_value)
       
        PADDING_LEN = E2E_PAYLOAD_LEN_EXPECTED - len(E2E_PAYLOAD)
        E2E_PAYLOAD += bytes(PADDING_LEN)

        # CRC Input Daten (WICHTIG: E2E-Felder Little Endian)
       
        # SOME/IP Header Part 2 (Big Endian)
        header_part2 = struct.pack("!HHBBBB", CLIENT_ID, SESSION_ID, 
                                    PROTOCOL_VERSION, INTERFACE_VERSION,
                                    MESSAGE_TYPE, RETURN_CODE)
       
        crc_input = header_part2
       
        # E2E-Länge und Data-ID Little Endian (<H)
        crc_input += struct.pack("<H", E2E_PAYLOAD_LEN_EXPECTED) 
        crc_input += struct.pack("B", SQC)                    
        crc_input += E2E_PAYLOAD                             
        crc_input += struct.pack("<H", DATA_ID)                  

        crc = calc_crc16(crc_input)

       
        # 1. E2E Header (CRC, E2E Payload Length, SQC)
        e2e_header = struct.pack("<HHB", crc, E2E_PAYLOAD_LEN_EXPECTED, SQC)
       
        # 2. Data ID (Little Endian)
        DATA_ID_PACKED = struct.pack("<H", DATA_ID)

        # 3. SOME/IP Payload
        someip_payload = e2e_header + E2E_PAYLOAD + DATA_ID_PACKED
       
        # 4. SOME/IP Message Length (Big Endian)
        someip_length = 86
       
        # 5. SOME/IP Header Teil 1 (Big Endian)
        message_id = (SERVICE_ID << 16) | METHOD_ID
        header_part1 = struct.pack("!II", message_id, someip_length)

        # 6. UDP Payload (SOME/IP Message)
        udp_payload = header_part1 + header_part2 + someip_payload

        # UDP Aufbau
        udp_length = len(udp_payload) + 8
        udp_checksum = 0x0000 

        udp_header = struct.pack("!HHHH", SOURCE_PORT, RADAR_PORT, udp_length, udp_checksum)
        udp_datagram = udp_header + udp_payload
       
       
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((SOURCE_IP, SOURCE_PORT))

        print(f"\n--- Sende SOME/IP Paket (SQC: {SQC}) ---")
        print(f"SOME/IP Length Feld: {someip_length} Byte")
        print(f"E2E Payload Länge: {len(E2E_PAYLOAD)} Byte")
        print(f"Berechneter CRC: 0x{crc:04X}")

        sock.sendto(udp_datagram, (RADAR_IP, RADAR_PORT))
        print("Nachricht erfolgreich gesendet.")
       
        sock.close()
        time.sleep(0.2)

    except Exception as e:
        print(f"Fehler beim Senden: {e}")
        break