import socket
import struct
import time
import binascii
import numpy as np

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

def hex_to_float32(hex_value: int) -> float:            # Konvertiert 32-bit Integer (Hexform) zu Float32
    try:
        if not isinstance(hex_value, int):
            raise TypeError("hex_value muss ein int sein")
        hex_string = f"{hex_value:08X}"
        bytes_list = [hex_string[i:i+2] for i in range(0, 8, 2)]
        big_endian_hex = "".join(reversed(bytes_list))
        bytes_data = binascii.unhexlify(big_endian_hex)
        float_value = struct.unpack('>f', bytes_data)[0]
        return float_value
    except Exception as e:
        print(f"[Fehler] Konvertierung von '{hex_value}': {e}")
        return 0.0

def float32_to_uint32_be_int(value: float) -> int:
    value32 = np.float32(value)
    bytes_le = struct.pack('<f', value32)   # little-endian bytes
    bytes_be = bytes_le[::-1]
    uint32 = int.from_bytes(bytes_be, byteorder='big', signed=False)            # Konvertiere big-endian bytes zu Integer
    return uint32


# Netzwerk / SOME/IP Konfig
SOURCE_IP = "192.168.16.5"
RADAR_IP = "192.168.16.15"
SOURCE_PORT = 2001
DEST_PORT = 60000
INTERFACE = b"eth0.34\0"  # VLAN 0x22 (ID 34)

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

float_signals_list = [
    float32_to_uint32_be_int(-0.0002),  # YawRate
    float32_to_uint32_be_int(-0.0111), # StWhlAngle
    float32_to_uint32_be_int(0.2070),   # LatAccel
    float32_to_uint32_be_int(0.0),      # WhlVelFrLeft
    float32_to_uint32_be_int(0.0),      # WhlVelFrRight
    float32_to_uint32_be_int(0.0625),   # WhlVelReLeft
    float32_to_uint32_be_int(0.0),      # WhlVelReRight
    float32_to_uint32_be_int(4.5977),   # VehVelocityExt
    float32_to_uint32_be_int(0.7000)    # VehLongAccelExt
]

qf_signals_list = [
    0x00,  # YawRate_qf
    0x00,  # StWheelAngle_Qf
    0x00,  # LatAccel_Qf
    0x00,  # WhlVelFrLeft_Qf
    0x00,  # WhlVelFrRight_Qf
    0x00,  # WhlVeReLeft_Qf
    0x00,  # WhlVeReRight_Qf
    0x00,  # VehVelocityExt_Qf
    0x00   # VehLongAccelExt_Qf
]

print(f"Testausgabe der neuen Funktion (StWhlAngle raw int): {float_signals_list[1]:#010X}")

# Socket aufbauen
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, 25, INTERFACE)  
sock.bind((SOURCE_IP, SOURCE_PORT))

try:
    while True:
        try:

            E2E_PAYLOAD_RAW = b''
            for val in float_signals_list:
                if not isinstance(val, int):
                    raise TypeError(f"Erwarte int für float_signals_list, bekam {type(val)}")
                E2E_PAYLOAD_RAW += struct.pack("<I", val)

            for qf in qf_signals_list:
                E2E_PAYLOAD_RAW += struct.pack("B", qf)

            if len(E2E_PAYLOAD_RAW) < E2E_PAYLOAD_LENGTH:
                E2E_PAYLOAD_RAW += bytes(E2E_PAYLOAD_LENGTH - len(E2E_PAYLOAD_RAW))
            elif len(E2E_PAYLOAD_RAW) > E2E_PAYLOAD_LENGTH:
                print(f"[WARN] E2E payload länger ({len(E2E_PAYLOAD_RAW)}) als erwartet ({E2E_PAYLOAD_LENGTH})")

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

            # CRC Eingabe
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

            # Gesamter Frame
            udp_payload = header_part1 + header_part2 + someip_payload
            sock.sendto(udp_payload, (RADAR_IP, DEST_PORT))

            readable_stwhl = hex_to_float32(float_signals_list[0])
            print(f"SOME/IP Nachricht gesendet (SQC={SQC}, CRC=0x{crc:04X}) - YawRate = {readable_stwhl}")

            SQC = (SQC + 1) % 256
            time.sleep(0.02)

        except Exception as e:
            print(f"Fehler: {e}")
            break
finally:
    sock.close()