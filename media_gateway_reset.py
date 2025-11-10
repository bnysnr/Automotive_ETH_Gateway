import socket
import struct

# Ziel-IP und Port
MEDIA_GATEWAY_IP = "192.168.0.49"   
MEDIA_GATEWAY_PORT = 30491

# SOME/IP Header-Felder
SERVICE_ID = 0x0124
METHOD_ID = 0x0001        # Reset Method
CLIENT_ID = 0x0001
SESSION_ID = 0x0001
PROTOCOL_VERSION = 0x01
INTERFACE_VERSION = 0x01
MESSAGE_TYPE = 0x01      # Request
RETURN_CODE = 0x00
REQUEST_ID = (CLIENT_ID << 16) | SESSION_ID

# Länge = 8 (feste Headerteile nach Length) + Payload (hier 0)
payload = b""
LENGTH = 8 + len(payload)

# SOME/IP Header zusammenbauen (16 Bytes)
someip_header = struct.pack(
    "!HHI4B",              # Netzwerkbyte-Reihenfolge (Big Endian)
    SERVICE_ID,
    METHOD_ID,
    LENGTH,
    (REQUEST_ID >> 24) & 0xFF,
    (REQUEST_ID >> 16) & 0xFF,
    (REQUEST_ID >> 8) & 0xFF,
    REQUEST_ID & 0xFF
)

# Weitere 4 Bytes: ProtocolVersion, InterfaceVersion, MessageType, ReturnCode
someip_tail = struct.pack("!4B", PROTOCOL_VERSION, INTERFACE_VERSION, MESSAGE_TYPE, RETURN_CODE)

# Gesamtnachricht
packet = someip_header + someip_tail + payload

# UDP Socket erstellen
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.168.0.100", 0))  

# Paket senden
sock.sendto(packet, (MEDIA_GATEWAY_IP, MEDIA_GATEWAY_PORT))
print(f"Reset-Request (MethodID=0x0010) an {MEDIA_GATEWAY_IP}:{MEDIA_GATEWAY_PORT} gesendet.")

# Auf Antwort warten (optional)
sock.settimeout(3)
try:
    data, addr = sock.recvfrom(1024)
    print(f"Antwort erhalten von {addr}: {data.hex()}")
except socket.timeout:
    print("Keine Antwort erhalten (Gerät könnte bereits neugestartet sein).")

sock.close()