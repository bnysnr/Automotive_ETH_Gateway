import binascii
import struct


def hex_to_float32(hex_value: int) -> float:
    """Konvertiert Hexadiazimalwert (Integer) zu Float32"""
    try:
        # Konvertiere die Ganzzahl in einen 8-stelligen Hex-String
        hex_string = f"{hex_value:08X}"
        print(f"[DEBUG] Hex-String nach Padding: {hex_string}")

        # Teile in Byte-Paare und kehre um (Little Endian -> Big Endian)
        bytes_list = [hex_string[i:i+2] for i in range(0, 8, 2)]
        big_endian_hex = "".join(reversed(bytes_list))

        # Konvertiere zu Bytes und dann zu Float
        bytes_data = binascii.unhexlify(big_endian_hex)
        float_value = struct.unpack('>f', bytes_data)[0]

        return float_value
    except Exception as e:
        print(f"[Fehler] Konvertierung von '{hex_value}': {e}")
        return 0.0
    
if __name__ == "__main__":
    hex_value = 0x8A6CA43C
    result = hex_to_float32(hex_value)
    print(f"Ergebnis:  {result}")