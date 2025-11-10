import cantools
import can
import numpy as np
import struct


def float32_to_uint32_be_int(value: float) -> int:
    value32 = np.float32(value)
    bytes_le = struct.pack('<f', value32)   # little-endian bytes
    bytes_be = bytes_le[::-1]
    uint32 = int.from_bytes(bytes_be, byteorder='big', signed=False)            # Konvertiere big-endian bytes zu Integer
    return uint32


def test():
    try:
        db = cantools.database.load_file('/home/admin/Praxissemester/dbc/J1939_MAN_1.dbc')
    except Exception as e:
        print(f"Fehler bei der Datenbank: {e}")
    target_id = 0x18F0093E

    try:
        message = db.get_message_by_frame_id(target_id)
    except KeyError:
        print(f"Fehler; Target ID: {hex(target_id)} nicht in der DBC gefunden")
        exit()


    print(f" Details für die Nachricht: {message.name} (ID: {hex(message.frame_id)})")
    bus = can.interface.Bus(channel='can0', interface='socketcan')
    msg = bus.recv()

    for signal in message.signals:
        if signal.name == "VDC2_YawRate_3E":
            data_hex = ' '.join(format(byte, '02X') for byte in msg.data)  # Hex-Daten formatieren
            print(f"Hex Wert: {data_hex}")
            data_hex_formatted = data_hex.replace(" ", "")
            print(f"Signalname: {signal.name}")
            """
            print(f"Start Bit: {signal.start}")
            print(f"Laenge: {signal.length}")
            print(f"DBC: {signal.initial}")
            if signal.byte_order == 'little_endian':
                endianness = "Little Endian"
            else:
                endianness = "Big Endian"
            print(f"Endinaness: {endianness}")

            print(f"Einheit: {signal.unit}")
            """
            print(f"Faktor: {(signal.scale)}")
            print(f"Offset: {signal.offset}")
            """
            print(f"Hex Wert: {data_hex}")
            """
            final_result = data_hex_formatted[(signal.start // 4): (signal.start // 4 + signal.length // 4)]
            print(f"Hex Neu: {final_result}")
            byte_paare = [final_result[i:i+2] for i in range (0, len(final_result), 2)]
            byte_paare_little_endian = list(reversed(byte_paare))
            ergebnis = " ".join(byte_paare_little_endian)
            print(f"Byte Paare Little Endina: {byte_paare_little_endian}")
            endergebnis = "".join(byte_paare_little_endian)
            print(f"ENdergebnis: {endergebnis}")
            hex_to_decimal_value = int(endergebnis, 16)
            print(f"Berechneter Hex Wert: {hex_to_decimal_value}")
            final_decimal_value = (hex_to_decimal_value * signal.scale) + signal.offset 
            print(f"finaler neuer HEX-Wert: {final_decimal_value}")
            return float32_to_uint32_be_int(final_decimal_value)
    

if __name__ == "__main__":
    print(f"New: {test()}")