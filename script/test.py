import cantools
db = cantools.database.load_file('/home/admin/Praxissemester/dbc/J1939_MAN_1.dbc')

target_id = 0x18F0093E

try:
    message = db.get_message_by_frame_id(target_id)
except KeyError:
    print(f"Fehler; Target ID: {hex(target_id)} nicht in der DBC gefunden")
    exit()


print(f" Details für die Nachricht: {message.name} (ID: {hex(message.frame_id)})")

for signal in message.signals:
    if signal.name == "VDC2_YawRate_3E":
        print(f"Signalname: {signal.name}")
        print(f"Start Bit: {signal.start}")
        print(f"Laenge: {signal.length}")
        
        if signal.byte_order == 'little_endian':
            endianness = "Little Endian"
        else:
            endianness = "Big Endian"
        print(f"Endinaness: {endianness}")

        print(f"Einheit: {signal.unit}")
        print(f"Faktor: {(signal.scale)}")
        print(f"Offset: {signal.offset}")
        print("*****************************************************")
    
    # Gibt die Informationen zu den einzelnen CAN Botschaften aus