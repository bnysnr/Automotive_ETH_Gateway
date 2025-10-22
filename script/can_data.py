import can
import json
import cantools

db = cantools.database.load_file('/home/admin/Praxissemester/dbc/J1939_MAN_1.dbc')
    
def json_reader(filename):
    try:
        with open(filename, 'r') as datei:
            daten = json.load(datei)
       
        can_ids = daten.get("can_ids", [])
        
       #  Ausgabe der übergebeben CAN-Signals ID's
        if can_ids:
            for id in can_ids:
                print(f"{id}")
        
    except Exception as a:
        print(f"Fehler: {a}")
    return can_ids

def test(can_id_input):
    bus = can.interface.Bus(channel='can0', interface='socketcan')
    message_test = bus.recv()

    # Konvertiere die CAN-ID von Hex-String in Integer
    for i in range(len(can_id_input)):
        can_id = int(can_id_input[i], 16)

        target_id = 0x18F0093E

        try:
            message = db.get_message_by_frame_id(target_id)
        except KeyError:
            print(f"Fehler; Target ID: {hex(target_id)} nicht in der DBC gefunden")
            exit()


        print(f" Details für die Nachricht: {message.name} (ID: {hex(message.frame_id)})")
        
        for signal in message.signals:
            if "YawRate" in signal.name:
                print("Signal gefunden")
                print(f"Signalname: {signal.name}")
                print(f"Start Bit: {signal.start}")
                print(f"Laenge: {signal.length}")
                
                if signal.byte_order == 'little_endian':
                    endianness = "Little Endian"
                else:
                    endianness = "Big Endian"
                print(f"Endinaness: {endianness}")

                print(f"Einheit: {signal.unit}")
                print(f"Faktor: {signal.scale}")
                print(f"Offset: {signal.offset}")
                

                print("Signal gefunden)")
                data_hex = ' '.join(format(byte, '02X') for byte in message_test.data)
                print(f"can0 {hex(message_test.arbitration_id)[2:].upper()} [{len(message_test.data)}] {data_hex}")
                print(f"Signalname: {signal.name}")
                start = int(signal.start / 8)
                length_buffer = int(signal.length / 8) 
                print(f"Start: {start} | {signal.start}")
                print(f"Neuer Start: {start}, Ziel: {length_buffer - 1}")
                data_arr = data_hex.split()
                lsb = data_arr[start]
                msb = data_arr[start + length_buffer - 1]
                print(f"LSB: {lsb}, MSB: {msb}")


                print("*****************************************************")
            # Nach dem gewünschten Signal suchen








    
    try:
        #while True:
            message = bus.recv()
            if message.arbitration_id == can_id:

                print("Signal gefunden)")
                data_hex = ' '.join(format(byte, '02X') for byte in message.data)
                print(f"can0 {hex(message.arbitration_id)[2:].upper()} [{len(message.data)}] {data_hex}")
                print(f"Signalname: {signal.name}")
                start = int(signal.start / 8) 
                print(f"Start: {start} | {signal.start}")
                print(f"Tes3: {data_hex.split()[start]}")
                

    except KeyboardInterrupt:
        print("\nProgramm beendet.")
        
    except Exception as e:
        print(f"Fehler: {e}")
    
    

    if bus:
        bus.shutdown()
        

if __name__ == "__main__":
    signals_id_arr = json_reader("/home/admin/Praxissemester/script/signal.json")
    test(signals_id_arr)