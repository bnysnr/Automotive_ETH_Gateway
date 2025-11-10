import can
import json
import cantools

# Laden der DBC-Datei
db = cantools.database.load_file('/home/admin/Praxissemester/dbc/J1939_MAN_1.dbc')
"""
def json_reader(filename):
    try:
        with open(filename, 'r') as datei:
            daten = json.load(datei)

        can_ids = daten.get("signal_names", [])

        # Ausgabe der übergebenen CAN-Signals ID's
        if can_ids:
            for id in can_ids:
                print(f"{id}")

    except Exception as a:
        print(f"Fehler: {a}")
    
    return can_ids
"""
    

def test():
    bus = can.interface.Bus(channel='can0', interface='socketcan')
    
    # Ziel-CAN-ID
    target_id = 0x18F0093E

    try:
        message = db.get_message_by_frame_id(target_id)
    except KeyError:
        print(f"Fehler: Target ID: {hex(target_id)} nicht in der DBC gefunden")
        return

    print(f"Details für die Nachricht: {message.name} (ID: {hex(message.frame_id)})")
    
    # Schleife zur Verarbeitung von CAN-Nachrichten
    try:
       # while True:
            message = bus.recv()  # Empfange eine CAN-Nachricht
            
            
            data_hex = ' '.join(format(byte, '02X') for byte in message.data)  # Hex-Daten formatieren
            #print(f"can0 {hex(message.arbitration_id)[2:].upper()} [{len(message.data)}] {data_hex}")  # Ausgabe im Format: can0 ID [Länge] Daten
            print(data_hex)
            
            # Hier kannst du zusätzliche Logik hinzufügen, um die Signale zu verarbeiten, falls erforderlich
            
    except KeyboardInterrupt:
        print("\nProgramm beendet.")
    except Exception as e:
        print(f"Fehler: {e}")

    if bus:
        bus.shutdown()

if __name__ == "__main__":
    #signals_id_arr = json_reader("/home/admin/Praxissemester/script/signal.json")
    test()
