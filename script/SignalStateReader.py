import pyshark
import sys

def capture_eth0():
    service_id_printed = False  

    try:
        capture = pyshark.LiveCapture(interface='eth0')

        while True:
            capture.sniff(packet_count=1)
            for packet in capture:
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    if src_ip == "192.168.16.15":
                        if hasattr(packet, 'data'):
                            # Datenbytes ausgeben
                            #print(f"Data bytes from {src_ip}: {packet.data.data}")
                            if packet.data.data[:4] == "0007":
                             #   print("found relevant signal")
                                return packet.data.data
                            
                            # Service ID nur einmal ausgeben
                           # if not service_id_printed:
                            #    service_id = packet.data.data[:4]  # ersten 4 Bytes als Service ID
                             #   service_id_printed = True
                              #  return service_id
                            #if service_id_printed:
                             #   sys.exit()
                        else:
                            print(f"No raw data in packet from {src_ip}")
    

    except KeyboardInterrupt:
        print("\nCapture finished")
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")

def signal_state_mapping(arr, state_values):
    for i in range(0, len(state_values), 2):
        arr.append(state_values[i+1:i+2])
    return arr

if __name__ == "__main__":
    signal_state_arr = []
    udp_data_payload = capture_eth0()
    signal_status_value = udp_data_payload[322:336]
    print(udp_data_payload, len(udp_data_payload), " - " ,{signal_status_value})
    new_arr = signal_state_mapping(signal_state_arr, signal_status_value)
    print(f"Array: {new_arr}")