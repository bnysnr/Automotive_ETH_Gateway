import pyshark
import sys

SERVICE_ID = '0007'
sensor_ip_arr = ["192.168.16.15", "192.168.16.12", "192.168.16.13", "192.168.16.14"]

def capture_eth0(service_id):
    try:
        capture = pyshark.LiveCapture(interface='eth0')

        while True:
            capture.sniff(packet_count=1)
            for packet in capture:
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    for i in range(len(sensor_ip_arr)):
                        if src_ip == sensor_ip_arr[i]:
                            if hasattr(packet, 'data'):
                                print(f"Daten gefunden aus: {sensor_ip_arr[i]}")
                                
                                # Datenbytes vergleichen
                                if packet.data.data[:4] == service_id:
                                    return packet.data.data
                                
                            else:
                                print(f"No raw data in packet from IP adress: {sensor_ip_arr[i]}")
    

    except KeyboardInterrupt:
        print("\nCapture finished")
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")

def signal_state_mapping(arr, state_values):
    for i in range(0, len(state_values), 2):
        arr.append(state_values[i+1:i+2])
    return arr

def print_func(arr):
    print("Signal Status Value")
    print(f"Longitudinal Velocity: {arr[0]}")
    print(f"Longitudinal Acceleration: {arr[1]}")
    print(f"LateralAcceleration: {arr[2]}")
    print(f"YawRate: {arr[3]}")
    print(f"SteeringAngle: {arr[4]}")
    print(f"DrivingDirection: {arr[5]}")
    print(f"CharacteristicSpeed: {arr[6]}")


if __name__ == "__main__":
    signal_state_arr = []
    udp_data_payload = capture_eth0(SERVICE_ID)
    signal_status_value = udp_data_payload[322:336]
    print(udp_data_payload, len(udp_data_payload), " - " ,{signal_status_value})
    new_arr = signal_state_mapping(signal_state_arr, signal_status_value)
    print_func(new_arr)