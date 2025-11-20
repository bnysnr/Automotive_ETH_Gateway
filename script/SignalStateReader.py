import pyshark
import datetime

sensor_ips = ["192.168.16.15", "192.168.16.12", "192.168.16.13", "192.168.16.14"]


DST_PORT = 40000
capture = pyshark.LiveCapture(
        interface="eth0",
        display_filter=f"udp && udp.dstport == {DST_PORT}"
    )

def read_udp_packet():
    

    print("Warte auf UDP-Pakete...")

    for packet in capture.sniff_continuously():
        try:
            if "ip" not in packet:
                continue

            if packet.ip.src not in sensor_ips:
                continue

            # schneller Zugriff auf Payload (keine teure Dekodierung)
            raw = packet.udp.payload.replace(":", "")
            if raw[0:4] == '0007':
                return raw[322:336]

        except KeyboardInterrupt:
            capture.close()
            print("Capture finished")

        except Exception as e:
            print("Fehler:", e)



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
    while True:
        signale_state_arr = []
        start = datetime.datetime.now()
        udp_packet_extracted = read_udp_packet()
        signal_states = signal_state_mapping(signale_state_arr, udp_packet_extracted)
        print_func(signal_states)
        ende = datetime.datetime.now()
        print(f"Dauer: {ende - start}")
        print("***************************************************************")