import socket
import struct
import datetime


sensor_ips = {"192.168.16.15", "192.168.16.12", "192.168.16.13", "192.168.16.14"}

# Multicast-Adresse und Port
MCAST_GRP = '239.22.0.3'
UDP_PORT = 40000
INTERFACE_IP = '192.168.16.5'  

# Socket erstellen
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', UDP_PORT))  # auf alle Interfaces binden

# Multicast-Gruppe beitreten
mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(INTERFACE_IP))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print(f"Listening on multicast {MCAST_GRP} port {UDP_PORT}...")

def read_udp_packet():
    while True:
        data, addr = sock.recvfrom(4096)  
        if addr[0] not in sensor_ips:
            continue

        raw = data.hex()
        if raw.startswith("0007"):
            print(f"Sensor state values from IP Adress: {addr[0]}")     # addr[0] = IP Adress, addr[1] = Port
            extracted = raw[322:336]
            return extracted
        # Pakete, die nicht mit 0007 starten, ignorieren
        else:
            continue


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