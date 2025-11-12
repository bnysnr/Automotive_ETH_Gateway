import pyshark
import time

def capture_eth0():
    ip_addr_arr = []
    try:
        capture = pyshark.LiveCapture(interface='eth0')

        start_time = time.time()
        while True:
            capture.sniff(packet_count=1)  
            for packet in capture:
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    if src_ip not in ip_addr_arr:
                        ip_addr_arr.append(src_ip)

            # 5 Sekunden Timer
            if time.time() - start_time >= 5:
                break 

        print(f"Founded IP-Adresses: {ip_addr_arr}")

    except KeyboardInterrupt:
        print("\nCapture finished")
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")

if __name__ == "__main__":
    capture_eth0()
