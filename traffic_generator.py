import socket
import json
import time

TARGET_HOST = '127.0.0.1'
TARGET_PORT = 8080

def send_packet(src_ip, payload_str):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_HOST, TARGET_PORT))
        
        packet = json.dumps({
            "src_ip": src_ip, 
            "dest_port": 443, 
            "payload": payload_str
        })
        
        s.sendall(packet.encode('utf-8'))
        s.close()
        print(f"[+] Sent from {src_ip}: {payload_str}")
        return True
        
    except ConnectionRefusedError:
        print("[-] Connection refused. The firewall service has crashed!")
        return False

if __name__ == "__main__":
    print("Sending normal traffic...")
    for _ in range(2):
        send_packet("10.0.0.99", "NORMAL_DATA")
        time.sleep(0.5)

    print("\nSending traffic from blacklisted IP...")
    send_packet("192.168.1.100", "MALICIOUS_SCAN")
    time.sleep(1)

    print("\nSending poisoned packets to trigger the non-deterministic crash...")
    for i in range(1, 20):
        if not send_packet("10.0.0.99", f"POISON_HEX_0xDEADBEEF (Attempt {i})"):
            print("Successfully verified the firewall termination.")
            break
        time.sleep(0.2)