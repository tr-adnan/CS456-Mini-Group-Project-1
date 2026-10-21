import socket
import json
import random
import sys
import threading
import time

TRAFFIC_HOST = '127.0.0.1'
TRAFFIC_PORT = 8080
BLACKLISTED_IP = "192.168.1.100"

# Option A: the firewall periodically sends heartbeats to the monitor.
MONITOR_HOST = '127.0.0.1'
MONITOR_PORT = 9999
HEARTBEAT_INTERVAL = 1.0


def send_heartbeats():
    """Send UDP heartbeat messages while this process is running."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as heartbeat_socket:
        while True:
            heartbeat_socket.sendto(b"HEARTBEAT", (MONITOR_HOST, MONITOR_PORT))
            time.sleep(HEARTBEAT_INTERVAL)


def inspect_packet(data):
    """
    Parses incoming dummy traffic, flags blacklisted IPs,
    and applies the stochastic crash trigger.
    """
    try:
        packet = json.loads(data.decode('utf-8'))
        src_ip = packet.get('src_ip')
        payload = packet.get('payload', '')

        # Check for blacklisted IP
        if src_ip == BLACKLISTED_IP:
            print(f"[-] BLOCKED: Dropped packet from blacklisted IP: {src_ip}")
            return

        print(f"[*] ALLOWED: Inspected packet from {src_ip}: {payload}")

        # Non-deterministic crash trigger on poisoned payloads
        if "POISON" in payload:
            if random.random() < 0.20:
                print("[!] FATAL ERROR: Unhandled memory exception triggered by poisoned payload.")
                sys.exit(1)

    except json.JSONDecodeError:
        print("[-] Dropped malformed packet.")


def run_firewall():
    """Main execution for the independent running process."""
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allows rapid restarting of the script during testing
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.bind((TRAFFIC_HOST, TRAFFIC_PORT))
    tcp_socket.listen(5)

    print(f"Firewall agent active. Listening for traffic on port {TRAFFIC_PORT}...")

    # Daemon thread stops when the firewall process exits after a crash.
    threading.Thread(target=send_heartbeats, daemon=True).start()
    print(f"Heartbeat sender active. Sending to {MONITOR_HOST}:{MONITOR_PORT} every {HEARTBEAT_INTERVAL}s")

    while True:
        client_conn, addr = tcp_socket.accept()
        data = client_conn.recv(1024)
        if data:
            inspect_packet(data)
        client_conn.close()


if __name__ == "__main__":
    run_firewall()
