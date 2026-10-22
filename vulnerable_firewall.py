import socket
import json
import random
import sys
import threading
import time

# Firewall settings
TRAFFIC_HOST = "127.0.0.1"
TRAFFIC_PORT = 8080
BLACKLISTED_IPS = {"192.168.1.100", "192.168.1.101"}

# Heartbeat settings (Option A: Push)
MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 9999
HEARTBEAT_INTERVAL = 1.0


def send_heartbeats():
    """Send a heartbeat to the monitor every second."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as heartbeat_socket:
        while True:
            heartbeat_socket.sendto(b"HEARTBEAT", (MONITOR_HOST, MONITOR_PORT))
            time.sleep(HEARTBEAT_INTERVAL)


def inspect_packet(data):
    """Inspect simulated traffic and occasionally crash on poisoned payloads."""
    try:
        packet = json.loads(data.decode("utf-8"))
        src_ip = packet.get("src_ip")
        payload = packet.get("payload", "")

        if src_ip in BLACKLISTED_IPS:
            print(f"[-] BLOCKED: Packet from blacklisted IP {src_ip}")
            return

        print(f"[*] ALLOWED: Packet from {src_ip}: {payload}")

        # Simulate a crash with a 20% chance for poisoned payloads
        if "POISON" in payload and random.random() < 0.20:
            print("[!] Simulated firewall crash triggered by poisoned packet.")
            sys.exit(1)

    except json.JSONDecodeError:
        print("[-] Dropped malformed packet.")


def run_firewall():
    """Start the firewall and its background heartbeat sender."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((TRAFFIC_HOST, TRAFFIC_PORT))
        tcp_socket.listen(5)

        print(f"Firewall running on {TRAFFIC_HOST}:{TRAFFIC_PORT}")

        # Stop the heartbeat thread when the firewall process exits
        threading.Thread(target=send_heartbeats, daemon=True).start()
        print(f"Sending heartbeats to {MONITOR_HOST}:{MONITOR_PORT} every {HEARTBEAT_INTERVAL}s")

        while True:
            client_conn, _ = tcp_socket.accept()
            with client_conn:
                data = client_conn.recv(1024)
                if data:
                    inspect_packet(data)


if __name__ == "__main__":
    run_firewall()
