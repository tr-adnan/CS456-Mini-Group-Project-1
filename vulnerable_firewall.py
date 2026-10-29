import socket
import json
import random
import sys
import threading
import time

from checkpoint import save_checkpoint

# Firewall settings
TRAFFIC_HOST = "127.0.0.1"
TRAFFIC_PORT = 8080
BLACKLISTED_IPS = {"192.168.1.100", "192.168.1.101"}

# Heartbeat settings (Option A: Push)
MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 9999
HEARTBEAT_INTERVAL = 1.0

# Checkpoint settings (Option A: Passive Redundancy)
CHECKPOINT_INTERVAL = 1.0

# Dynamic firewall state, shared by the request handler and the checkpoint thread
state_lock = threading.Lock()
state = {
    "blocklist": set(BLACKLISTED_IPS),
    "allowed": 0,
    "blocked": 0
}


def snapshot_state():
    """Return a JSON-friendly copy of the current firewall state."""
    with state_lock:
        return {
            "blocklist": sorted(state["blocklist"]),
            "allowed": state["allowed"],
            "blocked": state["blocked"]
        }


def restore_state(saved_state):
    """Replace the current firewall state with one loaded from a checkpoint."""
    with state_lock:
        state["blocklist"] = set(saved_state.get("blocklist", BLACKLISTED_IPS))
        state["allowed"] = saved_state.get("allowed", 0)
        state["blocked"] = saved_state.get("blocked", 0)


def send_heartbeats():
    """Send a heartbeat to the monitor every second."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as heartbeat_socket:
        while True:
            heartbeat_socket.sendto(b"HEARTBEAT", (MONITOR_HOST, MONITOR_PORT))
            time.sleep(HEARTBEAT_INTERVAL)


def save_checkpoints():
    """Periodically save the firewall state so a backup can resume from it."""
    while True:
        try:
            save_checkpoint(snapshot_state())
        except OSError as e:
            print(f"[!] Checkpoint save failed: {e}")
        time.sleep(CHECKPOINT_INTERVAL)


def block_ip(ip):
    """Add an IP to the dynamic blocklist."""
    with state_lock:
        state["blocklist"].add(ip)

    print(f"[+] RULE ADDED: {ip} is now blocked")
    return {"result": "blocked", "ip": ip}


def inspect_packet(data):
    """Inspect simulated traffic, answer state requests, and occasionally crash on poisoned payloads."""
    try:
        packet = json.loads(data.decode("utf-8"))

        # Control requests read or change the firewall state and get a reply
        if packet.get("type") == "status":
            return snapshot_state()
        if packet.get("type") == "block" and isinstance(packet.get("ip"), str):
            return block_ip(packet["ip"])

        src_ip = packet.get("src_ip")
        payload = packet.get("payload", "")

        with state_lock:
            is_blocked = src_ip in state["blocklist"]
            state["blocked" if is_blocked else "allowed"] += 1

        if is_blocked:
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
    """Start the firewall and its background heartbeat and checkpoint threads."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        # Prevent two firewalls from using the same port on Windows
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((TRAFFIC_HOST, TRAFFIC_PORT))
        tcp_socket.listen(5)

        print(f"Firewall running on {TRAFFIC_HOST}:{TRAFFIC_PORT}")

        # Stop the heartbeat thread when the firewall process exits
        threading.Thread(target=send_heartbeats, daemon=True).start()
        print(f"Sending heartbeats to {MONITOR_HOST}:{MONITOR_PORT} every {HEARTBEAT_INTERVAL}s")

        threading.Thread(target=save_checkpoints, daemon=True).start()
        print(f"Saving checkpoints every {CHECKPOINT_INTERVAL}s")

        while True:
            client_conn, _ = tcp_socket.accept()
            with client_conn:
                data = client_conn.recv(1024)
                if data:
                    reply = inspect_packet(data)
                    if reply is not None:
                        client_conn.sendall(json.dumps(reply).encode("utf-8"))


if __name__ == "__main__":
    run_firewall()
