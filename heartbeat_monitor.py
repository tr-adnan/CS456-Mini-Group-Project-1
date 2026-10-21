import logging
import socket
import time
from datetime import datetime
from pathlib import Path

MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 9999

HEARTBEAT_INTERVAL = 1.0  # Expected seconds between heartbeats (T)
MISSED_BEAT_LIMIT = 3     # Allowed missed heartbeats (N)
DELAY_TOLERANCE = 0.5     # Extra time to avoid false positives
TIMEOUT_WINDOW = HEARTBEAT_INTERVAL * MISSED_BEAT_LIMIT + DELAY_TOLERANCE

logging.basicConfig(
    filename=Path(__file__).with_name("heartbeat.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def main():
    last_heartbeat = time.monotonic()
    is_down = False

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as monitor_socket:
        monitor_socket.bind((MONITOR_HOST, MONITOR_PORT))
        monitor_socket.settimeout(0.5)  # Periodically check for timeouts

        print(f"[{timestamp()}] Monitor listening on {MONITOR_HOST}:{MONITOR_PORT}")
        logging.info("Heartbeat monitor started")

        try:
            while True:
                try:
                    message, _ = monitor_socket.recvfrom(1024)
                    if message == b"HEARTBEAT":
                        last_heartbeat = time.monotonic()
                        if is_down:
                            print(f"[{timestamp()}] RECOVERED: Firewall heartbeat received")
                            logging.info("Firewall heartbeat restored")
                            is_down = False
                        else:
                            print(f"[{timestamp()}] HEARTBEAT received: Firewall healthy")
                except socket.timeout:
                    pass

                if not is_down and time.monotonic() - last_heartbeat >= TIMEOUT_WINDOW:
                    print(f"[{timestamp()}] ALERT: Firewall unresponsive (no heartbeat for {TIMEOUT_WINDOW:.1f}s)")
                    logging.error("Firewall unresponsive: heartbeat timeout")
                    is_down = True
        except KeyboardInterrupt:
            print(f"\n[{timestamp()}] Heartbeat monitor stopped")
            logging.info("Heartbeat monitor stopped")


if __name__ == "__main__":
    main()
