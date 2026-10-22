import logging
import socket
import time
from datetime import datetime
from pathlib import Path

# Monitor settings
MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 9999

# Heartbeat timing settings
HEARTBEAT_INTERVAL = 1.0
MISSED_BEAT_LIMIT = 3
DELAY_TOLERANCE = 0.5
TIMEOUT_WINDOW = HEARTBEAT_INTERVAL * MISSED_BEAT_LIMIT + DELAY_TOLERANCE

# Save monitor events to a log file
logging.basicConfig(
    filename=Path(__file__).with_name("heartbeat.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


def timestamp():
    """Return the current date and time."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_monitor():
    """Listen for heartbeats and detect when the firewall stops responding."""
    last_heartbeat = time.monotonic()
    firewall_down = False

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as monitor_socket:
        monitor_socket.bind((MONITOR_HOST, MONITOR_PORT))
        monitor_socket.settimeout(0.5)

        print(f"[{timestamp()}] Monitor listening on {MONITOR_HOST}:{MONITOR_PORT}")
        logging.info("Heartbeat monitor started")

        try:
            while True:
                try:
                    message, _ = monitor_socket.recvfrom(1024)

                    if message == b"HEARTBEAT":
                        last_heartbeat = time.monotonic()

                        # Check if the firewall has recovered
                        if firewall_down:
                            print(f"[{timestamp()}] RECOVERED: Firewall is responding again")
                            logging.info("Firewall heartbeat restored")
                            firewall_down = False
                        else:
                            print(f"[{timestamp()}] HEARTBEAT received: Firewall healthy")

                except socket.timeout:
                    pass

                # Alert if no heartbeat arrives within the timeout window
                if not firewall_down and time.monotonic() - last_heartbeat >= TIMEOUT_WINDOW:
                    print(f"[{timestamp()}] ALERT: Firewall unresponsive (no heartbeat for {TIMEOUT_WINDOW:.1f}s)")
                    logging.error("Firewall unresponsive: heartbeat timeout")
                    firewall_down = True

        except KeyboardInterrupt:
            print(f"\n[{timestamp()}] Heartbeat monitor stopped")
            logging.info("Heartbeat monitor stopped")


if __name__ == "__main__":
    run_monitor()
