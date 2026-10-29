import json
import logging
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Set to True if testing MP1.2. Keep False if testing MP1.1.
ENABLE_AUTO_FAILOVER = True

# Monitor settings
MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 9999

# Heartbeat timing settings
HEARTBEAT_INTERVAL = 1.0
MISSED_BEAT_LIMIT = 3
DELAY_TOLERANCE = 0.5
TIMEOUT_WINDOW = HEARTBEAT_INTERVAL * MISSED_BEAT_LIMIT + DELAY_TOLERANCE

FIREWALL_HOST = "127.0.0.1"
FIREWALL_PORT = 8080
BACKUP_SCRIPT = Path(__file__).with_name("backup_firewall.py")

logging.basicConfig(
    filename=Path(__file__).with_name("heartbeat.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def timestamp():
    """Return the current date and time."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def firewall_responding():
    """Check whether a firewall is answering client status requests."""
    try:
        with socket.create_connection((FIREWALL_HOST, FIREWALL_PORT), timeout=0.5) as conn:
            conn.settimeout(0.5)
            conn.sendall(b'{"type":"status"}')
            conn.shutdown(socket.SHUT_WR)
            reply = conn.recv(2048)
        status = json.loads(reply.decode("utf-8"))
        return isinstance(status, dict) and "blocklist" in status
    except (OSError, ValueError):
        return False


def run_monitor():
    """Detect missing heartbeats and optionally launch the backup firewall."""
    last_heartbeat = time.monotonic()
    firewall_down = False
    heartbeat_seen = False
    warned_primary_alive = False
    failover_started = False
    backup_process = None
    service_restored = False
    next_retry_time = 0.0

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
                        heartbeat_seen = True
                        last_heartbeat = time.monotonic()
                        if firewall_down:
                            if not ENABLE_AUTO_FAILOVER or firewall_responding():
                                print(f"[{timestamp()}] RECOVERED: Firewall heartbeat received")
                                logging.info("Firewall heartbeat restored")
                                firewall_down = False
                                warned_primary_alive = False
                        else:
                            print(f"[{timestamp()}] HEARTBEAT received: Firewall healthy")
                except socket.timeout:
                    pass

                if not firewall_down and time.monotonic() - last_heartbeat >= TIMEOUT_WINDOW:
                    print(f"[{timestamp()}] ALERT: Firewall unresponsive (no heartbeat for {TIMEOUT_WINDOW:.1f}s)")
                    logging.error("Firewall unresponsive: heartbeat timeout")
                    firewall_down = True

                # Only fail over once a primary has been observed sending heartbeats.
                if (ENABLE_AUTO_FAILOVER and firewall_down and heartbeat_seen
                        and not failover_started and time.monotonic() >= next_retry_time):
                    if firewall_responding():
                        if not warned_primary_alive:
                            print(f"[{timestamp()}] WARNING: Firewall still responds; failover withheld")
                            logging.warning("Heartbeat missing, but firewall still responds")
                            warned_primary_alive = True
                    else:
                        print(f"[{timestamp()}] [Crash Detected] Firewall not responding")
                        logging.error("[Crash Detected] Firewall not responding")
                        failover_started = True
                        try:
                            # Keep the backup independent of the monitor terminal.
                            process_options = (
                                {"creationflags": subprocess.CREATE_NEW_CONSOLE}
                                if sys.platform == "win32" else {"start_new_session": True}
                            )
                            backup_process = subprocess.Popen(
                                [sys.executable, str(BACKUP_SCRIPT)],
                                cwd=str(BACKUP_SCRIPT.parent),
                                **process_options,
                            )
                            print(f"[{timestamp()}] [Failover Triggered] Starting backup firewall")
                            logging.info("[Failover Triggered] Starting backup firewall")
                        except OSError as error:
                            print(f"[{timestamp()}] ERROR: Could not start backup: {error}")
                            logging.error("Could not start backup: %s", error)
                            failover_started = False
                            next_retry_time = time.monotonic() + 2.0

                # Confirm the new service is running before logging successful recovery.
                if backup_process is not None and not service_restored:
                    if firewall_responding():
                        print(f"[{timestamp()}] [Service Restored] Backup firewall is responding")
                        logging.info("[Service Restored] Backup firewall is responding")
                        service_restored = True
                        last_heartbeat = time.monotonic()
                        firewall_down = False
                    elif backup_process.poll() is not None:
                        print(f"[{timestamp()}] ERROR: Backup exited before recovery")
                        logging.error("Backup exited before recovery")
                        backup_process = None
                        failover_started = False
                        next_retry_time = time.monotonic() + 2.0

        except KeyboardInterrupt:
            print(f"\n[{timestamp()}] Heartbeat monitor stopped")
            logging.info("Heartbeat monitor stopped")


if __name__ == "__main__":
    run_monitor()
