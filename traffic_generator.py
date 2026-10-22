import socket
import json
import sys
import time

# Firewall connection settings
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8080

# Simulated source IPs used for testing
ALLOWED_TEST_IPS = ("10.0.0.99", "10.0.0.100")
BLACKLISTED_TEST_IPS = ("192.168.1.100", "192.168.1.101")


def send_packet(src_ip, payload):
    """Send a simulated packet to the firewall."""
    packet = json.dumps({
        "src_ip": src_ip,
        "dest_port": 443,
        "payload": payload
    })

    try:
        with socket.create_connection((TARGET_HOST, TARGET_PORT)) as connection:
            connection.sendall(packet.encode("utf-8"))

        print(f"[+] Sent from {src_ip}: {payload}")
        return True

    except ConnectionRefusedError:
        print("[-] Connection refused. Firewall may have stopped or crashed.")
        return False


def main():
    """Run normal tests, with crash testing only when requested."""
    print("Sending normal traffic...")
    for ip in ALLOWED_TEST_IPS:
        send_packet(ip, "NORMAL_DATA")
        time.sleep(0.5)

    print("\nSending traffic from blacklisted IPs...")
    for ip in BLACKLISTED_TEST_IPS:
        send_packet(ip, "TEST_BLOCK")
        time.sleep(0.5)

    # Only send poisoned traffic when crash testing is requested
    if "--crash-test" not in sys.argv:
        print("\nNormal testing complete. No poisoned traffic sent.")
        return

    print("\nSending poisoned traffic to test random firewall crashes...")
    for i in range(1, 20):
        if not send_packet("10.0.0.99", f"POISON_HEX_0xDEADBEEF (Attempt {i})"):
            print("Firewall unavailable. Stopping traffic test.")
            break
        time.sleep(0.2)


if __name__ == "__main__":
    main()
