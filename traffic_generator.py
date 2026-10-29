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
DYNAMIC_BLOCK_IP = "10.0.0.66"


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


def send_request(request):
    """Send a control request to the firewall and return its JSON reply."""
    try:
        with socket.create_connection((TARGET_HOST, TARGET_PORT)) as connection:
            connection.sendall(json.dumps(request).encode("utf-8"))
            connection.shutdown(socket.SHUT_WR)

            reply = b""
            while chunk := connection.recv(1024):
                reply += chunk

        return json.loads(reply.decode("utf-8")) if reply else None

    except ConnectionRefusedError:
        print("[-] Connection refused. Firewall may have stopped or crashed.")
        return None


def print_status():
    """Ask the firewall for its current state and print it."""
    status = send_request({"type": "status"})
    if status is None:
        return

    print("\nFirewall state:")
    print(f"    Blocklist: {', '.join(status['blocklist'])}")
    print(f"    Allowed: {status['allowed']}  Blocked: {status['blocked']}")


def main():
    """Run normal tests, with crash testing or status checks only when requested."""
    # Only query the firewall state, e.g. after a failover
    if "--status" in sys.argv:
        print_status()
        return

    print("Sending normal traffic...")
    for ip in ALLOWED_TEST_IPS:
        send_packet(ip, "NORMAL_DATA")
        time.sleep(0.5)

    print("\nSending traffic from blacklisted IPs...")
    for ip in BLACKLISTED_TEST_IPS:
        send_packet(ip, "TEST_BLOCK")
        time.sleep(0.5)

    print(f"\nAdding a dynamic block rule for {DYNAMIC_BLOCK_IP}...")
    if send_request({"type": "block", "ip": DYNAMIC_BLOCK_IP}):
        send_packet(DYNAMIC_BLOCK_IP, "TEST_DYNAMIC_BLOCK")
        time.sleep(0.5)

    print_status()

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
