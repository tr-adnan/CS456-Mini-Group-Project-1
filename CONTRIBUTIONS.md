# Team Member Contributions

## MP1.1

### Adnan Alturkestani
Developed `heartbeat_monitor.py` to detect firewall failures, log alerts, and track recovery. Added the heartbeat sender to `vulnerable_firewall.py` and updated `traffic_generator.py` with additional test IPs and optional crash testing. Also reviewed and cleaned up the code, helped improve `adversary_assessment.py`, and created the repository `README.md`.

### Bode Kaanta
Developed `voulnerable_firewall.py` to set up a defective firewall that reads incoming payloads and will block certain payloads based off of ip address as well as have a 20% chance of crashing if the payload contains "POISON". If a payload is poisned and the 20% odds hit, then the firewall simulate a crash with an exit(1). Also created `traffic_generator.py` to test the firewall. The script tests the firewall by sending payloads with blocked ip's, allowed ip's, and allowed ip's with poised data. 

### Logan Uyetake
Developed `adversayry_assessment.py` to set up an attacker script to attempt to exploit a vulnerability in the architecture of `vulnerable_firewall.py` and `heartbeat_monitor.py`. Designed attack 1 to attempt to create a UDP socket and send hardcoded payloads to the monitor to fake a pulse from the firewall. Also Designed attack 2 to sniff out an outbound heartbeat packet from the firewall to capture the payload then repeat the process of attack 1.

### Crawford Rash
Wrote the write up, and recorded the video demo

## MP1.2

### Adnan Alturkestani
Updated `heartbeat_monitor.py` to automatically detect primary firewall failures, launch `backup_firewall.py`, and verify service recovery. Added timestamped failover logs and basic safeguards against false failovers while preserving Part 1 functionality. Also improved checkpoint validation and error handling in `checkpoint.py` and `backup_firewall.py`, cleaned up `README.md`, and tested automatic failover and state recovery.

### Bode Kaanta
Implemented the passive redundancy (Option A) state handling. Updated `vulnerable_firewall.py` to keep a dynamic blocklist and traffic counters and save them as checkpoints every second, created `checkpoint.py` to save and verify those checkpoints, and created `backup_firewall.py` to restore the latest checkpoint and take over after a crash. Also updated `traffic_generator.py` to add block rules and check the firewall state, and added the run instructions to `README.md`.

### Logan Uyetake
Developed `adversary_assessment2.py` to set up an attacker script to attempt to create a split-brain scenario by forcing the monitor to spin up a back up firewall when the original firewall was still active through a man in the middle tactic. Also designed scenario 2 to attempt to test checkpoint integrity in `heartbeat_monitor.py`. Scenario 2 test consisted of corrupting various aspects of checkpoint JSON.

### Crawford Rash

