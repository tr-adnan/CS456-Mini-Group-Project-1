# Team Member Contributions

### Adnan Alturkestani
Developed `heartbeat_monitor.py` to detect firewall failures, log alerts, and track recovery. Added the heartbeat sender to `vulnerable_firewall.py` and updated `traffic_generator.py` with additional test IPs and optional crash testing. Also reviewed and cleaned up the code, helped improve `adversary_assessment.py`, and created the repository `README.md`.

### Bode Kaanta
Developed `voulnerable_firewall.py` to set up a defective firewall that reads incoming payloads and will block certain payloads based off of ip address as well as have a 20% chance of crashing if the payload contains "POISON". If a payload is poisned and the 20% odds hit, then the firewall simulate a crash with an exit(1). Also created `traffic_generator.py` to test the firewall. The script tests the firewall by sending payloads with blocked ip's, allowed ip's, and allowed ip's with poised data. 

### Logan Uyetake
Developed `adversayry_assessment.py` to set up an attacker script to attempt to exploit a vulnerability in the architecture of `vulnerable_firewall.py` and `heartbeat_monitor.py`. Designed attack 1 to attempt to create a UDP socket and send hardcoded payloads to the monitor to fake a pulse from the firewall. Also Designed attack 2 to sniff out an outbound heartbeat packet from the firewall to capture the payload then repeat the process of attack 1.