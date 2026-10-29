# CS456 - Mini Group Project 1

This repository contains our group project for **CS456: Modern Cybersecurity** at **Colorado State University**.

The project focuses on building a simple firewall service and a heartbeat monitoring system to detect unexpected crashes and explore system availability.

## Project Files
- `vulnerable_firewall.py` - Simulates a firewall (primary node) that inspects traffic, keeps a dynamic blocklist and traffic counters, checkpoints that state every second, and randomly crashes when processing certain test payloads.
- `checkpoint.py` - Saves and loads signed firewall checkpoints (Part 2, Option A: Passive Redundancy).
- `backup_firewall.py` - Standby firewall that loads the latest checkpoint and takes over the primary's address.
- `traffic_generator.py` - Generates simulated traffic to test the firewall. Use `--crash-test` to send poisoned traffic and `--status` to query the firewall's current state.
- `heartbeat_monitor.py` - Monitors the firewall's availability.
- `adversary_assessment.py` - Tests heartbeat spoofing and replay attacks against the monitor.

## How to Run
### Part 1: Crash Detection
1. **Terminal 1** - Start the monitor:
   ```
   python heartbeat_monitor.py
   ```
2. **Terminal 2** - Start the firewall (do this within a few seconds of step 1, or the monitor will alert before the firewall is up):
   ```
   python vulnerable_firewall.py
   ```
   The monitor should start printing `HEARTBEAT received: Firewall healthy` every second.
3. **Terminal 3** - Send traffic:
   ```
   python traffic_generator.py
   ```
   To trigger the random crash, run `python traffic_generator.py --crash-test`. Repeat it until the firewall prints `Simulated firewall crash triggered by poisoned packet.` and exits.
4. About 3.5 seconds after the crash, the monitor prints an `ALERT: Firewall unresponsive` message. Alerts and recoveries are also saved to `heartbeat.log`.

### Part 2: Failover with Checkpoints
1. Follow Part 1, steps 1-3 (including `--crash-test`). While the primary runs, it saves its state to `firewall_checkpoint.json` every second.
2. **Terminal 2** - Once the primary has crashed, start the backup:
   ```
   python backup_firewall.py
   ```
   The backup prints the checkpoint it restored, then takes over port 8080. The monitor prints `RECOVERED: Firewall is responding again`.
3. **Terminal 3** - Confirm the pre-crash state survived:
   ```
   python traffic_generator.py --status
   ```
   The blocklist should still include the dynamically added `10.0.0.66`. The counters should match the backup's restored values, minus any traffic received after the last checkpoint.

### Adversarial Assessment (Part 1)
- **Heartbeat spoofing:** with the monitor and firewall running, run `python adversary_assessment.py --spoof` in a new terminal, then crash the firewall. The monitor keeps reporting the firewall as healthy.
- **Replay attack:** with the monitor stopped, run `python adversary_assessment.py --replay`, then start the firewall. After the heartbeat is captured, start the monitor and crash the firewall. The monitor keeps reporting the firewall as healthy.

## Disclaimer
This project was developed strictly for educational purposes as part of our cybersecurity coursework at CSU. All testing is performed in a controlled, local environment using simulated traffic. The code is not intended for malicious activities or use against any systems without proper authorization.
