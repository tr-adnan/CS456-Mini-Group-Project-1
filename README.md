# CS456 - Mini Group Project 1

This repository contains our group project for **CS456: Modern Cybersecurity** at **Colorado State University**.

The project explores system availability through a simulated firewall, heartbeat monitoring, automatic failover, and adversarial testing.

## Project Files

- `vulnerable_firewall.py` - Primary firewall with dynamic state and simulated crashes.
- `heartbeat_monitor.py` - Detects failures and triggers automatic failover.
- `backup_firewall.py` - Restores saved state and takes over after a crash.
- `checkpoint.py` - Saves and verifies firewall checkpoints.
- `traffic_generator.py` - Generates test traffic and checks firewall state.
- `adversary_assessment.py` - Part 1 spoofing and replay attacks.
- `adversary_assessment2.py` - Part 2 false failover and checkpoint tampering attacks.

## How to Run

Run each script in a separate terminal. Stop previous processes before starting another experiment.

**Default settings (except Part 2, Scenario 1):**
- Firewall: `MONITOR_PORT = 9999`
- Monitor: `FIREWALL_PORT = 8080`

### Part 1: Crash Detection

Set `ENABLE_AUTO_FAILOVER = False` in `heartbeat_monitor.py`.

**Normal Operation:**

`python vulnerable_firewall.py` → `python heartbeat_monitor.py` → `python traffic_generator.py`

**Crash Detection:**

`python vulnerable_firewall.py` → `python heartbeat_monitor.py` → `python traffic_generator.py --crash-test`

**Attack 1 - Heartbeat Spoofing:**

`python vulnerable_firewall.py` → `python heartbeat_monitor.py` → `python adversary_assessment.py --spoof` → `python traffic_generator.py --crash-test`

**Attack 2 - Replay Attack:**

`python adversary_assessment.py --replay` → `python vulnerable_firewall.py` → Wait for heartbeat capture → `python heartbeat_monitor.py` → `python traffic_generator.py --crash-test`

For both attacks, press `Ctrl+C` in the adversarial script's terminal to stop the fake heartbeats and observe the monitor detecting the failure.

### Part 2: Automatic Failover

Set `ENABLE_AUTO_FAILOVER = True` in `heartbeat_monitor.py`.

**Execution Order:**

`python vulnerable_firewall.py` → `python heartbeat_monitor.py` → `python traffic_generator.py` → `python traffic_generator.py --crash-test` → Wait for automatic recovery → `python traffic_generator.py --status`

The monitor automatically starts the backup after a crash. The restored state should include the dynamically blocked IP `10.0.0.66`.

### Part 2: Adversarial Assessment

**Scenario 1 - False Failover (Split-Brain)**

Change the following settings:
- Firewall: `MONITOR_PORT = 9998`
- Monitor: `FIREWALL_PORT = 8070`
- In `adversary_assessment2.py`, set `attack_mode = True` to block heartbeat communication (`False` for normal forwarding).

**Execution Order:**

`python adversary_assessment2.py --scenario-1` → `python vulnerable_firewall.py` → `python heartbeat_monitor.py`

The attacker acts as a proxy and interrupts communication while the primary is still running to test false failover behavior.

**Scenario 2 - Checkpoint Tampering**

Restore the default port settings (`9999` and `8080`).

**Execution Order:**

`python vulnerable_firewall.py` → `python heartbeat_monitor.py` → `python adversary_assessment2.py --scenario-2 malformed` → `python traffic_generator.py --crash-test`

Available test modes:
- `malformed` - Corrupts the checkpoint format.
- `timestamp` - Changes the checkpoint timestamp.
- `signature` - Modifies the checkpoint signature.

Run one mode at a time and observe how the backup handles the modified checkpoint.

## Disclaimer

This project was developed strictly for educational purposes as part of our cybersecurity coursework at CSU. All testing is performed in a controlled, local environment using simulated traffic. The code is not intended for malicious activities or use against systems without proper authorization.
