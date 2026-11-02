
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

**Important:** Check the settings before each test. Scenario 1 uses different ports, which must be reset afterward.

### Part 1: Crash Detection

**Required Settings:**

In `vulnerable_firewall.py`:
- `MONITOR_PORT = 9999`

In `heartbeat_monitor.py`:
- `ENABLE_AUTO_FAILOVER = False`
- `MONITOR_PORT = 9999`
- `FIREWALL_PORT = 8080`

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

**Required Settings:**

In `vulnerable_firewall.py`:
- `MONITOR_PORT = 9999`

In `heartbeat_monitor.py`:
- `ENABLE_AUTO_FAILOVER = True`
- `MONITOR_PORT = 9999`
- `FIREWALL_PORT = 8080`

**Execution Order:**

`python vulnerable_firewall.py` → `python heartbeat_monitor.py` → `python traffic_generator.py` → `python traffic_generator.py --crash-test` → Wait for automatic recovery → `python traffic_generator.py --status`

The monitor should receive heartbeats every second. Once the primary crashes, it automatically starts the backup and restores the saved state. The blocklist should still include `10.0.0.66`.

### Part 2: Adversarial Assessment

#### Scenario 1 - False Failover (Split-Brain)

**Required Settings:**

In `vulnerable_firewall.py`:
- `MONITOR_PORT = 9998`

In `heartbeat_monitor.py`:
- `ENABLE_AUTO_FAILOVER = True`
- `MONITOR_PORT = 9999`
- `FIREWALL_PORT = 8070`

In `adversary_assessment2.py`:
- `attack_mode = True` - Blocks communication after forwarding several heartbeats.
- Set to `False` for normal forwarding.

**Execution Order:**

`python adversary_assessment2.py --scenario-1` → `python vulnerable_firewall.py` → `python heartbeat_monitor.py`

The attacker acts as a proxy, forwarding heartbeats from port `9998` to `9999` before blocking them. The monitor sends status requests through port `8070`. This simulates a communication failure while the primary firewall is still running.

**Important:** Reset the ports to `9999` and `8080` after this test.

#### Scenario 2 - Checkpoint Tampering

**Required Settings:**

In `vulnerable_firewall.py`:
- `MONITOR_PORT = 9999`

In `heartbeat_monitor.py`:
- `ENABLE_AUTO_FAILOVER = True`
- `MONITOR_PORT = 9999`
- `FIREWALL_PORT = 8080`

**Execution Order:**

`python vulnerable_firewall.py` → `python heartbeat_monitor.py` → `python traffic_generator.py` → `python adversary_assessment2.py --scenario-2 malformed` → `python traffic_generator.py --crash-test`

Available attack modes:
- `malformed` - Corrupts the checkpoint format.
- `timestamp` - Changes the checkpoint timestamp.
- `signature` - Modifies the checkpoint signature.

Replace `malformed` with either of the other modes to test them separately. Observe whether the backup rejects the altered checkpoint and starts with default rules.

## Disclaimer

This project was developed for educational purposes as part of our cybersecurity coursework at CSU. All testing is performed locally using simulated traffic. The code is not intended for malicious activity or use against systems without authorization.
