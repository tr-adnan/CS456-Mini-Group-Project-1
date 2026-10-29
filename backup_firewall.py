from datetime import datetime

import vulnerable_firewall as firewall
from checkpoint import load_checkpoint


def timestamp():
    """Return the current date and time."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_backup():
    """Load the latest checkpoint, then take over the primary firewall's address."""
    print(f"[{timestamp()}] BACKUP: Activating standby firewall")

    saved_state, saved_at = load_checkpoint()

    if saved_state is None:
        # Stay available with the default rules rather than refusing to start
        print(f"[{timestamp()}] BACKUP WARNING: No valid checkpoint found.")
        print("Starting with default rules. Previous dynamic state was not restored.")
    else:
        firewall.restore_state(saved_state)
        saved_time = datetime.fromtimestamp(saved_at).strftime("%Y-%m-%d %H:%M:%S") if saved_at else "unknown"
        restored = firewall.snapshot_state()
        print(f"[{timestamp()}] BACKUP: Restored checkpoint saved at {saved_time}")
        print(f"    Blocklist: {', '.join(restored['blocklist'])}")
        print(f"    Allowed: {restored['allowed']}  Blocked: {restored['blocked']}")

    firewall.run_firewall()


if __name__ == "__main__":
    run_backup()
