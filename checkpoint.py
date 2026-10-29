import hashlib
import hmac
import json
import os
import time
import math
from pathlib import Path

# Checkpoint settings (Option A: Passive Redundancy)
CHECKPOINT_FILE = Path(__file__).with_name("firewall_checkpoint.json")
TEMP_FILE = CHECKPOINT_FILE.with_suffix(".tmp")

# Shared secret used to sign checkpoints so tampering can be detected
CHECKPOINT_KEY = os.environ.get("CHECKPOINT_KEY", "cs456-demo-checkpoint-key").encode("utf-8")


def sign_state(state, saved_at):
    """Sign the firewall state and checkpoint timestamp."""
    data = {"state": state, "saved_at": saved_at}
    state_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
    return hmac.new(CHECKPOINT_KEY, state_bytes, hashlib.sha256).hexdigest()


def save_checkpoint(state):
    """Write the firewall state to disk as a signed checkpoint."""
    saved_at = time.time()

    record = {
        "saved_at": saved_at,
        "state": state,
        "signature": sign_state(state, saved_at)
    }

    # Write to a temp file first, then swap it in, so a crash mid-write
    # never leaves a half-written checkpoint behind
    TEMP_FILE.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(TEMP_FILE, CHECKPOINT_FILE)


def load_checkpoint():
    """Return (state, saved_at) from the latest checkpoint, or (None, None) if unusable."""
    try:
        record = json.loads(CHECKPOINT_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print("[!] No checkpoint file found.")
        return None, None
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        print("[!] Checkpoint file is corrupted and could not be read.")
        return None, None

    state = record.get("state") if isinstance(record, dict) else None
    signature = record.get("signature") if isinstance(record, dict) else None
    saved_at = record.get("saved_at") if isinstance(record, dict) else None

    # Check that the timestamp is valid
    if (isinstance(saved_at, bool)
            or not isinstance(saved_at, (int, float))
            or not math.isfinite(saved_at)
            or saved_at <= 0):
        print("[!] Checkpoint has an invalid timestamp.")
        return None, None

    # Verify checkpoint integrity
    if (not isinstance(state, dict)
            or not isinstance(signature, str)
            or not hmac.compare_digest(signature, sign_state(state, saved_at))):
        print("[!] Checkpoint failed integrity check. It may have been tampered with.")
        return None, None

    return state, saved_at
