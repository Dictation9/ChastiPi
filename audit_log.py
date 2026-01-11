import json
import os
import hashlib
from datetime import datetime
from typing import Any, Dict, Optional

# Default file name inside APP_DIR (passed in by caller)
AUDIT_FILENAME = "audit.log.jsonl"


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def append_audit_event(
    app_dir: str,
    event_type: str,
    details: Optional[Dict[str, Any]] = None,
    *,
    max_bytes: int = 2_000_000,
) -> None:
    """
    Append one audit event as JSON Lines (one JSON object per line).

    - Uses a simple hash chain so tampering is detectable:
      each line includes prev_hash + entry_hash
    - Rotates file to .1 when it exceeds max_bytes
    - Never throws (best-effort logging)
    """
    details = details or {}

    try:
        os.makedirs(app_dir, exist_ok=True)
        path = os.path.join(app_dir, AUDIT_FILENAME)

        # Read previous line hash (best effort)
        prev_hash = "0" * 64
        if os.path.exists(path) and os.path.getsize(path) > 0:
            try:
                with open(path, "rb") as f:
                    # read last ~4KB to find last line
                    f.seek(max(0, os.path.getsize(path) - 4096))
                    chunk = f.read()
                lines = chunk.splitlines()
                if lines:
                    last = json.loads(lines[-1].decode("utf-8"))
                    prev_hash = last.get("entry_hash", prev_hash)
            except Exception:
                prev_hash = "0" * 64

        entry = {
            "ts": _utc_now_iso(),
            "type": event_type,
            "details": details,
            "prev_hash": prev_hash,
        }

        entry_bytes = json.dumps(entry, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        entry_hash = _sha256_hex(entry_bytes)
        entry["entry_hash"] = entry_hash

        line = (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")

        # Rotate if too big
        if os.path.exists(path) and os.path.getsize(path) + len(line) > max_bytes:
            rotated = os.path.join(app_dir, AUDIT_FILENAME + ".1")
            try:
                if os.path.exists(rotated):
                    os.remove(rotated)
                os.replace(path, rotated)
            except Exception:
                pass

        with open(path, "ab") as f:
            f.write(line)

    except Exception:
        # Never break the app if audit logging fails
        return
