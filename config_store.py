import json
import os
import base64

APP_DIR = os.path.join(os.environ.get("APPDATA", "."), "Chasti-Lockbox")
os.makedirs(APP_DIR, exist_ok=True)

DATA_FILE = os.path.join(APP_DIR, "lockbox.dat")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")


def load_config():
    if not os.path.exists(CONFIG_FILE):
        import os as _os
        salt = _os.urandom(16)
        return {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "pin_hash": None,
            "override_pin_hash": None,
            "lock_until": None,           # ISO datetime string or None
            "last_seen_time": None,       # ISO datetime string or None
            "clock_violation_count": 0,   # int
        }

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    cfg.setdefault("pin_hash", None)
    cfg.setdefault("override_pin_hash", None)
    cfg.setdefault("lock_until", None)
    cfg.setdefault("last_seen_time", None)
    cfg.setdefault("clock_violation_count", 0)
    return cfg


def save_config(cfg: dict):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
