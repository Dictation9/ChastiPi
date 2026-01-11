import json
import os
import base64
import sys

APP_FOLDER_NAME = "Chasti-Lockbox"
PORTABLE_FLAG_NAME = "portable.flag"
PORTABLE_DATA_DIR_NAME = "data"


def _app_base_dir() -> str:
    """
    Where the running program lives:
    - When running as a PyInstaller EXE: folder containing the EXE
    - When running from source: folder containing this file
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _is_portable_mode() -> bool:
    """
    Portable mode is enabled when a file named 'portable.flag'
    exists in the same folder as the EXE (or project when running from source).
    """
    return os.path.exists(os.path.join(_app_base_dir(), PORTABLE_FLAG_NAME))


def _get_app_dir() -> str:
    """
    Returns the directory where config + vault data are stored.
    """
    if _is_portable_mode():
        # Store beside the app (USB-friendly)
        return os.path.join(_app_base_dir(), PORTABLE_DATA_DIR_NAME)

    # Normal installed mode: store in AppData
    appdata = os.environ.get("APPDATA", ".")
    return os.path.join(appdata, APP_FOLDER_NAME)


APP_DIR = _get_app_dir()
os.makedirs(APP_DIR, exist_ok=True)

DATA_FILE = os.path.join(APP_DIR, "lockbox.dat")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")


def load_config():
    if not os.path.exists(CONFIG_FILE):
        salt = os.urandom(16)
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
