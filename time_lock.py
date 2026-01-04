from datetime import datetime, timedelta
from config_store import save_config


def parse_lock_until(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def format_remaining(td: timedelta) -> str:
    total = int(td.total_seconds())
    if total < 0:
        total = 0
    h = total // 3600
    m = (total % 3600) // 60
    s = total % 60
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def add_months(now: datetime, months: int) -> datetime:
    """
    Calendar-aware month addition (clamps day if needed).
    Example: Jan 31 + 1 month -> Feb 28/29 (depending on year).
    """
    if months == 0:
        return now

    import calendar

    year = now.year
    month = now.month + months
    year += (month - 1) // 12
    month = ((month - 1) % 12) + 1

    last_day = calendar.monthrange(year, month)[1]
    day = min(now.day, last_day)

    return now.replace(year=year, month=month, day=day)


def validate_system_time(cfg: dict) -> bool:
    """
    Anti clock-roll-back check:
    - Detect if system time goes backwards vs last_seen_time
    - If time-lock is set, extend lock_until to preserve duration
    - Update last_seen_time
    """
    now = datetime.now()

    last_seen_raw = cfg.get("last_seen_time")
    if last_seen_raw:
        try:
            last_seen = datetime.fromisoformat(last_seen_raw)
        except ValueError:
            last_seen = None

        if last_seen and now < last_seen:
            cfg["clock_violation_count"] = int(cfg.get("clock_violation_count", 0)) + 1

            lock_until = parse_lock_until(cfg.get("lock_until"))
            if lock_until:
                rollback_delta = last_seen - now
                cfg["lock_until"] = (lock_until + rollback_delta).isoformat(timespec="seconds")

            cfg["last_seen_time"] = last_seen.isoformat(timespec="seconds")
            save_config(cfg)
            return False

    cfg["last_seen_time"] = now.isoformat(timespec="seconds")
    save_config(cfg)
    return True
