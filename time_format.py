"""Bahrain (AST, UTC+3) display formatting for UI and PDF reports."""

from datetime import datetime, timedelta, timezone

# Arabia Standard Time year-round (no daylight saving).
BAHRAIN_TZ = timezone(timedelta(hours=3))

MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


def _parse_iso(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(BAHRAIN_TZ)


def format_bahrain_datetime(value, missing="Unknown time"):
    """Full date and time label, e.g. ``11 Oct 2026, 01:30 PM AST``."""
    local = _parse_iso(value)
    if local is None:
        return missing
    hour = local.hour % 12 or 12
    period = "AM" if local.hour < 12 else "PM"
    return (
        f"{local.day:02d} {MONTHS[local.month - 1]} {local.year}, "
        f"{hour:02d}:{local.minute:02d} {period} AST"
    )


def format_bahrain_date(value, missing="—"):
    """Short calendar date, e.g. ``11 Oct 2026``."""
    local = _parse_iso(value)
    if local is None:
        return missing
    return f"{local.day:02d} {MONTHS[local.month - 1]} {local.year}"


def format_month_day(month, day):
    """Chart axis label, e.g. ``Oct 11``."""
    return f"{MONTHS[month - 1]} {day:02d}"
