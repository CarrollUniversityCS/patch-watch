"""Approved extra snapshot days (the T2 release-event burst), read from docs/approved_days.json.

Plan amendment T2, section 4: burst dates are entered by Jack, each citing the section 12 row that adopts the
amendment, and burst-day readings are excluded by date from every v1.0 and T1 computation (adoption curve, Turnbull
estimate, test-retest, the early-stop rule). This module is the single place that knows those dates. Stdlib only.

File format:  {"burst_days": [{"date": "2026-11-20", "adopted_by": "<the section 12 row that authorises it>"}]}

A bad file never adds a day: load() returns no burst days and a list of errors, and the callers report them.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
PATH = ROOT / "docs" / "approved_days.json"
MAX_BURST_DAYS = 7                      # amendment T2: at most 7 burst days (the plan allows 22 snapshot days in all)
LOCAL_TZ = ZoneInfo("America/Chicago")  # the schedule's calendar, as in live_day


def load(path: Path = PATH, planned: frozenset[dt.date] = frozenset()) -> tuple[frozenset[dt.date], list[str]]:
    """(burst days, errors). A missing file means no burst days; any error means none are used."""
    path = Path(path)
    if not path.exists():
        return frozenset(), []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return frozenset(), [f"{path.name} cannot be read: {exc}"]
    entries = data.get("burst_days") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return frozenset(), [f"{path.name}: expected an object with a 'burst_days' list"]
    errors: list[str] = []
    days: list[dt.date] = []
    for i, e in enumerate(entries, 1):
        if not isinstance(e, dict):
            errors.append(f"entry {i}: expected an object with 'date' and 'adopted_by'")
            continue
        try:
            day = dt.date.fromisoformat(str(e.get("date", "")))
        except ValueError:
            errors.append(f"entry {i}: 'date' must be YYYY-MM-DD, got {e.get('date')!r}")
            continue
        if not str(e.get("adopted_by", "")).strip():
            errors.append(f"entry {i} ({day}): 'adopted_by' must name the section 12 row that authorises it")
        if day in days:
            errors.append(f"entry {i}: {day} is listed twice")
        if day in planned:
            errors.append(f"entry {i}: {day} is already a planned snapshot day")
        days.append(day)
    if len(days) > MAX_BURST_DAYS:
        errors.append(f"{len(days)} burst days; the amendment allows at most {MAX_BURST_DAYS}")
    return (frozenset(), errors) if errors else (frozenset(days), [])


def run_date(started_at_utc: str) -> dt.date:
    """The America/Chicago calendar date of a run's start (run rows store UTC like 2026-11-11T14:00:02Z)."""
    when = dt.datetime.fromisoformat(started_at_utc.replace("Z", "+00:00"))
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return when.astimezone(LOCAL_TZ).date()


def is_burst_run(started_at_utc: str | None, burst_days: frozenset[dt.date]) -> bool:
    return bool(started_at_utc) and bool(burst_days) and run_date(started_at_utc) in burst_days