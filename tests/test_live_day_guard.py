"""Section 2.5 once-per-day guard (``scripts/live_day.py``).

Why this file exists: the guard used a *strict* 24 h lookback against the previous run's
``started_at_utc``. The off-schedule Wisconsin run of 2026-10-26 (21:52Z) therefore refused
the scheduled 2026-10-27 09:00 task 16 h later and ate that snapshot day outright, and with
the daily task firing at ~14:00:1xZ the scheduled run sits within *seconds* of exactly 24 h
from the day before - clock jitter alone decided whether a whole day got captured. The
tolerance below keeps the promise section 2.5 actually makes (a site is not visited twice in
a day) without gambling a scheduled day on seconds.
"""

import datetime as dt
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("live_day", ROOT / "scripts" / "live_day.py")
live_day = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(live_day)

YESTERDAY = "2026-10-28T14:00:16Z"


def _seed(monkeypatch, tmp_path, runs):
    """Minimal ``runs`` table - prior_run_for() names only these three columns."""
    db = tmp_path / "study.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE runs (run_id TEXT, started_at_utc TEXT, config_json TEXT)")
    conn.executemany(
        "INSERT INTO runs VALUES (?, ?, ?)",
        [(rid, ts, json.dumps({"region": reg})) for rid, ts, reg in runs],
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(live_day, "DB_PATH", db)
    return db


def test_scheduled_run_just_under_24h_is_allowed(tmp_path, monkeypatch):
    """The regression: 09:00 today vs 09:00:16 yesterday must NOT be refused."""
    _seed(monkeypatch, tmp_path, [("R_WI", YESTERDAY, "wisconsin")])
    now = dt.datetime(2026, 10, 29, 14, 0, 5, tzinfo=dt.timezone.utc)  # 11 s short of 24 h
    assert live_day.prior_run_for("wisconsin", live_day.run_guard_window(now)) == ""


def test_manual_rerun_same_day_is_still_refused(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path, [("R_WI", "2026-10-29T14:00:16Z", "wisconsin")])
    now = dt.datetime(2026, 10, 29, 19, 30, tzinfo=dt.timezone.utc)    # 5 h 30 m later
    already = live_day.prior_run_for("wisconsin", live_day.run_guard_window(now))
    assert "R_WI" in already


def test_run_inside_the_day_is_refused(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path, [("R_WI", "2026-10-28T18:00:00Z", "wisconsin")])
    now = dt.datetime(2026, 10, 29, 14, 0, tzinfo=dt.timezone.utc)     # 20 h later
    assert "R_WI" in live_day.prior_run_for("wisconsin", live_day.run_guard_window(now))


def test_other_region_does_not_block_wisconsin(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path, [("R_CMP", YESTERDAY, "ontario")])
    now = dt.datetime(2026, 10, 29, 14, 0, 5, tzinfo=dt.timezone.utc)
    assert live_day.prior_run_for("wisconsin", live_day.run_guard_window(now)) == ""


def test_unreadable_config_raises_so_caller_refuses(tmp_path, monkeypatch):
    db = tmp_path / "study.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE runs (run_id TEXT, started_at_utc TEXT, config_json TEXT)")
    conn.execute("INSERT INTO runs VALUES ('R_X', ?, 'not json')", (YESTERDAY,))
    conn.commit()
    conn.close()
    monkeypatch.setattr(live_day, "DB_PATH", db)
    with pytest.raises(ValueError):
        live_day.prior_run_for("wisconsin", live_day.run_guard_window())


def test_tolerance_is_bounded():
    """A generous tolerance would quietly permit twice-daily traffic. 15 min is the ceiling."""
    assert live_day.GUARD_TOLERANCE <= dt.timedelta(minutes=15)
