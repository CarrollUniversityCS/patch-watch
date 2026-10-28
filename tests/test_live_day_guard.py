"""``scripts/live_day.py``: schedule, once-per-day guard, cut-off and the plan's early stop.

Why this file exists: the schedule kept losing days. The guard used a rolling 24 h lookback,
so an off-schedule 16:52 run on 2026-10-26 refused the scheduled 2026-10-27 09:00 task, and
consecutive 09:00 runs sat seconds from the boundary. The task also needed a date argument,
so a recurring task carrying a fixed date refused every later day. These tests pin the
replacements: one recurring task, the plan's snapshot days, a calendar-day guard with a
12 h floor, a 19:00 cut-off, and the section 6 early-stop rule (EOL counts as exposed).
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

CHI = live_day.LOCAL_TZ


def chi(y, mo, d, h, mi=0):
    return dt.datetime(y, mo, d, h, mi, tzinfo=CHI)


def _seed(monkeypatch, tmp_path, runs, obs=()):
    """runs: (run_id, started_utc, region[, finished, kill_switch, mock]); obs: (run_id, class)."""
    db = tmp_path / "study.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE runs (run_id TEXT, started_at_utc TEXT, finished_at_utc TEXT,"
                 " kill_switch TEXT, config_json TEXT)")
    conn.execute("CREATE TABLE observations (run_id TEXT, class TEXT)")
    for r in runs:
        rid, ts, reg, fin, kill, mock = (*r, *(None,) * (6 - len(r)))[:6]
        conn.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?)",
                     (rid, ts, ts if fin is None else fin, kill,
                      json.dumps({"region": reg, "mock": bool(mock)})))
    conn.executemany("INSERT INTO observations VALUES (?, ?)", obs)
    conn.commit()
    conn.close()
    monkeypatch.setattr(live_day, "DB_PATH", db)
    return db


# ------------------------------------------------------------------ once per day
def test_scheduled_run_just_under_24h_is_allowed(tmp_path, monkeypatch):
    """09:00 today vs 09:00:16 yesterday must not be refused."""
    _seed(monkeypatch, tmp_path, [("R_WI", "2026-10-28T14:00:16Z", "wisconsin")])
    assert live_day.prior_run_for("wisconsin", chi(2026, 10, 29, 9, 0)) == ""


def test_off_schedule_evening_run_does_not_eat_next_day(tmp_path, monkeypatch):
    """The 2026-10-27 regression: 16:52 the day before, 09:00 next day is 16 h later."""
    _seed(monkeypatch, tmp_path, [("R_WI", "2026-10-26T21:52:39Z", "wisconsin")])
    assert live_day.prior_run_for("wisconsin", chi(2026, 10, 27, 9, 0)) == ""


def test_manual_rerun_same_day_is_refused(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path, [("R_WI", "2026-10-29T14:00:16Z", "wisconsin")])
    assert "R_WI" in live_day.prior_run_for("wisconsin", chi(2026, 10, 29, 14, 30))


def test_runs_either_side_of_midnight_are_refused(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path, [("R_WI", "2026-10-29T04:30:00Z", "wisconsin")])  # 23:30 CDT
    assert "R_WI" in live_day.prior_run_for("wisconsin", chi(2026, 10, 29, 6, 0))   # 6.5 h later


def test_other_region_does_not_block_wisconsin(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path, [("R_CMP", "2026-10-29T14:00:00Z", "comparison")])
    assert live_day.prior_run_for("wisconsin", chi(2026, 10, 29, 10, 0)) == ""


def test_unreadable_config_raises_so_caller_refuses(tmp_path, monkeypatch):
    db = tmp_path / "study.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE runs (run_id TEXT, started_at_utc TEXT, finished_at_utc TEXT,"
                 " kill_switch TEXT, config_json TEXT)")
    conn.execute("INSERT INTO runs VALUES ('R_X', '2026-10-28T14:00:00Z', NULL, NULL, 'not json')")
    conn.commit()
    conn.close()
    monkeypatch.setattr(live_day, "DB_PATH", db)
    with pytest.raises(ValueError):
        live_day.prior_run_for("wisconsin", chi(2026, 10, 29, 9, 0))


def test_gap_floor_is_bounded():
    """A short floor would quietly permit twice-daily traffic."""
    assert live_day.MIN_GAP >= dt.timedelta(hours=12)


# ------------------------------------------------------------------ schedule
def test_schedule_matches_plan_section_6():
    days = sorted(live_day.SNAPSHOT_DAYS)
    assert days[0] == dt.date(2026, 10, 23) and days[-1] == dt.date(2027, 1, 19)
    assert dt.date(2026, 11, 4) in live_day.SNAPSHOT_DAYS          # day 14
    assert dt.date(2026, 11, 5) not in live_day.SNAPSHOT_DAYS
    assert len(days) == 18                                          # runbook section 4
    assert len(days) <= 22                                          # plan D3 ceiling


# ------------------------------------------------------------------ main()
@pytest.fixture
def at(monkeypatch, tmp_path):
    """Freeze the clock and point every path at an empty sandbox."""
    sample = tmp_path / "wi_frame.csv"
    sample.write_text("domain\n", encoding="utf-8")
    monkeypatch.setattr(live_day, "SAMPLE", sample)
    monkeypatch.setattr(live_day, "ROOT", tmp_path)
    monkeypatch.setattr(live_day, "ABUSE_FLAG", tmp_path / "abuse.flag")
    monkeypatch.setattr(live_day, "DB_PATH", tmp_path / "none.db")
    monkeypatch.setenv("PATCHWATCH_REGIONS", "wisconsin")
    calls = []
    monkeypatch.setattr(live_day.subprocess, "call", lambda cmd, cwd=None: calls.append(cmd) or 0)

    def _at(when):
        monkeypatch.setattr(live_day, "now_local", lambda: when)
        return calls
    return _at


def test_no_argument_runs_today(at):
    calls = at(chi(2026, 10, 29, 9, 0))
    assert live_day.main(["live_day.py"]) == 0
    assert calls and "WI_20261029" in calls[0]


def test_fixed_old_argument_refuses(at):
    at(chi(2026, 10, 29, 9, 0))
    with pytest.raises(SystemExit) as e:
        live_day.main(["live_day.py", "20261024"])
    assert e.value.code == live_day.EXIT_WRONG_DAY


def test_non_snapshot_day_sends_nothing(at):
    calls = at(chi(2026, 11, 5, 9, 0))
    assert live_day.main(["live_day.py"]) == 0 and calls == []


def test_catch_up_allowed_before_cutoff_refused_after(at):
    calls = at(chi(2026, 10, 30, 18, 59))
    assert live_day.main(["live_day.py"]) == 0 and calls
    at(chi(2026, 10, 30, 19, 0))
    with pytest.raises(SystemExit) as e:
        live_day.main(["live_day.py"])
    assert e.value.code == live_day.EXIT_TOO_LATE


# ------------------------------------------------------------------ early stop (plan section 6)
TWO_RUNS = [("R1", "2026-10-26T21:52:39Z", "wisconsin"), ("R2", "2026-10-28T14:00:16Z", "wisconsin")]


def test_eol_keeps_the_study_running(tmp_path, monkeypatch):
    """PI decision 2026-10-28: EOL counts as exposed for the stop rule."""
    _seed(monkeypatch, tmp_path, TWO_RUNS, [("R1", "EOL_UNFIXED"), ("R2", "EOL_UNFIXED")])
    assert live_day.stop_rule_met() == ""


def test_two_clean_snapshots_stop(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path, TWO_RUNS, [("R1", "PATCHED_UPSTREAM"), ("R2", "PHP_VERSION_HIDDEN")])
    assert "R1" in live_day.stop_rule_met()


def test_halted_or_mock_runs_do_not_count(tmp_path, monkeypatch):
    runs = [("R0", "2026-10-24T14:00:14Z", "wisconsin"),
            ("R1", "2026-10-26T21:52:39Z", "wisconsin", None, "overload"),
            ("RM", "2026-10-27T00:00:00Z", "wisconsin", None, None, True),
            ("R2", "2026-10-28T14:00:16Z", "wisconsin")]
    _seed(monkeypatch, tmp_path, runs, [("R0", "VULNERABLE_BY_VERSION")])
    assert live_day.stop_rule_met() == ""                 # R0 and R2 are the last two complete


def test_comparison_region_is_ignored(tmp_path, monkeypatch):
    runs = TWO_RUNS[:1] + [("C1", "2026-10-27T14:00:00Z", "comparison")]
    _seed(monkeypatch, tmp_path, runs)
    assert live_day.stop_rule_met() == ""                 # only one Wisconsin snapshot


def test_stop_rule_refuses_the_day(at, tmp_path, monkeypatch):
    calls = at(chi(2026, 10, 29, 9, 0))
    _seed(monkeypatch, tmp_path, TWO_RUNS)
    with pytest.raises(SystemExit) as e:
        live_day.main(["live_day.py"])
    assert e.value.code == live_day.EXIT_STOP_RULE and calls == []
