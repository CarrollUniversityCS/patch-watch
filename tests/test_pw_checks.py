"""``scripts/pw_checks.py``: the standalone daily checks and the local hub page.

Why this file exists: the checks replaced Hermes's 08:30 / 09:45 / 11:30 / 18:00 jobs, and
two of them can act on the schedule. These tests pin the limits on those actions: the
missed-day catch-up starts the live task at most once, never after 19:00 and never under
an abuse flag, and a halt pauses the schedule instead of backing up. Nothing here touches
Task Scheduler or the network: ``ps`` and ``run`` are replaced.
"""

import datetime as dt
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("pw_checks", ROOT / "scripts" / "pw_checks.py")
pw = importlib.util.module_from_spec(_spec)
sys.modules["pw_checks"] = pw
_spec.loader.exec_module(pw)

DAY = dt.date(2026, 10, 29)          # a snapshot day
OFF_DAY = dt.date(2026, 11, 6)       # not a snapshot day


def chi(d, h, mi=0):
    return dt.datetime(d.year, d.month, d.day, h, mi, tzinfo=pw.CHI)


@pytest.fixture
def box(monkeypatch, tmp_path):
    """Point every path at tmp_path and record PowerShell calls instead of running them."""
    logs, reports = tmp_path / "logs", tmp_path / "reports"
    logs.mkdir()
    reports.mkdir()
    db = tmp_path / "study.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE runs (run_id TEXT, snapshot_label TEXT, started_at_utc TEXT, finished_at_utc TEXT,"
                " attempted INT, responded INT, errors INT, sends INT, kill_switch TEXT, config_json TEXT)")
    con.commit()
    con.close()
    for name, val in {"DB": db, "LOGS": logs, "CRON_OUT": logs / "cron.out", "ABUSE_FLAG": logs / "abuse.flag",
                      "RUN_LOCK": logs / "run.lock", "REPORTS": reports, "HUB": logs / "hub",
                      "CHECKS": logs / "hub" / "checks", "HERMES_JOBS": tmp_path / "none.json"}.items():
        monkeypatch.setattr(pw, name, val)
    calls = []
    monkeypatch.setattr(pw, "ps", lambda script, timeout=60: (calls.append(script), (0, ""))[1])
    monkeypatch.setattr(pw, "run", lambda cmd, timeout=120, env=None: (calls.append(" ".join(map(str, cmd))), (0, ""))[1])
    monkeypatch.setattr(pw, "tasks", lambda: [])

    class Box:
        pass
    b = Box()
    b.calls, b.db, b.logs, b.reports = calls, db, logs, reports

    def add_run(label, finished=True, kill=None, run_id=None):
        c = sqlite3.connect(db)
        c.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (run_id or f"R_{label}", label, "2026-10-29T14:00:00Z", "2026-10-29T14:05:00Z" if finished else None,
                   833, 705, 128, 906, kill, json.dumps({"mock": False})))
        c.commit()
        c.close()
    b.add_run = add_run
    b.cron = lambda *lines: (logs / "cron.out").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return b


def starts(calls):
    return [c for c in calls if "Start-ScheduledTask" in c]


def test_captured_day_is_ok_and_starts_nothing(box):
    box.add_run("WI_20261029")
    res = pw.check_started(chi(DAY, 9, 45), last_chance=False)
    assert [r.status for r in res] == ["ok"]
    assert not starts(box.calls)


def test_off_day_does_nothing(box):
    res = pw.check_started(chi(OFF_DAY, 9, 45), last_chance=False)
    assert res[0].status == "info" and not starts(box.calls)


def test_task_never_fired_starts_it_exactly_once(box):
    first = pw.check_started(chi(DAY, 9, 45), last_chance=False)
    assert first[0].status == "warn" and len(starts(box.calls)) == 1
    second = pw.check_started(chi(DAY, 18, 0), last_chance=True)
    assert second[0].status == "fail" and len(starts(box.calls)) == 1


def test_no_catch_up_after_1900(box):
    res = pw.check_started(chi(DAY, 19, 5), last_chance=True)
    assert res[0].status == "fail" and not starts(box.calls)


def test_no_catch_up_under_abuse_flag(box):
    (box.logs / "abuse.flag").write_text("ABUSE_COMPLAINT", encoding="utf-8")
    res = pw.check_started(chi(DAY, 9, 45), last_chance=False)
    assert res[0].status == "fail" and not starts(box.calls)


def test_refusal_line_is_reported_not_retried(box):
    box.cron("live_day 2026-10-29T09:00:01: REFUSING - logs/abuse.flag exists")
    res = pw.check_started(chi(DAY, 9, 45), last_chance=False)
    assert res[0].status == "fail" and "REFUSING" in res[0].detail
    assert not starts(box.calls)


def test_running_line_without_exit_is_in_progress(box):
    box.cron("live_day 2026-10-29T09:44:00: RUNNING python.exe run_snapshot.py --label WI_20261029")
    res = pw.check_started(chi(DAY, 9, 45), last_chance=False)
    assert res[0].status == "warn" and not starts(box.calls)


def test_postrun_halt_pauses_schedule_and_skips_backup(box):
    box.add_run("WI_20261029", kill="kill switch (overload)")
    res = pw.check_postrun(chi(DAY, 11, 30))
    assert any("Disable-ScheduledTask" in c for c in box.calls)
    assert not any("backup_now.py" in c for c in box.calls)
    assert any(r.name.startswith("Schedule paused") for r in res)


def test_postrun_clean_run_backs_up(box):
    box.add_run("WI_20261029")
    (box.reports / "run_R_WI_20261029.md").write_text("## Safety audit\n\n- No violations found.\n", encoding="utf-8")
    res = pw.check_postrun(chi(DAY, 11, 30))
    assert any("backup_now.py" in c for c in box.calls)
    assert not any("Disable-ScheduledTask" in c for c in box.calls)
    assert {r.name: r.status for r in res}["Run report safety audit"] == "ok"


def test_hub_escapes_log_text(box):
    box.cron("live_day 2026-10-29T09:00:01: REFUSING - <script>x</script>")
    page = pw.build_hub().read_text(encoding="utf-8")
    assert "<script>x" not in page and "&lt;script&gt;" in page
