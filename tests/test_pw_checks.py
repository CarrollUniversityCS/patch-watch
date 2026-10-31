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
                      "CHECKS": logs / "hub" / "checks", "HERMES_JOBS": tmp_path / "none.json",
                      "NAT_ACTIVE": tmp_path / "national_active_wave.txt", "NAT_NOTICE": logs / "notice_live.txt"}.items():
        monkeypatch.setattr(pw, name, val)
    calls = []
    monkeypatch.setattr(pw, "ps", lambda script, timeout=60: (calls.append(script), (0, ""))[1])
    monkeypatch.setattr(pw, "run", lambda cmd, timeout=120, env=None: (calls.append(" ".join(map(str, cmd))), (0, ""))[1])
    monkeypatch.setattr(pw, "tasks", lambda: [])

    class Box:
        pass
    b = Box()
    b.calls, b.db, b.logs, b.reports = calls, db, logs, reports
    b.tmp = tmp_path

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


@pytest.fixture
def optbox(box, monkeypatch, tmp_path):
    """box plus an opt-out log, a local blocklist, and a fetch-free blocklist reader."""
    local = tmp_path / "blocklist.local.txt"
    monkeypatch.setattr(pw, "OPTOUTS", box.logs / "optouts.md")
    monkeypatch.setattr(pw, "BLOCKLIST_LOCAL", local)
    monkeypatch.setattr(pw, "load_blocklist", lambda: {"cisa.gov"} | (
        {ln.split("#")[0].strip() for ln in local.read_text(encoding="utf-8").splitlines()} - {""}
        if local.exists() else set()))
    c = sqlite3.connect(box.db)
    c.execute("CREATE TABLE observations (run_id TEXT, domain TEXT, status_code INT)")
    c.commit()
    c.close()
    box.local = local
    box.optout = lambda *heads: (box.logs / "optouts.md").write_text(
        "# Opt-out and complaint log\n\n## Entries\n\n" + "\n\n".join(heads) + "\n", encoding="utf-8")

    def observe(domain, label, started):
        box.add_run(label, run_id=f"R_{label}")
        c = sqlite3.connect(box.db)
        c.execute("UPDATE runs SET started_at_utc = ? WHERE run_id = ?", (started, f"R_{label}"))
        c.execute("INSERT INTO observations VALUES (?,?,200)", (f"R_{label}", domain))
        c.commit()
        c.close()
    box.observe = observe
    return box


def test_optout_missing_from_blocklist_is_added(optbox):
    optbox.optout("## 2026-10-29 13:00 UTC — Example.GOV\nChannel: email")
    res = {r.name: r for r in pw.check_optout(chi(DAY, 8, 45))}
    assert res["Blocklist covers every opt-out"].status == "warn"
    assert optbox.local.read_text(encoding="utf-8").startswith("example.gov ")
    again = {r.name: r for r in pw.check_optout(chi(DAY, 8, 45))}
    assert again["Blocklist covers every opt-out"].status == "ok"
    assert optbox.local.read_text(encoding="utf-8").count("example.gov") == 1


def test_traffic_before_optout_is_fine(optbox):
    optbox.optout("## 2026-10-29 13:00 UTC — example.gov")
    optbox.observe("example.gov", "WI_20261028", "2026-10-28T14:00:00Z")
    res = {r.name: r.status for r in pw.check_optout(chi(DAY, 8, 45))}
    assert res["No traffic after opt-out"] == "ok"
    assert not any("Disable-ScheduledTask" in c for c in optbox.calls)


def test_traffic_after_optout_pauses_schedule(optbox):
    optbox.optout("## 2026-10-27 13:00 UTC — example.gov")
    optbox.observe("example.gov", "WI_20261028", "2026-10-28T14:00:00Z")
    res = {r.name: r.status for r in pw.check_optout(chi(DAY, 8, 45))}
    assert res["No traffic after opt-out"] == "fail"
    assert any("Disable-ScheduledTask" in c for c in optbox.calls)


def test_committed_blocklist_domain_never_allowed(optbox):
    optbox.optout()
    optbox.observe("cisa.gov", "WI_20261028", "2026-10-28T14:00:00Z")
    res = {r.name: r.status for r in pw.check_optout(chi(DAY, 8, 45))}
    assert res["No traffic after opt-out"] == "fail"


def test_hub_escapes_log_text(box):
    box.cron("live_day 2026-10-29T09:00:01: REFUSING - <script>x</script>")
    page = pw.build_hub().read_text(encoding="utf-8")
    assert "<script>x" not in page and "&lt;script&gt;" in page


# ------------------------------------------------------------------ the national arm (silent until a wave is released)
def release(box, wave="1"):
    (box.tmp / "national_active_wave.txt").write_text(wave, encoding="utf-8")
    (box.logs / "notice_live.txt").write_text("2026-10-30 confirmed\n", encoding="utf-8")


def nat_results(res):
    return [r for r in res if r.name.startswith("National")]


def test_national_checks_are_silent_until_a_wave_and_the_notice_are_in_place(box):
    box.add_run("WI_20261029")
    assert nat_results(pw.check_started(chi(DAY, 18, 0), last_chance=True)) == []
    (box.tmp / "national_active_wave.txt").write_text("1", encoding="utf-8")            # wave but no notice
    assert nat_results(pw.check_started(chi(DAY, 18, 0), last_chance=True)) == []


def test_a_clean_national_day_is_ok_and_post_run_reads_its_report(box):
    release(box)
    box.add_run("WI_20261029")
    box.add_run("NAT_20261029")
    (box.reports / "run_R_NAT_20261029.md").write_text("# Run\nNo violations found\n", encoding="utf-8")
    assert [r.status for r in nat_results(pw.check_started(chi(DAY, 9, 45), last_chance=False))] == ["ok"]
    post = nat_results(pw.check_postrun(chi(DAY, 11, 30)))
    assert [r.status for r in post] == ["ok", "ok"] and "safety audit" in post[1].name


def test_a_national_report_that_is_not_clean_fails_post_run(box):
    release(box)
    box.add_run("WI_20261029")
    box.add_run("NAT_20261029")
    post = nat_results(pw.check_postrun(chi(DAY, 11, 30)))
    assert post[1].status == "fail"


def test_a_halted_national_run_fails_and_says_how_to_resume_without_touching_the_schedule(box):
    release(box)
    box.add_run("WI_20261029")
    box.add_run("NAT_20261029", kill="kill switch (overload)")
    for res in (pw.check_started(chi(DAY, 9, 45), last_chance=False), pw.check_postrun(chi(DAY, 11, 30))):
        n = nat_results(res)
        assert n[0].status == "fail" and "re-release" in n[0].detail
    assert not [c for c in box.calls if "National" in c or "national" in c]


def test_a_missed_national_day_is_info_at_0945_and_a_failure_after_the_run_was_due(box):
    release(box)
    box.add_run("WI_20261029")
    assert nat_results(pw.check_started(chi(DAY, 9, 45), last_chance=False))[0].status == "info"
    assert nat_results(pw.check_postrun(chi(DAY, 11, 30)))[0].status == "fail"
    assert nat_results(pw.check_started(chi(DAY, 18, 0), last_chance=True))[0].status == "fail"


def test_a_national_refusal_while_wisconsin_is_still_pending_is_only_a_warning(box):
    release(box)
    box.cron("national_day 2026-10-29T10:00:03: REFUSING - Wisconsin has not completed a clean snapshot today; the primary arm goes first")
    first = nat_results(pw.check_started(chi(DAY, 10, 30), last_chance=False))
    assert first[0].status == "warn" and "REFUSING" in first[0].detail
    assert nat_results(pw.check_started(chi(DAY, 18, 0), last_chance=True))[0].status == "fail"


def test_an_unfinished_national_run_with_no_lock_is_a_crash_at_last_chance(box):
    release(box)
    box.add_run("WI_20261029")
    box.add_run("NAT_20261029", finished=False)
    assert nat_results(pw.check_started(chi(DAY, 9, 45), last_chance=False))[0].status == "warn"
    assert nat_results(pw.check_started(chi(DAY, 18, 0), last_chance=True))[0].status == "fail"


def test_a_national_day_off_the_calendar_reports_nothing(box):
    release(box)
    assert nat_results(pw.check_started(chi(OFF_DAY, 9, 45), last_chance=False)) == []
