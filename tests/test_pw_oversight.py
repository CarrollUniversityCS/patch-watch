"""scripts/pw_checks.py `oversight`: runbook sections 8.1 and 8.2 as code.

Every item has a passing and a failing fixture. Nothing touches Task Scheduler, the network or the real
database: paths point at tmp_path, `ps` and `run` are replaced, and the database is built in the test.
"""

import datetime as dt
import json
import sqlite3
import sys
from pathlib import Path

import pytest

from test_pw_checks import DAY, box, chi, pw  # noqa: F401  (box is a fixture)

MONDAY = dt.date(2026, 11, 2)
TASK = {"name": "patch-watch live day", "state": "Ready", "next": "2026-10-30 09:00", "last": "", "result": 0}


@pytest.fixture
def ov(box, monkeypatch, tmp_path):                                  # noqa: F811
    con = sqlite3.connect(box.db)
    con.executescript("""
        CREATE TABLE observations (run_id TEXT, domain TEXT, status_code INT);
        CREATE TABLE domains (domain TEXT, domain_type TEXT, stratum TEXT);
        CREATE TABLE request_ledger (run_id TEXT, ts_utc TEXT, domain TEXT, phase TEXT, status_code INT);
    """)
    con.commit()
    con.close()
    backups = tmp_path / "backups"
    backups.mkdir()
    monkeypatch.setattr(pw, "BACKUPS", backups)
    monkeypatch.setattr(pw, "OVERSIGHT", tmp_path / "logs" / "oversight")
    monkeypatch.setattr(pw, "load_blocklist", lambda: set())
    monkeypatch.setattr(pw, "egress_result", lambda: pw.Result("Egress network", "ok", "AS40379"))
    monkeypatch.setattr(pw, "tasks", lambda: [dict(TASK)])
    monkeypatch.setenv("PATCHWATCH_BACKUP_DIR", str(tmp_path / "offsite"))
    (tmp_path / "offsite").mkdir()

    def git(porcelain):
        orig = pw.run
        monkeypatch.setattr(pw, "run", lambda cmd, timeout=120, env=None:
                            (0, porcelain) if cmd[:2] == ["git", "status"] else orig(cmd, timeout, env))
    git("")
    box.git = git
    box.backups, box.offsite = backups, tmp_path / "offsite"

    def sql(q, *a):
        c = sqlite3.connect(box.db)
        c.execute(q, a)
        c.commit()
        c.close()
    box.sql = sql

    def good_report(run_id="R_WI_20261029"):
        (box.reports / f"run_{run_id}.md").write_text("# Run\nNo violations found\n", encoding="utf-8")
    box.good_report = good_report

    def backup(name="study_20261029_1135.db", copy=True, corrupt=False):
        p = backups / name
        if corrupt:
            p.write_bytes(b"not a database at all" * 50)
        else:
            c = sqlite3.connect(p)
            c.execute("CREATE TABLE t (x)")
            c.commit()
            c.close()
        if copy:
            (box.offsite / "backups").mkdir(exist_ok=True)       # scripts/backup_now.py copies into <dest>/backups
            (box.offsite / "backups" / name).write_bytes(p.read_bytes())
    box.backup = backup
    return box


def review(b, day=DAY):
    return pw.check_oversight(chi(day, 11, 45))


def item(res, prefix):
    hits = [r for r in res if r.name.startswith(prefix)]
    assert hits, [r.name for r in res]
    return hits[0]


def pauses(b):
    return [c for c in b.calls if "Disable-ScheduledTask" in c]


def clean_day(b):
    b.add_run("WI_20261029")
    b.good_report()
    b.backup()


# ------------------------------------------------------------------ an all-green day
def test_a_clean_day_passes_every_item_and_changes_nothing(ov):
    clean_day(ov)
    res = review(ov)
    for prefix in ("8.1-1", "8.1-2", "8.1-3", "8.1-4", "8.1-5", "8.1-6", "8.1-7", "8.1-8", "8.1-9"):
        assert item(res, prefix).status == "ok", (prefix, item(res, prefix))
    assert not pauses(ov) and not [c for c in ov.calls if "Start-ScheduledTask" in c or "Enable-ScheduledTask" in c]


def test_the_review_is_written_as_markdown(ov):
    clean_day(ov)
    review(ov)
    text = (ov.logs / "oversight" / "2026-10-29.md").read_text(encoding="utf-8")
    assert text.startswith("# Oversight review 2026-10-29") and "**PASS** 8.1-1" in text


# ------------------------------------------------------------------ item 1
def test_missing_report_fails_item_1_without_pausing(ov):
    ov.add_run("WI_20261029")
    ov.backup()
    r = item(review(ov), "8.1-1")
    assert r.status == "fail" and "report missing" in r.detail and not pauses(ov)


def test_a_report_that_is_not_clean_fails_item_1(ov):
    ov.add_run("WI_20261029")
    (ov.reports / "run_R_WI_20261029.md").write_text("Violations: 2\n", encoding="utf-8")
    assert item(review(ov), "8.1-1").status == "fail"


def test_a_halt_is_only_fine_if_the_schedule_is_paused(ov, monkeypatch):
    ov.add_run("WI_20261029", kill="overload")
    assert item(review(ov), "8.1-1").status == "fail"
    monkeypatch.setattr(pw, "tasks", lambda: [{**TASK, "state": "Disabled"}])
    assert item(review(ov), "8.1-1").status == "ok"


def test_an_alert_report_counts_as_a_halt(ov):
    ov.add_run("WI_20261029")
    (ov.reports / "ALERT_R_WI_20261029.md").write_text("alert", encoding="utf-8")
    assert "halted" in item(review(ov), "8.1-1").detail


def test_no_run_today_skips_items_that_need_one(ov):
    res = review(ov)
    for prefix in ("8.1-1", "8.1-4", "8.1-5"):
        assert item(res, prefix).status == "info" and "SKIP" in item(res, prefix).detail


# ------------------------------------------------------------------ item 2
def ledger(b, domain, pairs, ts="2026-10-29T14:01:00Z"):
    for i, (run, phase) in enumerate(pairs):
        b.sql("INSERT INTO request_ledger VALUES (?,?,?,?,?)", run, ts, domain, phase, 200)


def test_request_budget_three_pairs_passes(ov):
    clean_day(ov)
    ledger(ov, "a.example.test", [("R1", "https"), ("R1", "retry"), ("R1", "http")])
    assert item(review(ov), "8.1-2").status == "ok" and not pauses(ov)


def test_request_budget_four_pairs_fails_and_pauses(ov):
    clean_day(ov)
    ledger(ov, "a.example.test", [("R1", "https"), ("R1", "retry"), ("R1", "http"), ("R2", "https")])
    assert item(review(ov), "8.1-2").status == "fail" and len(pauses(ov)) == 1


def test_repeated_requests_in_one_pair_do_not_count_twice(ov):
    clean_day(ov)
    ledger(ov, "a.example.test", [("R1", "https")] * 9)
    assert item(review(ov), "8.1-2").status == "ok"


def test_yesterdays_ledger_is_not_today(ov):
    clean_day(ov)
    ledger(ov, "a.example.test", [("R1", "a"), ("R1", "b"), ("R1", "c"), ("R2", "a")], ts="2026-10-28T14:01:00Z")
    assert item(review(ov), "8.1-2").status == "ok"


# ------------------------------------------------------------------ item 3
def test_two_runs_in_one_region_fail_item_3_without_pausing(ov):
    c = sqlite3.connect(ov.db)
    for rid in ("A", "B"):
        c.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (rid, "WI_20261029", "2026-10-29T14:00:00Z", "2026-10-29T14:05:00Z", 1, 1, 0, 1, None,
                   json.dumps({"region": "wisconsin"})))
    c.commit()
    c.close()
    r = item(review(ov), "8.1-3")
    assert r.status == "fail" and "wisconsin" in r.detail and not pauses(ov)


def test_one_run_per_region_passes(ov):
    clean_day(ov)
    ov.sql("UPDATE runs SET config_json = ?", json.dumps({"region": "wisconsin"}))
    assert item(review(ov), "8.1-3").status == "ok"


# ------------------------------------------------------------------ item 4
def test_a_blocklisted_domain_that_answered_fails_and_pauses(ov, monkeypatch):
    clean_day(ov)
    ov.sql("INSERT INTO observations VALUES ('R_WI_20261029', 'blocked.example.test', 200)")
    monkeypatch.setattr(pw, "load_blocklist", lambda: {"blocked.example.test"})
    assert item(review(ov), "8.1-4").status == "fail" and len(pauses(ov)) == 1


def test_a_blocklisted_domain_with_no_status_passes(ov, monkeypatch):
    clean_day(ov)
    ov.sql("INSERT INTO observations VALUES ('R_WI_20261029', 'blocked.example.test', NULL)")
    monkeypatch.setattr(pw, "load_blocklist", lambda: {"blocked.example.test"})
    assert item(review(ov), "8.1-4").status == "ok" and not pauses(ov)


def test_an_old_response_from_a_later_blocklisted_domain_is_not_todays_problem(ov, monkeypatch):
    clean_day(ov)
    ov.sql("INSERT INTO observations VALUES ('R_OLD', 'blocked.example.test', 200)")
    monkeypatch.setattr(pw, "load_blocklist", lambda: {"blocked.example.test"})
    assert item(review(ov), "8.1-4").status == "ok"


# ------------------------------------------------------------------ item 5
@pytest.mark.parametrize("dtype,stratum", [("Tribal", ""), ("Tribal - Election", ""), ("City", "Tribal")])
def test_a_tribal_domain_fails_and_pauses(ov, dtype, stratum):
    clean_day(ov)
    ov.sql("INSERT INTO domains VALUES ('n.example.test', ?, ?)", dtype, stratum)
    ov.sql("INSERT INTO observations VALUES ('R_WI_20261029', 'n.example.test', 200)")
    assert item(review(ov), "8.1-5").status == "fail" and len(pauses(ov)) == 1


def test_non_tribal_domains_pass(ov):
    clean_day(ov)
    ov.sql("INSERT INTO domains VALUES ('c.example.test', 'City', 'Town')")
    ov.sql("INSERT INTO observations VALUES ('R_WI_20261029', 'c.example.test', 200)")
    assert item(review(ov), "8.1-5").status == "ok"


# ------------------------------------------------------------------ item 6
def test_no_backup_today_fails_item_6(ov):
    ov.add_run("WI_20261029")
    ov.good_report()
    assert item(review(ov), "8.1-6").status == "fail"


def test_a_corrupt_backup_fails_item_6(ov):
    clean_day(ov)
    for p in ov.backups.iterdir():
        p.unlink()
    ov.backup(corrupt=True)
    assert item(review(ov), "8.1-6").status == "fail"


def test_unset_backup_dir_is_a_known_warning_not_a_failure(ov, monkeypatch):
    clean_day(ov)
    monkeypatch.delenv("PATCHWATCH_BACKUP_DIR")
    r = item(review(ov), "8.1-6")
    assert r.status == "warn" and "off-machine" in r.detail


def test_a_backup_that_never_reached_the_second_location_fails(ov):
    clean_day(ov)
    for p in (ov.offsite / "backups").iterdir():
        p.unlink()
    assert item(review(ov), "8.1-6").status == "fail"


# ------------------------------------------------------------------ item 7
def test_only_the_gate_line_is_fine(ov):
    clean_day(ov)
    ov.git(" M src/config.py\n?? scratch.txt\n")
    assert item(review(ov), "8.1-7").status == "ok"


def test_changed_code_fails_but_never_pauses(ov):
    clean_day(ov)
    ov.git(" M src/fetch.py\n M src/config.py\n")
    r = item(review(ov), "8.1-7")
    assert r.status == "fail" and "src/fetch.py" in r.detail and not pauses(ov)


def test_document_edits_only_warn(ov):
    clean_day(ov)
    ov.git(" M README.md\n M src/config.py\n")
    assert item(review(ov), "8.1-7").status == "warn"


# ------------------------------------------------------------------ items 8 and 9
def test_missing_task_fails_and_paused_task_skips(ov, monkeypatch):
    clean_day(ov)
    monkeypatch.setattr(pw, "tasks", lambda: [])
    assert item(review(ov), "8.1-8").status == "fail"
    monkeypatch.setattr(pw, "tasks", lambda: [{**TASK, "state": "Disabled"}])
    assert item(review(ov), "8.1-8").status == "info"


def test_low_disk_fails_and_does_not_pause(ov, monkeypatch):
    clean_day(ov)
    monkeypatch.setattr(pw, "MIN_FREE_GB", 10**9)
    assert item(review(ov), "8.1-9").status == "fail" and not pauses(ov)


def test_egress_result_is_included(ov):
    clean_day(ov)
    assert item(review(ov), "Egress").status == "ok"


# ------------------------------------------------------------------ Mondays (8.2)
def test_weekly_items_run_only_on_mondays(ov):
    assert item(review(ov), "8.2").detail.startswith("SKIP")
    res = review(ov, MONDAY)
    assert {r.name[:5] for r in res} >= {"8.2-1", "8.2-2", "8.2-3", "8.2-4"}


def test_weekly_analysis_failure_is_reported(ov, monkeypatch):
    monkeypatch.setattr(pw, "run", lambda cmd, timeout=120, env=None:
                        (1, "boom") if "analyze.py" in " ".join(map(str, cmd)) else (0, ""))
    assert item(review(ov, MONDAY), "8.2-1").status == "fail"


def test_a_modified_provenance_line_fails_the_weekly_analysis(ov, monkeypatch):
    monkeypatch.setattr(pw, "run", lambda cmd, timeout=120, env=None:
                        (0, "provenance: abc123 MODIFIED") if "analyze.py" in " ".join(map(str, cmd)) else (0, ""))
    assert item(review(ov, MONDAY), "8.2-1").status == "fail"


def test_weekly_run_count_compares_with_the_plan(ov):
    res = review(ov, MONDAY)
    r = item(res, "8.2-3")
    assert r.status == "warn" and "Wisconsin run(s) in the last 7 days" in r.detail


def test_weekly_integrity_check_reports_ok(ov):
    assert item(review(ov, MONDAY), "8.2-2").status == "ok"


def test_refusal_trend_counts_403_429_and_5xx(ov):
    ov.sql("INSERT INTO request_ledger VALUES ('R', '2026-10-30T14:00:00Z', 'd', 'p', 403)")
    ov.sql("INSERT INTO request_ledger VALUES ('R', '2026-10-31T14:00:00Z', 'd', 'p', 503)")
    ov.sql("INSERT INTO request_ledger VALUES ('R', '2026-10-31T14:00:00Z', 'd', 'p', 200)")
    r = item(review(ov, MONDAY), "8.2-4")
    assert "403: 1" in r.detail and "503: 1" in r.detail and "200" not in r.detail


# ------------------------------------------------------------------ wiring and limits
def test_oversight_is_a_registered_check_and_a_hub_card():
    assert "oversight" in pw.CHECKS_FN and pw.CHECK_NAMES["oversight"] == "11:45 oversight"


def test_main_accepts_the_oversight_subcommand(monkeypatch):
    seen = []
    monkeypatch.setattr(pw, "run_check", lambda name: seen.append(name) or 0)
    assert pw.main(["pw_checks.py", "oversight"]) == 0 and seen == ["oversight"]


def test_oversight_never_starts_enables_or_edits_anything(ov):
    clean_day(ov)
    ov.sql("INSERT INTO request_ledger VALUES ('R', '2026-10-29T14:00:00Z', 'a', 'p1', 200)")
    review(ov)
    for call in ov.calls:
        assert "Start-ScheduledTask" not in call and "Enable-ScheduledTask" not in call
        assert "git commit" not in call and "git push" not in call


def test_the_database_is_opened_read_only(ov):
    src = (Path(pw.__file__)).read_text(encoding="utf-8")
    body = src[src.index("def _ro_db"):src.index("def _pause_live_task")]
    assert "mode=ro" in body


def test_the_installer_is_untouched_and_scheduling_is_left_to_the_pi():
    root = Path(pw.__file__).resolve().parents[1]
    import re
    text = (root / "scripts" / "install_checks.ps1").read_text(encoding="utf-8")
    assert not re.search(r"pw_checks\.py.*oversight", text) and "check 1145" not in text and "11:45" not in text


def test_the_hub_shows_an_oversight_card_with_todays_result(ov, monkeypatch):
    clean_day(ov)
    monkeypatch.setattr(pw, "now_local", lambda: chi(DAY, 11, 50))
    assert pw.run_check("oversight") in (0, 2)
    page = (ov.logs / "hub" / "index.html").read_text(encoding="utf-8")
    assert "11:45 oversight" in page and "8.1-1 run reports" in page
