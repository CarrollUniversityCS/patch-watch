"""``pw_checks.check_phpwatch``: the daily check that makes a new PHP release impossible to miss.

A flag in a JSON file is not a trigger, so the check turns red while any release has not been acknowledged,
and again when the watcher itself stops reading php.net. Nothing here touches the network or Task Scheduler.
"""

import datetime as dt
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if "pw_checks" in sys.modules:
    pw = sys.modules["pw_checks"]
else:
    _spec = importlib.util.spec_from_file_location("pw_checks", ROOT / "scripts" / "pw_checks.py")
    pw = importlib.util.module_from_spec(_spec)
    sys.modules["pw_checks"] = pw
    _spec.loader.exec_module(pw)

DAY = dt.date(2026, 11, 9)


def chi(d, h, mi=0):
    return dt.datetime(d.year, d.month, d.day, h, mi, tzinfo=pw.CHI)


@pytest.fixture
def phpbox(monkeypatch, tmp_path):
    folder = tmp_path / "phpwatch"
    folder.mkdir()
    toasts = []
    monkeypatch.setattr(pw, "PHPWATCH", folder)
    monkeypatch.setattr(pw, "notify", lambda title, body: toasts.append((title, body)))
    return folder, toasts


def _write(folder, now, *, failures=0, success_delta=dt.timedelta(hours=1), expected="2026-11-18",
           new=(), ack=(), known=60):
    success = (now.astimezone(dt.timezone.utc) - success_delta).isoformat().replace("+00:00", "Z")
    (folder / "health.json").write_text(json.dumps({"last_success_utc": success, "consecutive_failures": failures}),
                                        encoding="utf-8")
    (folder / "state.json").write_text(json.dumps({"seen": {f"8.5.{i}": {} for i in range(known)}}), encoding="utf-8")
    (folder / "last_run.json").write_text(json.dumps({"releases_known": known, "next": {"expected": expected}}),
                                          encoding="utf-8")
    lines = [json.dumps({"version": v, "date": d, "first_seen_utc": "2026-11-19T21:50:00+00:00"}) for v, d in new]
    (folder / "new_releases.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    if ack:
        (folder / "ack.txt").write_text("\n".join(ack) + "\n", encoding="utf-8")


def test_not_installed_warns(phpbox):
    assert pw.check_phpwatch(chi(DAY, 9)) == [pw.Result("PHP release watcher", "warn", "not installed yet (no state)")]


def test_fresh_success_is_ok_and_names_the_next_expected_release(phpbox):
    folder, _ = phpbox
    now = chi(DAY, 9)
    _write(folder, now)
    r = pw.check_phpwatch(now)
    assert r[0].status == "ok" and "2026-11-18" in r[0].detail and "60" in r[0].detail


def test_stale_success_fails(phpbox):
    folder, _ = phpbox
    now = chi(DAY, 9)
    _write(folder, now, success_delta=dt.timedelta(hours=37))
    r = pw.check_phpwatch(now)
    assert r[0].status == "fail" and "stale" in r[0].detail


def test_three_consecutive_failures_fail(phpbox):
    folder, _ = phpbox
    now = chi(DAY, 9)
    _write(folder, now, failures=3)
    r = pw.check_phpwatch(now)
    assert r[0].status == "fail" and "3 consecutive" in r[0].detail


def test_corrupt_state_fails_instead_of_crashing(phpbox):
    folder, _ = phpbox
    now = chi(DAY, 9)
    _write(folder, now)
    (folder / "health.json").write_text("{not json", encoding="utf-8")
    r = pw.check_phpwatch(now)
    assert r[0].status == "fail" and "could not read" in r[0].detail


def test_missed_run_inside_the_release_window_fails_even_when_fresh_enough_otherwise(phpbox):
    folder, _ = phpbox
    now = chi(dt.date(2026, 11, 18), 9)
    _write(folder, now, success_delta=dt.timedelta(hours=14), expected="2026-11-18")
    r = pw.check_phpwatch(now)
    assert r[0].status == "fail" and "release window" in r[0].detail
    _write(folder, now, success_delta=dt.timedelta(hours=2), expected="2026-11-18")
    assert pw.check_phpwatch(now)[0].status == "ok"


def test_unacknowledged_release_is_red_toasts_once_and_clears_when_acknowledged(phpbox):
    folder, toasts = phpbox
    now = chi(dt.date(2026, 11, 19), 17)
    _write(folder, now, new=[("8.5.13", "2026-11-19")])
    r = pw.check_phpwatch(now)
    rel = next(x for x in r if x.name == "PHP release 8.5.13")
    assert rel.status == "fail" and "ack.txt" in rel.detail and "2026-11-19" in rel.detail
    assert toasts == [("patch-watch: new PHP release", "8.5.13 (2026-11-19)")]
    pw.check_phpwatch(now)
    assert len(toasts) == 1
    (folder / "ack.txt").write_text("8.5.13\n", encoding="utf-8")
    r = pw.check_phpwatch(now)
    assert not [x for x in r if x.status == "fail"]


def test_ack_file_tolerates_bom_crlf_and_blank_lines(phpbox):
    folder, _ = phpbox
    now = chi(dt.date(2026, 11, 19), 17)
    _write(folder, now, new=[("8.5.13", "2026-11-19"), ("8.4.28", "2026-11-19")])
    (folder / "ack.txt").write_bytes("﻿8.5.13\r\n\r\n8.4.28\r\n".encode("utf-8"))
    assert not [x for x in pw.check_phpwatch(now) if x.status == "fail"]


def test_check_is_registered_and_pw_checks_does_not_import_the_watcher():
    assert "phpwatch" in pw.CHECKS_FN and pw.CHECK_NAMES["phpwatch"]
    text = (ROOT / "scripts" / "pw_checks.py").read_text(encoding="utf-8")
    assert "import php_release_watch" not in text and "from php_release_watch" not in text


def test_installer_mentions_no_live_task_and_has_a_dry_run():
    text = (ROOT / "scripts" / "install_php_release_watch.ps1").read_text(encoding="utf-8")
    for forbidden in ("live_day", "national_day", "run_snapshot", "PATCHWATCH_GATE_A", "SNAPSHOT_DAYS", "study.db"):
        assert forbidden not in text
    assert "[switch]$DryRun" in text and "Unregister-ScheduledTask" in text
    assert "php_release_watch.py" in text and "pw_checks.py" in text and '"phpwatch"' in text
    # A new release must raise its alert straight after the read, not at the next morning's check.
    assert "function New-WatchActions" in text and "`" + '"$Checks`" phpwatch' in text
    assert text.count("-Action (New-WatchActions)") == 2
    assert (ROOT / "scripts" / "php_release_watch.py").exists() and (ROOT / "scripts" / "pw_checks.py").exists()
