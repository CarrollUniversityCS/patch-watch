"""The T2 burst days (docs/approved_days.json): validation, schedule union, and exclusion from v1.0 computations."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path

import approved_days as ad
import pytest

ROOT = Path(__file__).resolve().parent.parent
PLANNED = frozenset({dt.date(2026, 11, 18), dt.date(2026, 12, 5)})


def write(tmp_path, entries):
    p = tmp_path / "approved_days.json"
    p.write_text(json.dumps({"burst_days": entries}), encoding="utf-8")
    return p


def entry(day, by="plan T2 section 12, row dated 2026-11-19"):
    return {"date": day, "adopted_by": by}


def test_the_committed_file_is_valid_and_empty():
    days, errors = ad.load(planned=PLANNED)
    assert days == frozenset() and errors == []


def test_a_missing_file_means_no_burst_days(tmp_path):
    assert ad.load(tmp_path / "nope.json") == (frozenset(), [])


def test_valid_entries_are_loaded(tmp_path):
    days, errors = ad.load(write(tmp_path, [entry("2026-11-20"), entry("2026-11-21")]), PLANNED)
    assert errors == [] and days == {dt.date(2026, 11, 20), dt.date(2026, 11, 21)}


def test_any_error_means_no_day_is_used(tmp_path):
    cases = {
        "adopted_by": [entry("2026-11-20"), {"date": "2026-11-21", "adopted_by": " "}],
        "twice": [entry("2026-11-20"), entry("2026-11-20")],
        "planned": [entry("2026-11-18")],
        "YYYY-MM-DD": [entry("20-11-2026")],
        "at most 7": [entry(f"2026-12-{d:02d}") for d in range(10, 18)],
    }
    for needle, entries in cases.items():
        days, errors = ad.load(write(tmp_path, entries), PLANNED)
        assert days == frozenset(), needle
        assert any(needle in e for e in errors), (needle, errors)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    days, errors = ad.load(bad)
    assert days == frozenset() and errors
    bad.write_text('["a list"]', encoding="utf-8")
    assert ad.load(bad)[0] == frozenset()


def test_run_date_uses_the_chicago_calendar():
    assert ad.run_date("2026-11-20T14:00:02Z") == dt.date(2026, 11, 20)
    assert ad.run_date("2026-11-21T01:30:00Z") == dt.date(2026, 11, 20)     # 19:30 CST the day before
    burst = frozenset({dt.date(2026, 11, 20)})
    assert ad.is_burst_run("2026-11-20T14:00:02Z", burst)
    assert not ad.is_burst_run("2026-11-18T14:00:02Z", burst)
    assert not ad.is_burst_run(None, burst) and not ad.is_burst_run("2026-11-20T14:00:02Z", frozenset())


def load_live_day(monkeypatch, days, errors=()):
    monkeypatch.setattr(ad, "load", lambda path=ad.PATH, planned=frozenset(): (frozenset(days), list(errors)))
    spec = importlib.util.spec_from_file_location("live_day_burst", ROOT / "scripts" / "live_day.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_live_day_runs_on_approved_burst_days_and_only_those(monkeypatch):
    plain = load_live_day(monkeypatch, [])
    assert plain.SNAPSHOT_DAYS == plain.PLAN_DAYS and dt.date(2026, 11, 20) not in plain.SNAPSHOT_DAYS
    burst = load_live_day(monkeypatch, [dt.date(2026, 11, 20), dt.date(2026, 11, 22)])
    assert burst.SNAPSHOT_DAYS == burst.PLAN_DAYS | {dt.date(2026, 11, 20), dt.date(2026, 11, 22)}
    assert dt.date(2026, 11, 21) not in burst.SNAPSHOT_DAYS


def test_live_day_reports_a_bad_file_and_adds_nothing(monkeypatch, capsys):
    mod = load_live_day(monkeypatch, [], ["entry 1: bad"])
    assert mod.SNAPSHOT_DAYS == mod.PLAN_DAYS and mod.APPROVED_DAYS_ERRORS == ["entry 1: bad"]
    with pytest.raises(SystemExit):                                     # a wrong day refuses; the warning comes first
        mod.main(["live_day.py", "20990101"])
    assert "docs/approved_days.json is not used: entry 1: bad" in capsys.readouterr().out