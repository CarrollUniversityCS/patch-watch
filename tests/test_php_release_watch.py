"""The PHP release watcher: bootstrap records without flagging, a new release is flagged once, failures keep state."""
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "php_release_watch", Path(__file__).resolve().parent.parent / "scripts" / "php_release_watch.py")
prw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prw)

BASE = [("8.5.9", "30 Jul 2026"), ("8.5.10", "27 Aug 2026"), ("8.5.11", "24 Sep 2026"), ("8.5.12", "21 Oct 2026")]


def _raw(*pairs):
    return {v: {"date": d, "source": []} for v, d in pairs}


def test_parse_skips_non_stable_and_bad_dates():
    out = prw.parse_releases({**_raw(*BASE), "8.6.0RC4": {"date": "21 Oct 2026"}, "8.1.1": {"date": "not a date"}})
    assert out == {"8.5.9": "2026-07-30", "8.5.10": "2026-08-27", "8.5.11": "2026-09-24", "8.5.12": "2026-10-21"}


def test_bootstrap_then_new_release_flagged_once(tmp_path):
    f = tmp_path / "rel.json"
    f.write_text(json.dumps(_raw(*BASE)), encoding="utf-8")
    code, rep = prw.run(tmp_path / "s", str(f))
    assert code == 0 and rep["bootstrap"] and rep["new"] == []
    assert rep["next"]["expected"] == "2026-11-18" and rep["next"]["gaps_equal_28"] == 2
    f.write_text(json.dumps(_raw(*BASE, ("8.5.13", "19 Nov 2026"))), encoding="utf-8")
    clock = lambda: datetime(2026, 11, 19, 15, 0, tzinfo=timezone.utc)  # noqa: E731
    code, rep = prw.run(tmp_path / "s", str(f), clock=clock)
    assert [n["version"] for n in rep["new"]] == ["8.5.13"]
    lines = (tmp_path / "s" / "new_releases.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["first_seen_utc"].startswith("2026-11-19T15:00")
    code, rep = prw.run(tmp_path / "s", str(f))
    assert rep["new"] == []
    assert len((tmp_path / "s" / "new_releases.jsonl").read_text(encoding="utf-8").splitlines()) == 1


def test_unreadable_list_keeps_state(tmp_path):
    f = tmp_path / "rel.json"
    f.write_text(json.dumps(_raw(*BASE)), encoding="utf-8")
    prw.run(tmp_path / "s", str(f))
    before = (tmp_path / "s" / "state.json").read_text(encoding="utf-8")
    f.write_text("{}", encoding="utf-8")
    code, rep = prw.run(tmp_path / "s", str(f))
    assert code == 2 and rep["errors"]
    assert (tmp_path / "s" / "state.json").read_text(encoding="utf-8") == before


def test_health_file_tracks_success_and_consecutive_failures(tmp_path):
    f = tmp_path / "rel.json"
    f.write_text(json.dumps(_raw(*BASE)), encoding="utf-8")
    t1 = lambda: datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)  # noqa: E731
    prw.run(tmp_path / "s", str(f), clock=t1)
    health = json.loads((tmp_path / "s" / "health.json").read_text(encoding="utf-8"))
    assert health == {"last_success_utc": "2026-11-07T12:00:00+00:00", "consecutive_failures": 0}
    f.write_text("{}", encoding="utf-8")
    t2 = lambda: datetime(2026, 11, 7, 18, 0, tzinfo=timezone.utc)  # noqa: E731
    prw.run(tmp_path / "s", str(f), clock=t2)
    prw.run(tmp_path / "s", str(f), clock=t2)
    health = json.loads((tmp_path / "s" / "health.json").read_text(encoding="utf-8"))
    assert health == {"last_success_utc": "2026-11-07T12:00:00+00:00", "consecutive_failures": 2}
    f.write_text(json.dumps(_raw(*BASE)), encoding="utf-8")
    prw.run(tmp_path / "s", str(f), clock=t2)
    health = json.loads((tmp_path / "s" / "health.json").read_text(encoding="utf-8"))
    assert health == {"last_success_utc": "2026-11-07T18:00:00+00:00", "consecutive_failures": 0}


def test_first_run_failure_does_not_create_seen_state_and_later_success_bootstraps(tmp_path):
    f = tmp_path / "rel.json"
    f.write_text("{}", encoding="utf-8")
    code, _ = prw.run(tmp_path / "s", str(f))
    assert code == 2 and not (tmp_path / "s" / "state.json").exists()
    assert json.loads((tmp_path / "s" / "health.json").read_text(encoding="utf-8"))["consecutive_failures"] == 1
    f.write_text(json.dumps(_raw(*BASE)), encoding="utf-8")
    code, rep = prw.run(tmp_path / "s", str(f))
    assert code == 0 and rep["bootstrap"] and rep["new"] == []


def test_source_never_touches_study_data_or_gov_hosts():
    src = Path(prw.__file__).read_text(encoding="utf-8")
    assert "study.db" not in src and "sqlite" not in src and "wi_frame" not in src
    assert ".gov" not in src and ".mil" not in src
