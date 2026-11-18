import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import region_map as rm  # noqa: E402


def test_division_map_covers_every_state_once():
    rm.check_division_map()


def test_bands_and_rounding():
    assert [rm.issue_band(n) for n in (0, 9, 10, 24, 25, 99)] == ["under 10", "under 10", "10 to 24", "10 to 24", "25 or more", "25 or more"]
    assert rm.round_sites(2976) == 3000 and rm.round_sites(49) == 0


def test_summary_publishes_bands_only_and_zero_reads_as_under_10():
    rows = [("WI", "VULNERABLE_BY_VERSION", 19), ("WI", "NO_PHP_EVIDENCE", 1502), ("CA", "NO_PHP_EVIDENCE", 1162),
            ("NY", "EOL_UNFIXED", 32), ("TX", "VULNERABLE_BY_VERSION", 6)]
    m = rm.summarise(rows, "2026-11-18")
    text = json.dumps(m)
    rm.validate(m)
    by = {r["region"]: r for r in m["regions"]}
    assert by["Midwest"]["issues"] == "10 to 24" and by["Northeast"]["issues"] == "25 or more"
    pac = [d for d in by["West"]["divisions"] if d["division"] == "Pacific"][0]
    assert pac["issues"] == "under 10"                      # a true zero is shown as under 10
    assert '"19"' not in text and ": 19" not in text and ": 32" not in text   # no exact issue counts
    assert not any(k in text for k in ("WI", "CA", "NY", "TX"))   # no state codes


def test_validate_refuses_exact_counts():
    m = rm.summarise([("WI", "VULNERABLE_BY_VERSION", 19)], "2026-11-18")
    m["regions"][0]["issues"] = "13"
    with pytest.raises(ValueError):
        rm.validate(m)
    m = rm.summarise([("WI", "VULNERABLE_BY_VERSION", 19)], "2026-11-18")
    m["regions"][0]["sites_observed"] = 2976
    with pytest.raises(ValueError):
        rm.validate(m)


def test_joint_audit_recovers_nothing_from_bands():
    m = rm.summarise([("WI", "VULNERABLE_BY_VERSION", 19), ("IA", "EOL_UNFIXED", 6), ("NY", "EOL_UNFIXED", 32)], "2026-11-18")
    assert rm.audit(m) == []


def test_joint_audit_catches_a_pinned_cell():
    m = rm.summarise([("WI", "VULNERABLE_BY_VERSION", 19)], "2026-11-18")
    # a region band of "under 10" forces its divisions to be at most 9, but "25 or more" with every division "under 10"
    # is impossible, so a (wrongly) published combination fails the audit instead of passing silently
    mw = [r for r in m["regions"] if r["region"] == "Midwest"][0]
    mw["issues"] = "25 or more"
    for d in mw["divisions"]:
        d["issues"] = "under 10"
    with pytest.raises(ValueError):
        rm.validate(m)


def test_refresh_refuses_a_burst_day_snapshot(tmp_path, monkeypatch):
    import sqlite3
    import datetime as dt
    db = tmp_path / "s.db"
    c = sqlite3.connect(db)
    c.executescript("CREATE TABLE runs(snapshot_label TEXT, started_at_utc TEXT);"
                    "CREATE TABLE domains(domain TEXT, state TEXT);"
                    "CREATE TABLE observations(domain TEXT, snapshot_label TEXT, class TEXT);"
                    "INSERT INTO runs VALUES('WI_20261118','2026-11-18T14:00:02Z'),('WI_20261120','2026-11-20T14:00:02Z');")
    c.commit()
    monkeypatch.setattr(rm.approved_days, "load", lambda *a, **k: (frozenset({dt.date(2026, 11, 20)}), []))
    conn = sqlite3.connect(db)
    assert rm.burst_labels(conn) == {"WI_20261120"}
    assert rm.latest_labels(conn) == ["WI_20261118"]
    with pytest.raises(SystemExit):
        rm.main(["--db", str(db), "--labels", "WI_20261120", "--out", str(tmp_path / "o.json")])
