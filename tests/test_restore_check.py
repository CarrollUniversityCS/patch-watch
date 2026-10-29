"""scripts/restore_check.py on synthetic backups."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

import db

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("restore_check", ROOT / "scripts" / "restore_check.py")
rc = importlib.util.module_from_spec(spec)
sys.modules["restore_check"] = rc
spec.loader.exec_module(rc)


def make_backup(path, runs=2, obs=3):
    conn = db.connect(path)
    db.init_db(conn)
    for i in range(runs):
        conn.execute("INSERT INTO runs(run_id, started_at_utc, kill_switch) VALUES (?,?,?)",
                     (f"R{i}", f"2026-10-2{4 + i}T14:00:00Z", "overload" if i == 1 else None))
    for i in range(obs):
        conn.execute("INSERT INTO observations(run_id, domain) VALUES ('R0', ?)", (f"zz{i}.example.test",))
    conn.commit()
    conn.close()


def test_a_good_backup_is_restorable_and_summarised(tmp_path, capsys):
    make_backup(tmp_path / "b.db")
    assert rc.main([str(tmp_path / "b.db")]) == 0
    out = capsys.readouterr().out
    assert "integrity_check: ok" in out and "RESTORABLE" in out and "NOT RESTORABLE" not in out
    assert "runs 2" in out and "observations 3" in out and "1 halted" in out
    assert "from 2026-10-24T14:00:00Z to 2026-10-25T14:00:00Z" in out and "distinct domains observed: 3" in out


def test_json_output_has_the_same_facts(tmp_path, capsys):
    make_backup(tmp_path / "b.db")
    rc.main([str(tmp_path / "b.db"), "--json"])
    r = json.loads(capsys.readouterr().out)
    assert r["restorable"] is True and r["row_counts"]["observations"] == 3 and r["runs"]["halted"] == 1


def test_no_domain_or_header_is_ever_printed(tmp_path, capsys):
    make_backup(tmp_path / "b.db")
    rc.main([str(tmp_path / "b.db")])
    rc.main([str(tmp_path / "b.db"), "--json"])
    assert "example.test" not in capsys.readouterr().out


def test_a_missing_table_is_not_restorable(tmp_path, capsys):
    make_backup(tmp_path / "b.db")
    c = sqlite3.connect(tmp_path / "b.db")
    c.execute("DROP TABLE request_ledger")
    c.commit()
    c.close()
    assert rc.main([str(tmp_path / "b.db")]) == 2
    assert "MISSING TABLES: request_ledger" in capsys.readouterr().out


def test_a_missing_column_is_not_restorable(tmp_path, capsys):
    p = tmp_path / "old.db"
    c = sqlite3.connect(p)
    c.executescript(db.SCHEMA.replace("headers_raw_json       TEXT,", ""))
    c.commit()
    c.close()
    assert rc.main([str(p)]) == 2
    assert "MISSING COLUMNS in observations: headers_raw_json" in capsys.readouterr().out


def test_an_extra_column_is_reported_but_not_a_failure(tmp_path, capsys):
    make_backup(tmp_path / "b.db")
    c = sqlite3.connect(tmp_path / "b.db")
    c.execute("ALTER TABLE runs ADD COLUMN newer_field TEXT")
    c.commit()
    c.close()
    assert rc.main([str(tmp_path / "b.db")]) == 0
    assert "extra columns in runs" in capsys.readouterr().out


def test_a_corrupt_file_is_refused_not_crashed(tmp_path, capsys):
    p = tmp_path / "bad.db"
    p.write_bytes(b"this is not a database" * 100)
    assert rc.main([str(p)]) == 1
    assert "not a readable SQLite database" in capsys.readouterr().err


def test_a_missing_path_is_refused(tmp_path):
    assert rc.main([str(tmp_path / "none.db")]) == 1


def test_a_database_with_damaged_pages_fails_integrity(tmp_path, capsys):
    make_backup(tmp_path / "b.db", obs=400)
    data = bytearray((tmp_path / "b.db").read_bytes())
    for i in range(len(data) // 2, len(data) // 2 + 2000):
        data[i] = 0xFF
    (tmp_path / "b.db").write_bytes(bytes(data))
    code = rc.main([str(tmp_path / "b.db")])
    assert code in (1, 2)


def test_the_backup_file_is_not_modified(tmp_path):
    make_backup(tmp_path / "b.db")
    before = (tmp_path / "b.db").read_bytes()
    rc.main([str(tmp_path / "b.db")])
    assert (tmp_path / "b.db").read_bytes() == before


def test_the_expected_schema_matches_db_py():
    want = rc.expected_schema()
    assert {"domains", "runs", "observations", "request_ledger", "patch_events", "meta"} <= set(want)
    assert "headers_json" in want["observations"] and "kill_switch" in want["runs"]


def test_the_script_writes_nothing_and_opens_read_only():
    src = (ROOT / "scripts" / "restore_check.py").read_text(encoding="utf-8")
    assert "mode=ro" in src and "INSERT" not in src and "DELETE" not in src and "write_text" not in src
