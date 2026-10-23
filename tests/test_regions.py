"""Wisconsin and comparison states run as SEPARATE snapshots (plan §6, D6). Loopback only."""

from __future__ import annotations

import csv
import json

import pytest

import analyze
import config
import db
import pipeline
import versions

COLS = ["domain", "region", "state", "stratum", "domain_type", "organization", "entity_id", "city"]


def write_frame(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        for r in rows:
            w.writerow({c: "" for c in COLS} | {"stratum": "Town", "domain_type": "City"} | r)


def frame_rows(n_wi=3, n_cmp=3):
    out = [{"domain": f"wi{i}.gov", "region": "wisconsin", "state": "WI",
            "entity_id": f"WI:{i}", "organization": f"Town of W{i}"} for i in range(n_wi)]
    out += [{"domain": f"mn{i}.gov", "region": "comparison", "state": "MN",
             "entity_id": f"MN:{i}", "organization": f"City of M{i}"} for i in range(n_cmp)]
    return out


def test_select_region_keeps_one_region_only(tmp_path):
    p = tmp_path / "f.csv"
    write_frame(p, frame_rows())
    rows = pipeline.load_sample(p)
    assert {r["domain"] for r in pipeline.select_region(rows, "comparison")} == \
        {"mn0.gov", "mn1.gov", "mn2.gov"}
    assert len(pipeline.select_region(rows, None)) == 6


def test_select_region_refuses_a_sample_without_regions():
    with pytest.raises(SystemExit):
        pipeline.select_region([{"domain": "a.gov", "stratum": "City"}], "wisconsin")


def test_a_region_run_touches_only_that_region(tmp_path, monkeypatch):
    for k, port in (("HTTP", 18451), ("HTTPS", 18452), ("HTTP_ONLY", 18455), ("DEAD", 18459)):
        monkeypatch.setenv(f"PATCHWATCH_MOCK_{k}_PORT", str(port))
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setattr(config, "ABUSE_FLAG_PATH", tmp_path / "logs" / "abuse.flag")
    frame = tmp_path / "f.csv"
    write_frame(frame, frame_rows())
    summary = pipeline.run_snapshot(sample_path=frame, db_path=tmp_path / "s.db", mock=True,
                                    snapshot_label="CMP", region="comparison", quiet=True)
    assert summary["region"] == "comparison" and summary["domains"] == 3
    conn = db.connect(tmp_path / "s.db")
    assert {r["domain"] for r in conn.execute("SELECT domain FROM observations")} == \
        {"mn0.gov", "mn1.gov", "mn2.gov"}
    assert {r["domain"] for r in conn.execute("SELECT DISTINCT domain FROM request_ledger")} <= \
        {"mn0.gov", "mn1.gov", "mn2.gov"}
    cfg = json.loads(conn.execute("SELECT config_json FROM runs").fetchone()["config_json"])
    assert cfg["region"] == "comparison"
    assert "region: comparison" in (tmp_path / "reports" / f"run_{summary['run_id']}.md").read_text()


# ------------------------------------------------------------------ RQ6 in the analysis
def xpb(v):
    return json.dumps({"x-powered-by": [f"PHP/{v}"]})


def test_rq6_matches_regions_by_day_not_by_run(tmp_path):
    p = tmp_path / "f.csv"
    write_frame(p, frame_rows(12, 12))
    conn = db.connect(tmp_path / "s.db")
    db.init_db(conn)
    # separate runs per region, 30 minutes apart, two days
    plan = [("W1", "wisconsin", "2026-10-23T14:00:00Z"), ("C1", "comparison", "2026-10-23T14:30:00Z"),
            ("W2", "wisconsin", "2026-10-24T14:00:00Z"), ("C2", "comparison", "2026-10-24T14:30:00Z")]
    for run, region, ts in plan:
        db.insert_run(conn, {"run_id": run, "snapshot_label": run, "started_at_utc": ts,
                             "notes": "live run", "config_json": json.dumps({"region": region})})
        prefix = "wi" if region == "wisconsin" else "mn"
        for i in range(12):
            # day 2: everyone exposed; day 3: 12/12 WI patched, 0/12 comparison patched
            ver = "8.3.36" if (run == "W2") else "8.3.35"
            conn.execute("INSERT INTO observations(run_id, domain, started_at_utc, status_code, "
                         "headers_json, php_hints_json, resolved_ip) VALUES(?,?,?,?,?,?,?)",
                         (run, f"{prefix}{i}.gov", ts, 200, xpb(ver), "{}", f"192.0.2.{i}"))
    conn.commit()
    text = analyze.build_report(conn, analyze.Frame.load(p), versions.PHP2SHELL,
                                sup=analyze.Suppressor())
    rq6 = text.split("## RQ6", 1)[1]
    assert "| 3 | 12 | 100% | 12 | 0% | +100 |" in rq6
    assert "| 2 | 12 | 0% | 12 | 0% | +0 |" in rq6


def test_rq6_absent_without_a_comparison_region(tmp_path):
    p = tmp_path / "f.csv"
    write_frame(p, frame_rows(3, 0))
    conn = db.connect(tmp_path / "s.db")
    db.init_db(conn)
    text = analyze.build_report(conn, analyze.Frame.load(p), versions.PHP2SHELL,
                                sup=analyze.Suppressor())
    assert "RQ6" not in text


def test_run_lock_refuses_a_second_live_run(tmp_path):
    lock = pipeline.RunLock(tmp_path / "run.lock")
    with lock:
        with pytest.raises(SystemExit, match="one-request-per-IP"):
            with pipeline.RunLock(tmp_path / "run.lock"):
                pass
    assert not (tmp_path / "run.lock").exists(), "released on exit"
    with pipeline.RunLock(tmp_path / "run.lock"):
        pass


def test_stale_lock_is_a_refusal_not_a_guess(tmp_path):
    (tmp_path / "run.lock").write_text("pid=1 started=2026-10-23T00:00:00Z\n")
    with pytest.raises(SystemExit, match="stale"):
        with pipeline.RunLock(tmp_path / "run.lock"):
            pass
