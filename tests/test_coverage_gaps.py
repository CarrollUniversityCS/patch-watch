"""Behaviour tests for the branches the first coverage pass found untested in the new modules: error paths, the
network-shaped paths (with the network replaced), and the table branches that need a larger synthetic study."""

from __future__ import annotations

import datetime as dt
import importlib.util
import io
import json
import pytest
import sqlite3
import sys
import urllib.error
from pathlib import Path


import analyze
import db
import inventory
import support_status as ss
from test_pw_checks import box, chi, pw, DAY  # noqa: F401,F811
from test_pw_oversight import ov  # noqa: F401,F811

ROOT = Path(__file__).resolve().parent.parent


def script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


kc = script("kev_census")

KEV = {"catalogVersion": "2026.10.28", "dateReleased": "2026-10-28T19:00:00Z", "vulnerabilities": [
    {"cveID": "CVE-2026-109619", "vendorProject": "PHP Group", "product": "PHP", "dateAdded": "2026-10-26", "dueDate": "2026-10-29"},
    {"cveID": "CVE-2026-5001", "vendorProject": "Unknown Corp", "product": "Gizmo", "dateAdded": "2026-10-27", "dueDate": "2026-11-17"},
]}
CVE_REC = {"containers": {"cna": {"affected": [{"cpes": ["cpe:2.3:h:acme:gizmo:1:*:*:*:*:*:*:*"]}]}}}


def kev_file(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps(KEV), encoding="utf-8")
    return p


# ------------------------------------------------------------------ kev_census with the network replaced
def fake_fetch(responses):
    def f(url, cache, timeout=30.0):
        for key, val in responses.items():
            if key in url:
                return val
        return None
    return f


def test_census_online_path_uses_cve_records_and_epss(tmp_path, monkeypatch):
    monkeypatch.setattr(kc.intake, "fetch_text", fake_fetch({
        "cves/2026/5xxx": json.dumps(CVE_REC), "api.first.org": json.dumps({"data": [{"cve": "CVE-2026-5001", "epss": "0.7"}]})}))
    out = tmp_path / "o"
    assert kc.main(["--cache", str(tmp_path / "c"), "--kev", str(kev_file(tmp_path)), "--out-dir", str(out),
                    "--sample-size", "2"]) == 0
    nums = json.loads((out / "kev_census_numbers.json").read_text(encoding="utf-8"))
    assert nums["with_cpe"] == 1 and nums["epss_scored"] == 1
    prop = json.loads((out / "kev_tiers_proposed.json").read_text(encoding="utf-8"))
    row = [r for r in prop["entries"] if r["cve"] == "CVE-2026-5001"][0]
    assert row["tier"] == "B_edge_or_server_product" and row["epss"] == 0.7      # a hardware CPE promotes it to the appliance tier


def test_census_survives_every_fetch_failing(tmp_path, monkeypatch):
    monkeypatch.setattr(kc.intake, "fetch_text", fake_fetch({}))
    assert kc.main(["--cache", str(tmp_path / "c"), "--kev", str(kev_file(tmp_path)), "--out-dir", str(tmp_path / "o")]) == 0


def test_census_survives_malformed_record_json(tmp_path, monkeypatch):
    monkeypatch.setattr(kc.intake, "fetch_text", fake_fetch({"cves/": "{not json"}))
    assert kc.main(["--cache", str(tmp_path / "c"), "--kev", str(kev_file(tmp_path)), "--out-dir", str(tmp_path / "o")]) == 0


def test_census_fetches_the_catalog_when_no_file_is_given(tmp_path, monkeypatch):
    monkeypatch.setattr(kc.intake, "fetch_text", fake_fetch({"known_exploited": json.dumps(KEV)}))
    assert kc.main(["--cache", str(tmp_path / "c"), "--out-dir", str(tmp_path / "o"), "--offline"]) == 0


def test_census_writes_the_dashboard_summary_when_asked(tmp_path):
    summ = tmp_path / "m.json"
    kc.main(["--cache", str(tmp_path / "c"), "--kev", str(kev_file(tmp_path)), "--offline", "--out-dir", str(tmp_path / "o"),
             "--summary-out", str(summ)])
    d = json.loads(summ.read_text(encoding="utf-8"))
    assert d["total"] == 2 and len(d["groups"][0]["examples"]) <= 10 and "keyword sort" in d["caveat"]


def make_study_db(path, n=30):
    conn = db.connect(path)
    db.init_db(conn)
    conn.execute("INSERT INTO runs(run_id, started_at_utc, finished_at_utc, attempted, config_json) VALUES "
                 "('R1','2026-10-28T14:00:00Z','2026-10-28T14:05:00Z', ?, '{\"region\": \"wisconsin\"}')", (n,))
    for i in range(n):
        conn.execute("INSERT INTO domains(domain, domain_type) VALUES (?, 'City')", (f"d{i}.example.test",))
        conn.execute("INSERT INTO observations(run_id, domain, class, status_code, headers_json, php_evidence) VALUES "
                     "('R1', ?, 'PATCHED_UPSTREAM', 200, ?, 1)", (f"d{i}.example.test", json.dumps({"x-powered-by": ["PHP/8.5.12"]})))
    conn.commit()
    conn.close()


def test_census_uses_inventory_counts_for_q3_when_given_a_database(tmp_path):
    make_study_db(tmp_path / "t.db")
    out = tmp_path / "o"
    kc.main(["--cache", str(tmp_path / "c"), "--kev", str(kev_file(tmp_path)), "--offline", "--out-dir", str(out),
             "--db", str(tmp_path / "t.db")])
    nums = json.loads((out / "kev_census_numbers.json").read_text(encoding="utf-8"))
    assert nums["q3_available"] is True
    prop = json.loads((out / "kev_tiers_proposed.json").read_text(encoding="utf-8"))
    assert [r for r in prop["entries"] if r["cve"] == "CVE-2026-109619"][0]["q3_common_in_frame"] == "yes"


# ------------------------------------------------------------------ support_status edges
def test_datetime_as_of_and_unparseable_cycles():
    assert ss.status("php", (8, 1), dt.datetime(2026, 10, 28, 12, 0)) == ss.END_OF_LIFE
    snap = {"products": {"x": {"cycles": [{"cycle": "weird", "eol": False}]}}}
    assert ss.status("x", (3, 0), "2026-01-01", snapshot=snap) == ss.UNKNOWN
    snap2 = {"products": {"x": {"cycles": []}}}
    assert ss.status("x", (3, 0), "2026-01-01", snapshot=snap2) == ss.UNKNOWN


def test_a_branch_older_than_the_oldest_cycle_stays_unknown_when_that_cycle_is_maintained():
    snap = {"products": {"x": {"cycles": [{"cycle": "2.0", "releaseDate": "2020-01-01", "eol": False}]}}}
    assert ss.status("x", (1, 0), "2026-01-01", snapshot=snap) == ss.UNKNOWN


# ------------------------------------------------------------------ inventory edges
def test_inventory_main_json_output(tmp_path, capsys):
    make_study_db(tmp_path / "t.db")
    assert inventory.main(["--db", str(tmp_path / "t.db"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["products"]["php"]["named"] == "30"


def test_inventory_of_a_region_with_no_run_is_empty(tmp_path):
    make_study_db(tmp_path / "t.db")
    assert inventory.aggregate(tmp_path / "t.db", region="comparison").attempted == 0


# ------------------------------------------------------------------ the oversight check's boundaries
def test_oversight_without_a_database_skips_what_needs_one(ov):
    ov.db.unlink()
    res = pw.check_oversight(chi(DAY, 11, 45))
    names = {r.name: r for r in res}
    assert names["8.1-2 request budget"].status == "info" and names["8.1-1 run reports"].status == "info"


def test_a_run_with_unreadable_config_json_counts_as_unknown_region(ov):
    c = sqlite3.connect(ov.db)
    c.execute("INSERT INTO runs VALUES ('R1','WI_20261029','2026-10-29T14:00:00Z','2026-10-29T14:05:00Z',1,1,0,1,NULL,'{bad')")
    c.commit()
    c.close()
    assert "unknown" in [r for r in pw.check_oversight(chi(DAY, 11, 45)) if r.name.startswith("8.1-3")][0].detail


def test_egress_result_reports_the_network_and_its_failure(monkeypatch):
    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(pw.urllib.request, "urlopen", lambda *a, **k: Resp(b"AS40379 Carroll College"))
    assert pw.egress_result().status == "ok"
    monkeypatch.setattr(pw.urllib.request, "urlopen", lambda *a, **k: Resp(b"AS7018 Somewhere"))
    assert pw.egress_result().status == "warn"

    def boom(*a, **k):
        raise urllib.error.URLError("offline")
    monkeypatch.setattr(pw.urllib.request, "urlopen", boom)
    assert pw.egress_result().status == "warn"


def test_pausing_failure_is_reported_when_the_task_cannot_be_disabled(box, monkeypatch):
    monkeypatch.setattr(pw, "ps", lambda script, timeout=60: (1, "Access is denied"))
    r = pw._pause_live_task("test")
    assert r.status == "fail" and "pause it by hand" in r.detail


# ------------------------------------------------------------------ analysis sections with a larger synthetic study
def big_study(tmp_path, n=60):
    import test_analyze as ta
    fp = tmp_path / "f.csv"
    ta.write_frame(fp, [{"domain": f"d{i}.gov", "entity_id": f"WI:{i}", "organization": f"Town {i}",
                         "stratum": "Election office" if i < 30 else "Town",
                         "domain_type": "City - Election" if i < 30 else "City"} for i in range(n)])
    conn = db.connect(tmp_path / "s.db")
    db.init_db(conn)
    ta.add_run(conn, "S1", "2026-10-28T14:00:00Z")
    conn.execute("UPDATE runs SET config_json = '{\"region\": \"wisconsin\"}'")
    for i in range(n):
        eol = i % 3 == 0
        hdr = {"server": ["Apache/2.4.58" if i % 2 else "nginx/1.24.0"],
               "x-powered-by": ["PHP/7.4.33" if eol else "PHP/8.5.12"]}
        ta.add_obs(conn, "S1", f"d{i}.gov", "2026-10-28T14:00:00Z", headers=json.dumps(hdr), ip=f"192.0.2.{i % 5}")
        conn.execute("UPDATE observations SET class = ? WHERE domain = ?",
                     ("EOL_UNFIXED" if eol else "PATCHED_UPSTREAM", f"d{i}.gov"))
    conn.commit()
    return conn, analyze.Frame.load(fp), [dict(r) for r in conn.execute("SELECT * FROM runs")]


def test_platform_section_prints_both_tables_when_cells_are_large(tmp_path):
    conn, frame, runs = big_study(tmp_path)
    text = "\n".join(analyze._platforms(conn, frame, runs, analyze.Suppressor()))
    assert "server platform (largest first)" in text and "PHP sites with a placeable version" in text
    assert "d1.gov" not in text and "apache" not in text.lower()


def test_unsupported_section_prints_the_by_type_table_when_large(tmp_path):
    conn, frame, runs = big_study(tmp_path)
    text = "\n".join(analyze._unsupported(conn, frame, runs, analyze.Suppressor()))
    assert "by entity type" in text and "| php |" in text


def test_election_section_reports_the_stratum_when_cells_are_large(tmp_path):
    conn, frame, runs = big_study(tmp_path)
    text = "\n".join(analyze._election(conn, frame, runs, analyze.Suppressor(on=False)))
    assert "relative to election day" in text and "| 2026-10-28 | before |" in text


# ------------------------------------------------------------------ dashboard main
def test_dashboard_main_writes_a_page_to_the_chosen_path(tmp_path, capsys):
    import dashboard
    out = tmp_path / "page.html"
    assert dashboard.main(["--out", str(out)]) == 0
    assert "Patch Watch" in out.read_text(encoding="utf-8") and "wrote" in capsys.readouterr().out
    frag = tmp_path / "frag.html"
    assert dashboard.main(["--out", str(frag), "--fragment"]) == 0
    assert "<html" not in frag.read_text(encoding="utf-8")


# ------------------------------------------------------------------ boundaries the audit's mutation pass found unguarded
def test_a_branch_is_security_only_on_the_day_active_support_ends_and_supported_the_day_before():
    snap = {"products": {"x": {"cycles": [{"cycle": "2.0", "releaseDate": "2020-01-01", "support": "2026-06-01", "eol": "2028-01-01"}]}}}
    assert ss.status("x", (2, 0), "2026-05-31", snapshot=snap) == ss.SUPPORTED
    assert ss.status("x", (2, 0), "2026-06-01", snapshot=snap) == ss.SECURITY_ONLY


def test_plain_http_to_an_allowed_host_is_refused(tmp_path):
    import intake
    with pytest.raises(ValueError):
        intake.fetch_text("http://raw.githubusercontent.com/x", tmp_path)


def test_a_gov_host_is_refused_even_if_someone_adds_it_to_the_allow_list(tmp_path, monkeypatch):
    import intake
    monkeypatch.setattr(intake, "ALLOWED_HOSTS", frozenset({"raw.githubusercontent.com", "town.example.gov"}))
    with pytest.raises(ValueError):
        intake.fetch_text("https://town.example.gov/x", tmp_path)


def test_restore_check_asks_sqlite_for_its_integrity_verdict(tmp_path, monkeypatch):
    rc = script("restore_check")
    make_study_db(tmp_path / "t.db")
    assert rc.check(tmp_path / "t.db")["integrity"] == ["ok"]
