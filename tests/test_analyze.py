"""Stage 7 analysis (src/analyze.py) on a synthetic database. No network."""

from __future__ import annotations

import csv
import json

import pytest

import analyze
import baseline_cc
import db
import versions

T0 = versions.PHP2SHELL.t0_utc          # 2026-10-21T14:00:00Z
FRAME_COLS = ["domain", "region", "state", "stratum", "domain_type", "organization",
              "entity_id", "city"]


def xpb(v):
    return json.dumps({"x-powered-by": [f"PHP/{v}"]})


def write_frame(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FRAME_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({**{c: "" for c in FRAME_COLS}, "region": "wisconsin", "state": "WI",
                        "domain_type": "City", "stratum": "Town", **r})


def add_run(conn, run_id, started, *, kill=None, notes="live run"):
    db.insert_run(conn, {"run_id": run_id, "snapshot_label": run_id, "started_at_utc": started,
                         "kill_switch": kill, "notes": notes, "config_json": "{}"})


def add_obs(conn, run_id, domain, ts, *, headers="{}", status=200, ip="192.0.2.1",
            error=None, cert=0, off=0, skipped=None):
    conn.execute(
        "INSERT INTO observations(run_id, domain, started_at_utc, status_code, headers_json, "
        "php_hints_json, error_type, cert_error, redirect_off_domain, resolved_ip, skipped_reason)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, domain, ts, status, headers, "{}", error, cert, off, ip, skipped))


@pytest.fixture
def study(tmp_path):
    frame_path = tmp_path / "frame.csv"
    write_frame(frame_path, [
        {"domain": "a.gov", "entity_id": "WI:a", "organization": "Town of A"},
        {"domain": "a2.gov", "entity_id": "WI:a", "organization": "Town of A"},
        {"domain": "b.gov", "entity_id": "WI:b", "organization": "Town of B"},
        {"domain": "c.gov", "entity_id": "WI:c", "organization": "Town of C"},
        {"domain": "d.gov", "entity_id": "WI:d", "organization": "Town of D"},
        {"domain": "nation.gov", "entity_id": "WI:n", "organization": "A Nation",
         "domain_type": "Tribal", "stratum": "Tribal"},
    ])
    conn = db.connect(tmp_path / "s.db")
    db.init_db(conn)
    add_run(conn, "S1", "2026-10-23T14:00:00Z")
    add_run(conn, "S2", "2026-10-24T14:00:00Z")
    add_run(conn, "BAD", "2026-10-25T14:00:00Z", kill="audit_violation")
    day = {"S1": "2026-10-23T14:00:00Z", "S2": "2026-10-24T14:00:00Z",
           "BAD": "2026-10-25T14:00:00Z"}
    # a: one domain patched, the other still exposed -> entity EXPOSED (worst rule), then both patched
    add_obs(conn, "S1", "a.gov", day["S1"], headers=xpb("8.3.36"))
    add_obs(conn, "S1", "a2.gov", day["S1"], headers=xpb("8.3.35"))
    add_obs(conn, "S2", "a.gov", day["S2"], headers=xpb("8.3.36"))
    add_obs(conn, "S2", "a2.gov", day["S2"], headers=xpb("8.3.36"))
    # b: exposed, then hides the version (never patched)
    add_obs(conn, "S1", "b.gov", day["S1"], headers=xpb("8.2.34"))
    add_obs(conn, "S2", "b.gov", day["S2"],
            headers=json.dumps({"set-cookie": ["PHPSESSID=x"]}))
    # c: already patched
    add_obs(conn, "S1", "c.gov", day["S1"], headers=xpb("8.4.27"))
    add_obs(conn, "S2", "c.gov", day["S2"], headers=xpb("8.4.27"))
    # d: blocklisted both times -> NOT_MEASURED -> UNREACHED
    add_obs(conn, "S1", "d.gov", day["S1"], status=None, error="skipped_blocklist",
            skipped="blocklisted")
    add_obs(conn, "S2", "d.gov", day["S2"], status=None, error="skipped_blocklist",
            skipped="blocklisted")
    # the untrustworthy run says everything is patched; it must be ignored
    for dom in ("a.gov", "a2.gov", "b.gov"):
        add_obs(conn, "BAD", dom, day["BAD"], headers=xpb("8.5.12"))
    conn.commit()
    return conn, analyze.Frame.load(frame_path)


def test_tribal_rows_never_enter_the_frame(study):
    _, frame = study
    assert "nation.gov" not in frame.rows


def test_audit_violation_run_is_not_analysed(study):
    conn, frame = study
    live, runs = analyze.load_live(conn, frame, versions.PHP2SHELL)
    assert {r["run_id"] for r in runs} == {"S1", "S2"}
    assert all(r.point != "BAD" for r in live)


def test_entity_worst_rule_and_states(study):
    conn, frame = study
    live, _ = analyze.load_live(conn, frame, versions.PHP2SHELL)
    st = analyze.unit_states(live, frame, analyze.Scenario())
    assert st["S1"] == {"WI:a": "EXPOSED", "WI:b": "EXPOSED", "WI:c": "PATCHED", "WI:d": "UNREACHED"}
    assert st["S2"]["WI:a"] == "PATCHED" and st["S2"]["WI:b"] == "OPAQUE"
    dom = analyze.unit_states(live, frame, analyze.Scenario(unit="domain"))
    assert dom["S1"]["a.gov"] == "PATCHED" and dom["S1"]["a2.gov"] == "EXPOSED"


def test_cohort_curve_intervals_and_hiding(study):
    conn, frame = study
    live, _ = analyze.load_live(conn, frame, versions.PHP2SHELL)
    days = analyze.point_days(live)
    co = analyze.cohort_analysis(analyze.unit_states(live, frame, analyze.Scenario()), days)
    assert co.members == ["WI:a", "WI:b"]
    s2 = co.curve[-1]
    assert (s2["patched"], s2["exposed"], s2["went_dark"]) == (1, 0, 1)
    assert s2["denominator"] == 1, "went-dark is never counted as patched or exposed"
    assert co.hid_without_patching == 1
    assert sorted(co.intervals) == [(pytest.approx(2.0), pytest.approx(3.0)),
                                    (pytest.approx(2.0), float("inf"))]


def test_baseline_takes_latest_capture_before_cutoff(study):
    conn, frame = study
    baseline_cc.init_schema(conn)
    for crawl, date, ver in (("C1", "2026-09-01T00:00:00Z", "8.3.30"),
                             ("C2", "2026-10-05T00:00:00Z", "8.3.35"),
                             ("C3", "2026-10-18T00:00:00Z", "8.3.36")):   # after exploitation
        conn.execute("INSERT INTO baseline_observations(crawl_id, domain, captured, "
                     "warc_date_utc, status_code, headers_json, php_hints_json, warc_ip) "
                     "VALUES(?,?,?,?,?,?,?,?)", (crawl, "c.gov", 1, date, 200, xpb(ver), "{}", "192.0.2.9"))
    rs, info = analyze.load_baseline(conn, frame, versions.PHP2SHELL)
    assert len(rs) == 1 and rs[0].verdict.version == (8, 3, 35)
    assert info["captures_on_or_after_cutoff"] == 1
    assert rs[0].day < 0


def test_turnbull_exact_and_censored():
    cdf = dict(analyze.turnbull([(0, 1), (1, 2)]))
    assert cdf[1] == pytest.approx(0.5) and cdf[2] == pytest.approx(1.0)
    # Overlapping intervals: all mass can sit at t=1, which both contain - the NPMLE does.
    assert dict(analyze.turnbull([(0, 1), (0, 2)]))[1] == pytest.approx(1.0)
    cdf = dict(analyze.turnbull([(0, 1), (1, float("inf"))]))
    assert cdf[1] == pytest.approx(0.5), "a right-censored unit never reaches F=1"


def test_flapping_is_judged_per_domain_not_per_merged_entity(study):
    conn, frame = study
    live, _ = analyze.load_live(conn, frame, versions.PHP2SHELL)
    _, d2u = analyze.unit_states_and_map(live, frame, analyze.Scenario())
    assert analyze.flapping_units(live, d2u) == set()


def test_suppressor_primary_and_complementary():
    sup = analyze.Suppressor()
    # one suppressed cell + a shown total would give it away: hide the smallest other cell
    assert sup.row([25, 3, 40]) == ["§", "<10", "40"]
    assert sup.row([25, 3, 4]) == ["25", "<10", "<10"]
    assert sup.row([0, 12, 40]) == ["0", "12", "40"]
    assert sup.share(3, 40) == "§" and sup.share(20, 40) == "50%" and sup.share(5, 8) == "§"
    off = analyze.Suppressor(on=False)
    assert off.row([3]) == ["3"] and off.share(3, 8) == "38%"


def test_report_never_names_a_domain_or_organization(study):
    conn, frame = study
    text = analyze.build_report(conn, frame, versions.PHP2SHELL, sup=analyze.Suppressor())
    for d, r in frame.rows.items():
        assert d not in text and r["organization"] not in text
    assert "<10" in text, "tiny synthetic counts must be suppressed"
    assert "RQ2" in text and "Sensitivity" in text


def test_historical_event_rereads_archived_headers(study):
    conn, frame = study
    baseline_cc.init_schema(conn)
    for dom, ver in (("a.gov", "8.3.7"), ("b.gov", "8.3.8"), ("c.gov", "8.2.20")):
        conn.execute("INSERT INTO baseline_observations(crawl_id, domain, captured, "
                     "warc_date_utc, status_code, headers_json, php_hints_json) "
                     "VALUES(?,?,?,?,?,?,?)", ("CC-MAIN-2024-30", dom, 1, "2024-07-20T00:00:00Z",
                                                200, xpb(ver), "{}"))
    per = analyze.load_historical(conn, frame, versions.CVE_2024_4577)
    st = analyze.unit_states(per[0]["readings"], frame, analyze.Scenario())["CC-MAIN-2024-30"]
    assert st == {"WI:a": "EXPOSED", "WI:b": "PATCHED", "WI:c": "PATCHED"}


# ------------------------------------------------------------------ hosting
def test_asn_table_lookup_and_concentration(tmp_path):
    import gzip

    import hosting
    p = tmp_path / "ip2asn.tsv.gz"
    with gzip.open(p, "wt", encoding="utf-8") as fh:
        fh.write("192.0.2.0\t192.0.2.255\t64500\tUS\tEXAMPLE-HOST\n")
        fh.write("198.51.100.0\t198.51.100.255\t0\tNone\tNot routed\n")
    t = hosting.AsnTable.load(p)
    assert t.lookup("192.0.2.77") == 64500
    assert t.lookup("198.51.100.1") is None, "AS 0 is 'not routed', not a cluster"
    assert t.lookup("203.0.113.1") is None and t.lookup("not-an-ip") is None
    c = hosting.concentration(["x"] * 5 + ["y", "z", None])
    assert c["clusters"] == 3 and c["largest_cluster"] == 5
    assert c["share_in_clusters_ge5"] == pytest.approx(5 / 7)
    assert c["effective_independent"] == pytest.approx(1 / ((5 / 7) ** 2 + 2 * (1 / 7) ** 2))
