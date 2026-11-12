"""scripts/t2_endpoints.py: the national, baseline-fixed host cohort and A_host(d) of Amendment T2 (draft).

The code is written and tested on synthetic data BEFORE any T2 reading exists, so the endpoint definitions cannot be shaped by data.
Nothing here touches the network or writes to the database.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]
import t2_endpoints as t2  # noqa: E402
import versions  # noqa: E402

EV = versions.PatchEvent(key="t2_test", title="synthetic", t0_utc="2026-11-19T12:00:00Z",
                         fixed_releases={(8, 3): (8, 3, 37), (8, 4): (8, 4, 28)}, published=True)
OLD, NEW, EOL83 = "PHP/8.3.36", "PHP/8.3.37", "PHP/7.4.33"

SCHEMA = ("create table observations (id integer primary key, run_id text, snapshot_label text, domain text, started_at_utc text,"
          " status_code int, error_type text, skipped_reason text, headers_json text, php_hints_json text, cert_error int,"
          " resolved_ip text)")


def hdr(php=None, edge=False, extra=None):
    h = {}
    if php:
        h["x-powered-by"] = [php]
    if edge:
        h["cf-ray"] = ["abc"]
        h["server"] = ["cloudflare"]
    h.update(extra or {})
    return json.dumps(h)


def build(path, plan):
    """plan: {label: (date, [(domain, ip, headers_json_or_None_for_unreached), ...])}"""
    conn = sqlite3.connect(path)
    conn.execute(SCHEMA)
    for label, (day, rows) in plan.items():
        for dom, ip, h in rows:
            conn.execute("insert into observations(run_id,snapshot_label,domain,started_at_utc,status_code,headers_json,"
                         "php_hints_json,cert_error,resolved_ip) values (?,?,?,?,?,?,?,0,?)",
                         (f"R{label}", label, dom, f"{day}T14:00:00Z", 200 if h else None, h or "{}", "{}", ip))
    conn.commit()
    conn.close()


def run(path, labels, t0="2026-11-19", baseline="B"):
    conn = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return t2.endpoints(conn, EV, baseline_label=baseline, point_labels=labels, t0_date=t0)
    finally:
        conn.close()


@pytest.fixture
def db(tmp_path):
    return tmp_path / "study.db"


def test_day_convention_is_the_utc_calendar_offset_from_the_t0_date():
    assert t2.day_offset("2026-11-20T14:00:02Z", "2026-11-19") == 1
    assert t2.day_offset("2026-11-26T14:00:02Z", "2026-11-19") == 7
    assert t2.day_offset("2026-11-19T23:59:59Z", "2026-11-19") == 0


def test_a_host_at_day_seven_counts_patched_over_patched_plus_exposed(db):
    # four at-risk hosts at baseline (all OLD); by day 3 two patched; by day 7 three patched
    base = ("2026-11-18", [(f"s{i}.example", f"10.0.0.{i}", hdr(OLD)) for i in range(4)] + [("eol.example", "10.0.1.1", hdr(EOL83))])
    d3 = ("2026-11-22", [("s0.example", "10.0.0.0", hdr(NEW)), ("s1.example", "10.0.0.1", hdr(NEW)),
                         ("s2.example", "10.0.0.2", hdr(OLD)), ("s3.example", "10.0.0.3", hdr(OLD))])
    d7 = ("2026-11-26", [("s0.example", "10.0.0.0", hdr(NEW)), ("s1.example", "10.0.0.1", hdr(NEW)),
                         ("s2.example", "10.0.0.2", hdr(NEW)), ("s3.example", "10.0.0.3", hdr(OLD))])
    build(db, {"B": base, "P3": d3, "P7": d7})
    res = run(db, ["P3", "P7"])
    assert res["cohort_hosts"] == 4 and res["not_in_cohort"]["eol"] == 1
    assert res["days"][3]["patched"] == 2 and res["days"][3]["exposed"] == 2 and res["days"][3]["rate"] == 0.5
    assert res["days"][7]["patched"] == 3 and res["days"][7]["exposed"] == 1 and res["days"][7]["rate"] == 0.75
    assert res["never_patched_by_last"] == 1
    lo, hi = res["days"][7]["ci95"]
    assert 0.194 < lo < 0.195 and 0.993 < hi < 0.994                   # exact (Clopper-Pearson) interval for 3 of 4: 0.194 to 0.994


def test_host_is_frozen_at_the_baseline_address(db):
    base = ("2026-11-18", [("a.example", "10.0.0.1", hdr(OLD)), ("b.example", "10.0.0.2", hdr(OLD))])
    # on day 7 both sites moved to ONE new address: they must still be two hosts
    d7 = ("2026-11-26", [("a.example", "10.9.9.9", hdr(NEW)), ("b.example", "10.9.9.9", hdr(OLD))])
    build(db, {"B": base, "P7": d7})
    res = run(db, ["P7"])
    assert res["cohort_hosts"] == 2 and res["days"][7]["patched"] == 1 and res["days"][7]["exposed"] == 1


def test_sites_on_one_baseline_address_are_one_host_and_the_worst_site_decides(db):
    base = ("2026-11-18", [("a.example", "10.0.0.1", hdr(OLD)), ("b.example", "10.0.0.1", hdr(OLD)),
                           ("c.example", "10.0.0.2", hdr(OLD))])
    d7 = ("2026-11-26", [("a.example", "10.0.0.1", hdr(NEW)), ("b.example", "10.0.0.1", hdr(OLD)),
                         ("c.example", "10.0.0.2", hdr(NEW))])
    build(db, {"B": base, "P7": d7})
    res = run(db, ["P7"])
    assert res["cohort_hosts"] == 2
    assert res["days"][7]["patched"] == 1 and res["days"][7]["exposed"] == 1       # host .1 stays exposed until b is patched
    assert res["sites_in_cohort"] == 3


def test_edge_fronted_sites_are_each_their_own_unit_even_on_a_shared_address(db):
    base = ("2026-11-18", [("a.example", "104.0.0.1", hdr(OLD, edge=True)), ("b.example", "104.0.0.1", hdr(OLD, edge=True)),
                           ("c.example", "10.0.0.5", hdr(OLD)), ("d.example", "10.0.0.5", hdr(OLD))])
    build(db, {"B": base})
    res = run(db, [])
    assert res["cohort_hosts"] == 3                                    # a, b separate; c+d share one host
    assert res["edge_units"] == 2


def test_hidden_version_is_never_counted_as_patched(db):
    base = ("2026-11-18", [("a.example", "10.0.0.1", hdr(OLD)), ("b.example", "10.0.0.2", hdr(OLD))])
    d7 = ("2026-11-26", [("a.example", "10.0.0.1", hdr("PHP")), ("b.example", "10.0.0.2", hdr(NEW))])   # a hid its version
    build(db, {"B": base, "P7": d7})
    res = run(db, ["P7"])
    assert res["days"][7]["patched"] == 1 and res["days"][7]["exposed"] == 0 and res["days"][7]["hid"] == 1
    assert res["days"][7]["rate"] == 1.0                               # rate is patched / (patched + exposed) only
    assert res["days"][7]["denominator"] == 1


def test_host_with_no_site_read_on_the_day_is_not_estimable_and_left_out(db):
    base = ("2026-11-18", [("a.example", "10.0.0.1", hdr(OLD)), ("b.example", "10.0.0.2", hdr(OLD))])
    d7 = ("2026-11-26", [("a.example", "10.0.0.1", hdr(NEW)), ("b.example", "10.0.0.2", None)])      # b unreached
    build(db, {"B": base, "P7": d7})
    res = run(db, ["P7"])
    assert res["days"][7]["not_estimable"] == 1 and res["days"][7]["denominator"] == 1


def test_a_day_without_a_reading_within_one_day_is_not_estimable_not_filled_in(db):
    base = ("2026-11-18", [("a.example", "10.0.0.1", hdr(OLD))])
    d1 = ("2026-11-20", [("a.example", "10.0.0.1", hdr(NEW))])
    build(db, {"B": base, "P1": d1})
    res = run(db, ["P1"])
    assert res["days"][1]["patched"] == 1
    assert res["days"][3]["estimable"] is False and res["days"][7]["estimable"] is False
    assert res["days"][3]["reading_day"] == 1                           # the last earlier reading is shown, not used


def test_domains_not_observed_at_baseline_are_excluded_and_counted(db):
    base = ("2026-11-18", [("a.example", "10.0.0.1", hdr(OLD))])
    d7 = ("2026-11-26", [("a.example", "10.0.0.1", hdr(NEW)), ("late.example", "10.0.0.7", hdr(OLD))])
    build(db, {"B": base, "P7": d7})
    res = run(db, ["P7"])
    assert res["cohort_hosts"] == 1 and res["not_in_baseline"] == 1


def test_fewer_than_the_minimum_cohort_is_descriptive_only(db):
    for n, expect in ((29, True), (30, False)):
        rows = [(f"s{i}.example", f"10.1.0.{i}", hdr(OLD)) for i in range(n)]
        p = db.with_name(f"c{n}.db")
        build(p, {"B": ("2026-11-18", rows)})
        assert run(p, [])["descriptive_only"] is expect


def test_branch_without_a_fix_is_end_of_life_and_not_in_the_cohort(db):
    base = ("2026-11-18", [("a.example", "10.0.0.1", hdr(OLD)), ("b.example", "10.0.0.2", hdr(EOL83))])
    build(db, {"B": base})
    res = run(db, [])
    assert res["cohort_hosts"] == 1 and res["not_in_cohort"]["eol"] == 1


def test_an_unpublished_event_is_refused(db):
    build(db, {"B": ("2026-11-18", [("a.example", "10.0.0.1", hdr(OLD))])})
    unpublished = versions.CVE_2026_115560
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    with pytest.raises(ValueError, match="not published"):
        t2.endpoints(conn, unpublished, baseline_label="B", point_labels=[], t0_date="2026-11-19")


def test_read_only_and_silent_on_the_network(db, monkeypatch):
    build(db, {"B": ("2026-11-18", [("a.example", "10.0.0.1", hdr(OLD))])})

    def boom(*a, **k):
        raise AssertionError("network used")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    before = db.read_bytes()
    run(db, [])
    assert db.read_bytes() == before


def test_private_output_names_no_domain_and_hides_small_cells(db, capsys):
    rows = [(f"s{i}.example", f"10.2.0.{i}", hdr(OLD)) for i in range(40)]
    d3 = [(f"s{i}.example", f"10.2.0.{i}", hdr(NEW if i < 5 else OLD)) for i in range(40)]
    build(db, {"B": ("2026-11-18", rows), "P3": ("2026-11-22", d3)})
    res = run(db, ["P3"])
    text = t2.render(res)
    assert "example" not in text and "<10" in text and "PRIVATE" in text and "REHEARSAL" in text
