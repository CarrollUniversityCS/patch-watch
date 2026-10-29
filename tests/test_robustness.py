"""Randomized and boundary tests for the new modules. Seeded loops (no extra dependency): the same seed
gives the same cases, so a failure is reproducible."""

from __future__ import annotations

import json
import random
import sqlite3
import string
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

import db
import inventory
import intake
import platforms
import support_status as ss
from analyze import SUPPRESS_BELOW, Suppressor

ROOT = Path(__file__).resolve().parent.parent
SEEDS = range(40)


def rand_text(rng, n=None):
    alphabet = string.printable + "éß漢字✓§—\x00\x7f\xff"
    return "".join(rng.choice(alphabet) for _ in range(n if n is not None else rng.randint(0, 40)))


def rand_headers(rng):
    shape = rng.randint(0, 6)
    names = ["server", "x-powered-by", "x-generator", "link", "x-pingback", "via", rand_text(rng, 6)]
    if shape == 0:
        return None
    if shape == 1:
        return rng.choice([{}, [], "", 0, 3.5, True])
    if shape == 2:
        return {rng.choice(names): [rand_text(rng) for _ in range(rng.randint(0, 3))] for _ in range(rng.randint(0, 5))}
    if shape == 3:
        return {rng.choice(names): rand_text(rng) for _ in range(rng.randint(0, 5))}
    if shape == 4:
        return [[rng.choice(names), rand_text(rng)] for _ in range(rng.randint(0, 5))]
    if shape == 5:
        return {rng.choice(names): [rng.choice([None, 3, "x", ["nested"]]) for _ in range(2)] for _ in range(3)}
    return {rng.choice(names): ["Apache/%d.%d.%d" % (rng.randint(0, 99), rng.randint(0, 99), rng.randint(0, 999))]}


# ------------------------------------------------------------------ never raises
@pytest.mark.parametrize("seed", SEEDS)
def test_header_parsers_never_raise_on_arbitrary_input(seed):
    rng = random.Random(seed)
    for _ in range(50):
        h = rand_headers(rng)
        reads = inventory.parse_headers(h)
        assert all(r.product in inventory.PRODUCTS for r in reads.values())
        cat, tok = platforms.platform_of(h)
        assert cat in platforms.CATEGORIES and isinstance(tok, str)


@pytest.mark.parametrize("seed", SEEDS)
def test_a_rankable_read_always_has_three_numbers_and_no_package_suffix(seed):
    rng = random.Random(seed)
    for _ in range(50):
        for r in inventory.parse_headers(rand_headers(rng)).values():
            if r.rankable:
                assert r.version is not None and len(r.version) == 3 and r.distro_family is None
            if r.version is not None:
                assert all(isinstance(x, int) and x >= 0 for x in r.version)


# ------------------------------------------------------------------ support status
@pytest.mark.parametrize("product", ["php", "apache", "nginx", "openssl", "wordpress"])
def test_support_never_comes_back_once_a_branch_is_end_of_life(product):
    rng = random.Random(7)
    cycles = ss.load_snapshot()["products"][product]["cycles"]
    for c in cycles:
        version = tuple(int(x) for x in c["cycle"].split("."))
        days = sorted(date(2015, 1, 1) + timedelta(days=rng.randint(0, 5800)) for _ in range(80))
        states = [ss.status(product, version, d) for d in days]
        if ss.END_OF_LIFE in states:
            first = states.index(ss.END_OF_LIFE)
            assert all(s == ss.END_OF_LIFE for s in states[first:]), (product, c["cycle"])


@pytest.mark.parametrize("seed", SEEDS)
def test_status_is_always_a_documented_value(seed):
    rng = random.Random(seed)
    for _ in range(100):
        prod = rng.choice(["php", "apache", "nginx", "openssl", "wordpress", "iis", rand_text(rng, 4)])
        v = tuple(rng.randint(0, 12) for _ in range(rng.randint(0, 4)))
        d = rng.choice([date(2026, 10, 28), "2026-10-28", "garbage", None, "", date(1999, 1, 1)])
        assert ss.status(prod, v, d) in ss.STATUSES


# ------------------------------------------------------------------ suppression
def shown_numbers(values):
    out = []
    for v in values:
        if isinstance(v, str) and v.isdigit():
            out.append(int(v))
    return out


@pytest.mark.parametrize("seed", SEEDS)
def test_suppressor_never_shows_a_count_below_the_threshold(seed):
    rng = random.Random(seed)
    sup = Suppressor()
    for _ in range(100):
        vals = [rng.choice([0, rng.randint(1, 9), rng.randint(10, 500)]) for _ in range(rng.randint(1, 8))]
        for cell in sup.row(vals):
            if cell.isdigit():
                assert int(cell) == 0 or int(cell) >= SUPPRESS_BELOW
        assert sup.count(rng.randint(1, SUPPRESS_BELOW - 1)) == f"<{SUPPRESS_BELOW}"


@pytest.mark.parametrize("seed", SEEDS)
def test_inventory_public_never_shows_a_small_count(seed):
    rng = random.Random(seed)
    inv = inventory.Inventory(as_of="2026-10-28")
    inv.attempted = rng.randint(0, 300)
    inv.answering = rng.randint(0, inv.attempted)
    for p in inventory.PRODUCTS:
        c = inventory.Counts()
        c.answering = inv.answering
        c.named = rng.randint(0, inv.answering)
        c.disclosed = rng.randint(0, c.named)
        c.rankable = rng.randint(0, c.disclosed)
        c.placed = rng.randint(0, c.rankable)
        c.eol = rng.randint(0, c.placed)
        c.eol_distro = rng.randint(0, 20)
        inv.by_product[p] = c
        for t in ("City", "Town", "Rare"):
            d = inventory.Counts(answering=rng.randint(0, 40), named=0)
            d.disclosed = rng.randint(0, d.answering)
            inv.by_type.setdefault(t, {})[p] = d
    pub = inv.public()
    flat = json.dumps(pub)
    for p, v in pub["products"].items():
        for k in ("named", "disclosed", "rankable", "distro_labelled", "unsupported", "unsupported_basis"):
            for n in shown_numbers([v[k]]):
                assert n == 0 or n >= SUPPRESS_BELOW, (p, k, v[k])
    assert "example" not in flat


@pytest.mark.parametrize("seed", SEEDS)
def test_platform_public_never_shows_a_small_count_or_a_name(seed):
    rng = random.Random(seed)
    t = platforms.PlatformTable(answering=rng.randint(0, 400), as_of="2026-10-28")
    for c in platforms.CATEGORIES:
        t.by_category[c] = rng.randint(0, 120)
    for i in range(rng.randint(0, 8)):
        t.by_token[f"secrettoken{i}"] = rng.randint(1, 80)
    t.ip_cluster_sizes = sorted((rng.randint(1, 30) for _ in range(rng.randint(0, 40))), reverse=True)
    pub = platforms.public(t)
    assert "secrettoken" not in json.dumps(pub)
    for v in pub["by_category"].values():
        for n in shown_numbers([v["n"]]):
            assert n == 0 or n >= SUPPRESS_BELOW
    for p in pub["by_platform"]:
        for n in shown_numbers([p["n"]]):
            assert n >= SUPPRESS_BELOW


# ------------------------------------------------------------------ intake sampling
@pytest.mark.parametrize("seed", SEEDS)
def test_stratified_sample_is_unique_bounded_and_repeatable(seed):
    rng = random.Random(seed)
    rows = [{"cve": f"CVE-{rng.randint(2015, 2026)}-{i}", "added": f"{rng.randint(2021, 2026)}-01-01",
             "tier": rng.choice([intake.TIER_A, intake.TIER_B, intake.TIER_C])} for i in range(rng.randint(0, 300))]
    size = rng.randint(0, 150)
    a = intake.stratified_sample(rows, size, seed=seed)
    assert a == intake.stratified_sample(rows, size, seed=seed)
    assert len(a) <= min(size, len(rows)) and len({r["cve"] for r in a}) == len(a)


@pytest.mark.parametrize("seed", SEEDS)
def test_kev_loaders_survive_random_junk(seed):
    rng = random.Random(seed)
    junk = {"vulnerabilities": [rng.choice([{}, {"cveID": rand_text(rng, 8)}, {"cveID": "CVE-2026-1234", "vendorProject": rand_text(rng)},
                                            {"cveID": None}]) for _ in range(10)]}
    k = intake.load_kev(junk)
    rows = intake.build_rows(k)
    assert all(r["proposed_tier"] not in ("live", "awaiting_fix") for r in rows)
    assert intake.parse_epss(rand_text(rng)) == {}
    assert intake.extract_cpes(rng.choice([None, {}, {"containers": []}, {"containers": {"cna": {"affected": [{"cpes": [rand_text(rng)]}]}}}])) == []


# ------------------------------------------------------------------ database boundaries
def test_database_with_missing_tables_is_an_error_not_a_crash(tmp_path):
    p = tmp_path / "empty.db"
    sqlite3.connect(p).close()
    with pytest.raises(sqlite3.Error):
        inventory.aggregate(p)
    assert inventory.main(["--db", str(p)]) == 2


def test_file_that_is_not_a_database_is_an_error(tmp_path):
    p = tmp_path / "not.db"
    p.write_text("this is not sqlite", encoding="utf-8")
    assert inventory.main(["--db", str(p)]) == 2


def test_rows_with_null_columns_do_not_crash_the_inventory(tmp_path):
    conn = db.connect(tmp_path / "t.db")
    db.init_db(conn)
    conn.execute("INSERT INTO runs(run_id, started_at_utc, finished_at_utc, config_json) VALUES "
                 "('R1', NULL, '2026-10-28T14:05:00Z', '{\"region\": \"wisconsin\"}')")
    conn.execute("INSERT INTO domains(domain) VALUES ('a.example.test')")
    conn.execute("INSERT INTO observations(run_id, domain) VALUES ('R1', 'a.example.test')")
    conn.commit()
    conn.close()
    inv = inventory.aggregate(tmp_path / "t.db", run_id="R1")
    assert inv.attempted == 1 and inv.as_of == ""
    inventory.Inventory.public(inv)


def test_headers_json_of_every_wrong_type_is_handled(tmp_path):
    conn = db.connect(tmp_path / "t.db")
    db.init_db(conn)
    conn.execute("INSERT INTO runs(run_id, started_at_utc, finished_at_utc, config_json) VALUES "
                 "('R1', '2026-10-28T14:00:00Z', '2026-10-28T14:05:00Z', '{\"region\": \"wisconsin\"}')")
    for i, text in enumerate(["null", "[]", "5", '"s"', "{not json", "", '{"server": 7}', '{"server": [[1]]}']):
        conn.execute("INSERT INTO domains(domain) VALUES (?)", (f"d{i}.example.test",))
        conn.execute("INSERT INTO observations(run_id, domain, class, status_code, headers_json) VALUES "
                     "('R1', ?, 'NO_PHP_EVIDENCE', 200, ?)", (f"d{i}.example.test", text))
    conn.commit()
    conn.close()
    assert inventory.aggregate(tmp_path / "t.db").answering == 8
    c = db.connect(tmp_path / "t.db")
    assert platforms.aggregate_conn(c).answering == 8
    c.close()


# ------------------------------------------------------------------ Windows console and encoding
NEW_SCRIPTS = ["kev_census", "intake_weekly", "ha_coverage", "link_census_of_governments", "contact_fill_rate",
               "notification_power", "make_tables"]
NEW_SCRIPTS = [s for s in NEW_SCRIPTS if (ROOT / "scripts" / f"{s}.py").exists()]     # some are kept out of the public clone


@pytest.mark.parametrize("script", NEW_SCRIPTS)
def test_help_runs_under_a_cp1252_console(script):
    r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / f"{script}.py"), "--help"],
                       capture_output=True, env={"PYTHONIOENCODING": "cp1252", "PATH": ""}, timeout=60)
    assert r.returncode == 0, r.stderr.decode("cp1252", "replace")[-300:]


@pytest.mark.parametrize("script", NEW_SCRIPTS)
def test_bad_arguments_exit_nonzero_not_with_a_traceback(script):
    r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / f"{script}.py"), "--definitely-not-a-flag"],
                       capture_output=True, timeout=60)
    assert r.returncode == 2 and b"Traceback" not in r.stderr
