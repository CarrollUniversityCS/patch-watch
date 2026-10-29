"""src/platforms.py: classification, concentration, suppression, and the no-vendor-names default."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import db
import platforms
from analyze import SUPPRESS_BELOW, Suppressor

ROOT = Path(__file__).resolve().parent.parent


def cat(headers):
    return platforms.platform_of(headers)[0]


# ------------------------------------------------------------------ classification
@pytest.mark.parametrize("headers,want", [
    ({"server": ["Apache/2.4.58 (Ubuntu)"]}, platforms.SELF_RUN),
    ({"server": ["nginx/1.24.0"]}, platforms.SELF_RUN),
    ({"server": ["LiteSpeed"]}, platforms.SELF_RUN),
    ({"server": ["Microsoft-IIS/10.0"]}, platforms.MICROSOFT),
    ({"server": ["cloudflare"]}, platforms.EDGE),
    ({"server": ["AkamaiGHost"]}, platforms.EDGE),
    ({"server": ["nginx"], "cf-ray": ["abc-ORD"]}, platforms.EDGE),      # edge header beats the origin's token
    ({"x-amz-cf-id": ["x"]}, platforms.EDGE),
    ({"server": ["Squarespace"]}, platforms.BUILDER),
    ({"server": ["Pepyaka"]}, platforms.BUILDER),
    ({"server": ["SomethingCustom/3"]}, platforms.OTHER),
    ({"x-powered-by": ["ASP.NET"]}, platforms.MICROSOFT),
    ({}, platforms.NO_HEADER),
    (None, platforms.NO_HEADER),
    ({"server": [""]}, platforms.NO_HEADER),
])
def test_platform_classes(headers, want):
    assert cat(headers) == want


def test_every_category_is_declared():
    for h in ({"server": ["Apache"]}, {"server": ["cloudflare"]}, {}, {"server": ["zz"]}):
        assert cat(h) in platforms.CATEGORIES


def test_server_token_drops_version_and_comment():
    assert platforms.server_token({"server": ["Apache/2.4.58 (Ubuntu)"]}) == "apache"
    assert platforms.server_token({"server": ["Microsoft-IIS/10.0"]}) == "microsoft-iis"
    assert platforms.server_token({"server": ["DPS/2.0.0+sha-abc"]}) == "dps"
    assert platforms.server_token({"server": ["   "]}) == ""


@pytest.mark.parametrize("bad", [None, {}, [], "x", 5, {"server": None}, {"server": ["\x00"]}, {"server": [9999 * "a"]}])
def test_odd_headers_never_raise(bad):
    assert platforms.platform_of(bad)[0] in platforms.CATEGORIES


# ------------------------------------------------------------------ concentration
def test_hhi_extremes_and_empty():
    assert platforms.hhi([10]) == 1.0
    assert platforms.hhi([5, 5]) == pytest.approx(0.5)
    assert platforms.hhi([1] * 100) == pytest.approx(0.01)
    assert platforms.hhi([]) is None and platforms.hhi([0, 0]) is None


def test_hhi_is_larger_when_concentrated():
    assert platforms.hhi([90, 5, 5]) > platforms.hhi([34, 33, 33])


# ------------------------------------------------------------------ aggregation
def make_db(path, rows):
    conn = db.connect(path)
    db.init_db(conn)
    conn.execute("INSERT INTO runs(run_id, started_at_utc, finished_at_utc, config_json) VALUES "
                 "('R1','2026-10-28T14:00:00Z','2026-10-28T14:05:00Z','{\"region\": \"wisconsin\"}')")
    for i, (cls, headers, ip) in enumerate(rows):
        conn.execute("INSERT INTO observations(run_id, domain, class, status_code, headers_json, resolved_ip) "
                     "VALUES ('R1', ?, ?, 200, ?, ?)", (f"site{i}.example.test", cls, json.dumps(headers), ip))
    conn.commit()
    conn.close()


def table(tmp_path, rows):
    make_db(tmp_path / "t.db", rows)
    conn = db.connect(tmp_path / "t.db")
    try:
        return platforms.aggregate_conn(conn)
    finally:
        conn.close()


def rows_mixed():
    r = [("NO_PHP_EVIDENCE", {"server": ["cloudflare"]}, "192.0.2.1")] * 30
    r += [("NO_PHP_EVIDENCE", {"server": ["Apache/2.4.58"]}, f"198.51.100.{i}") for i in range(20)]
    r += [("EOL_UNFIXED", {"server": ["nginx/1.18.0"], "x-powered-by": ["PHP/7.4.33"]}, f"203.0.113.{i}") for i in range(12)]
    r += [("PATCHED_UPSTREAM", {"server": ["nginx/1.24.0"], "x-powered-by": ["PHP/8.5.12"]}, f"203.0.114.{i}") for i in range(10)]
    return r


def test_counts_and_ip_cluster_sizes(tmp_path):
    t = table(tmp_path, rows_mixed())
    assert t.answering == 72
    assert t.by_category[platforms.EDGE] == 30 and t.by_category[platforms.SELF_RUN] == 42
    assert t.ip_cluster_sizes[0] == 30 and sum(t.ip_cluster_sizes) == 72
    assert t.php_by_category[platforms.SELF_RUN] == {"eol": 12, "patched": 10}


def test_not_measured_rows_are_not_counted(tmp_path):
    t = table(tmp_path, [("NOT_MEASURED", {"server": ["nginx"]}, None), ("NO_RESPONSE", None, None)])
    assert t.answering == 0


def test_only_domains_limits_the_table(tmp_path):
    make_db(tmp_path / "t.db", rows_mixed())
    conn = db.connect(tmp_path / "t.db")
    t = platforms.aggregate_conn(conn, only_domains={"site0.example.test", "site1.example.test"})
    conn.close()
    assert t.answering == 2


def test_the_table_keeps_sizes_not_addresses(tmp_path):
    t = table(tmp_path, rows_mixed())
    assert all(isinstance(s, int) for s in t.ip_cluster_sizes)
    assert "192.0.2" not in json.dumps(platforms.public(t)) and "198.51.100" not in json.dumps(platforms.public(t))


# ------------------------------------------------------------------ disclosure
def test_vendors_are_not_named_by_default(tmp_path):
    assert platforms.NAME_VENDORS is False
    pub = platforms.public(table(tmp_path, rows_mixed()))
    text = json.dumps(pub).lower()
    for word in ("cloudflare", "apache", "nginx", "akamai", "squarespace"):
        assert word not in text, word
    assert [p["platform"] for p in pub["by_platform"]][0] == "platform 1"


def test_naming_is_possible_only_when_asked_for(tmp_path):
    pub = platforms.public(table(tmp_path, rows_mixed()), name_vendors=True)
    assert "cloudflare" in [p["platform"] for p in pub["by_platform"]]


def test_small_categories_and_platforms_are_suppressed(tmp_path):
    rows = rows_mixed() + [("NO_PHP_EVIDENCE", {"server": ["Squarespace"]}, "192.0.2.9")] * 3
    pub = platforms.public(table(tmp_path, rows))
    assert pub["by_category"][platforms.BUILDER]["n"] == "<10"
    assert pub["by_category"][platforms.BUILDER]["share"] == "§"
    assert "squarespace" not in json.dumps(pub).lower()
    assert all(p["n"] == "<10" or int(p["n"]) >= SUPPRESS_BELOW for p in pub["by_platform"])


def test_a_lone_hidden_category_forces_a_complementary_cell(tmp_path):
    rows = rows_mixed() + [("NO_PHP_EVIDENCE", {"server": ["Squarespace"]}, "192.0.2.9")] * 3
    pub = platforms.public(table(tmp_path, rows))
    cells = [v["n"] for v in pub["by_category"].values()]
    assert "<10" in cells and "§" in cells


def test_a_hidden_cell_has_no_visible_share(tmp_path):
    rows = rows_mixed() + [("NO_PHP_EVIDENCE", {"server": ["Squarespace"]}, "192.0.2.9")] * 3
    pub = platforms.public(table(tmp_path, rows))
    for v in pub["by_category"].values():
        if v["n"] in ("<10", "§"):
            assert v["share"] == "§"


def test_small_platforms_fold_into_other_and_remainder_is_not_a_lone_small_number(tmp_path):
    rows = [("NO_PHP_EVIDENCE", {"server": ["alpha/1"]}, None)] * 40
    rows += [("NO_PHP_EVIDENCE", {"server": ["beta/1"]}, None)] * 12
    rows += [("NO_PHP_EVIDENCE", {"server": ["gamma/1"]}, None)] * 4
    pub = platforms.public(table(tmp_path, rows))
    names = [p["platform"] for p in pub["by_platform"]]
    assert "other platforms" in names
    other = [p for p in pub["by_platform"] if p["platform"] == "other platforms"][0]
    assert other["n"] != "<10"        # 4 alone would be a recoverable small remainder: beta folded in


def test_unsuppressed_mode_shows_raw_counts(tmp_path):
    rows = [("NO_PHP_EVIDENCE", {"server": ["Squarespace"]}, None)] * 3
    pub = platforms.public(table(tmp_path, rows), Suppressor(on=False))
    assert pub["by_category"][platforms.BUILDER]["n"] == "3"


def test_hhi_hidden_for_tiny_answering_sets(tmp_path):
    pub = platforms.public(table(tmp_path, [("NO_PHP_EVIDENCE", {"server": ["nginx"]}, None)] * 3))
    assert pub["platform_hhi"] == "§"


def test_no_domain_names_in_output(tmp_path):
    text = json.dumps(platforms.public(table(tmp_path, rows_mixed())))
    assert "example.test" not in text and re.search(r"site\d", text) is None


def test_module_name_does_not_shadow_the_standard_library():
    import platform as std
    assert hasattr(std, "system") and not (ROOT / "src" / "platform.py").exists()


# ------------------------------------------------------------------ the analysis section
def test_analysis_section_is_exploratory_and_names_no_vendor(tmp_path):
    import analyze
    import test_analyze as ta
    frame_path = tmp_path / "f.csv"
    ta.write_frame(frame_path, [{"domain": f"d{i}.gov", "entity_id": f"WI:{i}", "organization": f"Town {i}"}
                                for i in range(25)])
    conn = db.connect(tmp_path / "s.db")
    db.init_db(conn)
    ta.add_run(conn, "S1", "2026-10-24T14:00:00Z")
    conn.execute("UPDATE runs SET config_json = '{\"region\": \"wisconsin\"}'")
    for i in range(25):
        ta.add_obs(conn, "S1", f"d{i}.gov", "2026-10-24T14:00:00Z",
                   headers=json.dumps({"server": ["cloudflare" if i % 2 else "Apache/2.4.58"]}), ip=f"192.0.2.{i}")
    conn.commit()
    frame = analyze.Frame.load(frame_path)
    runs = [dict(r) for r in conn.execute("SELECT * FROM runs")]
    text = "\n".join(analyze._platforms(conn, frame, runs, analyze.Suppressor()))
    assert "Exploratory: platform and hosting concentration" in text and "NOT pre-registered" in text
    assert "cloudflare" not in text.lower() and "d1.gov" not in text and "Town 1" not in text


# ------------------------------------------------------------------ election-office view (analyze._election)
def _election_study(tmp_path, n_dom, n_php, n_eol):
    import analyze
    import test_analyze as ta
    frame_path = tmp_path / "f.csv"
    ta.write_frame(frame_path, [{"domain": f"e{i}.gov", "entity_id": f"WI:e{i}", "organization": f"Office {i}",
                                 "stratum": "Election office", "domain_type": "City - Election"}
                                for i in range(n_dom)])
    conn = db.connect(tmp_path / "s.db")
    db.init_db(conn)
    ta.add_run(conn, "S1", "2026-10-28T14:00:00Z")
    conn.execute("UPDATE runs SET config_json = '{\"region\": \"wisconsin\"}'")
    for i in range(n_dom):
        v = "7.4.33" if i < n_eol else "8.5.12"
        hdr = json.dumps({"x-powered-by": [f"PHP/{v}"]}) if i < n_php else json.dumps({"server": ["nginx"]})
        ta.add_obs(conn, "S1", f"e{i}.gov", "2026-10-28T14:00:00Z", headers=hdr)
    conn.commit()
    frame = analyze.Frame.load(frame_path)
    runs = [dict(r) for r in conn.execute("SELECT * FROM runs")]
    return analyze, conn, frame, runs


def test_election_table_is_withheld_whole_when_any_cell_is_small(tmp_path):
    analyze, conn, frame, runs = _election_study(tmp_path, n_dom=40, n_php=8, n_eol=3)
    text = "\n".join(analyze._election(conn, frame, runs, analyze.Suppressor()))
    assert "Too few election-office domains" in text and "| 2026-10-28 |" not in text
    assert "e1.gov" not in text and "Office 1" not in text


def test_election_table_is_shown_when_every_count_is_large_enough(tmp_path):
    analyze, conn, frame, runs = _election_study(tmp_path, n_dom=60, n_php=30, n_eol=12)
    text = "\n".join(analyze._election(conn, frame, runs, analyze.Suppressor()))
    assert "| 2026-10-28 | before | 60 | 30 | 30 | 12 |" in text


def test_election_section_is_exploratory_and_dated_against_election_day(tmp_path):
    analyze, conn, frame, runs = _election_study(tmp_path, n_dom=60, n_php=30, n_eol=12)
    text = "\n".join(analyze._election(conn, frame, runs, analyze.Suppressor()))
    assert "NOT pre-registered" in text and analyze.ELECTION_DAY == "2026-11-03"


def test_no_election_stratum_means_no_section(tmp_path):
    import analyze
    import test_analyze as ta
    frame_path = tmp_path / "f.csv"
    ta.write_frame(frame_path, [{"domain": "a.gov", "entity_id": "WI:a", "organization": "Town A"}])
    conn = db.connect(tmp_path / "s.db")
    db.init_db(conn)
    assert analyze._election(conn, analyze.Frame.load(frame_path), [], analyze.Suppressor()) == []
