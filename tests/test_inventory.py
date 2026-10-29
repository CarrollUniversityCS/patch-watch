"""src/inventory.py: header parsing traps, funnel counts, suppression. No network, no real data."""

from __future__ import annotations

import json
import sqlite3

import pytest

import db
import inventory
from analyze import SUPPRESS_BELOW, Suppressor


def p(headers):
    return inventory.parse_headers(headers)


# ------------------------------------------------------------- parsing traps
def test_apache_bare_version_is_rankable():
    r = p({"server": ["Apache/2.4.58"]})["apache"]
    assert r.version == (2, 4, 58) and r.rankable and r.disclosed


def test_apache_with_distro_comment_is_disclosed_but_not_rankable():
    r = p({"server": ["Apache/2.4.58 (Ubuntu)"]})["apache"]
    assert r.disclosed and not r.rankable and r.distro_family == "ubuntu"


def test_apache_red_hat_comment_family():
    r = p({"server": ["Apache/2.4.37 (Red Hat Enterprise Linux)"]})["apache"]
    assert r.distro_family == "el" and not r.rankable


def test_apache_without_version_is_named_only():
    r = p({"server": ["Apache"]})["apache"]
    assert r.named and not r.disclosed and not r.rankable


def test_apache_coyote_is_not_apache_httpd():
    assert "apache" not in p({"server": ["Apache-Coyote/1.1"]})


def test_apache_httpclient_is_not_apache_httpd():
    assert "apache" not in p({"server": ["Apache-HttpClient/4.5"]})


def test_nginx_version():
    r = p({"server": ["nginx/1.24.0"]})["nginx"]
    assert r.version == (1, 24, 0) and r.rankable


def test_nginx_ubuntu_comment_not_rankable():
    r = p({"server": ["nginx/1.18.0 (Ubuntu)"]})["nginx"]
    assert r.disclosed and not r.rankable


def test_openresty_is_not_nginx():
    assert "nginx" not in p({"server": ["openresty/1.21.4.1"]})


def test_iis_two_part_version_is_partial_not_rankable():
    r = p({"server": ["Microsoft-IIS/10.0"]})["iis"]
    assert r.disclosed and r.partial and not r.rankable and r.version is None


def test_two_part_version_never_becomes_dot_zero():
    r = p({"server": ["Apache/2.4"]})["apache"]
    assert r.version is None and r.partial


def test_php_in_x_powered_by():
    r = p({"x-powered-by": ["PHP/8.2.35"]})["php"]
    assert r.version == (8, 2, 35) and r.rankable


def test_php_ubuntu_suffix_not_rankable():
    r = p({"x-powered-by": ["PHP/8.1.2-1ubuntu2.14"]})["php"]
    assert r.disclosed and not r.rankable and r.distro_family == "ubuntu"


def test_php_named_without_version():
    r = p({"x-powered-by": ["PHP"]})["php"]
    assert r.named and not r.disclosed


def test_phpbb_is_not_php():
    assert "php" not in p({"x-powered-by": ["phpBB"]})


def test_php_fpm_is_not_php_version():
    r = p({"x-powered-by": ["PHP-FPM"]}).get("php")
    assert r is None or not r.disclosed


def test_php_in_server_header_via_mod_php():
    r = p({"server": ["Apache/2.4.58 PHP/8.3.36"]})
    assert r["php"].version == (8, 3, 36) and r["apache"].version == (2, 4, 58)


def test_multiple_server_values_all_considered():
    r = p({"server": ["cloudflare", "nginx/1.25.3"]})
    assert r["nginx"].rankable


def test_best_read_wins_when_values_conflict():
    r = p({"server": ["nginx", "nginx/1.25.3"]})["nginx"]
    assert r.rankable


def test_openssl_in_server_comment_token():
    r = p({"server": ["Apache/2.4.58 OpenSSL/3.0.13"]})
    assert r["openssl"].version == (3, 0, 13)


def test_openssl_letter_patch_keeps_suffix():
    r = p({"server": ["Apache/2.4.51 OpenSSL/1.1.1k"]})["openssl"]
    assert r.version == (1, 1, 1) and r.suffix == "k"


def test_litespeed_named_only():
    r = p({"server": ["LiteSpeed"]})["litespeed"]
    assert r.named and not r.disclosed


def test_wordpress_from_generator_header():
    r = p({"x-generator": ["WordPress 6.5.3"]})["wordpress"]
    assert r.disclosed or r.partial or r.version


def test_wordpress_evidence_from_rest_link_has_no_version():
    r = p({"link": ['<https://x.example/wp-json/>; rel="https://api.w.org/"']})["wordpress"]
    assert r.named and not r.disclosed


def test_header_names_are_case_insensitive():
    assert "nginx" in p({"Server": ["nginx/1.24.0"]})


def test_pair_list_shape_accepted():
    assert "nginx" in p([["server", "nginx/1.24.0"]])


def test_scalar_values_accepted():
    assert "nginx" in p({"server": "nginx/1.24.0"})


@pytest.mark.parametrize("bad", [None, {}, [], "text", 7, {"server": None}, {"server": [None]},
                                 {"server": [""]}, {1: ["x"]}, [["only-one"]], {"server": ["\x00\xff"]},
                                 {"server": ["Apache/"]}, {"server": ["nginx/ "]}])
def test_odd_input_never_raises(bad):
    assert isinstance(p(bad), dict)


def test_garbage_version_slot_is_unranked():
    r = p({"server": ["nginx/abc"]}).get("nginx")
    assert r is None or not r.rankable


# ------------------------------------------------------------- aggregation
def make_db(path, rows, run_id="R1", region="wisconsin", kill=None):
    conn = db.connect(path)
    db.init_db(conn)
    conn.execute(
        "INSERT INTO runs(run_id, started_at_utc, finished_at_utc, kill_switch, config_json) VALUES (?,?,?,?,?)",
        (run_id, "2026-10-28T14:00:00Z", "2026-10-28T14:05:00Z", kill, json.dumps({"region": region})))
    for i, (cls, headers, dtype, php_ev) in enumerate(rows):
        dom = f"site{i}.example.test"
        conn.execute("INSERT INTO domains(domain, domain_type) VALUES (?,?)", (dom, dtype))
        conn.execute(
            "INSERT INTO observations(run_id, domain, class, headers_json, php_evidence) VALUES (?,?,?,?,?)",
            (run_id, dom, cls, json.dumps(headers) if headers is not None else None, php_ev))
    conn.commit()
    conn.close()


def test_funnel_counts(tmp_path):
    rows = [("NO_RESPONSE", None, "City", 0), ("NOT_MEASURED", None, "City", 0)]
    rows += [("PATCHED_UPSTREAM", {"x-powered-by": ["PHP/8.3.36"]}, "City", 1)] * 3
    rows += [("PHP_VERSION_HIDDEN", {"x-powered-by": ["PHP"]}, "City", 1)] * 2
    rows += [("NO_PHP_EVIDENCE", {"server": ["nginx"]}, "County", 0)] * 4
    make_db(tmp_path / "t.db", rows)
    inv = inventory.aggregate(tmp_path / "t.db")
    assert inv.funnel("php") == {"attempted": 11, "answering": 9, "named": 5, "disclosed": 3, "rankable": 3}
    assert inv.by_product["nginx"].named == 4


def test_php_evidence_from_body_counts_as_named_not_disclosed(tmp_path):
    make_db(tmp_path / "t.db", [("PHP_VERSION_HIDDEN", {"server": ["Apache"]}, "City", 1)])
    c = inventory.aggregate(tmp_path / "t.db").by_product["php"]
    assert (c.named, c.disclosed) == (1, 0)


def test_halted_run_is_not_the_latest_run(tmp_path):
    make_db(tmp_path / "t.db", [("NO_PHP_EVIDENCE", {"server": ["nginx"]}, "City", 0)], kill="overload")
    assert inventory.aggregate(tmp_path / "t.db").attempted == 0


def test_explicit_run_id_reads_a_halted_run(tmp_path):
    make_db(tmp_path / "t.db", [("NO_PHP_EVIDENCE", {"server": ["nginx"]}, "City", 0)], kill="overload")
    assert inventory.aggregate(tmp_path / "t.db", run_id="R1").attempted == 1


def test_other_region_is_not_selected(tmp_path):
    make_db(tmp_path / "t.db", [("NO_PHP_EVIDENCE", {"server": ["nginx"]}, "City", 0)], region="comparison")
    assert inventory.aggregate(tmp_path / "t.db", region="wisconsin").attempted == 0


def test_database_is_opened_read_only(tmp_path):
    make_db(tmp_path / "t.db", [("NO_PHP_EVIDENCE", {"server": ["nginx"]}, "City", 0)])
    conn = inventory._open_ro(tmp_path / "t.db")
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM observations")
    conn.close()


def test_malformed_headers_json_is_treated_as_no_headers(tmp_path):
    make_db(tmp_path / "t.db", [("NO_PHP_EVIDENCE", None, "City", 0)])
    conn = sqlite3.connect(tmp_path / "t.db")
    conn.execute("UPDATE observations SET headers_json = '{not json'")
    conn.commit()
    conn.close()
    inv = inventory.aggregate(tmp_path / "t.db")
    assert inv.answering == 1 and inv.by_product["nginx"].named == 0


def test_empty_database_gives_empty_inventory(tmp_path):
    conn = db.connect(tmp_path / "t.db")
    db.init_db(conn)
    conn.commit()
    conn.close()
    inv = inventory.aggregate(tmp_path / "t.db")
    assert inv.attempted == 0 and inv.public()["answering"] == "0"


# ------------------------------------------------------------- suppression
def test_public_hides_counts_below_threshold(tmp_path):
    rows = [("PATCHED_UPSTREAM", {"x-powered-by": ["PHP/8.3.36"]}, "City", 1)] * (SUPPRESS_BELOW - 1)
    rows += [("NO_PHP_EVIDENCE", {"server": ["nginx/1.24.0"]}, "City", 0)] * 20
    make_db(tmp_path / "t.db", rows)
    pub = inventory.aggregate(tmp_path / "t.db").public()
    assert pub["products"]["php"]["named"] == "<10"
    assert pub["products"]["php"]["disclosure_rate"] == "§"
    assert pub["products"]["nginx"]["named"] == "20"


def test_public_with_suppression_off_shows_counts(tmp_path):
    make_db(tmp_path / "t.db", [("PATCHED_UPSTREAM", {"x-powered-by": ["PHP/8.3.36"]}, "City", 1)])
    pub = inventory.aggregate(tmp_path / "t.db").public(Suppressor(on=False))
    assert pub["products"]["php"]["named"] == "1"


def test_small_entity_types_fold_into_other(tmp_path):
    rows = [("NO_PHP_EVIDENCE", {"server": ["nginx/1.24.0"]}, "City", 0)] * 30
    rows += [("NO_PHP_EVIDENCE", {"server": ["nginx/1.24.0"]}, "Library", 0)] * 3
    rows += [("NO_PHP_EVIDENCE", {"server": ["nginx/1.24.0"]}, "Port", 0)] * 4
    make_db(tmp_path / "t.db", rows)
    by_type = inventory.aggregate(tmp_path / "t.db").public()["by_type"]
    assert set(by_type) == {"City", "Other"}
    assert by_type["Other"]["answering"] == "<10"


def test_no_domain_names_in_public_output(tmp_path):
    make_db(tmp_path / "t.db", [("NO_PHP_EVIDENCE", {"server": ["nginx/1.24.0"]}, "City", 0)] * 12)
    text = json.dumps(inventory.aggregate(tmp_path / "t.db").public())
    assert "example.test" not in text and "site0" not in text


def test_cli_missing_database_exits_nonzero(tmp_path, capsys):
    assert inventory.main(["--db", str(tmp_path / "nope.db")]) == 2


def test_cli_prints_table(tmp_path, capsys):
    make_db(tmp_path / "t.db", [("NO_PHP_EVIDENCE", {"server": ["nginx/1.24.0"]}, "City", 0)] * 12)
    assert inventory.main(["--db", str(tmp_path / "t.db")]) == 0
    out = capsys.readouterr().out
    assert "| nginx |" in out and "example.test" not in out


# ------------------------------------------------------------- support status in the inventory
def test_unsupported_share_counts_only_unambiguous_placed_branches(tmp_path):
    rows = [("EOL_UNFIXED", {"x-powered-by": ["PHP/7.4.33"]}, "City", 1)] * 3
    rows += [("PATCHED_UPSTREAM", {"x-powered-by": ["PHP/8.5.12"]}, "City", 1)] * 5
    rows += [("POSSIBLY_BACKPORTED", {"x-powered-by": ["PHP/7.4.33-1ubuntu1"]}, "City", 1)] * 2
    make_db(tmp_path / "t.db", rows)
    c = inventory.aggregate(tmp_path / "t.db").by_product["php"]
    assert (c.placed, c.eol, c.eol_distro) == (8, 3, 2)


def test_support_is_judged_on_the_runs_own_date(tmp_path):
    make_db(tmp_path / "t.db", [("PATCHED_UPSTREAM", {"x-powered-by": ["PHP/8.1.30"]}, "City", 1)])
    conn = sqlite3.connect(tmp_path / "t.db")
    conn.execute("UPDATE runs SET started_at_utc = '2025-06-01T14:00:00Z'")
    conn.commit()
    conn.close()
    assert inventory.aggregate(tmp_path / "t.db").by_product["php"].eol == 0
    conn = sqlite3.connect(tmp_path / "t.db")
    conn.execute("UPDATE runs SET started_at_utc = '2026-10-28T14:00:00Z'")
    conn.commit()
    conn.close()
    assert inventory.aggregate(tmp_path / "t.db").by_product["php"].eol == 1


def test_partial_version_places_a_branch_but_is_not_rankable():
    r = inventory.parse_headers({"server": ["Apache/2.2"]})["apache"]
    assert r.branch == (2, 2) and not r.rankable and r.status_version == (2, 2)


def test_only_domains_filter_limits_the_counts(tmp_path):
    make_db(tmp_path / "t.db", [("NO_PHP_EVIDENCE", {"server": ["nginx/1.24.0"]}, "City", 0)] * 3)
    conn = inventory._open_ro(tmp_path / "t.db")
    inv = inventory.aggregate_conn(conn, only_domains={"site0.example.test"})
    conn.close()
    assert inv.attempted == 1


def test_types_override_groups_by_reporting_type(tmp_path):
    make_db(tmp_path / "t.db", [("NO_PHP_EVIDENCE", {"server": ["nginx/1.24.0"]}, "City", 0)] * 2)
    conn = inventory._open_ro(tmp_path / "t.db")
    inv = inventory.aggregate_conn(conn, types={"site0.example.test": "Town", "site1.example.test": "Town"})
    conn.close()
    assert set(inv.by_type) == {"Town"}


def test_unclassified_observation_counts_as_answering_when_it_has_a_status(tmp_path):
    make_db(tmp_path / "t.db", [(None, {"server": ["nginx/1.24.0"]}, "City", 0)])
    conn = sqlite3.connect(tmp_path / "t.db")
    conn.execute("UPDATE observations SET status_code = 200")
    conn.commit()
    conn.close()
    assert inventory.aggregate(tmp_path / "t.db").answering == 1
