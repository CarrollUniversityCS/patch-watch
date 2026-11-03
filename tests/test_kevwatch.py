import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import kevwatch as kw  # noqa: E402

import hashlib
import importlib.util
import json
import random
import re
from datetime import date

import pytest


def test_constants():
    assert kw.V1_PRODUCTS == ("php", "apache", "nginx")
    assert kw.MIN_ENTRIES == 500
    assert kw.BURST_DAYS == 7


def test_norm():
    assert kw.norm("  PHP   Group ") == "php group"
    assert kw.norm(None) == ""


def test_snapshot_days_match_live_day():
    spec = importlib.util.spec_from_file_location("live_day", ROOT / "scripts" / "live_day.py")
    live_day = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(live_day)
    assert set(kw.SNAPSHOT_DAYS) == {day.isoformat() for day in live_day.SNAPSHOT_DAYS}


def catalog(entries, version="fixture"):
    return json.dumps({"catalogVersion": version, "vulnerabilities": entries})


def entry(cve, vendor="Acme", product="Widget", added="2026-01-01", due="2026-01-22"):
    return {
        "cveID": cve,
        "vendorProject": vendor,
        "product": product,
        "dateAdded": added,
        "dueDate": due,
    }


def valid_catalog(size=600):
    return catalog([entry(f"CVE-2026-{i}") for i in range(size)])


def test_fetch_returns_text_and_hash(tmp_path):
    text = valid_catalog()
    result, digest = kw.fetch_catalog(tmp_path, lambda url, cache: text)
    assert result == text
    assert digest == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_fetch_calls_once_with_the_kev_url(tmp_path):
    calls = []

    def stub(url, cache_dir):
        calls.append((url, Path(cache_dir)))
        return valid_catalog()

    kw.fetch_catalog(tmp_path, stub)
    assert len(calls) == 1
    assert calls[0][0] == kw.intake.KEV_URL


def test_fetch_uses_a_new_cache_dir_each_time_and_removes_it(tmp_path):
    calls = []

    def stub(url, cache_dir):
        calls.append(Path(cache_dir))
        return valid_catalog()

    kw.fetch_catalog(tmp_path, stub)
    kw.fetch_catalog(tmp_path, stub)
    assert len(calls) == 2
    assert calls[0] != calls[1]
    assert all(not path.exists() for path in calls)


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        "<html>",
        "{",
        catalog([entry(f"CVE-2026-{i}") for i in range(499)]),
        "{" + (" " * 26_000_000),
    ],
    ids=["none", "empty", "html", "bad-json", "too-few", "too-large"],
)
def test_fetch_rejects_bad_catalogs(tmp_path, text):
    with pytest.raises(kw.FeedError):
        kw.fetch_catalog(tmp_path, lambda url, cache: text)


def test_module_has_no_network_code():
    text = (ROOT / "src" / "kevwatch.py").read_text(encoding="utf-8")
    for forbidden in ("urllib", "urlopen", "requests", "socket", "http.client"):
        assert forbidden not in text


def test_state_round_trip_and_missing_file(tmp_path):
    path = tmp_path / "state.json"
    state = kw.new_state("2026-11-01T00:00:00Z")
    assert kw.load_state(path) is None
    kw.save_state(path, state)
    assert kw.load_state(path) == state
    kw.save_state(path, state)
    assert path.with_suffix(".json.prev").exists()


@pytest.mark.parametrize(
    "data",
    [
        b"{",
        b'{"schema": 2, "seen": {}, "candidates": {}, "consecutive_failures": 0}',
        b'{"schema": 1, "seen": [], "candidates": {}, "consecutive_failures": 0}',
        b'{"schema": 1, "seen": {"CVE-2026-1": {"added": "2026-01-01", "vendor": "A", "product": "B"}}, "candidates": {}, "consecutive_failures": 0}',
        b'{"schema": 1, "seen": {}, "candidates": {}, "consecutive_failures": -1}',
    ],
)
def test_corrupt_state_is_rejected_without_modification(tmp_path, data):
    path = tmp_path / "state.json"
    path.write_bytes(data)
    before = path.read_bytes()
    with pytest.raises(kw.StateCorrupt):
        kw.load_state(path)
    assert path.read_bytes() == before


def test_save_state_replace_failure_preserves_old_file(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    old_state = kw.new_state("old")
    kw.save_state(path, old_state)
    before = path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("simulated crash")

    monkeypatch.setattr(kw.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated crash"):
        kw.save_state(path, kw.new_state("new"))
    assert path.read_bytes() == before


def test_parse_catalog_rejects_duplicate_cves():
    text = catalog([entry("CVE-2026-1"), entry("CVE-2026-1")])
    with pytest.raises(kw.FeedError, match="duplicate cveID"):
        kw.parse_catalog(text)


def test_diff_detects_new_changed_and_removed_without_mutating_state():
    state = kw.bootstrap_state(
        kw.parse_catalog(catalog([entry("CVE-2026-1"), entry("CVE-2026-2")])),
        "bootstrap",
    )
    updated = kw.parse_catalog(
        catalog(
            [
                entry("CVE-2026-1", due="2026-02-01"),
                entry("CVE-2026-3"),
            ],
            version="next",
        )
    )
    before = json.loads(json.dumps(state))
    diff = kw.diff_catalog(state, updated)
    assert [row["cve"] for row in diff.new] == ["CVE-2026-3"]
    assert [(old["added"], old["due"], new["cve"]) for old, new in diff.changed] == [
        ("2026-01-01", "2026-01-22", "CVE-2026-1")
    ]
    assert diff.removed == ["CVE-2026-2"]
    assert state == before


def test_diff_empty_for_identical_catalogs():
    cat = kw.parse_catalog(catalog([entry("CVE-2026-1")]))
    state = kw.bootstrap_state(cat, "bootstrap")
    diff = kw.diff_catalog(state, cat)
    assert diff.new == [] and diff.changed == [] and diff.removed == []


def test_bootstrap_state_records_all_entries_without_candidates():
    cat = kw.parse_catalog(catalog([entry("CVE-2026-1"), entry("CVE-2026-2")], "v1"))
    state = kw.bootstrap_state(cat, "now")
    assert state["seen"] == {row["cve"]: kw.seen_record(row) for row in cat["entries"]}
    assert state["candidates"] == {}
    assert state["catalog_version"] == "v1"
    assert state["catalog_sha256"] == cat["sha256"]


def test_diff_catalog_property_over_randomized_inputs():
    rng = random.Random(7)
    all_cves = [f"CVE-2026-{i}" for i in range(100)]
    for _ in range(200):
        current_ids = rng.sample(all_cves, rng.randint(20, 60))
        prior_ids = rng.sample(all_cves, rng.randint(0, 60))
        rows = kw.parse_catalog(
            catalog([entry(cve, due="2026-02-01" if rng.random() < 0.5 else "2026-01-22") for cve in current_ids])
        )["entries"]
        state = kw.new_state("bootstrap")
        for cve in prior_ids:
            state["seen"][cve] = {
                "added": "2026-01-01",
                "due": "2026-01-22",
                "vendor": "Acme",
                "product": "Widget",
            }
        diff = kw.diff_catalog(state, {"entries": rows})
        current = {row["cve"] for row in rows}
        new_ids = {row["cve"] for row in diff.new}
        changed_ids = {new["cve"] for _, new in diff.changed}
        unchanged_ids = current & set(state["seen"]) - changed_ids
        assert new_ids | unchanged_ids | changed_ids == current
        assert not (new_ids & unchanged_ids or new_ids & changed_ids or unchanged_ids & changed_ids)


@pytest.mark.parametrize(
    ("vendor", "product", "kind", "product_key"),
    [
        ("PHP Group", "PHP", "candidate", "php"),
        ("PHP", "PHP", "candidate", "php"),
        ("PHP", "FastCGI Process Manager (FPM)", "candidate", "php"),
        ("PHP", "PHP-FPM", "candidate", "php"),
        ("PHP", "PHP-CGI", "candidate", "php"),
        ("Apache", "HTTP Server", "candidate", "apache"),
        ("Apache", "Apache", "candidate", "apache"),
        ("Apache Software Foundation", "Apache HTTP Server", "candidate", "apache"),
        ("The Apache Software Foundation", "httpd", "candidate", "apache"),
        ("F5", "NGINX", "candidate", "nginx"),
        ("F5 Networks", "NGINX Plus", "candidate", "nginx"),
        ("F5, Inc.", "nginx open source", "candidate", "nginx"),
        ("PHP", "PHPMailer", "near_miss", None),
        ("PHPUnit", "PHPUnit", "near_miss", None),
        ("ThinkPHP", "ThinkPHP", "near_miss", None),
        ("phpMyAdmin", "phpMyAdmin", "near_miss", None),
        ("Apache", "Tomcat", "near_miss", None),
        ("Apache", "Struts", "near_miss", None),
        ("Apache", "Log4j2", "near_miss", None),
        ("Oracle", "HTTP Server and Oracle Weblogic Server Proxy Plug-in", "near_miss", None),
        ("Nostromo", "nhttpd", "near_miss", None),
        ("F5", "NGINX Ingress Controller", "near_miss", None),
        ("WordPress", "WordPress", "other", None),
        ("Microsoft", "Exchange Server", "other", None),
        ("OpenResty", "OpenResty", "other", None),
    ],
)
def test_classification_rules(vendor, product, kind, product_key):
    result = kw.classify_entry({"vendor": vendor, "product": product})
    assert result.kind == kind
    assert result.product_key == product_key
    assert result.tier == kw.intake.tier_keyword(vendor, product)
    if kind == "other":
        assert result.tier


def test_classification_normalizes_vendor_spacing_and_case():
    expected = kw.classify_entry({"vendor": "PHP Group", "product": "PHP"})
    actual = kw.classify_entry({"vendor": "  pHp   gRoUp ", "product": " pHp "})
    assert actual == expected


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        ({"added": "2026-10-26", "due": "2026-10-29"}, (3, "kev_dueDate")),
        ({"added": "2028-02-28", "due": "2028-03-01"}, (2, "kev_dueDate")),
        ({"added": "2026-10-26"}, (None, "missing")),
        ({"added": "2026-10-29", "due": "2026-10-26"}, (None, "invalid: due before added")),
        ({"added": "garbage", "due": "also garbage"}, (None, "missing")),
    ],
)
def test_window_days(item, expected):
    assert kw.window_days(item) == expected


def test_burst_proposal_matches_planned_and_future_examples():
    first = kw.burst_proposal(
        {"added": "2026-10-26", "due": "2026-10-29"},
        date(2026, 10, 27),
    )
    assert first["proposed_days"] == [
        "2026-10-27", "2026-10-28", "2026-10-29", "2026-10-30",
        "2026-10-31", "2026-11-01", "2026-11-02",
    ]
    assert first["already_past"] == []
    assert first["already_planned"] == first["proposed_days"]
    assert first["extra_days"] == []
    assert first["planned_in_window"] == first["with_burst_in_window"] == 4

    second = kw.burst_proposal(
        {"added": "2026-11-10", "due": "2026-11-13"},
        date(2026, 11, 10),
    )
    assert second["proposed_days"] == [
        "2026-11-11", "2026-11-12", "2026-11-13", "2026-11-14",
        "2026-11-15", "2026-11-16", "2026-11-17",
    ]
    assert second["already_planned"] == ["2026-11-11"]
    assert second["extra_days"] == [
        "2026-11-12", "2026-11-13", "2026-11-14", "2026-11-15", "2026-11-16", "2026-11-17",
    ]
    assert second["planned_in_window"] == 1
    assert second["with_burst_in_window"] == 3
    late = kw.burst_proposal(
        {"added": "2026-11-10", "due": "2026-11-13"},
        date(2026, 11, 14),
    )
    assert late["already_past"] == ["2026-11-11", "2026-11-12", "2026-11-13"]


def test_burst_proposal_handles_missing_window_and_exact_note():
    result = kw.burst_proposal({"added": "bad", "due": None}, date(2026, 11, 1))
    assert result["planned_in_window"] is None
    assert result["with_burst_in_window"] is None
    assert result["note"] == (
        "Proposal only. PI decision D10. Needs a frozen per-event plan, a person-verified table "
        "and the notice check. Nothing was scheduled."
    )


PHP_RECORD = {
    "containers": {
        "cna": {
            "affected": [
                {
                    "versions": [
                        {"status": "affected", "version": "8.2.*", "lessThan": "8.2.35", "versionType": "semver"},
                        {"status": "affected", "version": "8.3.*", "lessThan": "8.3.36", "versionType": "semver"},
                        {"status": "affected", "version": "8.4.*", "lessThan": "8.4.27", "versionType": "semver"},
                        {"status": "affected", "version": "8.5.*", "lessThan": "8.5.12", "versionType": "semver"},
                    ]
                }
            ]
        }
    }
}


def assert_hint_provenance(record, hints):
    serialized = json.dumps(record)
    assert all(hint["fixed"] is None or hint["fixed"] in serialized for hint in hints)


def test_extract_php_fixed_version_hints():
    hints, errors = kw.extract_hints(PHP_RECORD, "php")
    assert errors == []
    assert [hint["fixed"] for hint in hints] == ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]
    assert all(hint["kind"] == "lessThan" and hint["confidence"] == "range" for hint in hints)
    assert_hint_provenance(PHP_RECORD, hints)


def test_extract_apache_last_affected_hint_does_not_invent_fix():
    record = {
        "containers": {
            "cna": {
                "affected": [{"versions": [
                    {"lessThanOrEqual": "2.4.59", "status": "affected", "version": "2.4.0", "versionType": "semver"}
                ]}]
            }
        }
    }
    hints, errors = kw.extract_hints(record, "apache")
    assert errors == []
    assert hints == [{
        "branch": "2.4",
        "fixed": None,
        "kind": "lessThanOrEqual",
        "confidence": "range",
        "note": "last affected is 2.4.59; first fixed version not stated",
    }]
    assert_hint_provenance(record, hints)


def test_extract_apache_version_text_and_description_hint():
    record = {
        "containers": {
            "cna": {
                "affected": [{"versions": [
                    {"status": "affected", "version": "Apache HTTP Server 2.4 2.4.49"}
                ]}],
                "descriptions": [{"value": "The issue is fixed in version 2.4.60."}],
            }
        }
    }
    hints, errors = kw.extract_hints(record, "apache")
    assert errors == []
    assert [(hint["fixed"], hint["kind"]) for hint in hints] == [
        (None, "version_text"),
        ("2.4.60", "description"),
    ]
    assert_hint_provenance(record, hints)


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"containers": []},
        {"containers": {"cna": {"affected": "not a list"}}},
        {"containers": {"cna": {"affected": [{"versions": [
            {"status": "affected", "version": "8.2.*", "lessThan": "8.2"}
        ]}]}}},
    ],
)
def test_extract_hints_handles_malformed_record_shapes(record):
    hints, errors = kw.extract_hints(record, "php")
    assert isinstance(hints, list)
    assert isinstance(errors, list)
    assert not any(hint["fixed"] == "8.2" for hint in hints)
    assert_hint_provenance(record, hints)


def packet_facts(tmp_path, now="2026-11-01T12:00:00Z"):
    entry_record = {
        "cve": "CVE-2026-109619",
        "vendor": "PHP Group",
        "product": "PHP",
        "name": "PHP remote code execution",
        "added": "2026-10-26",
        "due": "2026-10-29",
    }
    hints, errors = kw.extract_hints(PHP_RECORD, "php")
    return {
        "entry": entry_record,
        "classification": kw.Classification("candidate", "php", "A_homepage_stack"),
        "window": kw.window_days(entry_record),
        "burst": kw.burst_proposal(entry_record, date(2026, 11, 1)),
        "hints": hints,
        "hint_errors": errors,
        "record_present": True,
        "baseline": {"available": False},
        "viability": {"available": False},
        "notice_live": False,
        "catalog_version": "2026.10.30",
        "catalog_sha256": "a" * 64,
        "now_utc": now,
    }


def test_render_packet_has_ordered_headings_golden_text_and_is_deterministic(tmp_path):
    facts = packet_facts(tmp_path)
    markdown, packet = kw.render_packet(facts)
    headings = [
        "Status", "KEV entry", "Deadline window", "Four-question test", "Fixed-version hints",
        "Draft event skeleton", "Burst proposal", "Stored data", "Notice and IRB", "Checklist",
        "Commands after verification", "Provenance",
    ]
    found = re.findall(r"^## (.+)$", markdown, re.MULTILINE)
    assert found == headings
    assert all(markdown.count(f"## {heading}") == 1 for heading in headings)
    assert "DRAFT. Nothing is scheduled, verified or approved. Read the vendor advisory before trusting any version below." in markdown
    assert (
        "Under BOD 26-04 (issued 2026-06-10) each KEV entry carries its own due date; "
        "the fastest tier is 3 days; it binds federal civilian agencies only."
    ) in markdown
    assert "verified_by_person=False" in markdown
    assert len(re.findall(r"^\| 8\.\d", markdown, re.MULTILINE)) == 4
    assert packet["generator_version"] == kw.WATCHER_VERSION
    assert kw.render_packet(facts) == (markdown, packet)


def test_render_packet_hygiene_and_write_packet_idempotence(tmp_path):
    facts = packet_facts(tmp_path)
    facts["entry"]["vendor"] = "Unsafe example.gov"
    facts["entry"]["product"] = "PHP contact user@example.com"
    markdown, _ = kw.render_packet(facts)
    assert not re.search(r"\b[a-z0-9][a-z0-9.-]*\.gov\b", markdown.replace("cisa.gov", ""))
    assert not re.search(r"@[\w.-]+\.[A-Za-z]{2,}", markdown)

    facts = packet_facts(tmp_path)
    paths = kw.write_packet(tmp_path, facts)
    assert len(paths) == 2
    assert kw.write_packet(tmp_path, facts) == []
    folder = tmp_path / "docs" / "proposed" / "events" / "2026-10-26_CVE-2026-109619"
    original = (folder / "packet.md").read_bytes()
    facts["now_utc"] = "2026-11-01T12:00:01Z"
    stamped = kw.write_packet(tmp_path, facts)
    assert len(stamped) == 2 and "packet.20261101T120001Z.md" in stamped[0]
    assert (folder / "packet.md").read_bytes() == original


def test_write_packet_rejects_escaping_cve_path(tmp_path):
    facts = packet_facts(tmp_path)
    facts["entry"]["cve"] = "../x"
    with pytest.raises(ValueError):
        kw.write_packet(tmp_path, facts)


def test_enrich_uses_only_one_cvelist_request_and_cleans_cache(tmp_path):
    calls = []
    record_text = json.dumps(PHP_RECORD)

    def stub(url, cache):
        calls.append((url, Path(cache)))
        return record_text

    record, errors = kw.enrich("CVE-2026-109619", tmp_path, stub)
    assert record == PHP_RECORD and errors == []
    assert len(calls) == 1
    assert calls[0][0] == kw.intake.record_urls("CVE-2026-109619")[0]
    assert not calls[0][1].exists()


def test_enrich_reports_missing_malformed_and_raised_fetch(tmp_path):
    assert kw.enrich("broken", tmp_path, lambda *args: pytest.fail("unexpected fetch")) == (
        None, ["malformed CVE id"]
    )
    assert kw.enrich("CVE-2026-109619", tmp_path, lambda *args: None) == (
        None, ["no CVE record yet"]
    )
    record, errors = kw.enrich(
        "CVE-2026-109619", tmp_path, lambda *args: (_ for _ in ()).throw(OSError("offline"))
    )
    assert record is None and errors == ["OSError: offline"]


def test_bootstrap_state_sets_success_time():
    cat = kw.parse_catalog(catalog([entry("CVE-2026-1")], "v1"))
    state = kw.bootstrap_state(cat, "2026-11-02T12:00:00Z")
    assert state["last_attempt_utc"] == "2026-11-02T12:00:00Z"
    assert state["last_success_utc"] == "2026-11-02T12:00:00Z"
    assert state["consecutive_failures"] == 0
