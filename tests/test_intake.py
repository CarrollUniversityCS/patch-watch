"""src/intake.py and scripts/kev_census.py: proposals from fixture data. No network."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import re
import urllib.error
from pathlib import Path

import pytest

import intake

ROOT = Path(__file__).resolve().parent.parent

KEV = {
    "catalogVersion": "2026.10.28", "dateReleased": "2026-10-28T19:00:04Z", "count": 6,
    "vulnerabilities": [
        {"cveID": "CVE-2026-109619", "vendorProject": "PHP Group", "product": "PHP",
         "vulnerabilityName": "PHP2Shell", "dateAdded": "2026-10-26", "dueDate": "2026-10-29",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2026-109618", "vendorProject": "PHP Group", "product": "PHP",
         "vulnerabilityName": "PHP2Shell", "dateAdded": "2026-10-26", "dueDate": "2026-10-29"},
        {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks", "product": "PAN-OS",
         "dateAdded": "2024-04-12", "dueDate": "2024-04-19"},
        {"cveID": "CVE-2023-4863", "vendorProject": "Google", "product": "Chromium WebP",
         "dateAdded": "2023-09-13", "dueDate": "2023-10-04"},
        {"cveID": "CVE-2020-1234", "vendorProject": "WordPress", "product": "Some Plugin",
         "dateAdded": "2022-01-05", "dueDate": "2022-01-19"},
        {"vendorProject": "No", "product": "Id"},
    ],
}
CVE_REC = {"containers": {"cna": {"affected": [
    {"vendor": "PHP Group", "product": "PHP", "cpes": ["cpe:2.3:a:php_group:php:8.1.0:*:*:*:*:*:*:*"]}]},
    "adp": [{"affected": [{"cpes": ["cpe:2.3:h:vendor:box:1.0:*:*:*:*:*:*:*", "not-a-cpe"]}],
             "metrics": [{"other": {"type": "ssvc", "content": {"options": [
                 {"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]}}}]}]}}


# ------------------------------------------------------------------ loading
def test_load_kev_counts_sorts_and_skips_entries_without_an_id():
    k = intake.load_kev(KEV)
    assert k["version"] == "2026.10.28" and k["count"] == 5
    assert [e["added"] for e in k["entries"]] == sorted(e["added"] for e in k["entries"])


def test_load_kev_accepts_json_text():
    assert intake.load_kev(json.dumps(KEV))["count"] == 5


def test_load_kev_empty_catalog():
    assert intake.load_kev({})["entries"] == []


def test_php2shell_entry_keeps_its_kev_dates():
    e = {x["cve"]: x for x in intake.load_kev(KEV)["entries"]}["CVE-2026-109619"]
    assert (e["added"], e["due"]) == ("2026-10-26", "2026-10-29")


def test_record_bucket_and_urls():
    assert intake.record_bucket("CVE-2024-4577") == ("2024", "4xxx")
    assert intake.record_bucket("CVE-2026-109618") == ("2026", "109xxx")
    assert intake.record_bucket("not-a-cve") is None
    a, b = intake.record_urls("CVE-2024-4577")
    assert a.endswith("/cves/2024/4xxx/CVE-2024-4577.json") and b.endswith("/2024/4xxx/CVE-2024-4577.json")
    assert intake.record_urls("junk") is None


def test_extract_cpes_reads_cna_and_adp_and_ignores_garbage():
    assert intake.extract_cpes(CVE_REC, None, {}) == [("a", "php_group", "php"), ("h", "vendor", "box")]


def test_extract_ssvc():
    assert intake.extract_ssvc(CVE_REC) == {"Exploitation": "active", "Automatable": "yes",
                                            "Technical Impact": "total"}
    assert intake.extract_ssvc(None) == {}


def test_parse_epss():
    ok = json.dumps({"data": [{"cve": "CVE-2024-4577", "epss": "0.99987"}]})
    assert intake.parse_epss(ok) == {"CVE-2024-4577": 0.99987}
    for bad in (None, "", "{not json", json.dumps({"data": [{"nope": 1}]}), json.dumps({"data": "x"})):
        assert intake.parse_epss(bad) == {}


# ------------------------------------------------------------------ the four questions
def test_keyword_tiers():
    assert intake.tier_keyword("PHP Group", "PHP") == intake.TIER_A
    assert intake.tier_keyword("Palo Alto Networks", "PAN-OS") == intake.TIER_B
    assert intake.tier_keyword("Google", "Chromium WebP") == intake.TIER_C


def test_cpe_hardware_promotes_unmatched_to_appliance_only():
    assert intake.adjust_with_cpe(intake.TIER_C, [("h", "v", "p")])[0] == intake.TIER_B
    assert intake.adjust_with_cpe(intake.TIER_C, [("a", "v", "p")])[0] == intake.TIER_C
    assert intake.adjust_with_cpe(intake.TIER_B, [("h", "v", "p")])[0] == intake.TIER_B


def test_cpe_never_promotes_to_homepage_stack():
    assert intake.adjust_with_cpe(intake.TIER_C, [("a", "php_group", "php")])[0] == intake.TIER_C


@pytest.mark.parametrize("vendor,product", [("WordPress", "Some Plugin"), ("Oracle", "HTTP Server"),
                                            ("PHP", "PHPMailer"),
                                            ("WebPros", "cPanel & WHM and WP2 (WordPress Squared)")])
def test_plugins_and_look_alikes_are_not_the_platform(vendor, product):
    assert intake.inventory_product(vendor, product) is None


def test_inventory_product_names():
    assert intake.inventory_product("PHP Group", "PHP") == "php"
    assert intake.inventory_product("Apache", "HTTP Server") == "apache"
    assert intake.inventory_product("F5", "nginx") == "nginx"


def row(vendor, product, frame=None):
    e = {"cve": "CVE-2026-1", "vendor": vendor, "product": product, "added": "2026-10-26", "due": ""}
    t = intake.tier_keyword(vendor, product)
    q = intake.four_question(e, t, frame)
    return e, t, q


def test_php_with_a_common_frame_is_proposed_for_validation():
    e, t, q = row("PHP Group", "PHP", {"php": 198})
    assert q == {"q1_visible": "yes", "q2_version_changes": "yes", "q3_common_in_frame": "yes",
                 "q4_detector_passes": "unknown"}
    assert intake.propose(e, t, q)[0] == "validating"


def test_rare_product_is_archive_only():
    e, t, q = row("Apache", "HTTP Server", {"apache": 3})
    assert q["q3_common_in_frame"] == "rare" and intake.propose(e, t, q)[0] == "archive_only"


def test_some_is_between_rare_and_common():
    assert row("PHP Group", "PHP", {"php": 15})[2]["q3_common_in_frame"] == "some"


def test_q3_unknown_without_inventory_counts():
    assert row("PHP Group", "PHP")[2]["q3_common_in_frame"] == "unknown"


def test_client_software_is_not_measurable():
    e, t, q = row("Google", "Chromium WebP")
    assert q["q1_visible"] == "no" and q["q3_common_in_frame"] == "n/a"
    assert intake.propose(e, t, q)[0] == "not_measurable"


def test_edge_product_stays_untriaged():
    e, t, q = row("Palo Alto Networks", "PAN-OS")
    assert q["q1_visible"] == "maybe" and intake.propose(e, t, q)[0] == "untriaged"


def test_homepage_product_with_unknown_fix_behaviour_stays_untriaged():
    e, t, q = row("Adobe", "ColdFusion", {"php": 198})
    assert q["q2_version_changes"] == "unknown" and intake.propose(e, t, q)[0] == "untriaged"


def test_wordpress_core_version_is_not_assumed_visible():
    # Core's version is in page markup, not response headers, so Q2 stays open.
    e, t, q = row("WordPress", "Core", {"wordpress": 91})
    assert q["q2_version_changes"] == "unknown" and intake.propose(e, t, q)[0] == "untriaged"


def test_q4_is_never_decided_by_code():
    for v, p in (("PHP Group", "PHP"), ("Google", "Chrome"), ("Palo Alto Networks", "PAN-OS")):
        assert row(v, p, {"php": 500})[2]["q4_detector_passes"] == "unknown"


def test_a_proposal_is_never_live_or_awaiting_fix():
    k = intake.load_kev(KEV)
    for r in intake.build_rows(k, None, None, {"php": 198}):
        assert r["proposed_tier"] not in ("live", "awaiting_fix")


def test_build_rows_uses_cpe_note_and_epss():
    k = intake.load_kev(KEV)
    rows = {r["cve"]: r for r in intake.build_rows(
        k, {"CVE-2023-4863": [("h", "v", "p")]}, {"CVE-2026-109619": 0.5})}
    assert rows["CVE-2023-4863"]["tier"] == intake.TIER_B and rows["CVE-2023-4863"]["cpe_note"]
    assert rows["CVE-2026-109619"]["epss"] == 0.5 and rows["CVE-2024-3400"]["epss"] is None


def test_php2shell_is_proposed_for_validation_with_its_dates():
    rows = intake.build_rows(intake.load_kev(KEV), None, None, {"php": 198})
    r = {x["cve"]: x for x in rows}["CVE-2026-109619"]
    assert (r["added"], r["due"], r["proposed_tier"]) == ("2026-10-26", "2026-10-29", "validating")


# ------------------------------------------------------------------ census and sample
def synthetic_rows(n=400):
    rows = []
    for i in range(n):
        tier = (intake.TIER_A, intake.TIER_B, intake.TIER_C)[i % 3 if i % 7 else 2]
        rows.append({"cve": f"CVE-{2021 + i % 6}-{1000 + i}", "added": f"{2021 + i % 6}-06-01", "tier": tier})
    return rows


def test_census_counts():
    c = intake.census_counts(intake.build_rows(intake.load_kev(KEV)))
    assert c["n"] == 5 and sum(c["by_tier"].values()) == 5 and "2026" in c["by_year"]


def test_sample_is_deterministic_and_the_right_size():
    rows = synthetic_rows()
    a, b = intake.stratified_sample(rows, 120), intake.stratified_sample(rows, 120)
    assert a == b and len(a) == 120 and len({r["cve"] for r in a}) == 120


def test_sample_covers_every_tier_and_period():
    s = intake.stratified_sample(synthetic_rows(), 120)
    assert {r["tier"] for r in s} == {intake.TIER_A, intake.TIER_B, intake.TIER_C}
    assert {r["added"][:4] for r in s} >= {"2021", "2024", "2026"}


def test_sample_larger_than_population_returns_everything():
    assert len(intake.stratified_sample(synthetic_rows(30), 120)) == 30


def test_sample_seed_changes_the_draw():
    rows = synthetic_rows()
    assert intake.stratified_sample(rows, 60, seed=1) != intake.stratified_sample(rows, 60, seed=2)


# ------------------------------------------------------------------ the one network function
@pytest.mark.parametrize("url", ["https://example.gov/x", "https://www.cisa.gov/kev.json",
                                 "http://evil.example/x", "https://raw.githubusercontent.com.evil.example/x",
                                 "file:///etc/passwd", "ftp://raw.githubusercontent.com/x"])
def test_fetch_refuses_hosts_that_are_not_allow_listed(url, tmp_path):
    with pytest.raises(ValueError):
        intake.fetch_text(url, tmp_path)


def test_fetch_serves_from_cache_without_the_network(tmp_path, monkeypatch):
    url = intake.KEV_URL
    (tmp_path / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".json")).write_text("cached", encoding="utf-8")
    monkeypatch.setattr(intake.urllib.request, "urlopen", lambda *a, **k: pytest.fail("network used"))
    assert intake.fetch_text(url, tmp_path) == "cached"


def test_fetch_failure_returns_none_not_an_exception(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("down")
    monkeypatch.setattr(intake.urllib.request, "urlopen", boom)
    assert intake.fetch_text(intake.KEV_URL, tmp_path) is None


def test_urlopen_is_called_from_exactly_one_place():
    src = (ROOT / "src" / "intake.py").read_text(encoding="utf-8")
    assert len(re.findall(r"urllib\.request\.urlopen\(", src)) == 1


def test_the_allow_list_holds_only_public_data_feeds():
    assert intake.ALLOWED_HOSTS == {"raw.githubusercontent.com", "api.first.org"}
    assert not any(h.endswith(".gov") for h in intake.ALLOWED_HOSTS)


# ------------------------------------------------------------------ the census script
def load_script():
    spec = importlib.util.spec_from_file_location("kev_census", ROOT / "scripts" / "kev_census.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_census_script_offline_writes_proposals_and_a_blank_rater_sheet(tmp_path):
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps(KEV), encoding="utf-8")
    out = tmp_path / "out"
    assert load_script().main(["--cache", str(tmp_path / "c"), "--kev", str(kev), "--offline",
                               "--out-dir", str(out), "--sample-size", "4"]) == 0
    with open(out / "kev_rater_sample.csv", encoding="utf-8") as fh:
        sample = list(csv.DictReader(fh))
    assert len(sample) == 4 and all(r["rater_a"] == "" and r["rater_b"] == "" for r in sample)
    prop = json.loads((out / "kev_tiers_proposed.json").read_text(encoding="utf-8"))
    assert "PROPOSAL" in prop["status"] and prop["entries"]
    nums = json.loads((out / "kev_census_numbers.json").read_text(encoding="utf-8"))
    assert nums["n"] == 5 and nums["q3_available"] is False


def test_census_script_missing_catalog_exits_nonzero(tmp_path):
    # no --kev and an unreachable cache: the fetch returns None offline -> exit 2, not a crash
    mod = load_script()
    mod.intake.fetch_text = lambda *a, **k: None
    assert mod.main(["--cache", str(tmp_path), "--out-dir", str(tmp_path / "o"), "--offline"]) == 2


def test_census_script_never_writes_the_catalog():
    src = (ROOT / "scripts" / "kev_census.py").read_text(encoding="utf-8")
    assert "catalog.json" not in src.replace("never edits dashboard/catalog.json", "")


def test_triage_script_and_intake_share_one_keyword_list():
    src = (ROOT / "scripts" / "kev_triage.py").read_text(encoding="utf-8")
    assert "from intake import" in src and "A = [" not in src and "B = [" not in src
