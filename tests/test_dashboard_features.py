"""Dashboard features from the action plan: D1 preliminary points, exposure window, the
not-measurable summary, and catalog validation. No network."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import dashboard
import versions
from test_dashboard import entry, report, write_catalog

ROOT = Path(__file__).resolve().parent.parent
KEV = {"added": "2026-10-26", "federal_due": "2026-10-29", "verified": True, "note": "t"}


def run_at(started, region="wisconsin"):
    text = report({"PATCHED_UPSTREAM": 30, "EOL_UNFIXED": 12, "NO_PHP_EVIDENCE": 400})
    text = text.replace("2026-10-28T14:00:17Z", started)
    return dashboard.parse_run_report(text)


def model(runs, **kw):
    return dashboard.build_model([entry(kev=KEV, disclosed="2026-10-21", **kw)], runs)


def points(m):
    return m["entries"][0]["regions"][0]["points"]


# ------------------------------------------------------------------ D1 threshold
def test_threshold_is_the_primary_endpoint_day():
    assert dashboard.PRELIMINARY_BEFORE_DAYS == 14
    assert not hasattr(__import__("config"), "PRELIMINARY_BEFORE_DAYS"), "presentation rule stays out of config.py"


def test_points_before_day_14_are_preliminary_and_later_ones_are_not():
    t0 = versions.PHP2SHELL.t0_utc                                   # 2026-10-21T14:00:00Z
    early = run_at("2026-10-28T14:00:17Z")                           # day 7
    edge = run_at("2026-11-04T14:00:00Z")                            # exactly day 14
    late = run_at("2026-11-10T14:00:00Z")
    p = points(model([early, edge, late]))
    assert t0.startswith("2026-10-21")
    assert [x["preliminary"] for x in p] == [True, False, False]


def test_entry_carries_the_threshold_for_the_page():
    assert model([run_at("2026-10-28T14:00:17Z")])["entries"][0]["preliminary_before_days"] == 14


def test_federal_deadline_marker_is_kept_with_preliminary_points():
    p = points(model([run_at("2026-10-29T14:00:00Z")]))[0]
    assert p["preliminary"] and p["after_federal_due"]


# ------------------------------------------------------------------ exposure window
def test_kev_listing_is_the_onset_floor_when_nothing_better_is_recorded():
    on = dashboard.onset(entry(kev=KEV))
    assert on["date"] == "2026-10-26" and on["kind"] == "kev_listing" and "floor" in on["source"]


def test_a_recorded_exploitation_date_wins_over_the_kev_floor():
    on = dashboard.onset(entry(kev=KEV, exploitation={"first_seen": "2026-10-17", "kind": "vendor_reported",
                                                      "source": "a vendor advisory"}))
    assert on == {"date": "2026-10-17", "kind": "vendor_reported", "source": "a vendor advisory"}


def test_no_onset_without_any_source():
    assert dashboard.onset(entry()) is None


def test_days_between_and_since_text_state_direction_and_anchor():
    assert dashboard.days_between("2026-10-26", "2026-10-28T14:00:17Z") == 2.6
    assert dashboard.days_between("bad", "2026-10-28T14:00:17Z") is None
    kev = {"kind": "kev_listing"}
    assert dashboard.since_text(2.6, kev) == "2.6 days after CISA's KEV listing"
    assert dashboard.since_text(-1.4, kev) == "1.4 days before CISA's KEV listing"
    assert "first seen" in dashboard.since_text(3.0, {"kind": "vendor_reported"})
    assert dashboard.since_text(None, kev) == "" and dashboard.since_text(1.0, None) == ""


def test_timeline_lists_fix_onset_deadline_and_snapshots_in_date_order():
    tl = model([run_at("2026-10-24T14:00:17Z"), run_at("2026-10-28T14:00:17Z")])["entries"][0]["timeline"]
    assert [i["kind"] for i in tl] == ["disclosure", "snapshot", "onset", "snapshot", "due"]
    assert [i["date"] for i in tl] == sorted(i["date"] for i in tl)
    assert tl[0]["date"] == "2026-10-21" and tl[-1]["date"] == "2026-10-29"
    assert all("note" in i or i["kind"] == "snapshot" for i in tl)


def test_every_timeline_snapshot_has_its_own_text_equivalent():
    tl = model([run_at("2026-10-24T14:00:17Z")])["entries"][0]["timeline"]
    snap = [i for i in tl if i["kind"] == "snapshot"][0]
    assert snap["since_text"].endswith("before CISA's KEV listing") and snap["preliminary"] is True


def test_timeline_is_only_built_for_live_entries():
    m = dashboard.build_model([entry(tier="not_measurable", event=None, key="fw")], [])
    assert "timeline" not in m["entries"][0]


# ------------------------------------------------------------------ catalog validation
GOOD = entry(key="ok_key", cve_ids=["CVE-2026-1234"], disclosed="2026-10-21", sources=["https://x"])


def test_a_good_entry_passes():
    dashboard.validate_entry(GOOD)
    dashboard.validate_entry({**GOOD, "disclosed": "", "cve_ids": []})
    dashboard.validate_entry({**GOOD, "disclosed": "2026-10"})


@pytest.mark.parametrize("field", list(dashboard.REQUIRED_FIELDS))
def test_each_required_field_is_enforced(field):
    bad = dict(GOOD)
    del bad[field]
    with pytest.raises(ValueError, match=field):
        dashboard.validate_entry(bad)


@pytest.mark.parametrize("field,value", [("title", 5), ("cve_ids", "CVE-2026-1"), ("sources", "x"),
                                         ("tier", None), ("disclosed", 2026)])
def test_wrong_types_are_refused(field, value):
    with pytest.raises(ValueError):
        dashboard.validate_entry({**GOOD, field: value})


@pytest.mark.parametrize("key", ["", "Has Caps", "has-dash", "sp ace", "dot.key"])
def test_bad_keys_are_refused(key):
    with pytest.raises(ValueError, match="key"):
        dashboard.validate_entry({**GOOD, "key": key})


@pytest.mark.parametrize("cve", ["CVE-26-1", "cve-2026-1234", "CVE-2026-12", "2026-1234", ""])
def test_bad_cve_ids_are_refused(cve):
    with pytest.raises(ValueError, match="cve_ids"):
        dashboard.validate_entry({**GOOD, "cve_ids": [cve]})


@pytest.mark.parametrize("d", ["Oct 21", "2026-13", "21-10-2026", "2026-10-2"])
def test_bad_disclosed_dates_are_refused(d):
    with pytest.raises(ValueError, match="disclosed"):
        dashboard.validate_entry({**GOOD, "disclosed": d})


def test_exploitation_block_is_checked():
    ok = {"first_seen": "2026-10-17", "kind": "vendor_reported", "source": "advisory"}
    dashboard.validate_entry({**GOOD, "exploitation": ok})
    for bad in ({**ok, "first_seen": "Oct 17"}, {**ok, "kind": "rumour"}, {**ok, "source": "  "},
                {k: v for k, v in ok.items() if k != "source"}):
        with pytest.raises(ValueError, match="exploitation"):
            dashboard.validate_entry({**GOOD, "exploitation": bad})


def test_load_catalog_runs_the_shape_check(tmp_path):
    bad = {k: v for k, v in entry().items() if k != "why"}
    with pytest.raises(ValueError, match="why"):
        dashboard.load_catalog(write_catalog(tmp_path, [bad]))


def test_the_committed_catalog_is_valid():
    assert len(dashboard.load_catalog()) >= 4


# ------------------------------------------------------------------ not-measurable summary
SUMMARY = {"catalog_version": "v", "total": 10, "caveat": "c",
           "groups": [{"reason": "r", "count": 7, "examples": ["A", "B"]}]}


def test_missing_summary_file_is_fine(tmp_path):
    assert dashboard.load_measurability(tmp_path / "nope.json") is None


def test_a_good_summary_loads(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps(SUMMARY), encoding="utf-8")
    assert dashboard.load_measurability(p)["total"] == 10


@pytest.mark.parametrize("bad", [{k: v for k, v in SUMMARY.items() if k != "caveat"},
                                 {**SUMMARY, "groups": "x"},
                                 {**SUMMARY, "groups": [{"reason": "r", "count": 1}]},
                                 {**SUMMARY, "groups": [{"reason": "r", "count": 1, "examples": list("abcdefghijk")}]}])
def test_a_malformed_summary_stops_the_build(tmp_path, bad):
    p = tmp_path / "m.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError):
        dashboard.load_measurability(p)


def test_model_carries_the_summary():
    m = dashboard.build_model([entry()], [], measurability=SUMMARY)
    assert m["measurability"] == SUMMARY


def test_the_committed_summary_is_aggregate_public_kev_data():
    m = dashboard.load_measurability()
    assert m is not None and m["groups"][0]["count"] > 0
    text = json.dumps(m)
    assert re.search(r"\.gov|\.us\b|https?://", text) is None, "no domain or URL belongs in the summary"


# ------------------------------------------------------------------ the page
def test_template_has_the_new_blocks_and_text_equivalents():
    t = dashboard.TEMPLATE_PATH.read_text(encoding="utf-8")
    for needle in ("Not remotely measurable", "Preliminary (fewer than", "Show the dates as a list",
                   "Days since onset (negative = before)", "timelineBlock", "measurabilityBlock"):
        assert needle in t, needle
    assert 'class: "tl"' in t and '"aria-hidden": "true"' in t          # the strip is decoration only
    assert t.count("Show the") >= 3                                      # every chart has a table or list


def test_built_page_embeds_the_new_model_fields():
    html = (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    data = json.loads(re.search(r'id="pw-data">(.*?)</script>', html, re.S).group(1))
    live = [e for e in data["entries"] if e.get("regions")][0]
    assert live["preliminary_before_days"] == 14 and live["timeline"] and data["measurability"]
