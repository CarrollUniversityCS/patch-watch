"""src/dashboard.py: catalog checks, run-report parsing, suppression. No network."""

from __future__ import annotations

import json
import re

import pytest

import classify
import dashboard

LIVE = """# Run R20261028T140016Z_WI_20261028

- snapshot label: `WI_20261028` | region: wisconsin
- started / finished (UTC): 2026-10-28T14:00:17Z / 2026-10-28T14:05:35Z
- domains in sample: 833  |  responded 705  |  errored 128  |  skipped 0

## Classes

| class | n |
|---|---|
{rows}

## Changes vs previous observation

| event | n |
|---|---|
| class_change | 10 |
"""


def report(counts: dict[str, int], header: str | None = None) -> str:
    rows = "\n".join(f"| {c} | {counts.get(c, 0)} |" for c in classify.CLASSES)
    text = LIVE.format(rows=rows)
    if header:
        text = text.replace("`WI_20261028` | region: wisconsin", header)
    return text


def entry(**kw):
    e = {"key": "php2shell", "title": "PHP2Shell", "cve_ids": [], "component": "", "disclosed": "",
         "tier": "live", "event": "php2shell", "signal": "", "why": "", "sources": []}
    return {**e, **kw}


def write_catalog(tmp_path, entries):
    p = tmp_path / "catalog.json"
    p.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    return p


# ------------------------------------------------------------------ parsing
def test_parse_live_report():
    r = dashboard.parse_run_report(report({"PATCHED_UPSTREAM": 32, "EOL_UNFIXED": 10}))
    assert r["region"] == "wisconsin" and r["label"] == "WI_20261028"
    assert r["started"] == "2026-10-28T14:00:17Z"
    assert r["classes"]["PATCHED_UPSTREAM"] == 32
    assert "class_change" not in r["classes"]          # other tables are ignored


@pytest.mark.parametrize("header", ["`MOCKTEST_WI` (MOCK, loopback only) | region: wisconsin",
                                    "`C1` (MOCK, loopback only)"])
def test_mock_reports_are_skipped(header):
    assert dashboard.parse_run_report(report({}, header)) is None


def test_missing_class_row_raises():
    text = report({}).replace("| UNPARSEABLE | 0 |\n", "")
    with pytest.raises(ValueError, match="UNPARSEABLE"):
        dashboard.parse_run_report(text)


def test_committed_reports_parse():
    runs = dashboard.load_runs()
    assert runs and all(r["region"] in ("wisconsin", "comparison") for r in runs)
    assert not any("MOCK" in r["label"] for r in runs)


# ------------------------------------------------------------------ catalog
def test_committed_catalog_is_valid():
    keys = {e["key"] for e in dashboard.load_catalog()}
    assert "php2shell" in keys


@pytest.mark.parametrize("bad, msg", [
    ({"tier": "maybe"}, "unknown tier"),
    ({"event": "nope"}, "unknown event"),
    ({"event": None}, "names no event"),
    ({"event": "cve_2026_115560"}, "no published fixed releases"),
])
def test_catalog_rejects(tmp_path, bad, msg):
    with pytest.raises(ValueError, match=msg):
        dashboard.load_catalog(write_catalog(tmp_path, [entry(**bad)]))


def test_catalog_rejects_duplicate_keys(tmp_path):
    with pytest.raises(ValueError, match="duplicate"):
        dashboard.load_catalog(write_catalog(tmp_path, [entry(), entry()]))


def test_awaiting_fix_may_name_unpublished_event(tmp_path):
    dashboard.load_catalog(write_catalog(tmp_path, [entry(tier="awaiting_fix", event="cve_2026_115560")]))


# ------------------------------------------------------------------ model
def model_for(counts, suppressed=True):
    run = dashboard.parse_run_report(report(counts))
    m = dashboard.build_model([entry(), entry(key="fw", tier="not_measurable", event=None)],
                              [run], suppressed=suppressed)
    return m, m["entries"][0]["regions"][0]["points"][0]


def test_states_and_share():
    _, p = model_for({"PATCHED_UPSTREAM": 32, "EOL_UNFIXED": 10, "PHP_VERSION_HIDDEN": 156,
                      "NO_PHP_EVIDENCE": 454, "NO_RESPONSE": 126, "NOT_MEASURED": 55})
    assert p["cells"] == {"PATCHED": "32", "EXPOSED": "0", "EOL": "10", "AMBIGUOUS": "0", "OPAQUE": "156"}
    assert p["P_n"] == 198 and p["withheld"] == 0
    assert p["patched_share"] == "76%"
    assert p["funnel"] == {"domains": "833", "reached": "652", "php": "198", "visible": "42"}
    assert p["day"] == 7.0


def test_small_cells_are_withheld_with_complement():
    _, p = model_for({"PATCHED_UPSTREAM": 28, "VULNERABLE_BY_VERSION": 4, "EOL_UNFIXED": 10,
                      "PHP_VERSION_HIDDEN": 155})
    assert p["cells"]["EXPOSED"] == "<10" and p["cells"]["EOL"] == "§"
    assert set(p["shown"]) == {"PATCHED", "AMBIGUOUS", "OPAQUE"}
    assert p["withheld"] == 14


def test_tiny_population_withholds_everything():
    _, p = model_for({"PATCHED_UPSTREAM": 3, "PHP_VERSION_HIDDEN": 4})
    assert p["P"] == "<10" and p["P_n"] is None and p["withheld"] is None
    assert set(p["cells"].values()) == {"§"} and p["patched_share"] == "§"


def test_unsuppressed_shows_raw_counts():
    _, p = model_for({"PATCHED_UPSTREAM": 3, "VULNERABLE_BY_VERSION": 4, "PHP_VERSION_HIDDEN": 40},
                     suppressed=False)
    assert p["cells"]["PATCHED"] == "3" and p["withheld"] == 0 and p["patched_share"] == "43%"


def test_only_live_pipeline_event_gets_runs():
    m, _ = model_for({"PATCHED_UPSTREAM": 20})
    assert "regions" not in m["entries"][1]


def test_render_embeds_data_safely():
    m, _ = model_for({"PATCHED_UPSTREAM": 20})
    m["entries"][0]["why"] = "</script><b>x"
    html = dashboard.render(m, dashboard.TEMPLATE_PATH.read_text(encoding="utf-8"))
    blob = re.search(r'id="pw-data">(.*?)</script>', html, re.S).group(1)
    assert json.loads(blob)["entries"][0]["why"] == "</script><b>x"
    frag = dashboard.render(m, dashboard.TEMPLATE_PATH.read_text(encoding="utf-8"), fragment=True)
    assert "<html" not in frag and "<title>Patch Watch</title>" in frag
