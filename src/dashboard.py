"""Static dashboard: the vulnerability intake and each live event's patch state.

Reads two committed inputs and writes one self-contained HTML page:
  * dashboard/catalog.json - every vulnerability triaged so far, with its tier
    (live, validating, awaiting_fix, archive_only, not_measurable, untriaged);
  * reports/run_*.md       - the per-run class counts the pipeline already writes.
Mock and loopback runs are skipped. Nothing here touches the network or the database.

Counts are DOMAINS, as in the run reports. The pre-registered entity-level analysis
stays in reports/analysis_*.md; this page is a view, not an outcome.

Disclosure follows analyze.Suppressor: counts 1-9 print as "<10", a lone hidden
cell in a row takes a complementary "§", and a bar draws hidden cells as one
withheld block. --unsuppressed writes to data/ for the PI only.

    python -X utf8 src/dashboard.py                # -> dashboard/index.html
    python -X utf8 src/dashboard.py --unsuppressed # -> data/dashboard_UNSUPPRESSED.html
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import analyze
import classify
import config
import versions

DASHBOARD_DIR = config.ROOT / "dashboard"
CATALOG_PATH = DASHBOARD_DIR / "catalog.json"
TEMPLATE_PATH = DASHBOARD_DIR / "template.html"
DATA_MARKER = "/*__PATCHWATCH_DATA__*/null"

# Triage tiers, from "measuring now" down to "not looked at yet".
TIERS: tuple[tuple[str, str, str], ...] = (
    ("live", "Live", "Approved at Gate A and measured on every snapshot."),
    ("validating", "Detector in validation", "A detector exists and must pass the test matrix before Gate A."),
    ("awaiting_fix", "Awaiting a fixed release", "Measurable, but there is no fixed version to rank against yet."),
    ("archive_only", "Archive only", "Read from Common Crawl captures; no live requests."),
    ("not_measurable", "Not remotely measurable", "Leaves no passive fingerprint in an ordinary web response."),
    ("untriaged", "Untriaged", "In the intake, not yet reviewed."),
)
TIER_KEYS = tuple(t[0] for t in TIERS)

# Bar order: the analysis states that make up P (analyze.P_STATES), patched first.
BAR_STATES = ("PATCHED", "EXPOSED", "EOL", "AMBIGUOUS", "OPAQUE")
VERSION_VISIBLE = ("PATCHED", "EXPOSED", "EOL", "AMBIGUOUS")
assert set(BAR_STATES) == set(analyze.P_STATES)


# ------------------------------------------------------------------ inputs
def load_catalog(path: Path = CATALOG_PATH) -> list[dict[str, Any]]:
    """The intake list, checked against TIERS and versions.EVENTS."""
    entries = json.loads(Path(path).read_text(encoding="utf-8"))["entries"]
    seen: set[str] = set()
    for e in entries:
        k = e["key"]
        if k in seen:
            raise ValueError(f"catalog: duplicate key {k!r}")
        seen.add(k)
        if e["tier"] not in TIER_KEYS:
            raise ValueError(f"catalog: {k!r} has unknown tier {e['tier']!r}")
        ev = e.get("event")
        if ev is not None and ev not in versions.EVENTS:
            raise ValueError(f"catalog: {k!r} names unknown event {ev!r}")
        if e["tier"] in ("live", "archive_only"):
            if ev is None:
                raise ValueError(f"catalog: {k!r} is {e['tier']} but names no event")
            versions.get_event(ev)   # raises if the event has no published fix
    return entries


_LABEL = re.compile(r"^- snapshot label: `([^`]*)`(.*)$")
_STARTED = re.compile(r"^- started / finished \(UTC\): (\S+)")
_SAMPLE = re.compile(r"^- domains in sample: (\d+)")
_ROW = re.compile(r"^\|\s*([A-Z_]+)\s*\|\s*(\d+)\s*\|$")


def parse_run_report(text: str) -> dict[str, Any] | None:
    """One live run's header and class counts, or None for a mock/loopback run."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith("# Run "):
        return None
    run: dict[str, Any] = {"run_id": lines[0][6:].strip(), "classes": {}}
    in_classes = False
    for ln in lines[1:]:
        if m := _LABEL.match(ln):
            if "MOCK" in m.group(2):
                return None
            run["label"] = m.group(1)
            r = re.search(r"region:\s*(\w+)", m.group(2))
            run["region"] = r.group(1) if r else None
        elif m := _STARTED.match(ln):
            run["started"] = m.group(1)
        elif m := _SAMPLE.match(ln):
            run["domains"] = int(m.group(1))
        elif ln.startswith("## "):
            in_classes = ln.strip() == "## Classes"
        elif in_classes and (m := _ROW.match(ln)) and m.group(1) in classify.CLASSES:
            run["classes"][m.group(1)] = int(m.group(2))
    if not run.get("region") or not run.get("started"):
        return None
    missing = set(classify.CLASSES) - set(run["classes"])
    if missing:
        raise ValueError(f"{run['run_id']}: classes table lacks {sorted(missing)}")
    return run


def load_runs(reports_dir: Path = config.REPORTS_DIR) -> list[dict[str, Any]]:
    runs = []
    for p in sorted(Path(reports_dir).glob("run_*.md")):
        r = parse_run_report(p.read_text(encoding="utf-8"))
        if r:
            runs.append(r)
    return runs


# ------------------------------------------------------------------ model
def point(run: dict[str, Any], event: versions.PatchEvent, sup: analyze.Suppressor) -> dict[str, Any]:
    """One snapshot as the page draws it: shown cells only, hidden ones pooled."""
    states = {s: 0 for s in analyze.STATES}
    for cls, n in run["classes"].items():
        states[analyze.CLASS_TO_STATE[cls]] += n
    P = sum(states[s] for s in BAR_STATES)
    visible = sum(states[s] for s in VERSION_VISIBLE)
    units = sum(states.values())
    cells = dict(zip(BAR_STATES, sup.row([states[s] for s in BAR_STATES])))
    if sup.on and sup.hidden(P):
        cells = {s: "§" for s in BAR_STATES}
    shown = {s: int(c) for s, c in cells.items() if c.isdigit()}
    return {
        "run_id": run["run_id"],
        "label": run["label"],
        "started": run["started"],
        "day": round(analyze.days_from(event.t0_utc, run["started"]), 1),
        "cells": cells,
        "shown": shown,
        "P": sup.count(P),
        "P_n": None if sup.hidden(P) else P,
        "withheld": None if sup.hidden(P) else P - sum(shown.values()),
        "funnel": {
            "domains": sup.count(units),
            "reached": sup.count(units - states["UNREACHED"]),
            "php": sup.count(P),
            "visible": sup.count(visible),
        },
        "patched_share": sup.share(states["PATCHED"], visible),
        "exposed": sup.count(states["EXPOSED"] + states["EOL"]),
    }


def build_model(entries: list[dict[str, Any]], runs: list[dict[str, Any]], *,
                suppressed: bool = True) -> dict[str, Any]:
    sup = analyze.Suppressor(on=suppressed)
    pipeline_event = versions.get_event(None)
    out_entries = []
    for e in entries:
        e = dict(e)
        if e["tier"] == "live" and e["event"] == pipeline_event.key:
            by_region: dict[str, list] = {}
            for r in sorted(runs, key=lambda r: r["started"]):
                by_region.setdefault(r["region"], []).append(point(r, pipeline_event, sup))
            # Wisconsin is the primary aim; comparison states follow.
            e["regions"] = [{"region": k, "points": v} for k, v in
                            sorted(by_region.items(), key=lambda kv: kv[0] != "wisconsin")]
            e["t0_utc"] = pipeline_event.t0_utc
        out_entries.append(e)
    commit, dirty = _commit()
    return {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": commit,
        "dirty": dirty,
        "suppressed": suppressed,
        "tiers": [{"key": k, "label": lab, "blurb": b} for k, lab, b in TIERS],
        "entries": out_entries,
    }


def _commit() -> tuple[str, bool]:
    try:
        c = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=config.ROOT,
                           capture_output=True, text=True, timeout=5).stdout.strip()
        d = subprocess.run(["git", "status", "--porcelain", "src", "dashboard/catalog.json", "reports"],
                           cwd=config.ROOT, capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown", False
    return c or "unknown", bool(d)


# ------------------------------------------------------------------ output
def render(model: dict[str, Any], template: str, fragment: bool = False) -> str:
    if DATA_MARKER not in template:
        raise ValueError("template lacks the data marker")
    # "</" cannot appear inside an inline <script>; JSON allows the escape.
    data = json.dumps(model, ensure_ascii=False).replace("</", "<\\/")
    html = template.replace(DATA_MARKER, data)
    if fragment:   # for hosts that supply their own <html>/<head>/<body> skeleton
        html = re.sub(r"(?s)^.*?<!--FRAGMENT-START-->\s*", "", html)
        html = re.sub(r"(?s)\s*<!--FRAGMENT-END-->.*$", "\n", html)
    return html


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, help="output path (default: dashboard/index.html)")
    ap.add_argument("--unsuppressed", action="store_true",
                    help="raw counts; writes under data/ (PI only, never publish)")
    ap.add_argument("--fragment", action="store_true",
                    help="omit the <html>/<head>/<body> wrapper")
    args = ap.parse_args(argv)
    out = args.out or (config.DATA_DIR / "dashboard_UNSUPPRESSED.html" if args.unsuppressed
                       else DASHBOARD_DIR / "index.html")
    model = build_model(load_catalog(), load_runs(), suppressed=not args.unsuppressed)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(model, TEMPLATE_PATH.read_text(encoding="utf-8"), args.fragment),
                   encoding="utf-8")
    n_live = sum(len(r["points"]) for e in model["entries"] for r in e.get("regions", []))
    print(f"wrote {out} ({len(model['entries'])} catalog entries, {n_live} live snapshots)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
