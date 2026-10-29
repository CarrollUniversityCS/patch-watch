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
        validate_entry(e)
        k = e["key"]
        if k in seen:
            raise ValueError(f"catalog: duplicate key {k!r}")
        seen.add(k)
        if e["tier"] not in TIER_KEYS:
            raise ValueError(f"catalog: {k!r} has unknown tier {e['tier']!r}")
        ev = e.get("event")
        if ev is not None and ev not in versions.EVENTS:
            raise ValueError(f"catalog: {k!r} names unknown event {ev!r}")
        kev = e.get("kev")
        if kev is not None:
            for f in ("added", "federal_due"):
                if not _DATE.match(str(kev.get(f, ""))):
                    raise ValueError(f"catalog: {k!r} kev.{f} must be YYYY-MM-DD")
            if not isinstance(kev.get("verified"), bool):
                raise ValueError(f"catalog: {k!r} kev.verified must be true or false")
        if e["tier"] in ("live", "archive_only"):
            if ev is None:
                raise ValueError(f"catalog: {k!r} is {e['tier']} but names no event")
            versions.get_event(ev)   # raises if the event has no published fix
    return entries


_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DISCLOSED = re.compile(r"^(\d{4}-(0[1-9]|1[0-2])(-(0[1-9]|[12]\d|3[01]))?)?$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Decision D1 (maintainer decision): a chart point is "preliminary" until its snapshot is this many
# days after disclosure, matching the pre-registered primary endpoint (plan §7.0). A dashboard
# presentation rule only: it lives here, not in config.py, and changes no collection.
PRELIMINARY_BEFORE_DAYS = 14

REQUIRED_FIELDS: dict[str, type] = {
    "key": str, "title": str, "cve_ids": list, "component": str, "disclosed": str,
    "tier": str, "signal": str, "why": str, "sources": list,
}
EXPLOITATION_KINDS = ("vendor_reported", "kev_listing")


def validate_entry(e: dict[str, Any]) -> None:
    """Shape of one catalog entry (documented in dashboard/README.md). A malformed entry stops
    the build instead of publishing a half-filled card."""
    k = e.get("key", "<no key>")
    for f, typ in REQUIRED_FIELDS.items():
        if f not in e:
            raise ValueError(f"catalog: {k!r} lacks required field {f!r}")
        if not isinstance(e[f], typ):
            raise ValueError(f"catalog: {k!r} field {f!r} must be {typ.__name__}")
    if not e["key"] or not re.fullmatch(r"[a-z0-9_]+", e["key"]):
        raise ValueError(f"catalog: key {e['key']!r} must be lower-case letters, digits and underscores")
    if not all(isinstance(c, str) and _CVE.match(c) for c in e["cve_ids"]):
        raise ValueError(f"catalog: {k!r} cve_ids must look like CVE-YYYY-NNNN")
    if not _DISCLOSED.match(e["disclosed"]):
        raise ValueError(f"catalog: {k!r} disclosed must be empty, YYYY-MM or YYYY-MM-DD")
    if not all(isinstance(s, str) for s in e["sources"]):
        raise ValueError(f"catalog: {k!r} sources must be a list of strings")
    x = e.get("exploitation")
    if x is not None:
        if not _DATE.match(str(x.get("first_seen", ""))):
            raise ValueError(f"catalog: {k!r} exploitation.first_seen must be YYYY-MM-DD")
        if x.get("kind") not in EXPLOITATION_KINDS:
            raise ValueError(f"catalog: {k!r} exploitation.kind must be one of {EXPLOITATION_KINDS}")
        if not str(x.get("source", "")).strip():
            raise ValueError(f"catalog: {k!r} exploitation.source must say where the date comes from")


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
        "unsupported": unsupported(states, sup),
    }


def unsupported(states: dict[str, int], sup: analyze.Suppressor) -> dict[str, Any]:
    """Of the sites showing a PHP version we can place (no distro-build ambiguity), how
    many run a branch PHP no longer fixes. Same suppression as every other cell; `pct` is
    None whenever the share is withheld, so the page can never draw a hidden value."""
    placed = states["PATCHED"] + states["EXPOSED"] + states["EOL"]
    share = sup.share(states["EOL"], placed)
    return {
        "n": sup.count(states["EOL"]),
        "of": sup.count(placed),
        "share": share,
        "pct": int(share[:-1]) if share.endswith("%") else None,
    }


def onset(e: dict[str, Any]) -> dict[str, str] | None:
    """When exploitation started, with where the date comes from. A catalog `exploitation`
    block wins. Without one the KEV listing date is used and labelled as a floor: CISA lists a
    flaw after exploitation is seen, so it is not the first exploitation."""
    x = e.get("exploitation")
    if x:
        return {"date": x["first_seen"], "kind": x["kind"], "source": x["source"].strip()}
    kev = e.get("kev")
    if kev:
        return {"date": kev["added"], "kind": "kev_listing",
                "source": "CISA KEV dateAdded: a floor, not the first exploitation"}
    return None


def days_between(date_or_ts: str, ts: str) -> float | None:
    """Days from a date (YYYY-MM-DD or timestamp) to a snapshot timestamp, one decimal."""
    a = analyze._parse_ts(date_or_ts if "T" in date_or_ts else date_or_ts + "T00:00:00Z")
    b = analyze._parse_ts(ts)
    if a is None or b is None:
        return None
    return round((b - a).total_seconds() / 86400, 1)


def since_text(days: float | None, on: dict[str, str] | None) -> str:
    """'0.9 days after CISA's KEV listing': direction and anchor stated, never a bare number."""
    if days is None or not on:
        return ""
    what = "CISA's KEV listing" if on["kind"] == "kev_listing" else "exploitation was first seen"
    return f"{abs(days):.1f} days {'after' if days >= 0 else 'before'} {what}"


def timeline(e: dict[str, Any]) -> list[dict[str, Any]]:
    """The exposure window as an ordered list of dated events: disclosure, exploitation onset
    (with its source), the federal due date, and each Wisconsin-first snapshot. The page draws
    it as a strip and as a plain list; both read from this one list."""
    items: list[dict[str, Any]] = []
    if e.get("t0_utc"):
        items.append({"kind": "disclosure", "date": e["t0_utc"][:10], "label": "Fix released",
                      "note": e.get("disclosed", "")})
    on = e.get("onset")
    if on:
        label = ("Exploitation seen" if on["kind"] == "vendor_reported" else "Added to CISA's KEV list")
        items.append({"kind": "onset", "date": on["date"], "label": label, "note": on["source"]})
    due = (e.get("kev") or {}).get("federal_due")
    if due:
        items.append({"kind": "due", "date": due, "label": "Federal deadline",
                      "note": "binds federal civilian agencies, not state or local governments"})
    for rg in e.get("regions", []):
        if rg["points"]:
            for p in rg["points"]:
                items.append({"kind": "snapshot", "date": p["started"][:10], "region": rg["region"],
                              "label": "Snapshot", "day": p["day"], "preliminary": p["preliminary"],
                              "since_onset": p["since_onset"],
                              "since_text": since_text(p["since_onset"], on)})
            break                       # the primary region draws the strip
    order = {"disclosure": 0, "onset": 1, "due": 2, "snapshot": 3}
    return sorted(items, key=lambda i: (i["date"], order[i["kind"]]))


MEASURABILITY_PATH = DASHBOARD_DIR / "measurability.json"


def load_measurability(path: Path = MEASURABILITY_PATH) -> dict[str, Any] | None:
    """Optional aggregate summary of the KEV census (public KEV data, no domains): written by
    scripts/kev_census.py. Checked here so a bad file stops the build."""
    p = Path(path)
    if not p.exists():
        return None
    m = json.loads(p.read_text(encoding="utf-8"))
    for f in ("catalog_version", "total", "groups", "caveat"):
        if f not in m:
            raise ValueError(f"measurability: lacks {f!r}")
    if not isinstance(m["groups"], list) or not all(
            {"reason", "count", "examples"} <= set(g) and len(g["examples"]) <= 10 for g in m["groups"]):
        raise ValueError("measurability: each group needs reason, count and at most 10 examples")
    return m


def build_model(entries: list[dict[str, Any]], runs: list[dict[str, Any]], *,
                suppressed: bool = True, measurability: dict[str, Any] | None = None) -> dict[str, Any]:
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
            # A snapshot taken on or after the federal KEV due date (UTC calendar day).
            due = (e.get("kev") or {}).get("federal_due")
            on = onset(e)
            e["onset"] = on
            e["preliminary_before_days"] = PRELIMINARY_BEFORE_DAYS
            for rg in e["regions"]:
                for p in rg["points"]:
                    p["after_federal_due"] = bool(due) and p["started"][:10] >= due
                    p["preliminary"] = p["day"] < PRELIMINARY_BEFORE_DAYS
                    p["since_onset"] = days_between(on["date"], p["started"]) if on else None
            e["timeline"] = timeline(e)
        out_entries.append(e)
    commit, dirty = _commit()
    return {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": commit,
        "dirty": dirty,
        "suppressed": suppressed,
        "tiers": [{"key": k, "label": lab, "blurb": b} for k, lab, b in TIERS],
        "entries": out_entries,
        "measurability": measurability,
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
    model = build_model(load_catalog(), load_runs(), suppressed=not args.unsuppressed,
                        measurability=load_measurability())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(model, TEMPLATE_PATH.read_text(encoding="utf-8"), args.fragment),
                   encoding="utf-8")
    n_live = sum(len(r["points"]) for e in model["entries"] for r in e.get("regions", []))
    print(f"wrote {out} ({len(model['entries'])} catalog entries, {n_live} live snapshots)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
