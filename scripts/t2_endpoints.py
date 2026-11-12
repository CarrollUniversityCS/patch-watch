"""Endpoints of Amendment T2 (draft): a national, baseline-fixed host cohort and A_host(d). Sends nothing, writes nothing.

    python -X utf8 scripts/t2_endpoints.py --event php2shell --baseline-label WI_20261024 --points WI_20261026 WI_20261028 \
        --t0-date 2026-10-21 [--db data/study.db]

The study database is opened read-only. Output is PRIVATE aggregate working output (counts 1 to 9 hidden, no domain named). Run on
stored T1 data it is a REHEARSAL: it proves the definitions compute, nothing more. It is not a pre-registered result until
`docs/analysis_plan_t2_release_event.md` carries its freeze record, and it refuses an event whose fixed-version table is not
published (`versions.CVE_2026_115560` until a person fills it in through a section 12 row).

Definitions (Amendment T2, sections 3, 4 and 6):
* day offset = UTC calendar date of the snapshot minus the UTC date of t0;
* cohort = sites EXPOSED against the event table at the baseline snapshot; domains not in the baseline are excluded and counted;
* host = the resolved address in the BASELINE reading, frozen; an edge-fronted site (src/platforms.py) or a site with no address
  is its own unit;
* host state on a day = exposed if any cohort site read that day is EXPOSED; patched if every one read is PATCHED; hid if a site
  moved to OPAQUE and none is PATCHED; other otherwise; not estimable if no cohort site on the host was read;
* A_host(d) = patched / (patched + exposed) at the last reading whose offset is at most d, and only if that reading is within one
  day of d (a missing day is reported as not estimable, never filled in), with an exact Clopper-Pearson interval over hosts;
* fewer than analyze.MIN_COHORT cohort hosts means descriptive only.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]

import analyze  # noqa: E402
import platforms  # noqa: E402
import versions  # noqa: E402
from evidence_math import clopper_pearson  # noqa: E402

TARGET_DAYS = (1, 2, 3, 5, 7, 10)
SC = analyze.Scenario()


def day_offset(started_at_utc: str, t0_date: str) -> int:
    return (date.fromisoformat(started_at_utc[:10]) - date.fromisoformat(t0_date)).days


def _rows(conn: sqlite3.Connection, label: str) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM observations WHERE snapshot_label = ? ORDER BY started_at_utc", (label,)))


def _state(row: sqlite3.Row, event: versions.PatchEvent) -> str:
    return analyze.state_of(analyze._reclassify(row, event), SC)


def _is_edge(row: sqlite3.Row) -> bool:
    try:
        headers = json.loads(row["headers_json"] or "{}")
    except ValueError:
        return False
    return platforms.platform_of(headers)[0] == platforms.EDGE


def _host_state(states: list[str]) -> str:
    read = [s for s in states if s != "UNREACHED"]
    if not read:
        return "not_estimable"
    if "EXPOSED" in read:
        return "exposed"
    if all(s == "PATCHED" for s in read):
        return "patched"
    if "OPAQUE" in read:
        return "hid"
    return "other"


def endpoints(conn: sqlite3.Connection, event: versions.PatchEvent, *, baseline_label: str, point_labels: list[str],
              t0_date: str, target_days: tuple[int, ...] = TARGET_DAYS) -> dict:
    if not event.published:
        raise ValueError(f"event {event.key} is not published: a person must fill its fixed-version table through a section 12 row first")
    base = _rows(conn, baseline_label)
    unit_of: dict[str, str] = {}
    cohort_sites: dict[str, str] = {}                       # domain -> unit
    not_in_cohort: Counter = Counter()
    edge_units = 0
    names = {"EOL": "eol", "PATCHED": "patched_at_baseline", "OPAQUE": "hidden", "AMBIGUOUS": "ambiguous",
             "NO_PHP": "no_php", "UNREACHED": "unreached"}
    for r in base:
        st = _state(r, event)
        if st != "EXPOSED":
            not_in_cohort[names.get(st, st.lower())] += 1
            continue
        edge = _is_edge(r)
        unit = f"edge:{r['domain']}" if edge else (f"ip:{r['resolved_ip']}" if r["resolved_ip"] else f"solo:{r['domain']}")
        edge_units += edge
        unit_of[r["domain"]] = unit
        cohort_sites[r["domain"]] = unit
    hosts = sorted(set(cohort_sites.values()))
    baseline_domains = {r["domain"] for r in base}

    readings = []                                           # (offset, label, {domain: state})
    outside: set[str] = set()
    for label in point_labels:
        rows = _rows(conn, label)
        if not rows:
            continue
        off = day_offset(rows[0]["started_at_utc"], t0_date)
        states = {}
        for r in rows:
            if r["domain"] not in baseline_domains:
                outside.add(r["domain"])
                continue
            states[r["domain"]] = _state(r, event)
        readings.append((off, label, states))
    readings.sort()

    sites_by_host: dict[str, list[str]] = defaultdict(list)
    for dom, unit in cohort_sites.items():
        sites_by_host[unit].append(dom)

    def host_states(states: dict[str, str]) -> dict[str, str]:
        return {h: _host_state([states[d] for d in sites_by_host[h] if d in states]) for h in hosts}

    days: dict[int, dict] = {}
    ever_patched: set[str] = set()
    for _, _, states in readings:
        ever_patched |= {h for h, s in host_states(states).items() if s == "patched"}
    for d in target_days:
        usable = [x for x in readings if x[0] <= d]
        last = usable[-1] if usable else None
        entry: dict = {"reading_day": last[0] if last else None, "estimable": bool(last and d - last[0] <= 1)}
        if entry["estimable"]:
            hs = host_states(last[2])
            c = Counter(hs.values())
            patched, exposed = c["patched"], c["exposed"]
            denom = patched + exposed
            entry.update(patched=patched, exposed=exposed, hid=c["hid"], other=c["other"], not_estimable=c["not_estimable"],
                         denominator=denom, rate=(patched / denom if denom else None),
                         ci95=(clopper_pearson(patched, denom) if denom else None))
        days[d] = entry
    return {"event": event.key, "t0_date": t0_date, "baseline_label": baseline_label, "cohort_hosts": len(hosts),
            "sites_in_cohort": len(cohort_sites), "edge_units": edge_units, "not_in_cohort": dict(not_in_cohort),
            "not_in_baseline": len(outside), "never_patched_by_last": len(set(hosts) - ever_patched),
            "descriptive_only": len(hosts) < analyze.MIN_COHORT, "days": days}


def _cell(n) -> str:
    return "<10" if isinstance(n, int) and 0 < n < 10 else str(n)


def render(res: dict) -> str:
    out = [f"# T2 endpoints for {res['event']} (PRIVATE working output; REHEARSAL until Amendment T2 is frozen)", "",
           f"- t0 date {res['t0_date']}; baseline snapshot {res['baseline_label']}; day = UTC calendar offset",
           f"- cohort hosts {_cell(res['cohort_hosts'])} on {_cell(res['sites_in_cohort'])} sites; edge-fronted units {_cell(res['edge_units'])}",
           f"- not in cohort: {', '.join(f'{k} {_cell(v)}' for k, v in sorted(res['not_in_cohort'].items())) or 'none'}; "
           f"not in baseline {_cell(res['not_in_baseline'])}",
           f"- descriptive only (fewer than {analyze.MIN_COHORT} cohort hosts): {'yes' if res['descriptive_only'] else 'no'}", "",
           "| day | reading day | patched | exposed | hid | other | not estimable | A_host(d) | exact 95% interval |",
           "|---|---|---|---|---|---|---|---|---|"]
    for d, e in sorted(res["days"].items()):
        if not e["estimable"]:
            out.append(f"| {d} | {e['reading_day'] if e['reading_day'] is not None else '-'} | not estimable | | | | | | |")
            continue
        hide = any(isinstance(e[k], int) and 0 < e[k] < 10 for k in ("patched", "exposed"))
        rate = "hidden" if hide or e["rate"] is None else f"{e['rate']:.2f}"
        ci = "hidden" if hide or e["ci95"] is None else f"{e['ci95'][0]:.2f} to {e['ci95'][1]:.2f}"
        out.append(f"| {d} | {e['reading_day']} | {_cell(e['patched'])} | {_cell(e['exposed'])} | {_cell(e['hid'])} | "
                   f"{_cell(e['other'])} | {_cell(e['not_estimable'])} | {rate} | {ci} |")
    out += ["", f"Hosts never observed patched by the last reading: {_cell(res['never_patched_by_last'])}", ""]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=str(ROOT / "data" / "study.db"))
    ap.add_argument("--event", required=True, choices=sorted(versions.EVENTS))
    ap.add_argument("--baseline-label", required=True)
    ap.add_argument("--points", nargs="*", default=[])
    ap.add_argument("--t0-date", required=True, help="UTC date of t0, YYYY-MM-DD")
    args = ap.parse_args(argv)
    conn = sqlite3.connect(f"file:{Path(args.db).as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        print(render(endpoints(conn, versions.EVENTS[args.event], baseline_label=args.baseline_label,
                               point_labels=list(args.points), t0_date=args.t0_date)))
    except ValueError as exc:
        print(f"t2_endpoints: {exc}")
        return 2
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
