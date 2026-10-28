"""Read-only probes for the scheduled operator jobs — replaces every `python -c` one-liner.

Why this file exists: Hermes blocks `python.exe -c "..."` in unattended jobs ("Command flagged as
dangerous ... cron jobs run without a user present to approve it"), so any runbook check written as
a one-liner silently FAILS at 08:30/09:00/11:30 and the day gets paused for a tooling reason. Every
database check in docs/HERMES_RUNBOOK.md and profile_docs/patch-watch/OPERATOR_JOBS.md therefore
runs through a NAMED query here. This script never accepts SQL as an argument, never opens a
write transaction, and never touches the network.

    .venv\\Scripts\\python.exe -X utf8 scripts\\pw_probe.py <name> [args...]

Exit codes: 0 = probe ran, 1 = unknown name / bad args, 2 = the probe's own FAIL condition.
"""
from __future__ import annotations

import datetime as dt
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "study.db"


def _ro() -> sqlite3.Connection:
    if not DB.exists():
        raise SystemExit(f"pw_probe: no database at {DB} — nothing has run yet")
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _day(arg: str) -> str:
    d = arg.replace("-", "")
    if len(d) != 8 or not d.isdigit():
        raise SystemExit(f"pw_probe: expected YYYYMMDD, got {arg!r}")
    return d


# ---------------------------------------------------------------- probes
def runs_today(a):
    """Every run row for a date: did traffic go out, did it finish, did the kill switch speak?"""
    d = _day(a[0]) if a else dt.date.today().strftime("%Y%m%d")
    rows = _ro().execute(
        "SELECT run_id, snapshot_label, started_at_utc, finished_at_utc, attempted,"
        " responded, errors, sends, kill_switch FROM runs"
        " WHERE snapshot_label LIKE ? OR run_id LIKE ? ORDER BY started_at_utc",
        (f"%{d}%", f"%{d}%"),
    ).fetchall()
    if not rows:
        print(f"runs_today {d}: NO RUN ROWS (no traffic went out under this date)")
        return 0
    for r in rows:
        unfinished = "UNFINISHED(traffic already sent - do not re-run)" if not r["finished_at_utc"] else "finished"
        print(f"  {r['run_id']} | {unfinished} | attempted={r['attempted']} responded={r['responded']}"
              f" errors={r['errors']} sends={r['sends']} kill_switch={r['kill_switch']!r}")
    return 0


def ledger_codes(a):
    """Status-code breakdown for one run_id — the §5.1 evidence an URGENT message must carry."""
    if not a:
        raise SystemExit("usage: pw_probe ledger_codes <run_id>")
    rows = _ro().execute(
        "SELECT status_code, count(*) n FROM request_ledger WHERE run_id = ?"
        " GROUP BY status_code ORDER BY n DESC", (a[0],),
    ).fetchall()
    print(f"ledger_codes {a[0]}: " + (", ".join(f"{r['status_code']}x{r['n']}" for r in rows) or "no rows"))
    return 0


def optout_honour(a):
    """§7 step 3: every opt-out domain must be in the effective blocklist AND have no live row."""
    from fetch import load_blocklist
    blocked = load_blocklist()
    con = _ro()
    bad = 0
    live = dict(con.execute("SELECT domain, count(*) FROM observations WHERE status_code IS NOT NULL"
                            " GROUP BY domain").fetchall())
    for dom in sorted(blocked):
        hit = live.get(dom, 0)
        print(f"  {dom}: blocklisted=True rows_with_status={hit}")
        if hit:
            bad += 1
    print(f"optout_honour: {len(blocked)} domains on the list, {bad} with post-opt-out traffic")
    return 2 if bad else 0


def region_rows(a):
    """Per-region row counts for a date — how a held arm proves it stayed held."""
    d = _day(a[0]) if a else dt.date.today().strftime("%Y%m%d")
    con = _ro()
    for tag in ("WI", "CMP"):
        n = con.execute(
            "SELECT count(*) FROM observations WHERE snapshot_label LIKE ?", (f"%{tag}_{d}%",)
        ).fetchone()[0]
        print(f"  {tag}_{d}: {n} observation rows")
    return 0


def baseline_progress(a):
    """§9 Common Crawl baseline: usable rows only (candidates > 0), never raw row count."""
    con = _ro()
    tot, usable = con.execute(
        "SELECT count(*), sum(case when candidates > 0 then 1 else 0 end) FROM baseline_observations"
    ).fetchone()
    last = con.execute("SELECT max(collected_at_utc) FROM baseline_observations").fetchone()[0]
    print(f"baseline_progress: rows={tot} usable(candidates>0)={usable} last_collected={last}")
    return 0


PROBES = {
    "runs_today": runs_today,
    "ledger_codes": ledger_codes,
    "optout_honour": optout_honour,
    "region_rows": region_rows,
    "baseline_progress": baseline_progress,
}


def main(argv):
    if len(argv) < 2 or argv[1] not in PROBES:
        print(__doc__)
        print("probes:", ", ".join(sorted(PROBES)))
        return 1
    sys.path.insert(0, str(ROOT / "src"))
    return PROBES[argv[1]](argv[2:])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
