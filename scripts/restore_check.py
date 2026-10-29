"""Check that a backup of the study database could be restored. Read-only; prints aggregates only.

    python -X utf8 scripts/restore_check.py backups/study_20261029_1135.db [--json]

What it does, in order:
  1. opens the file read-only (it never writes to it, and refuses anything that is not a SQLite file);
  2. runs `PRAGMA integrity_check`, which must say `ok`;
  3. compares the tables and columns with what `src/db.py` would create today: a missing table or column means
     the backup cannot be used by today's code; an extra column (a newer or older schema) is reported, not failed;
  4. prints row counts per table, the number of runs and their date range, and the number of distinct domains
     observed. No domain, address or header is printed.

Exit codes: 0 = restorable, 2 = integrity or schema problem, 1 = bad arguments or not a database.
This is the drill the runbook's backup step (section 5.4) implies but does not run: a backup is only a backup
once it has been opened.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import db  # noqa: E402

COUNT_TABLES = ("domains", "runs", "observations", "request_ledger", "patch_events", "meta", "baseline_observations")


def expected_schema() -> dict[str, set[str]]:
    """Table -> column names that today's `db.init_db` creates, built in memory."""
    mem = sqlite3.connect(":memory:")
    mem.executescript(db.SCHEMA)
    out = {}
    for (name,) in mem.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
        out[name] = {r[1] for r in mem.execute(f"PRAGMA table_info({name})")}
    mem.close()
    return out


def check(path: Path) -> dict:
    uri = path.resolve().as_uri() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    try:
        integrity = [r[0] for r in con.execute("PRAGMA integrity_check")]
        have = {}
        for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            have[name] = {r[1] for r in con.execute(f"PRAGMA table_info({name})")}
        want = expected_schema()
        missing_tables = sorted(set(want) - set(have))
        missing_cols = {t: sorted(want[t] - have[t]) for t in want if t in have and want[t] - have[t]}
        extra_cols = {t: sorted(have[t] - want[t]) for t in want if t in have and have[t] - want[t]}
        counts = {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in COUNT_TABLES if t in have}
        runs = {}
        if "runs" in have and {"started_at_utc", "kill_switch"} <= have["runs"]:
            lo, hi = con.execute("SELECT MIN(started_at_utc), MAX(started_at_utc) FROM runs").fetchone()
            halted = con.execute("SELECT COUNT(*) FROM runs WHERE kill_switch IS NOT NULL AND kill_switch != ''").fetchone()[0]
            runs = {"first_started_utc": lo, "last_started_utc": hi, "halted": halted}
        domains = (con.execute("SELECT COUNT(DISTINCT domain) FROM observations").fetchone()[0]
                   if "observations" in have and "domain" in have["observations"] else None)
    finally:
        con.close()
    ok = integrity == ["ok"] and not missing_tables and not missing_cols
    return {"file": path.name, "bytes": path.stat().st_size, "integrity": integrity, "restorable": ok,
            "missing_tables": missing_tables, "missing_columns": missing_cols, "extra_columns": extra_cols,
            "row_counts": counts, "runs": runs, "distinct_domains_observed": domains}


def render(r: dict) -> str:
    lines = [f"{r['file']}: {r['bytes']:,} bytes", f"  integrity_check: {', '.join(r['integrity'])}"]
    if r["missing_tables"]:
        lines.append(f"  MISSING TABLES: {', '.join(r['missing_tables'])}")
    for t, cols in r["missing_columns"].items():
        lines.append(f"  MISSING COLUMNS in {t}: {', '.join(cols)}")
    for t, cols in r["extra_columns"].items():
        lines.append(f"  extra columns in {t} (not a failure): {', '.join(cols)}")
    lines.append("  rows: " + ", ".join(f"{t} {n}" for t, n in r["row_counts"].items()))
    if r["runs"]:
        lines.append(f"  runs from {r['runs']['first_started_utc']} to {r['runs']['last_started_utc']}; "
                     f"{r['runs']['halted']} halted")
    if r["distinct_domains_observed"] is not None:
        lines.append(f"  distinct domains observed: {r['distinct_domains_observed']}")
    lines.append("  RESTORABLE" if r["restorable"] else "  NOT RESTORABLE")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("backup", help="path to a study_*.db backup (opened read-only)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    path = Path(args.backup)
    if not path.is_file():
        print(f"error: not a file: {path}", file=sys.stderr)
        return 1
    try:
        r = check(path)
    except sqlite3.DatabaseError as e:
        print(f"error: not a readable SQLite database ({e})", file=sys.stderr)
        return 1
    print(json.dumps(r, indent=1) if args.json else render(r))
    return 0 if r["restorable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
