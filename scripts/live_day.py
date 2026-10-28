#!/usr/bin/env python
"""One live snapshot day: the Windows translation of scripts/cron.disabled's live line.

Why this file exists. `scripts/cron.disabled` is written for a POSIX crontab and this
host is Windows with no cron daemon, so the schedule cannot be installed as written
(runbook section 4, Windows note). This wrapper is NOT new collection logic. It runs the
same two commands, in the same order, in separate processes, exactly as the frozen cron
line does:

    scripts/run_snapshot.py --region wisconsin  --label WI_<day>   ... &&
    scripts/run_snapshot.py --region comparison --label CMP_<day>

Everything it adds is a refusal, never an action. Each one implements a limit that
already exists in the runbook, so the worst this file can do is skip a day:

  * the day it was given must be today's local date, else nothing runs -- a task that
    fired on the wrong day would silently double up or gap a snapshot (section 2.5);
  * nothing runs if logs/abuse.flag exists (section 2.1: a halt is a stop, not a bug);
  * nothing runs for a region that was already snapshotted in the last 24 hours
    (section 2.5: one live snapshot per region per day, enforced in code rather than by
    trusting that only one cron line existed);
  * if the check itself cannot be made, nothing runs -- a missed day is recoverable as a
    stated limitation, a broken promise to a site operator is not (runbook preamble);
  * comparison runs only if wisconsin exits 0, which is the `&&` in the cron line;
  * PATCHWATCH_REGIONS can hold one arm of the chain (PI decision, 2026-10-26: comparison
    held after the 2026-10-24 halt). Unset = both regions, exactly as section 4 writes them.
    A value that is not a subset of the region names refuses the day (exit 9) rather than
    capturing a quieter subset than anyone agreed to.

It does not set PATCHWATCH_GATE_A. The gate marker is supplied by the schedule, in
scripts/live_day.cmd, exactly as section 4 puts it in the crontab environment block --
deliberately not here, so that a hand-run of this file cannot authorise live traffic.

Usage:  python scripts/live_day.py 20261024
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "wi_frame.csv"
DB_PATH = ROOT / "data" / "study.db"
ABUSE_FLAG = ROOT / "logs" / "abuse.flag"
RUNNER = ROOT / "scripts" / "run_snapshot.py"

# Order is the chain itself (section 4): wisconsin first, comparison only if it exits 0.
ALL_REGIONS = ("wisconsin", "comparison")
LABEL_PREFIX = {"wisconsin": "WI", "comparison": "CMP"}


def selected_regions() -> tuple[str, ...]:
    """Which regions today's schedule captures — section 4's chain, or a held subset of it.

    PATCHWATCH_REGIONS lets the PI hold one arm of the study without deleting the collection
    logic: a comma-separated subset of the region names, default = all of them, in chain order.
    Anything unrecognised or empty refuses the whole day rather than quietly capturing a
    subset — a partial snapshot that nobody announced is worse than a missed one. A held region
    prints on every run, so the hold cannot become invisible.
    """
    raw = os.environ.get("PATCHWATCH_REGIONS", "").strip()
    if not raw:
        return ALL_REGIONS
    chosen = tuple(p.strip() for p in raw.split(",") if p.strip())
    unknown = [r for r in chosen if r not in ALL_REGIONS]
    if not chosen or unknown:
        refuse(f"PATCHWATCH_REGIONS={raw!r} is not a comma-separated subset of "
               f"{ALL_REGIONS}; refusing to guess which regions to capture today",
               EXIT_BAD_REGIONS)
    held = [r for r in ALL_REGIONS if r not in chosen]
    if held:
        print(f"live_day {dt.datetime.now().isoformat(timespec='seconds')}: HOLDING "
              f"{', '.join(held)} (PATCHWATCH_REGIONS={raw}); capturing {' then '.join(chosen)}")
    return chosen

# Exit codes: 0 all regions captured, 1 a region failed (as the child reported it),
# 4+ a refusal to send any traffic (see the refusal reasons in the docstring).
EXIT_WRONG_DAY, EXIT_NO_FRAME, EXIT_HALTED, EXIT_ALREADY_RAN, EXIT_CANNOT_CHECK = 4, 5, 6, 7, 8
EXIT_BAD_REGIONS = 9                        # PATCHWATCH_REGIONS set to something unparseable


def refuse(why: str, code: int) -> NoReturn:
    """Print a refusal and stop. Sends nothing, changes nothing."""
    print(f"live_day {dt.datetime.now().isoformat(timespec='seconds')}: REFUSING - {why}")
    raise SystemExit(code)


def parse_utc(stamp: str) -> dt.datetime:
    """`runs.started_at_utc` is an ISO instant; tolerate a trailing Z or an offset."""
    text = (stamp or "").strip().replace("Z", "+00:00")
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


GUARD_TOLERANCE = dt.timedelta(minutes=15)


def run_guard_window(now: dt.datetime | None = None) -> dt.datetime:
    """Start of the lookback that decides whether this region already ran today.

    24 h minus GUARD_TOLERANCE. The strict-24 h version ate the 2026-10-27 snapshot day (an
    off-schedule 2026-10-26 16:52 run was still inside 24 h at 09:00) and left every scheduled
    day balanced on seconds, because consecutive 09:00 tasks start ~14:00:1xZ apart. Section 2.5
    promises a site is not visited twice in a day; 15 minutes of overlap does not break that,
    while a same-day manual re-run is still hours early and still refused.
    """
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    return now - dt.timedelta(hours=24) + GUARD_TOLERANCE


def prior_run_for(region: str, window_start: dt.datetime) -> str:
    """Return a description of a same-region run inside the window, or '' if none.

    Raises so the caller refuses rather than guessing: an unreadable ledger cannot
    prove that today's run is the first one.
    """
    if not DB_PATH.exists():
        return ""                                     # no database yet = no prior run
    conn = sqlite3.connect(f"file:{DB_PATH.as_posix()}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT run_id, started_at_utc, config_json FROM runs").fetchall()
    finally:
        conn.close()
    for run_id, started, config_json in rows:
        if not started:
            continue
        if (config_json or "").strip():
            try:
                seen_region = json.loads(config_json).get("region")
            except (json.JSONDecodeError, AttributeError):
                raise ValueError(f"run {run_id} has unreadable config_json")
        else:
            raise ValueError(f"run {run_id} has no region in config_json")
        if seen_region != region:
            continue
        if parse_utc(started) >= window_start:
            return f"run_id={run_id} started_at_utc={started}"
    return ""


def main(argv: list[str]) -> int:
    if len(argv) != 2 or len(argv[1]) != 8 or not argv[1].isdigit():
        refuse("usage: live_day.py YYYYMMDD (the local date this task was created to capture)",
               EXIT_WRONG_DAY)
    day = argv[1]

    today = dt.date.today().strftime("%Y%m%d")
    if day != today:
        refuse(f"this task is dated {day} but today is {today}; running would break "
               f"one-snapshot-per-region-per-day (section 2.5)", EXIT_WRONG_DAY)

    if not SAMPLE.exists():
        refuse(f"no frame at {SAMPLE.relative_to(ROOT)} "
               f"(python src/wi_frame.py build --comparison MN,IL,MI,IA --skip-download)",
               EXIT_NO_FRAME)
    if ABUSE_FLAG.exists():
        refuse("logs/abuse.flag exists - the study is halted and only Jack clears a halt "
               "(section 2.1)", EXIT_HALTED)

    window_start = run_guard_window()
    regions = selected_regions()            # may be a held subset; refuses if unparseable

    for region in regions:
        label = f"{LABEL_PREFIX[region]}_{day}"
        already = ""
        try:
            already = prior_run_for(region, window_start)
        except (sqlite3.Error, ValueError) as exc:
            refuse(f"cannot verify whether {region} already ran today ({exc}); "
                   f"refusing rather than risking a second run (section 2.5)",
                   EXIT_CANNOT_CHECK)
        if already:
            refuse(f"{region} already snapshotted within the last 24 h "
                   f"({already}); a second live run per region per day is section 2.5",
                   EXIT_ALREADY_RAN)

        cmd = [sys.executable, "-X", "utf8", str(RUNNER),
               "--sample", str(SAMPLE), "--region", region, "--label", label]
        print(f"live_day {dt.datetime.now().isoformat(timespec='seconds')}: RUNNING "
              f"{' '.join(Path(c).name if i < 2 else c for i, c in enumerate(cmd))}")
        rc = subprocess.call(cmd, cwd=str(ROOT))
        print(f"live_day {dt.datetime.now().isoformat(timespec='seconds')}: "
              f"region={region} label={label} exit={rc}")
        if rc != 0:
            nxt = regions[regions.index(region) + 1:]
            print(f"live_day: stopping here - {nxt[0] if nxt else 'chain end'} "
                  f"is chained with && and {region} did not exit 0 (section 4)")
            return rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
