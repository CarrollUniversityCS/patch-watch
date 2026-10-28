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
already exists in the runbook or the frozen plan, so the worst this file can do is skip a day:

  * it runs only on the plan's snapshot days (SNAPSHOT_DAYS, plan section 6 and
    scripts/cron.disabled); on any other day it exits 0 having sent nothing, so ONE
    recurring daily task can carry the whole schedule and cannot drift into a 23rd run;
  * if a date is given it must be today's date in America/Chicago, else nothing runs; with
    no argument it uses today (a fixed argument on a recurring task refused every later day);
  * nothing starts at or after 19:00 Chicago time (runbook section 5.3), so a catch-up run
    after the machine wakes late cannot spill into the evening;
  * nothing runs once the plan's early-stop rule is met: two consecutive complete Wisconsin
    snapshots with no domain EXPOSED or on an end-of-life branch (plan section 6; EOL counts
    as exposed by PI decision 2026-10-28, section 12);
  * nothing runs if logs/abuse.flag exists (section 2.1: a halt is a stop, not a bug);
  * nothing runs for a region that already ran on today's Chicago date, or less than
    MIN_GAP (12 h) ago (section 2.5: one live snapshot per region per day, enforced in code
    rather than by trusting that only one scheduled task existed);
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

Usage:  python scripts/live_day.py            (today, America/Chicago)
        python scripts/live_day.py 20261029   (must equal today)
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
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "wi_frame.csv"
DB_PATH = ROOT / "data" / "study.db"
ABUSE_FLAG = ROOT / "logs" / "abuse.flag"
RUNNER = ROOT / "scripts" / "run_snapshot.py"

# The schedule's clock (plan section 6: 09:00 America/Chicago). Named, not the machine's
# local zone, so a host set to another zone cannot shift the calendar day.
LOCAL_TZ = ZoneInfo("America/Chicago")


def _days(first: dt.date, last: dt.date) -> tuple[dt.date, ...]:
    return tuple(first + dt.timedelta(days=i) for i in range((last - first).days + 1))


# Plan section 6 / scripts/cron.disabled: daily S1 .. day 14, then days 21, 28, 45, 60, 90.
SNAPSHOT_DAYS: frozenset[dt.date] = frozenset(
    _days(dt.date(2026, 10, 23), dt.date(2026, 11, 4))
    + (dt.date(2026, 11, 11), dt.date(2026, 11, 18), dt.date(2026, 12, 5),
       dt.date(2026, 12, 20), dt.date(2027, 1, 19)))
LATEST_START = dt.time(19, 0)               # runbook section 5.3: never start after 19:00
MIN_GAP = dt.timedelta(hours=12)            # floor between two runs of one region

# Plan section 6 early stop. Classes that keep the study running: below the fixed release,
# or on a branch with no official fix (EOL counts as exposed, PI decision 2026-10-28).
STILL_EXPOSED_CLASSES = ("VULNERABLE_BY_VERSION", "EOL_UNFIXED")
STOP_RULE_REGION = "wisconsin"
STOP_RULE_RUNS = 2

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
EXIT_TOO_LATE, EXIT_STOP_RULE = 10, 11      # after 19:00; plan section 6 early stop met


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


def now_local() -> dt.datetime:
    return dt.datetime.now(LOCAL_TZ)


def _runs(conn: sqlite3.Connection) -> list[tuple[str, str, str | None, str | None, dict]]:
    """(run_id, started, finished, kill_switch, config) for every run, oldest first.

    Raises so the caller refuses rather than guessing: an unreadable ledger cannot
    prove anything about earlier runs.
    """
    out = []
    for run_id, started, finished, kill, config_json in conn.execute(
            "SELECT run_id, started_at_utc, finished_at_utc, kill_switch, config_json "
            "FROM runs ORDER BY started_at_utc"):
        if not started:
            continue
        if not (config_json or "").strip():
            raise ValueError(f"run {run_id} has no region in config_json")
        try:
            config = json.loads(config_json)
            config.get("region")
        except (json.JSONDecodeError, AttributeError):
            raise ValueError(f"run {run_id} has unreadable config_json")
        out.append((run_id, started, finished, kill, config))
    return out


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(f"file:{DB_PATH.as_posix()}?mode=ro", uri=True)


def prior_run_for(region: str, now: dt.datetime) -> str:
    """Describe a same-region run on today's Chicago date or within MIN_GAP, or ''.

    The calendar day is what section 2.5 promises ("one per region per day"). The old
    rolling-24 h check ate the 2026-10-27 snapshot (an off-schedule 16:52 run the day
    before) and balanced every scheduled day on seconds; MIN_GAP keeps a late-evening
    run and an early-morning run from landing back to back across midnight.
    """
    if not DB_PATH.exists():
        return ""                                     # no database yet = no prior run
    conn = _connect()
    try:
        runs = _runs(conn)
    finally:
        conn.close()
    for run_id, started, _fin, _kill, config in runs:
        if config.get("region") != region:
            continue
        at = parse_utc(started)
        if at.astimezone(LOCAL_TZ).date() == now.astimezone(LOCAL_TZ).date() or now - at < MIN_GAP:
            return f"run_id={run_id} started_at_utc={started}"
    return ""


def stop_rule_met() -> str:
    """Plan section 6 early stop: describe it if met, else ''.

    Met when the last STOP_RULE_RUNS complete Wisconsin snapshots (finished, no kill-switch
    trip, not mock) each have no observation in STILL_EXPOSED_CLASSES. Halted or unfinished
    runs are not snapshots and do not count either way.
    """
    if not DB_PATH.exists():
        return ""
    conn = _connect()
    try:
        complete = [r for r in _runs(conn)
                    if r[4].get("region") == STOP_RULE_REGION and r[2] and not r[3]
                    and not r[4].get("mock")]
        last = complete[-STOP_RULE_RUNS:]
        if len(last) < STOP_RULE_RUNS:
            return ""
        marks = ",".join("?" * len(STILL_EXPOSED_CLASSES))
        for run_id, *_ in last:
            (n,) = conn.execute(
                f"SELECT COUNT(*) FROM observations WHERE run_id = ? AND class IN ({marks})",
                (run_id, *STILL_EXPOSED_CLASSES)).fetchone()
            if n:
                return ""
    finally:
        conn.close()
    return ("no Wisconsin domain was EXPOSED or EOL in the last "
            f"{STOP_RULE_RUNS} complete snapshots ({', '.join(r[0] for r in last)})")


def main(argv: list[str]) -> int:
    now = now_local()
    today = now.strftime("%Y%m%d")
    if len(argv) > 2 or (len(argv) == 2 and (len(argv[1]) != 8 or not argv[1].isdigit())):
        refuse("usage: live_day.py [YYYYMMDD]  (omit for today, America/Chicago)",
               EXIT_WRONG_DAY)
    day = argv[1] if len(argv) == 2 else today
    if day != today:
        refuse(f"this task is dated {day} but today is {today}; running would break "
               f"one-snapshot-per-region-per-day (section 2.5)", EXIT_WRONG_DAY)

    if now.date() not in SNAPSHOT_DAYS:
        print(f"live_day {now.isoformat(timespec='seconds')}: SKIPPING - {today} is not a "
              f"snapshot day (plan section 6); nothing sent")
        return 0
    if now.time() >= LATEST_START:
        refuse(f"it is {now:%H:%M} Chicago time; no live run starts after "
               f"{LATEST_START:%H:%M} (section 5.3). Today is a missed day - tell Jack",
               EXIT_TOO_LATE)

    if not SAMPLE.exists():
        refuse(f"no frame at {SAMPLE.relative_to(ROOT)} "
               f"(python src/wi_frame.py build --comparison MN,IL,MI,IA --skip-download)",
               EXIT_NO_FRAME)
    if ABUSE_FLAG.exists():
        refuse("logs/abuse.flag exists - the study is halted and only Jack clears a halt "
               "(section 2.1)", EXIT_HALTED)

    try:
        stopped = stop_rule_met()
    except (sqlite3.Error, ValueError) as exc:
        refuse(f"cannot check the plan's early-stop rule ({exc})", EXIT_CANNOT_CHECK)
    if stopped:
        refuse(f"plan section 6 early stop is met: {stopped}. Both regions stop; "
               f"message Jack", EXIT_STOP_RULE)

    regions = selected_regions()            # may be a held subset; refuses if unparseable

    for region in regions:
        label = f"{LABEL_PREFIX[region]}_{day}"
        already = ""
        try:
            already = prior_run_for(region, now)
        except (sqlite3.Error, ValueError) as exc:
            refuse(f"cannot verify whether {region} already ran today ({exc}); "
                   f"refusing rather than risking a second run (section 2.5)",
                   EXIT_CANNOT_CHECK)
        if already:
            refuse(f"{region} already snapshotted today or under {MIN_GAP} ago "
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
