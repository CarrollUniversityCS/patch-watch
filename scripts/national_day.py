#!/usr/bin/env python
"""One live snapshot day for the national extension (waves of states outside the approved arms).

This is live_day.py's sibling, not a change to it: live_day.py still reads only data/wi_frame.csv (a test pins that).
Everything this file adds is a refusal. It runs the same runner, with `--region national`, on the cumulative wave sample
for the wave the PI has released, and only when ALL of these hold:

  * today is a plan snapshot day (live_day.SNAPSHOT_DAYS), before 19:00 Chicago, no logs/abuse.flag, the plan's early
    stop is not met, and no national run has happened today or within MIN_GAP;
  * the wave files re-derive from the master list and seed (national.verify), so the approval list cannot have drifted;
  * the PI released a wave: data/national_active_wave.txt holds 1, 2 or 3 (absent or 0 refuses);
  * the PI confirmed the public notice names the extension: logs/notice_live.txt exists and is not empty;
  * Wisconsin completed today (a finished run with no kill-switch trip), so the primary arm is never crowded out.

It does not set PATCHWATCH_GATE_A; scripts/national_day.cmd supplies it, as live_day.cmd does for the approved arms.

Usage:  python scripts/national_day.py            (today, America/Chicago)
"""
from __future__ import annotations

import datetime as dt
import sqlite3
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "src"))

import live_day as ld

import national

NOTICE_FLAG = ROOT / "logs" / "notice_live.txt"
EXIT_NOT_RELEASED, EXIT_NO_NOTICE, EXIT_WI_NOT_DONE, EXIT_BAD_WAVES, EXIT_NATIONAL_HALTED = 12, 13, 14, 15, 16


def national_halt_since_release() -> str:
    """Describe the latest national run if it halted or never finished AFTER the PI last wrote the wave file, else ''.
    A kill-switch halt leaves no flag, so without this the next day's task would simply run again. Re-releasing the
    wave (writing the wave file again) is the PI's acknowledgement and clears it."""
    if not ld.DB_PATH.exists() or not national.ACTIVE_PATH.exists():
        return ""
    released = national.ACTIVE_PATH.stat().st_mtime
    conn = ld._connect()
    try:
        runs = [r for r in ld._runs(conn) if r[4].get("region") == "national" and not r[4].get("mock")]
    finally:
        conn.close()
    if not runs:
        return ""
    run_id, started, finished, kill, _cfg = runs[-1]
    if ld.parse_utc(started).timestamp() > released and (kill or not finished):
        return f"{run_id} {'halted: ' + kill if kill else 'did not finish'}"
    return ""


def wisconsin_done_today(now: dt.datetime) -> bool:
    if not ld.DB_PATH.exists():
        return False
    conn = ld._connect()
    try:
        for _id, started, finished, kill, config in ld._runs(conn):
            if (config.get("region") == "wisconsin" and finished and not kill and not config.get("mock")
                    and ld.parse_utc(started).astimezone(ld.LOCAL_TZ).date() == now.astimezone(ld.LOCAL_TZ).date()):
                return True
    finally:
        conn.close()
    return False


def refuse(why: str, code: int):
    print(f"national_day {dt.datetime.now().isoformat(timespec='seconds')}: REFUSING - {why}")
    raise SystemExit(code)


def main(argv: list[str]) -> int:
    now = ld.now_local()
    today = now.strftime("%Y%m%d")
    if len(argv) > 1:
        refuse("usage: national_day.py (no arguments; today, America/Chicago)", ld.EXIT_WRONG_DAY)
    if now.date() not in ld.SNAPSHOT_DAYS:
        print(f"national_day {now.isoformat(timespec='seconds')}: SKIPPING - {today} is not a snapshot day; nothing sent")
        return 0
    if now.time() >= ld.LATEST_START:
        refuse(f"it is {now:%H:%M} Chicago time; no live run starts after {ld.LATEST_START:%H:%M}", ld.EXIT_TOO_LATE)
    if ld.ABUSE_FLAG.exists():
        refuse("logs/abuse.flag exists - the study is halted and only Jack clears a halt", ld.EXIT_HALTED)

    wave = national.active_wave()
    if wave < 1:
        refuse("no wave is released (data/national_active_wave.txt is absent or 0); the PI releases each wave",
               EXIT_NOT_RELEASED)
    if not NOTICE_FLAG.exists() or not NOTICE_FLAG.read_text(encoding="utf-8", errors="ignore").strip():
        refuse("logs/notice_live.txt is missing: the PI has not confirmed the public notice names the extension",
               EXIT_NO_NOTICE)
    problems = national.verify()
    if problems:
        refuse("wave files do not verify: " + "; ".join(problems), EXIT_BAD_WAVES)

    try:
        stopped = ld.stop_rule_met()
        wi_done = wisconsin_done_today(now)
        already = ld.prior_run_for("national", now)
        halted = national_halt_since_release()
    except (sqlite3.Error, ValueError) as exc:
        refuse(f"cannot read the run ledger ({exc})", ld.EXIT_CANNOT_CHECK)
    if stopped:
        refuse(f"plan early stop is met: {stopped}", ld.EXIT_STOP_RULE)
    if not wi_done:
        refuse("Wisconsin has not completed a clean snapshot today; the primary arm goes first", EXIT_WI_NOT_DONE)
    if halted:
        refuse(f"the last national run did not complete cleanly ({halted}); re-release the wave to resume", EXIT_NATIONAL_HALTED)
    if already:
        refuse(f"national already snapshotted today or under {ld.MIN_GAP} ago ({already})", ld.EXIT_ALREADY_RAN)

    sample = national.write_sample(wave)
    label = f"NAT_{today}"
    cmd = [sys.executable, "-X", "utf8", str(ld.RUNNER), "--sample", str(sample), "--region", "national", "--label", label]
    print(f"national_day {dt.datetime.now().isoformat(timespec='seconds')}: RUNNING wave<={wave} {label}")
    rc = subprocess.call(cmd, cwd=str(ROOT))
    print(f"national_day {dt.datetime.now().isoformat(timespec='seconds')}: label={label} exit={rc}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
