# Hermes update, 2026-10-28: do not miss a snapshot day

**Goal.** Every snapshot day gets its Wisconsin run. Days 2026-10-25 and 2026-10-27 have
no Wisconsin run, and a missed day can never be recovered: the plan forbids running a
missed day on a later date. This update replaces how the schedule runs and adds checks
whose only job is to catch a missed day while it can still be saved (before 19:00
Chicago time).

Read this together with `docs/HERMES_RUNBOOK.md`. Where they differ, this file and the
updated runbook (§4, §5.3) win. Every hard limit in runbook §2 still applies.

## Why days were missed

1. **The task carried a fixed date.** `live_day.py` required a date argument and refused
   any date that was not today. A recurring task created with one date refused every
   later day (exit 4).
2. **The guard used a rolling 24 hours.** The off-schedule run on 2026-10-26 at 16:52
   made the guard refuse the scheduled 2026-10-27 09:00 run, which was only 16 h later
   (exit 7).
3. **Nothing caught up.** If the machine was asleep or off at 09:00, the day was lost.
4. **Nobody noticed in time.** A refusal goes only to `logs\cron.out`, and no check
   looked for it before the 19:00 cut-off.

## What changed (commit `9dac6cc`)

- **One recurring Windows task, `patch-watch live day`,** runs `scripts\live_day.cmd`
  with **no argument** every day at 09:00. If 09:00 is missed it starts as soon as the
  machine is awake, and it wakes the machine to run. Jack installs it once with
  `scripts\install_schedule.ps1`, which also removes any older dated tasks.
- **`live_day.py` decides everything in code:**
  - it runs only on the plan's snapshot days: daily to 2026-11-04, then 11-11, 11-18,
    12-05, 12-20 and 2027-01-19 (18 days);
  - "today" means today in America/Chicago;
  - one run per region per Chicago calendar day, at least 12 h apart;
  - no start at or after 19:00 Chicago time;
  - it stops for good once the plan's §6 early-stop rule is met (below).
- **Early-stop rule (plan §6), now enforced.** Collection stops once two consecutive
  complete Wisconsin snapshots have no domain below the fixed version **and** no domain
  on an end-of-life PHP branch. EOL counts as exposed by Jack's decision (plan §12,
  2026-10-28). The rule is not met today: 10 EOL domains remain.

## Exit codes in `logs\cron.out`

Every invocation writes one `live_day <time>:` line. Find today's.

| Line / exit | Meaning | What you do |
|---|---|---|
| `RUNNING ...` then `exit=0` | Snapshot taken | Post-run check as usual |
| `SKIPPING - ... not a snapshot day` (exit 0) | Not a plan day; nothing sent | Nothing |
| `exit=2` after `RUNNING` | Kill-switch or audit halt | Runbook §5.1. Never re-run |
| exit 4 `this task is dated ...` | Something passed an old date | Task is misconfigured: message Jack now |
| exit 5 `no frame` | `data\wi_frame.csv` missing | Runbook §6 fix, then the missed-day step below |
| exit 6 `abuse.flag exists` | Study halted | Do nothing. Only Jack clears it |
| exit 7 `already snapshotted today` | A run already happened today | Nothing; confirm the earlier run in `runs_today` |
| exit 8 `cannot verify` / `cannot check` | Database unreadable | Message Jack now |
| exit 9 `PATCHWATCH_REGIONS=...` | `live_day.cmd` region line broken | Message Jack now |
| exit 10 `no live run starts after 19:00` | Machine woke too late; the day is lost | Message Jack (missed day) |
| exit 11 `plan section 6 early stop is met` | The study's planned end | Message Jack. Do not try to restart |

## New checks, every day

All checks use `scripts\pw_probe.py` and `Get-ScheduledTask`; no `python -c`.

**08:30, pre-run (replaces runbook §5 check 7).**
- Run `Get-ScheduledTask -TaskName "patch-watch live day" | Get-ScheduledTaskInfo`.
- The task must exist, be **Ready** (not Disabled), and show a `NextRunTime` of today
  09:00 or earlier.
- If it is missing or disabled and no halt explains it: message Jack **immediately**.
  Do not create the task yourself.

**09:45, "did it start?" check (new).**
- Run `.venv\Scripts\python.exe -X utf8 scripts\pw_probe.py runs_today`.
- **A WI run row exists:** fine. Continue to the post-run check.
- **No row:** read today's lines in `logs\cron.out`.
  - **A REFUSING line:** act on it from the exit-code table.
  - **SKIPPING:** nothing to do.
  - **No line at all:** the task did not fire. Go to the missed-day step.

**Missed-day step (before 19:00 Chicago only).**
- Run `scripts\live_day.cmd` **once**, with no argument. This is runbook §5.3's single
  hand run.
- It is safe to run because `live_day.py` refuses a second run, a wrong day and anything
  after 19:00.
- Then do the post-run check and tell Jack the day was caught up by hand, and why.
- If it refuses, act on the exit code. Never run it twice in a day.
- Never pass a date. Never run a missed day on a later date.

**11:30, post-run check:** unchanged (runbook §5).

**18:00, last-chance check (new).**
- Repeat the 09:45 check.
- If a snapshot day still has no WI run row and no refusal that explains it, run the
  missed-day step now. After 19:00 it is lost: message Jack that the day was missed,
  with the `cron.out` lines.

## Jack's one-time actions before 2026-10-29 09:00

1. Get commit `9dac6cc` onto the collecting machine. It is on branch
   `claude/brave-ramanujan-yl8b4y`, not `main`, so merge or pull it. Keep your local
   `LIVE_REQUESTS_ENABLED = True` in `src\config.py`.
2. Run `powershell -ExecutionPolicy Bypass -File scripts\install_schedule.ps1`.
3. Confirm the machine's time zone is Central, so that 09:00 means 09:00 Central.
4. Run `Get-ScheduledTask -TaskName "patch-watch live day" | Get-ScheduledTaskInfo`.
   `NextRunTime` should be 2026-10-29 09:00.
5. In Power Options, allow wake timers so `WakeToRun` works. Leave the machine plugged
   in, or at least not shut down.

2026-10-29 is the federal KEV deadline for PHP2Shell, so that snapshot matters more than
most.

## What has not changed

- Gate A: still `LIVE_REQUESTS_ENABLED` plus `PATCHWATCH_GATE_A` set in `live_day.cmd`.
- The kill switch, the request limits, the blocklist and the comparison hold
  (`PATCHWATCH_REGIONS=wisconsin`).
- Runbook §2. You still never edit code, tests, `config.py` or the plan.
- Two items from earlier are still open:
  - the deviation rows for the off-schedule 2026-10-26 run are drafted but not yet in
    plan §12;
  - the prose still says a 50-outcome kill-switch window while the code uses 200.
