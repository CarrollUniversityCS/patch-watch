#!/usr/bin/env python
"""Standalone daily checks for the live schedule, and the local patch-watch hub page.

Why this file exists. The 08:30 / 09:45 / 11:30 / 18:00 checks in docs/HERMES_RUNBOOK.md
section 5 and docs/HERMES_UPDATE_2026-10-28.md were run by the Hermes agent. They are
mechanical, so they now run as plain Windows scheduled tasks (scripts/install_checks.ps1)
with no model in the loop. Hermes keeps only the jobs that need judgement: the opt-out
inbox and the weekly oversight audit.

Every check writes its result to logs/hub/checks/<date>_<check>.json and rebuilds
logs/hub/index.html, a local status page for all scheduled jobs. logs/ is gitignored, so
nothing here is ever published (hard rule 7).

    .venv\\Scripts\\python.exe -X utf8 scripts\\pw_checks.py prerun|started|postrun|lastchance|build

What a check may change, and nothing else:
  * started / lastchance: on a snapshot day with no run and no line in logs/cron.out (the
    task never fired), before 19:00, start the existing "patch-watch live day" task ONCE
    (the update doc's missed-day step). live_day.py still refuses a second run, a wrong
    day, a halt and anything after 19:00. A disabled task is never re-enabled.
  * postrun: on a halt (kill switch, audit violation, ALERT file) disable the live task,
    because a kill-switch halt leaves no flag and tomorrow would otherwise run (section
    5.1). Only Jack re-enables it. Then run the section 5.4 backup.
No check commits, pushes, clears a flag or edits code.

Exit codes: 0 = no failures, 2 = at least one check failed (a toast is shown).
"""
from __future__ import annotations

import datetime as dt
import html
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "study.db"
LOGS = ROOT / "logs"
CRON_OUT = LOGS / "cron.out"
ABUSE_FLAG = LOGS / "abuse.flag"
RUN_LOCK = LOGS / "run.lock"
REPORTS = ROOT / "reports"
BACKUPS = ROOT / "backups"
HUB = LOGS / "hub"
CHECKS = HUB / "checks"
PY = ROOT / ".venv" / "Scripts" / "python.exe"
HERMES_JOBS = (Path(os.environ.get("LOCALAPPDATA", "")) / "hermes" / "profiles"
               / "patch-watch-agent" / "cron" / "jobs.json")

_spec = importlib.util.spec_from_file_location("live_day", ROOT / "scripts" / "live_day.py")
live_day = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(live_day)
SNAPSHOT_DAYS = sorted(live_day.SNAPSHOT_DAYS)
CHI = live_day.LOCAL_TZ
LATEST_START = live_day.LATEST_START

LIVE_TASK = "patch-watch live day"
EXPECTED_ASN = "AS40379"
MIN_FREE_GB = 2
CHECK_NAMES = {"prerun": "08:30 pre-run", "started": "09:45 did it start?",
               "postrun": "11:30 post-run", "lastchance": "18:00 last chance"}
RANK = {"ok": 0, "info": 0, "warn": 1, "fail": 2}
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass
class Result:
    name: str
    status: str            # ok | info | warn | fail
    detail: str


# ---------------------------------------------------------------- helpers
def now_local() -> dt.datetime:
    return dt.datetime.now(CHI)


def run(cmd: list[str], timeout: int = 120, env: dict | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, env=env, creationflags=NO_WINDOW)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, f"{type(exc).__name__}: {exc}"


def ps(script: str, timeout: int = 60) -> tuple[int, str]:
    return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout)


def tasks() -> list[dict]:
    """Every patch-watch Windows task, read with Get-ScheduledTask (read-only)."""
    rc, out = ps(
        "$ErrorActionPreference='SilentlyContinue';"
        "@(Get-ScheduledTask | Where-Object { $_.TaskName -like 'patch-watch*' -or $_.TaskName -like 'PW_*' }"
        " | ForEach-Object { $i = $_ | Get-ScheduledTaskInfo; [pscustomobject]@{"
        " name=$_.TaskName; state=[string]$_.State;"
        " next=$(if ($i.NextRunTime) { $i.NextRunTime.ToString('yyyy-MM-dd HH:mm') } else { '' });"
        " last=$(if ($i.LastRunTime -and $i.LastRunTime.Year -gt 2000) { $i.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { '' });"
        " result=$i.LastTaskResult } }) | ConvertTo-Json -Compress")
    if rc != 0 or not out.strip():
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def cron_lines(day: dt.date) -> list[str]:
    """Today's timestamped live_day lines from logs/cron.out."""
    if not CRON_OUT.exists():
        return []
    prefix = f"live_day {day.isoformat()}T"
    return [ln.rstrip() for ln in CRON_OUT.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.startswith(prefix)]


def db_runs(label_like: str = "%") -> list[sqlite3.Row]:
    if not DB.exists():
        return []
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        return con.execute(
            "SELECT run_id, snapshot_label, started_at_utc, finished_at_utc, attempted, responded,"
            " errors, sends, kill_switch, config_json FROM runs WHERE snapshot_label LIKE ?"
            " ORDER BY started_at_utc", (label_like,)).fetchall()
    finally:
        con.close()


def is_mock(row: sqlite3.Row) -> bool:
    try:
        return bool(json.loads(row["config_json"] or "{}").get("mock"))
    except ValueError:
        return False


def wi_runs(day: dt.date) -> list[sqlite3.Row]:
    return [r for r in db_runs(f"WI_{day:%Y%m%d}") if not is_mock(r)]


def day_state(day: dt.date, now: dt.datetime) -> tuple[str, str]:
    """(state, detail) of one snapshot day's Wisconsin run, from the database and cron.out."""
    rows = wi_runs(day)
    if rows:
        r = rows[-1]
        if r["kill_switch"]:
            return "halted", f"{r['run_id']}: {r['kill_switch']}"
        if not r["finished_at_utc"]:
            return "running", f"{r['run_id']} has no finish time yet"
        return "captured", (f"{r['run_id']}: attempted {r['attempted']}, responded "
                            f"{r['responded']}, errors {r['errors']}")
    lines = cron_lines(day)
    refusals = [ln for ln in lines if "REFUSING" in ln]
    if any("SKIPPING" in ln for ln in lines):
        return "skipped", lines[-1]
    if any("RUNNING" in ln for ln in lines) and not any(" exit=" in ln for ln in lines):
        return "running", "live_day started; no exit line yet"
    if refusals:
        return "refused", refusals[-1]
    if day > now.date() or (day == now.date() and now.time() < dt.time(9, 0)):
        return "planned", ""
    if day == now.date() and now.time() < LATEST_START:
        return "pending", "no run and no cron.out line yet today"
    return "missed", "no run row and no cron.out line"


def latest_check(day: dt.date, name: str) -> dict | None:
    p = CHECKS / f"{day.isoformat()}_{name}.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def notify(title: str, body: str) -> None:
    """Best-effort Windows toast. A failure here never fails a check."""
    t, b = (s.replace("'", "''")[:240] for s in (title, body))
    ps("[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null;"
       "$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
       f"$n = $x.GetElementsByTagName('text'); $n.Item(0).InnerText = '{t}'; $n.Item(1).InnerText = '{b}';"
       "$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe';"
       "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))",
       timeout=30)


# ---------------------------------------------------------------- the checks
def check_prerun(now: dt.datetime) -> list[Result]:
    out: list[Result] = []
    today = now.date()
    snap = today in live_day.SNAPSHOT_DAYS
    out.append(Result("Snapshot day", "info", "yes" if snap else "no - live_day.py will skip today"))

    try:
        with urllib.request.urlopen("https://ipinfo.io/org", timeout=25) as resp:
            org = resp.read().decode("utf-8", "replace").strip()
        out.append(Result("Egress network", "ok" if EXPECTED_ASN in org else "warn", org))
    except OSError as exc:
        out.append(Result("Egress network", "warn", f"could not reach ipinfo.io: {exc}"))

    rc, cfg = run(["git", "diff", "--", "src/config.py"])
    rc2, st = run(["git", "status", "--porcelain"])
    gate_on = "+LIVE_REQUESTS_ENABLED = True" in cfg
    others = [ln for ln in st.splitlines() if not ln.endswith("src/config.py")]
    out.append(Result("Gate A flag (working tree)", "ok" if gate_on else "fail",
                      "LIVE_REQUESTS_ENABLED = True locally" if gate_on else
                      "src/config.py does not set LIVE_REQUESTS_ENABLED = True - the 09:00 run will refuse"))
    if others:
        out.append(Result("Other local changes", "info", "; ".join(ln.strip() for ln in others)))

    rc, txt = run([str(PY), "-X", "utf8", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--deselect",
                   "tests/test_fetch_rules.py::test_gate_a_is_closed_in_this_checkout"], timeout=900)
    tail = txt.splitlines()[-1] if txt else "(no output)"
    out.append(Result("Test suite", "ok" if rc == 0 else "fail", tail))

    env = {**os.environ, "PATCHWATCH_GATE_A": "APPROVED"}
    rc, txt = run([str(PY), "-X", "utf8", "src/pipeline.py", "--preflight-only",
                   "--sample", "data/wi_frame.csv", "--region", "wisconsin"], env=env)
    out.append(Result("Preflight (wisconsin, sends nothing)", "ok" if rc == 0 else "fail", txt[-400:]))

    out += halt_files(today)

    free = shutil.disk_usage(ROOT).free / 1e9
    out.append(Result("Disk free", "ok" if free >= MIN_FREE_GB else "fail", f"{free:,.0f} GB"))
    backups = sorted(BACKUPS.glob("study_*.db"), key=lambda p: p.stat().st_mtime)
    out.append(Result("Latest backup", "ok" if backups else "warn",
                      f"{backups[-1].name}" if backups else "no backups/study_*.db yet"))

    out.append(live_task_result(today, snap))
    return out


def halt_files(today: dt.date) -> list[Result]:
    out = [Result("abuse.flag", "fail" if ABUSE_FLAG.exists() else "ok",
                  "present - study halted; only Jack clears it" if ABUSE_FLAG.exists() else "absent")]
    lock = RUN_LOCK.exists()
    out.append(Result("run.lock", "warn" if lock else "ok",
                      "present - a run is going, or a crash left it behind" if lock else "absent"))
    fresh = [p.name for p in REPORTS.glob("ALERT_*.md")
             if dt.date.fromtimestamp(p.stat().st_mtime) >= today - dt.timedelta(days=1)]
    out.append(Result("New ALERT reports", "fail" if fresh else "ok", ", ".join(fresh) or "none since yesterday"))
    return out


def live_task_result(today: dt.date, snap: bool) -> Result:
    t = next((x for x in tasks() if x["name"] == LIVE_TASK), None)
    if not t:
        return Result("Live task", "fail", f"'{LIVE_TASK}' is missing - run scripts/install_schedule.ps1")
    if t["state"] == "Disabled":
        return Result("Live task", "fail", "Disabled (a halt pause, or someone paused it) - only Jack re-enables")
    when = f"next {t['next'] or '-'}, last {t['last'] or '-'}"
    due = t["next"].startswith(today.isoformat()) or t["last"].startswith(today.isoformat())
    if snap and not due and not wi_runs(today):
        return Result("Live task", "fail", f"{t['state']} but not due today: {when}")
    return Result("Live task", "ok", f"{t['state']}, {when}")


def check_started(now: dt.datetime, last_chance: bool) -> list[Result]:
    today = now.date()
    if today not in live_day.SNAPSHOT_DAYS:
        return [Result("Snapshot day", "info", "no - nothing should run today")]
    state, detail = day_state(today, now)
    if state == "captured":
        return [Result("Wisconsin run today", "ok", detail)]
    if state == "halted":
        return [Result("Wisconsin run today", "fail", f"HALTED - {detail}. The post-run check pauses the schedule.")]
    if state == "running":
        if last_chance and not RUN_LOCK.exists():
            return [Result("Wisconsin run today", "fail", f"unfinished with no run.lock - likely a crash after "
                                                          f"traffic went out; do not re-run ({detail})")]
        return [Result("Wisconsin run today", "warn", f"in progress: {detail}")]
    if state == "skipped":
        return [Result("Wisconsin run today", "info", detail)]
    if state == "refused":
        return [Result("Wisconsin run today", "fail", f"live_day refused: {detail}")]
    return [catch_up(now)]


def catch_up(now: dt.datetime) -> Result:
    """The update doc's missed-day step: start the existing live task once, before 19:00."""
    today = now.date()
    marker = CHECKS / f"{today.isoformat()}_catchup.json"
    if marker.exists():
        return Result("Missed-day catch-up", "fail",
                      f"already started once today ({json.loads(marker.read_text())['at']}) and still "
                      f"no run - not starting it again")
    if now.time() >= LATEST_START:
        return Result("Missed-day catch-up", "fail", "no run today and it is after 19:00 - the day is lost")
    if ABUSE_FLAG.exists():
        return Result("Missed-day catch-up", "fail", "no run, and abuse.flag is present - not starting anything")
    rc, txt = ps(f"Start-ScheduledTask -TaskName '{LIVE_TASK}' -ErrorAction Stop")
    if rc != 0:
        return Result("Missed-day catch-up", "fail", f"the task never fired and could not be started: {txt[-300:]}")
    CHECKS.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"at": now.isoformat(timespec="seconds")}), encoding="utf-8")
    return Result("Missed-day catch-up", "warn",
                  f"no run and no cron.out line today: started '{LIVE_TASK}' once at {now:%H:%M}")


def check_postrun(now: dt.datetime) -> list[Result]:
    today = now.date()
    if today not in live_day.SNAPSHOT_DAYS:
        return [Result("Snapshot day", "info", "no - nothing to check")]
    out: list[Result] = []
    rows = wi_runs(today)
    exits = [ln for ln in cron_lines(today) if f"label=WI_{today:%Y%m%d} exit=" in ln]
    halted = False
    if not rows:
        state, detail = day_state(today, now)
        out.append(Result("Wisconsin run today", "warn" if state in ("pending", "running") else "fail",
                          f"no run row yet ({state}: {detail}); the 18:00 check tries again"))
    else:
        r = rows[-1]
        report = REPORTS / f"run_{r['run_id']}.md"
        alert = REPORTS / f"ALERT_{r['run_id']}.md"
        text = report.read_text(encoding="utf-8", errors="replace") if report.exists() else ""
        clean = "No violations found" in text
        halted = bool(r["kill_switch"]) or alert.exists() or any(ln.endswith("exit=2") for ln in exits)
        if halted:
            why = r["kill_switch"] or (alert.name if alert.exists() else "exit 2")
            out.append(Result("Wisconsin run today", "fail", f"HALT: {why}"))
        elif not r["finished_at_utc"]:
            out.append(Result("Wisconsin run today", "warn", f"{r['run_id']} still running"))
        else:
            out.append(Result("Wisconsin run today", "ok",
                              f"{r['run_id']}: attempted {r['attempted']}, responded {r['responded']}, "
                              f"errors {r['errors']}, sends {r['sends']}"))
        out.append(Result("Run report safety audit", "ok" if clean else "fail",
                          "No violations found" if clean else f"{report.name} missing or audit not clean"))
    if exits:
        out.append(Result("cron.out exit line", "ok" if exits[-1].endswith("exit=0") else "fail", exits[-1]))

    if halted:
        rc, txt = ps(f"Disable-ScheduledTask -TaskName '{LIVE_TASK}' -ErrorAction Stop | Out-Null")
        out.append(Result("Schedule paused (section 5.1)", "fail",
                          "live task DISABLED; only Jack re-enables it" if rc == 0 else
                          f"could not disable the live task - pause it by hand: {txt[-200:]}"))
    elif rows and rows[-1]["finished_at_utc"]:
        rc, txt = run([str(PY), "-X", "utf8", "scripts/backup_now.py"], timeout=600)
        status = "ok" if rc == 0 else "warn" if rc == 3 else "fail"
        note = " (no off-machine copy: PATCHWATCH_BACKUP_DIR unset)" if rc == 3 else ""
        out.append(Result("Backup (section 5.4)", status, (txt.splitlines() or [""])[-1][:300] + note))

    rc, st = run(["git", "status", "--porcelain", "--", "reports"])
    pending = [ln[3:] for ln in st.splitlines() if "run_" in ln or "ALERT_" in ln]
    out.append(Result("Run reports not yet committed", "info",
                      f"{len(pending)} file(s); commit and push stay manual" if pending else "none"))
    return out


CHECKS_FN = {"prerun": lambda n: check_prerun(n), "started": lambda n: check_started(n, False),
             "postrun": lambda n: check_postrun(n), "lastchance": lambda n: check_started(n, True)}


def run_check(name: str) -> int:
    started = now_local()
    try:
        results = CHECKS_FN[name](started)
    except Exception as exc:  # a broken check must still show up on the hub
        results = [Result("Check crashed", "fail", f"{type(exc).__name__}: {exc}")]
    overall = {2: "fail", 1: "warn", 0: "ok"}[max((RANK[r.status] for r in results), default=0)]
    record = {"check": name, "title": CHECK_NAMES[name], "started": started.isoformat(timespec="seconds"),
              "finished": now_local().isoformat(timespec="seconds"), "overall": overall,
              "results": [asdict(r) for r in results]}
    CHECKS.mkdir(parents=True, exist_ok=True)
    (CHECKS / f"{started.date().isoformat()}_{name}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    build_hub()
    if overall == "fail":
        bad = "; ".join(f"{r.name}: {r.detail}" for r in results if r.status == "fail")
        notify(f"patch-watch {CHECK_NAMES[name]}: FAIL", bad)
    return 2 if overall == "fail" else 0


# ---------------------------------------------------------------- the hub page
STATE_CLASS = {"captured": "ok", "skipped": "info", "planned": "muted", "pending": "info",
               "running": "warn", "halted": "fail", "refused": "fail", "missed": "fail",
               "ok": "ok", "info": "info", "warn": "warn", "fail": "fail"}


def _pill(text: str, cls: str) -> str:
    return f'<span class="pill {STATE_CLASS.get(cls, cls)}">{html.escape(text)}</span>'


def hermes_jobs() -> list[dict]:
    try:
        return json.loads(HERMES_JOBS.read_text(encoding="utf-8")).get("jobs", [])
    except (OSError, ValueError):
        return []


def _short(stamp: str | None) -> str:
    return (stamp or "")[:16].replace("T", " ")


def build_hub() -> Path:
    now = now_local()
    today = now.date()
    e = html.escape

    # Banner
    if ABUSE_FLAG.exists():
        banner = ("fail", "HALTED: logs/abuse.flag is present. Only Jack clears it.")
    elif RUN_LOCK.exists():
        banner = ("warn", "A live snapshot is running now (logs/run.lock present).")
    else:
        live = next((t for t in tasks() if t["name"] == LIVE_TASK), None)
        if live is None:
            banner = ("fail", f"'{LIVE_TASK}' task is missing.")
        elif live["state"] == "Disabled":
            banner = ("fail", "The live schedule is PAUSED (task disabled).")
        else:
            nxt = next((d for d in SNAPSHOT_DAYS if d > today or (d == today and day_state(d, now)[0] in ("planned", "pending"))), None)
            banner = ("ok", f"Schedule armed. Next snapshot: {nxt.isoformat() if nxt else 'none - plan complete'}.")

    # Timeline
    cells = []
    counts: dict[str, int] = {}
    for i, d in enumerate(SNAPSHOT_DAYS, 1):
        state, detail = day_state(d, now)
        counts[state] = counts.get(state, 0) + 1
        cells.append(f'<li class="day {STATE_CLASS[state]}{" today" if d == today else ""}" title="{e(detail)}">'
                     f'<span class="n">{i}</span><span class="d">{d:%b %d}</span><span class="s">{e(state)}</span></li>')
    summary = " · ".join(f"{k} {v}" for k, v in sorted(counts.items()))

    # Today's checks
    cards = []
    for key, title in CHECK_NAMES.items():
        rec = latest_check(today, key)
        if not rec:
            cards.append(f'<section class="card"><h3>{e(title)}</h3><p class="muted">Not run yet today.</p></section>')
            continue
        rows = "".join(f'<tr><td>{_pill(r["status"], r["status"])}</td><td>{e(r["name"])}</td>'
                       f'<td class="detail">{e(r["detail"])}</td></tr>' for r in rec["results"])
        cards.append(f'<section class="card"><h3>{e(title)} {_pill(rec["overall"], rec["overall"])}</h3>'
                     f'<p class="muted">ran {e(_short(rec["started"]))}</p><table>{rows}</table></section>')

    # Scheduled jobs: Windows tasks + Hermes jobs
    job_rows = []
    for t in sorted(tasks(), key=lambda x: x["name"]):
        res = t.get("result")
        res_txt = "never run" if res == 267011 else "running" if res == 267009 else f"exit {res}"
        cls = "fail" if t["state"] == "Disabled" else "ok" if res in (0, 267011, 267009) else "warn"
        job_rows.append(f"<tr><td>{e(t['name'])}</td><td>Windows</td><td>{_pill(t['state'], cls)}</td>"
                        f"<td>{e(t['last'] or '-')}</td><td>{e(res_txt)}</td><td>{e(t['next'] or '-')}</td></tr>")
    for j in hermes_jobs():
        st = "Ready" if j.get("enabled") and j.get("state") == "scheduled" else (j.get("state") or "?")
        cls = "ok" if st == "Ready" else "warn"
        job_rows.append(f"<tr><td>{e(j.get('name', ''))}</td><td>Hermes</td><td>{_pill(st, cls)}</td>"
                        f"<td>{e(_short(j.get('last_run_at')))}</td><td>{e(j.get('last_status') or '-')}</td>"
                        f"<td>{e(_short(j.get('next_run_at')))}</td></tr>")

    # Run history (live runs only, aggregate counts)
    run_rows = []
    for r in reversed([r for r in db_runs() if not is_mock(r)]):
        ks = r["kill_switch"]
        run_rows.append(f"<tr><td>{e(r['snapshot_label'] or '')}</td><td>{e(_short(r['started_at_utc']))} UTC</td>"
                        f"<td>{r['attempted'] or 0}</td><td>{r['responded'] or 0}</td><td>{r['errors'] or 0}</td>"
                        f"<td>{_pill('halted', 'fail') if ks else _pill('clean', 'ok') if r['finished_at_utc'] else _pill('unfinished', 'warn')}</td></tr>")

    cron_tail = []
    if CRON_OUT.exists():
        cron_tail = [ln for ln in CRON_OUT.read_text(encoding="utf-8", errors="replace").splitlines()
                     if ln.startswith("live_day")][-12:]

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="120"><title>Patch Watch Hub</title>
<style>
:root {{ --bg:#f7f7f5; --panel:#fff; --ink:#1d1d1b; --muted:#6b6b66; --line:#e3e2dc;
  --ok:#1f7a4d; --okbg:#e3f3ea; --warn:#8a5a00; --warnbg:#fbf0d9; --fail:#a8261b; --failbg:#fbe4e1;
  --info:#2a5d9f; --infobg:#e3ecf8; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ --bg:#161615; --panel:#1f1f1d; --ink:#ecebe6;
  --muted:#9a9993; --line:#33332f; --ok:#6fd19c; --okbg:#173326; --warn:#f0c46b; --warnbg:#3a2e14;
  --fail:#ff8a7e; --failbg:#40201c; --info:#8fb6ee; --infobg:#1b2a40; }} }}
* {{ box-sizing:border-box }} body {{ margin:0; background:var(--bg); color:var(--ink);
  font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif }}
main {{ max-width:1180px; margin:0 auto; padding:20px 16px 48px }}
h1 {{ font-size:22px; margin:0 }} h2 {{ font-size:15px; margin:28px 0 10px; text-transform:uppercase;
  letter-spacing:.06em; color:var(--muted) }} h3 {{ font-size:15px; margin:0 0 2px }}
.top {{ display:flex; justify-content:space-between; align-items:baseline; gap:12px; flex-wrap:wrap }}
.muted {{ color:var(--muted); margin:0 0 8px }}
.banner {{ margin-top:14px; padding:12px 14px; border-radius:8px; font-weight:600 }}
.banner.ok {{ background:var(--okbg); color:var(--ok) }} .banner.warn {{ background:var(--warnbg); color:var(--warn) }}
.banner.fail {{ background:var(--failbg); color:var(--fail) }}
.timeline {{ list-style:none; padding:0; margin:0; display:grid; grid-template-columns:repeat(auto-fill,minmax(82px,1fr)); gap:6px }}
.day {{ background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--line); border-radius:6px;
  padding:6px 8px; display:flex; flex-direction:column; font-size:12px }}
.day .n {{ color:var(--muted) }} .day .d {{ font-weight:600; font-size:13px }}
.day.ok {{ border-left-color:var(--ok) }} .day.fail {{ border-left-color:var(--fail) }} .day.warn {{ border-left-color:var(--warn) }}
.day.info {{ border-left-color:var(--info) }} .day.today {{ outline:2px solid var(--ink); outline-offset:-1px }}
.day.ok .s {{ color:var(--ok) }} .day.fail .s {{ color:var(--fail) }} .day.warn .s {{ color:var(--warn) }} .day.info .s {{ color:var(--info) }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:12px }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px 14px; min-width:0 }}
.scroll {{ overflow-x:auto; background:var(--panel); border:1px solid var(--line); border-radius:8px }}
table {{ width:100%; border-collapse:collapse }} td, th {{ text-align:left; padding:6px 8px; border-top:1px solid var(--line); vertical-align:top }}
th {{ border-top:0; color:var(--muted); font-weight:600; font-size:12px }} .card td {{ padding:5px 4px }}
td.detail {{ color:var(--muted); word-break:break-word }}
.pill {{ display:inline-block; padding:1px 8px; border-radius:999px; font-size:12px; font-weight:600; white-space:nowrap }}
.pill.ok {{ background:var(--okbg); color:var(--ok) }} .pill.warn {{ background:var(--warnbg); color:var(--warn) }}
.pill.fail {{ background:var(--failbg); color:var(--fail) }} .pill.info, .pill.muted {{ background:var(--infobg); color:var(--info) }}
pre {{ margin:0; padding:12px; background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow-x:auto; font-size:12px }}
</style></head><body><main>
<div class="top"><h1>Patch Watch Hub</h1><span class="muted">updated {now:%Y-%m-%d %H:%M} Chicago · refreshes every 2 min</span></div>
<div class="banner {banner[0]}">{e(banner[1])}</div>
<h2>Snapshot plan ({len(SNAPSHOT_DAYS)} days) — {e(summary)}</h2>
<ul class="timeline">{''.join(cells)}</ul>
<h2>Today's checks</h2><div class="cards">{''.join(cards)}</div>
<h2>Scheduled jobs</h2><div class="scroll"><table><tr><th>Job</th><th>Runner</th><th>State</th><th>Last run</th><th>Last result</th><th>Next run</th></tr>{''.join(job_rows)}</table></div>
<h2>Live runs</h2><div class="scroll"><table><tr><th>Label</th><th>Started</th><th>Attempted</th><th>Responded</th><th>Errors</th><th>Outcome</th></tr>{''.join(run_rows)}</table></div>
<h2>logs/cron.out (latest)</h2><pre>{e(chr(10).join(cron_tail)) or 'empty'}</pre>
<p class="muted" style="margin-top:20px">Local only (logs/hub is gitignored). Built by scripts/pw_checks.py.</p>
</main></body></html>"""
    HUB.mkdir(parents=True, exist_ok=True)
    tmp = HUB / "index.html.tmp"
    tmp.write_text(page, encoding="utf-8")
    os.replace(tmp, HUB / "index.html")
    return HUB / "index.html"


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in (*CHECKS_FN, "build"):
        print(__doc__)
        return 1
    if argv[1] == "build":
        print(build_hub())
        return 0
    return run_check(argv[1])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
