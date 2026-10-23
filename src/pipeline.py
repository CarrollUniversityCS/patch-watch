"""Stage 4c: the snapshot runner. One snapshot, end to end.

One invocation writes: one row in `runs`, one observation+verdict row per domain,
every request the crawler made into `request_ledger`, and the change events
between each domain's previous observation and this one (src/detect.py).

This module holds no policy of its own - the hard rules live in src/fetch.py -
but it does refuse to start when they cannot be satisfied (preflight), and it
re-audits the ledger after the fact so a rule broken mid-run is caught before
the next snapshot rather than at publication time (postflight).

Gate A: fetch.assert_live_allowed() (src/fetch.py:88) raises unless src/config.py
enables LIVE_REQUESTS_ENABLED AND the PATCHWATCH_GATE_A env var is APPROVED. The
environment marker alone cannot open live traffic; see docs/OPERATIONS.md. The only way
to exercise this module before Gate A is --mock, which points every domain at the
loopback rig in tests/mock_server.py. Mock mode never resolves or contacts a real name,
and it is the only mode this repo has ever run in.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import csv
import itertools
import json
import logging
import os
import random
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import classify as classify_mod
import config
import db
import detect
import fetch


# --------------------------------------------------------------------------- naming
def new_run_id(snapshot_label: str = "", *, when: datetime | None = None) -> str:
    """R20261023T0415Z_A_day1 - sortable, unique per invocation, label kept legible."""
    ts = when or datetime.now(timezone.utc)
    label = re.sub(r"[^A-Za-z0-9_.-]", "_", snapshot_label) or "adhoc"
    return f"R{ts:%Y%m%dT%H%M%SZ}_{label}"


def excluded_by_scope(row: dict[str, str]) -> bool:
    """True for rows the study never measures (config.EXCLUDED_DOMAIN_TYPE_PREFIXES).

    Checked on domain_type and on stratum, so a sample that only carries one of the
    two (the national pilot sample has both) is still filtered. A sample with
    neither column cannot be checked and is refused by preflight instead.
    """
    for key in ("domain_type", "stratum"):
        val = (row.get(key) or "").strip()
        if any(val.startswith(p) for p in config.EXCLUDED_DOMAIN_TYPE_PREFIXES):
            return True
    return False


def load_sample(path: Path | str) -> list[dict[str, str]]:
    """Read a sample CSV. Keeps first occurrence of a domain, lower-cases it, and
    drops out-of-scope rows (tribal nations, see config) before anything else."""
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    with open(path, newline="", encoding="utf-8") as fh:
        for raw in csv.DictReader(fh):
            dom = (raw.get("domain") or "").strip().lower().rstrip(".")
            if not dom or dom in seen or excluded_by_scope(raw):
                continue
            seen.add(dom)
            rows.append({**{k: (v or "") for k, v in raw.items()}, "domain": dom})
    if not rows:
        raise ValueError(f"sample file {path} yielded zero domains")
    return rows


# --------------------------------------------------------------------------- guards
def preflight(*, sample_rows: list[dict[str, str]], blocklist: set[str],
              blocklist_path: Path, db_path: Path, mock: bool) -> list[str]:
    """Everything that must be true BEFORE a socket is opened. Returns problems."""
    problems: list[str] = []

    if not sample_rows:
        problems.append("sample is empty")
    elif not any(r.get("domain_type") or r.get("stratum") for r in sample_rows):
        problems.append("sample has no domain_type/stratum column, so the tribal-nation "
                        "exclusion cannot be checked (config.EXCLUDED_DOMAIN_TYPE_PREFIXES)")

    # Hard rule 5: an explicit opt-out list must exist and be non-trivial. A
    # missing file is not "nobody opted out", it is "nobody maintained the list",
    # and the two look identical in the data. Refuse to guess.
    if not blocklist_path.exists():
        problems.append(f"no blocklist at {blocklist_path} (hard rule 5)")
    elif not blocklist:
        problems.append(f"blocklist {blocklist_path} is empty after parsing (hard rule 5)")

    blocked_in_sample = sorted({r["domain"] for r in sample_rows} & blocklist)
    if len(blocked_in_sample) > len(sample_rows) // 2:
        problems.append(f"{len(blocked_in_sample)} of {len(sample_rows)} sampled domains are "
                        f"blocklisted - the sample was almost certainly drawn before the "
                        f"blocklist was updated")

    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        probe = db_path.parent / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        problems.append(f"cannot write to {db_path.parent}: {exc}")

    kill = fetch.KillSwitch()
    kill.check_external()
    if kill.tripped:
        problems.append(f"halted before start: {kill.tripped_reason}")

    if mock:
        fetch.assert_live_allowed(allow_loopback_only=True)
    else:
        try:
            fetch.assert_live_allowed()
        except fetch.GateClosed as exc:
            problems.append(f"GATE A: {exc}")

    return problems


def postflight(conn: db.sqlite3.Connection, crawler: fetch.Crawler,
               domains: Iterable[str], ledger_rows: list[dict[str, Any]], *,
               mock: bool) -> list[str]:
    """Re-check the ledger against reality after the run (hard rule 9).

    `mock` is the operator's stated intent (the --mock flag), passed in rather than
    inferred from the crawler, so that intent and construction disagreeing is itself
    a finding. Both directions are checked: a live run must not smuggle a loopback
    escape hatch into the allowlist, and a --mock run that somehow has no escape
    hatch can only have hit real DNS.
    """
    domains = list(domains)
    extra = set(crawler.approved.extra_hosts)
    if extra and not mock:
        return [f"crawler carries test_hosts {sorted(extra)} but the run was not started "
                f"with --mock - refusing to audit against a widened allowlist"]
    if mock and not extra:
        return ["--mock run built a crawler with no loopback test_hosts: it could only "
                "have resolved real domains"]

    roots = set(crawler.approved.roots) | extra
    budget_counts = {d: crawler.budget.count(d) for d in domains}
    # audit_ledger() holds the cap itself (it is the rule, not a knob); budget_counts
    # comes from the crawler's live per-domain counter, not from the ledger, so the
    # two disagreeing is itself a finding.
    return fetch.audit_ledger(ledger_rows, budget_counts, roots)


# --------------------------------------------------------------------------- capture
def classify_input(obs: fetch.Observation) -> dict[str, Any]:
    """Observation -> the dict shape classify.classify() documents.

    as_row() JSON-encodes headers for storage; classification needs the live
    dict, and passing the stored string would silently classify every site as
    NO_PHP_EVIDENCE. That failure mode is quiet, so it is spelled out here.
    """
    row = obs.as_row()
    return {**row, "headers": obs.headers, "php_hints": obs.php_hints}


async def capture(conn: db.sqlite3.Connection, *, sample_rows: list[dict[str, str]],
                  run_id: str, snapshot_label: str, blocklist: set[str],
                  url_for: Callable[[str], str] | None = None,
                  test_hosts: Iterable[str] = (),
                  mock: bool = False,
                  timeouts: tuple[float, float] | None = None,
                  region: str | None = None,
                  order_seed: int | None = None) -> dict[str, Any]:
    """Fetch, classify, store, diff. One snapshot (of one region, when given)."""
    order_seed = secrets.randbits(32) if order_seed is None else int(order_seed)
    domains = fetch_order([r["domain"] for r in sample_rows], order_seed)
    started = db.utc_now_iso()

    ledger = fetch.Ledger()
    kill = fetch.KillSwitch()
    kill.check_external()
    if kill.tripped:
        raise RuntimeError(f"refusing to start: {kill.tripped_reason}")

    crawler = fetch.Crawler(
        domains, blocklist=blocklist, run_id=run_id, snapshot_label=snapshot_label,
        url_for=url_for, test_hosts=test_hosts, kill_switch=kill, ledger=ledger,
        timeouts=timeouts)

    db.insert_run(conn, {
        "run_id": run_id, "snapshot_label": snapshot_label, "started_at_utc": started,
        "finished_at_utc": None, "sample_size": len(domains), "attempted": None,
        "responded": None, "errors": None, "sends": None, "kill_switch": None,
        "user_agent": config.USER_AGENT,
        "config_json": json.dumps({
            "max_sends_per_domain": config.MAX_SENDS_PER_DOMAIN,
            "max_concurrency": config.MAX_CONCURRENCY, "max_per_ip": config.MAX_PER_IP,
            "connect_timeout_s": crawler.connect_timeout, "total_timeout_s": crawler.total_timeout,
            "max_body_bytes": config.MAX_BODY_BYTES, "max_redirects": config.MAX_REDIRECTS,
            "cookie_jar": config.COOKIE_JAR, "mock": bool(test_hosts),
            "blocklist_size": len(blocklist), "region": region, "order_seed": order_seed,
        }, sort_keys=True),
        "notes": "mock loopback run" if test_hosts else "live run",
    })

    observations = await crawler.fetch_many(domains)

    # The ledger lands in the database BEFORE anything else happens, and is
    # committed on its own. It is the artifact that proves what we sent; a bug in
    # classification, change detection or reporting must not be able to lose it.
    # (fetch_many() is exception-contained for the same reason: a crash after real
    # traffic went out must not leave the run unaccounted for.)
    ledger_written = db.insert_ledger(conn, ledger.rows)
    conn.commit()

    counts = {c: 0 for c in classify_mod.CLASSES}
    responded = errors = skipped = 0
    for obs in observations:
        verdict = classify_mod.classify(classify_input(obs))
        db.insert_observation(conn, obs.as_row(), verdict.as_dict())
        counts[verdict.cls] = counts.get(verdict.cls, 0) + 1
        if obs.skipped_reason:
            skipped += 1
        elif obs.error_type and obs.error_type != "ok":
            errors += 1
        else:
            responded += 1

    events = detect.detect_changes(conn, run_id)
    events_written = db.insert_events(conn, events)
    flapping = detect.flapping_domains(conn, run_id)

    finished = db.utc_now_iso()
    audit_problems = postflight(conn, crawler, domains, ledger.rows, mock=mock)
    tripped = kill.tripped_reason or ("audit_violation" if audit_problems else None)
    db.insert_run(conn, {
        "run_id": run_id, "snapshot_label": snapshot_label, "started_at_utc": started,
        "finished_at_utc": finished, "sample_size": len(domains),
        "attempted": len(domains) - skipped, "responded": responded, "errors": errors,
        "sends": sum(o.sends for o in observations), "kill_switch": tripped,
        "user_agent": config.USER_AGENT, "config_json": None, "notes": None,
    })
    conn.commit()

    return {
        "run_id": run_id, "snapshot_label": snapshot_label, "started_at_utc": started,
        "finished_at_utc": finished, "domains": len(domains), "responded": responded,
        "errors": errors, "skipped": skipped, "sends": sum(o.sends for o in observations),
        "class_counts": counts, "ledger_rows": ledger_written,
        "events": len(events), "event_types": _tally(events, "event_type"),
        "flapping_domains": len(flapping), "kill_switch": tripped,
        "audit_problems": audit_problems,
        "ledger": ledger, "observations": observations, "mock": bool(test_hosts),
        "region": region, "order_seed": order_seed,
    }


def fetch_order(domains: list[str], seed: int) -> list[str]:
    """The run's request order: the frame sorted, then shuffled by `seed`.

    The frame is sorted by stratum, so firewalled sites (state agencies behind one CDN)
    and shared-host sites sit next to each other and land in the same kill-switch
    window. Shuffling spreads them out. Sorting first makes the order depend only on
    the set of domains and the seed, which the run records (plan §12, 2026-10-23).
    """
    out = sorted(domains)
    random.Random(seed).shuffle(out)
    return out


def _tally(rows: Iterable[dict[str, Any] | db.sqlite3.Row], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        v = r[key] if not isinstance(r, dict) else r.get(key)
        out[str(v)] = out.get(str(v), 0) + 1
    return out


# --------------------------------------------------------------------------- outputs
def export_ledger(ledger_rows: list[dict[str, Any]], path: Path | str) -> Path:
    """Per-request ledger to CSV. Local only - data/ is gitignored (hard rule 7)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    cols = ["run_id", "ts_utc", "domain", "method", "url", "phase",
            "redirect_hop", "status_code", "error_type"]
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(ledger_rows)
    return p


def run_markdown(summary: dict[str, Any]) -> str:
    """Run log. Counts only - a per-domain result never leaves the sqlite file."""
    lines = [
        f"# Run {summary['run_id']}",
        "",
        f"- snapshot label: `{summary['snapshot_label']}`"
        f"{' (MOCK, loopback only)' if summary['mock'] else ''}"
        f"{' | region: ' + summary['region'] if summary.get('region') else ''}",
        f"- started / finished (UTC): {summary['started_at_utc']} / {summary['finished_at_utc']}",
        f"- domains in sample: {summary['domains']}  |  responded {summary['responded']}"
        f"  |  errored {summary['errors']}  |  skipped {summary['skipped']}",
        f"- Budget-charged send phases: {summary['sends']} "
        f"(cap {config.MAX_SENDS_PER_DOMAIN}/domain: https, unverified retry, http fallback). "
        f"Ledger rows including same-domain redirect hops: {summary['ledger_rows']}",
        f"- User-Agent: `{config.USER_AGENT}`",
        f"- fetch order seed: `{summary.get('order_seed')}`",
        "",
        "## Classes",
        "",
        "| class | n |",
        "|---|---|",
    ]
    for cls, n in summary["class_counts"].items():
        lines.append(f"| {cls} | {n} |")
    lines += ["", "## Changes vs previous observation", ""]
    if summary["event_types"]:
        lines += ["| event | n |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in sorted(summary["event_types"].items())]
    else:
        lines.append("No previous observation to compare against (first snapshot of this sample).")
    lines += ["", f"- domains flagged flapping: {summary['flapping_domains']}", ""]

    problems = list(summary["audit_problems"])
    if summary["kill_switch"]:
        problems.insert(0, f"KILL SWITCH: {summary['kill_switch']}")
    lines.append("## Safety audit")
    lines.append("")
    if problems:
        lines += [f"- **{p}**" for p in problems]
    else:
        lines.append("- No violations found.")
    lines.append("")
    return "\n".join(lines)


def write_run_log(summary: dict[str, Any], reports_dir: Path | None = None) -> Path:
    # reports/, not logs/: `logs/*` is gitignored wholesale, and a run log is the
    # durable safety artifact for that snapshot, not transient stderr. `reports/*`
    # with `!reports/*.md` is the one place git keeps markdown evidence.
    d = Path(reports_dir or config.REPORTS_DIR)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"run_{summary['run_id']}.md"
    p.write_text(run_markdown(summary), encoding="utf-8")
    if summary["kill_switch"] or summary["audit_problems"]:
        alert = d / f"ALERT_{summary['run_id']}.md"
        alert.write_text(
            f"# ALERT - run {summary['run_id']}\n\n"
            f"Kill switch: {summary['kill_switch']}\n\n"
            "Audit problems:\n" + "".join(f"- {p_}\n" for p_ in summary["audit_problems"]) +
            "\n**The scheduler must not run again until this is read and cleared.**\n"
            f"Remove or blank `{config.ABUSE_FLAG_PATH}` only after you know what happened.\n",
            encoding="utf-8")
    return p


def attach_logging(log_dir: Path | None = None) -> logging.Handler | None:
    """Send fetch.py's REFUSING / halt lines to logs/capture.log, append-only.

    Hard rule 1 specifies the wording of a refusal but not where it goes; a WARNING
    that only reaches an unconfigured root logger lands on whatever console the cron
    job happens to redirect, which for a Sunday-night halt notice is not good enough
    to act on. Explicit UTF-8, because rule 1's literal wording contains an em dash
    and a cp1252 console would raise inside the logging handler instead of reporting
    the refusal. Idempotent, so repeated calls in one process (tests) do not
    duplicate every line.
    """
    log_dir = Path(log_dir or config.LOGS_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("patchwatch")
    target = log_dir / "capture.log"
    for h in logger.handlers:                      # already attached this process
        if isinstance(h, logging.FileHandler) and Path(getattr(h, "baseFilename", "")) == target:
            return h
    handler = logging.FileHandler(target, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return handler


def select_region(rows: list[dict[str, str]], region: str | None) -> list[dict[str, str]]:
    """Keep one frame region (plan §6: Wisconsin and the comparison states are separate
    snapshots, so a halt or complaint during the comparison run can never cost a
    Wisconsin reading). A sample with no region column cannot be split; refuse."""
    if not region:
        return rows
    if not any("region" in r for r in rows):
        raise SystemExit(f"--region {region}: the sample has no region column "
                         "(build it with src/wi_frame.py)")
    return [r for r in rows if r.get("region") == region]


class RunLock:
    """At most one LIVE run at a time on this machine.

    Rule 4 caps us at one request in flight per resolved IP, and that cap lives inside
    one process. Two overlapping runs (Wisconsin still going when the comparison run
    starts, or a manual run during a scheduled one) would each hold their own cap and
    put two requests on a shared-hosting IP. The lock is a file created with O_EXCL; a
    leftover one after a crash is a refusal, not something to guess about. Read
    it, confirm no run is going, and delete it.
    """

    def __init__(self, path: Path | None = None):
        self.path = Path(path or (config.LOGS_DIR / "run.lock"))
        self.held = False

    def __enter__(self) -> "RunLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            held_by = self.path.read_text(encoding="utf-8", errors="replace").strip()
            raise SystemExit(f"another live run holds {self.path} ({held_by}). Two live runs "
                             "at once would break the one-request-per-IP limit (rule 4). If no "
                             "run is going, the lock is stale from a crash: delete it.")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(f"pid={os.getpid()} started={db.utc_now_iso()}\n")
        self.held = True
        return self

    def __exit__(self, *exc) -> None:
        if self.held:
            self.path.unlink(missing_ok=True)
            self.held = False


def run_snapshot(*, sample_path: Path | str | None = None, db_path: Path | str | None = None,
                 blocklist_path: Path | str | None = None, snapshot_label: str = "",
                 run_id: str | None = None, limit: int | None = None,
                 mock: bool = False, mock_rotate: int = 0, quiet: bool = False,
                 region: str | None = None, order_seed: int | None = None) -> dict[str, Any]:
    """Synchronous entry point used by scripts/run_snapshot.py and the cron snippet."""
    attach_logging()
    sample_path = Path(sample_path or (config.DATA_DIR / "pilot_sample.csv"))
    db_path = Path(db_path or config.DB_PATH)
    blocklist_path = Path(blocklist_path or config.BLOCKLIST_PATH)

    sample_rows = select_region(load_sample(sample_path), region)
    if limit:
        sample_rows = sample_rows[:limit]
    blocklist = fetch.load_blocklist(blocklist_path)

    problems = preflight(sample_rows=sample_rows, blocklist=blocklist,
                         blocklist_path=blocklist_path, db_path=db_path, mock=mock)
    if problems:
        raise SystemExit("preflight refused the run:\n  - " + "\n  - ".join(problems))

    url_for: Callable[[str], str] | None = None
    test_hosts: list[str] = []
    stack = None
    if mock:
        sys.path.insert(0, str(config.ROOT / "tests"))
        from mock_server import MockStack  # type: ignore[import-not-found]  # noqa: PLC0415
        # Ports are overridable so two mock stacks can coexist (a test run and a demo
        # run on the same box). Default = the rig's usual 8451/8452/8455.
        stack = MockStack(
            http_port=int(os.environ.get("PATCHWATCH_MOCK_HTTP_PORT", 8451)),
            https_port=int(os.environ.get("PATCHWATCH_MOCK_HTTPS_PORT", 8452)),
            http_only_port=int(os.environ.get("PATCHWATCH_MOCK_HTTP_ONLY_PORT", 8455)),
            dead_port=int(os.environ.get("PATCHWATCH_MOCK_DEAD_PORT", 8459)))
        stack.start()
        test_hosts = ["127.0.0.1"]
        # All 200-level shapes on purpose: a status-503 case in the rotation would
        # trip the kill switch by design and bury the point of the smoke run.
        cases = ["vuln8335", "patched8336", "hidden_cookie", "ubuntu_suffix",
                 "eol81", "patched_newbranch", "garbage_word", "no_php",
                 "http_only_case", "redirect_loop"]
        cycle = itertools.cycle(cases)
        for _ in range(max(0, mock_rotate)):      # shift the deck: same domains, new answers
            next(cycle)
        url_for = lambda dom: stack.url_for(next(cycle))  # noqa: E731 - one-liner on purpose

    # Mock runs touch only loopback, so they need no lock and may run beside a live one.
    with (RunLock() if not mock else contextlib.nullcontext()):
        try:
            conn = db.connect(db_path)
            db.init_db(conn)
            db.upsert_domains(conn, sample_rows)
            try:
                summary = asyncio.run(capture(
                    conn, sample_rows=sample_rows, run_id=run_id or new_run_id(snapshot_label),
                    snapshot_label=snapshot_label or "adhoc", blocklist=blocklist,
                    url_for=url_for, test_hosts=test_hosts or (), mock=mock,
                    timeouts=(1.0, 3.0) if mock else None, region=region,
                    order_seed=order_seed))
                summary["ledger_csv"] = str(export_ledger(
                    summary["ledger"].rows,
                    config.DATA_DIR / f"ledger_{summary['run_id']}.csv"))
                summary["run_log"] = str(write_run_log(summary))
            finally:
                conn.close()
        finally:
            if stack is not None:
                stack.stop()

    if not quiet:
        print(json.dumps({k: v for k, v in summary.items()
                          if k not in ("ledger", "observations")}, indent=2, default=str))
    return summary


# --------------------------------------------------------------------------- cli
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="patch-watch snapshot runner (loopback mock only until Gate A opens)")
    ap.add_argument("--sample", help="sample CSV (default data/pilot_sample.csv)")
    ap.add_argument("--db", help="sqlite path (default data/study.db)")
    ap.add_argument("--blocklist", help="opt-out file (default blocklist.txt)")
    ap.add_argument("--label", default="", help="snapshot label, e.g. A_day1")
    ap.add_argument("--run-id", help="override the generated run id")
    ap.add_argument("--limit", type=int, help="only the first N domains (smoke test)")
    ap.add_argument("--order-seed", type=int,
                    help="fetch-order shuffle seed (default: drawn per run, always recorded)")
    ap.add_argument("--region", choices=("wisconsin", "comparison"),
                    help="snapshot one frame region only (plan §6: always run them separately)")
    ap.add_argument("--mock", action="store_true",
                    help="loopback mock server only - no DNS, no real domain, gate not required")
    ap.add_argument("--mock-rotate", type=int, default=0,
                    help="shift the mock case deck N places (second run -> real diffs to detect)")
    ap.add_argument("--preflight-only", action="store_true",
                    help="run the guards and exit without sending anything")
    args = ap.parse_args(argv)

    if args.preflight_only:
        rows = select_region(load_sample(Path(args.sample or (config.DATA_DIR / "pilot_sample.csv"))),
                             args.region)
        bl_path = Path(args.blocklist or config.BLOCKLIST_PATH)
        probs = preflight(sample_rows=rows, blocklist=fetch.load_blocklist(bl_path),
                          blocklist_path=bl_path, db_path=Path(args.db or config.DB_PATH),
                          mock=args.mock)
        print("preflight: OK" if not probs else "preflight problems:\n  - " + "\n  - ".join(probs))
        return 0 if not probs else 1

    s = run_snapshot(sample_path=args.sample, db_path=args.db, blocklist_path=args.blocklist,
                     snapshot_label=args.label, run_id=args.run_id, limit=args.limit,
                     mock=args.mock, mock_rotate=args.mock_rotate, region=args.region,
                     order_seed=args.order_seed)
    return 2 if (s["kill_switch"] or s["audit_problems"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
