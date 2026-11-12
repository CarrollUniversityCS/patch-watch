"""Passive PHP release watcher (reads php.net's public release list; sends nothing to any study site).

    python -X utf8 scripts/php_release_watch.py [--state-dir logs/phpwatch] [--from-file FILE]

Why it exists: PHP2Shell patching finished within days of the 2026-10-21 fix and before the 2026-10-26 KEV listing,
so a patch-speed event has to be triggered by the vendor release, read the same day. This script only notices a new
release and writes the fact down. It never starts a scan, never edits a schedule and never touches the study data.

Writes (all under --state-dir): state.json (releases already seen), health.json (last successful read and the count of
failures in a row), last_run.json, new_releases.jsonl (one line per new release, with the time it was first seen). The first run only records what is there (bootstrap): nothing is "new".
Exit 0 normally, 2 when the list could not be read (state is left as it was).
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
URL = "https://www.php.net/releases/index.php?json&max=60&version=8"
UA = "PatchWatchPhpReleaseWatch/1.0 (read-only release check; academic research)"
CADENCE_DAYS = 28
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_releases(raw: dict) -> dict[str, str]:
    """{version: ISO date} for stable x.y.z releases. Unreadable dates are skipped, not guessed."""
    out: dict[str, str] = {}
    for version, info in raw.items():
        if not VERSION_RE.match(version) or not isinstance(info, dict):
            continue
        try:
            out[version] = datetime.strptime(str(info.get("date", "")).strip(), "%d %b %Y").date().isoformat()
        except ValueError:
            continue
    return out


def next_expected(releases: dict[str, str]) -> dict:
    """Four-week rule from the latest release day, with the observed gaps so the claim can be checked."""
    days = sorted({date.fromisoformat(d) for d in releases.values()})
    if len(days) < 2:
        return {"latest": days[-1].isoformat() if days else None, "expected": None, "gaps": []}
    gaps = [(b - a).days for a, b in zip(days, days[1:])][-12:]
    return {"latest": days[-1].isoformat(), "expected": (days[-1] + timedelta(days=CADENCE_DAYS)).isoformat(),
            "gaps": gaps, "median_gap": statistics.median(gaps), "gaps_equal_28": sum(1 for g in gaps if g == CADENCE_DAYS)}


def diff(state: dict, releases: dict[str, str]) -> list[dict]:
    seen = set(state.get("seen", {}))
    return [{"version": v, "date": d} for v, d in sorted(releases.items(), key=lambda kv: (kv[1], kv[0])) if v not in seen]


def fetch(from_file: str | None) -> dict:
    if from_file:
        return json.loads(Path(from_file).read_text(encoding="utf-8"))
    req = urllib.request.Request(URL, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def write_health(state_dir: Path, stamp: str, ok: bool) -> None:
    """Success time and failures in a row, kept apart from state.json so a failed read can never touch the seen set."""
    path = state_dir / "health.json"
    try:
        prev = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        prev = {}
    last = prev.get("last_success_utc")
    fails = prev.get("consecutive_failures", 0)
    if ok:
        last, fails = stamp, 0
    else:
        fails = (fails if isinstance(fails, int) else 0) + 1
    path.write_text(json.dumps({"last_success_utc": last, "consecutive_failures": fails}), encoding="utf-8")


def run(state_dir: Path, from_file: str | None = None, clock=now_utc) -> tuple[int, dict]:
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / "state.json"
    started = clock()
    stamp = started.isoformat(timespec="seconds")
    report: dict = {"started_utc": stamp, "source": from_file or URL,
                    "network_requests": 0 if from_file else 1, "new": [], "errors": []}
    try:
        releases = parse_releases(fetch(from_file))
        if not releases:
            raise ValueError("no stable x.y.z releases parsed")
    except Exception as exc:  # noqa: BLE001 - any failure leaves the state untouched
        report["errors"].append(f"{type(exc).__name__}: {exc}"[:200])
        write_health(state_dir, stamp, ok=False)
        (state_dir / "last_run.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 2, report
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    bootstrap = not state
    new = [] if bootstrap else diff(state, releases)
    seen = dict(state.get("seen", {}))
    for v, d in releases.items():
        seen.setdefault(v, {"date": d, "first_seen_utc": stamp})
    report.update(bootstrap=bootstrap, new=new, releases_known=len(seen), next=next_expected(releases))
    if new:
        with open(state_dir / "new_releases.jsonl", "a", encoding="utf-8") as fh:
            for n in new:
                fh.write(json.dumps({**n, "first_seen_utc": stamp}) + "\n")
    state_path.write_text(json.dumps({"seen": seen}, indent=1, sort_keys=True), encoding="utf-8")
    write_health(state_dir, stamp, ok=True)
    (state_dir / "last_run.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0, report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state-dir", default=str(ROOT / "logs" / "phpwatch"))
    ap.add_argument("--from-file", default=None, help="read a saved release list instead of php.net (tests)")
    args = ap.parse_args(argv)
    code, rep = run(Path(args.state_dir), args.from_file)
    if code:
        print("php_release_watch: could not read the release list:", "; ".join(rep["errors"]))
    elif rep["new"]:
        print("php_release_watch: NEW RELEASE(S):", ", ".join(f"{n['version']} ({n['date']})" for n in rep["new"]))
    else:
        nxt = rep["next"]
        print(f"php_release_watch: nothing new ({rep['releases_known']} known); latest day {nxt['latest']}, "
              f"four-week rule expects {nxt['expected']}")
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
