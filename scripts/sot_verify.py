"""Source of truth for the Patch Watch experiment: verify claims, then log only the ones that hold.

    python -X utf8 scripts/sot_verify.py            # verify and append a dated block to docs/SOURCE_OF_TRUTH.md
    python -X utf8 scripts/sot_verify.py --tests    # also re-run the full test suite as a probe (about 3 minutes)
    python -X utf8 scripts/sot_verify.py --check    # verify only; exit 1 if a claim in the last logged block now fails
    python -X utf8 scripts/sot_verify.py --dry      # print the block, do not write

The rule: a claim is logged only when at least two probes with DIFFERENT origins (different tables, files, tools or
implementations) return the same value and no probe disagrees or fails. A probe that cannot run here (a missing tool or no
network) is shown as "not run" and does not count. A claim with fewer than two working probes, or any disagreement, is not
written to the document at all. Reads only: the study database is opened read-only; nothing is sent to any study site.
"""

from __future__ import annotations

import collections
import csv
import hashlib
import io
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "SOURCE_OF_TRUTH.md"
SRC = ROOT / "src"
LEAN_DIR_CANDIDATES = [ROOT / "lean", ROOT / ".claude" / "worktrees" / "patch-watch-history-ffeab6" / "lean"]
ELAN_BIN = Path.home() / ".elan" / "bin"
sys.path.insert(0, str(SRC))


class Unavailable(Exception):
    """A probe cannot run here (tool, file or network missing)."""


def conn() -> sqlite3.Connection:
    return sqlite3.connect(f"file:{ROOT / 'data' / 'study.db'}?mode=ro", uri=True)


def lean_dir() -> Path:
    for d in LEAN_DIR_CANDIDATES:
        if (d / "Suppression.lean").exists():
            return d
    raise Unavailable("no lean/ folder")


def lean_exe() -> str:
    for name in ("lean.exe", "lean"):
        if (ELAN_BIN / name).exists():
            return str(ELAN_BIN / name)
    raise Unavailable("lean is not installed")


def run_lean(args: list[str], stdin: str | None = None, timeout: int = 600, cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, PATH=str(ELAN_BIN) + os.pathsep + os.environ.get("PATH", ""))
    return subprocess.run([lean_exe(), *args], input=stdin, capture_output=True, text=True, timeout=timeout, env=env,
                          cwd=str(cwd or lean_dir()))


def lean_text(text: str) -> subprocess.CompletedProcess:
    """Check or evaluate a Lean source string in a scratch folder (the lean/ folder is not touched)."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "t.lean"
        p.write_text(text, encoding="utf-8")
        return run_lean([str(p)], cwd=Path(td))


def http(url: str, timeout: int = 60) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "patchwatch-sot/1"})
        return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
    except Exception as e:                           # noqa: BLE001
        raise Unavailable(f"network: {e}")


def git(*args: str) -> str:
    r = subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True, text=True)
    if r.returncode:
        raise Unavailable(r.stderr.strip()[:120])
    return r.stdout


def wi_labels() -> list[str]:
    return sorted(r[0] for r in conn().execute("select snapshot_label from runs where snapshot_label like 'WI_%'"))


def latest_wi() -> str:
    return wi_labels()[-1]


def report_for(label: str) -> str:
    hits = sorted((ROOT / "reports").glob(f"run_*_{label}.md"))
    if not hits:
        raise Unavailable(f"no run report for {label}")
    return hits[-1].read_text(encoding="utf-8")


def ledger_csvs(prefix: str) -> list[Path]:
    return sorted((ROOT / "data").glob(f"ledger_R*_{prefix}_*.csv"))


# ---------------------------------------------------------------------------------------------------------- probes
def wi_sample_runs():
    return sorted({r[0] for r in conn().execute("select sample_size from runs where snapshot_label like 'WI_%'")})


def wi_sample_obs():
    c = conn()
    return sorted({c.execute("select count(distinct domain) from observations where snapshot_label=?", (lab,)).fetchone()[0]
                   for lab in wi_labels()})


def frame_rows():
    return list(csv.DictReader(open(ROOT / "data" / "wi_frame.csv", encoding="utf-8", newline="")))


def wi_sample_frame():
    return [sum(1 for r in frame_rows() if r["region"] == "wisconsin")]


def frame_total_file():
    return len(frame_rows())


def frame_total_runs():
    c = conn()
    wi = c.execute("select max(sample_size) from runs where snapshot_label like 'WI_%'").fetchone()[0]
    cmp_ = c.execute("select max(sample_size) from runs where snapshot_label like 'CMP_%'").fetchone()[0]
    return wi + cmp_


def frame_total_report():
    text = (ROOT / "reports" / "analysis_weekly_2026-10-26_php2shell.md").read_text(encoding="utf-8")
    return int(re.search(r"- frame: (\d+) domains", text).group(1))


def ua_config():
    import config
    return config.USER_AGENT


def ua_db():
    vals = {r[0] for r in conn().execute("select distinct user_agent from runs where snapshot_label like 'WI_%' or snapshot_label like 'NAT_%'")}
    return vals.pop() if len(vals) == 1 else sorted(vals)


def ua_report():
    return re.search(r"User-Agent: `([^`]+)`", report_for(latest_wi())).group(1)


def cap_config():
    import config
    return config.MAX_SENDS_PER_DOMAIN == 3


def cap_csv():
    worst = 0
    for p in ledger_csvs("WI") + ledger_csvs("NAT"):
        per = collections.Counter(r["domain"] for r in csv.DictReader(open(p, encoding="utf-8", newline=""))
                                  if r["redirect_hop"] in ("0", ""))
        worst = max([worst, *per.values()])
    return worst <= 3


def cap_db():
    row = conn().execute("select max(n) from (select count(*) n from request_ledger where redirect_hop=0 "
                         "and (run_id like '%\\_WI\\_%' escape '\\' or run_id like '%\\_NAT\\_%' escape '\\') "
                         "group by run_id, domain)").fetchone()
    return row[0] <= 3


def start_db():
    c = conn()
    return sorted({r[0][11:16] for r in c.execute("select started_at_utc from runs where snapshot_label like 'WI_%' "
                                                  "and substr(snapshot_label,4)>='20261028'")})


def start_ledger():
    out = set()
    for p in ledger_csvs("WI"):
        if p.stem.split("_")[-1] >= "20261028":
            first = min(r["ts_utc"] for r in csv.DictReader(open(p, encoding="utf-8", newline="")))
            out.add(first[11:16])
    return sorted(out)


def start_reports():
    out = set()
    for p in sorted((ROOT / "reports").glob("run_*_WI_*.md")):
        if p.stem.split("_")[-1] >= "20261028":
            m = re.search(r"started / finished \(UTC\): (\S+)T(\d\d:\d\d)", p.read_text(encoding="utf-8"))
            out.add(m.group(2))
    return sorted(out)


def dates_db():
    return [lab[3:] for lab in wi_labels()]


def dates_reports():
    return sorted(re.search(r"_WI_(\d{8})\.md$", p.name).group(1) for p in (ROOT / "reports").glob("run_*_WI_*.md"))


def dates_ledger():
    return sorted(re.search(r"_WI_(\d{8})\.csv$", p.name).group(1) for p in ledger_csvs("WI"))


def nonzero(d):
    return {k: v for k, v in d.items() if v}


def classes_obs():
    c = conn()
    return nonzero(dict(c.execute("select class,count(*) from observations where snapshot_label=? group by 1", (latest_wi(),))))


def classes_domains():
    c = conn()
    run = c.execute("select run_id from runs where snapshot_label=?", (latest_wi(),)).fetchone()[0]
    return nonzero(dict(c.execute("select current_class,count(*) from domains where domain in "
                                  "(select domain from observations where run_id=?) group by 1", (run,))))


def classes_report():
    text = report_for(latest_wi())
    block = text.split("## Classes")[1].split("##")[0]
    return nonzero({m.group(1): int(m.group(2)) for m in re.finditer(r"\| (\w+) \| (\d+) \|", block)})


def trans_obs():
    c = conn()
    return c.execute("select count(*) from observations a join observations b on a.domain=b.domain "
                     "where a.snapshot_label='WI_20261024' and b.snapshot_label='WI_20261026' "
                     "and a.class!='PATCHED_UPSTREAM' and b.class='PATCHED_UPSTREAM'").fetchone()[0]


def trans_events():
    c = conn()
    a = c.execute("select run_id from runs where snapshot_label='WI_20261024'").fetchone()[0]
    b = c.execute("select run_id from runs where snapshot_label='WI_20261026'").fetchone()[0]
    return c.execute("select count(*) from patch_events where event_type='class_change' and to_class='PATCHED_UPSTREAM' "
                     "and from_run_id=? and to_run_id=?", (a, b)).fetchone()[0]


def waves_meta():
    d = json.load(open(ROOT / "data" / "national_waves_meta.json", encoding="utf-8"))["per_wave"]
    return [d["1"], d["2"], d["3"]]


def waves_csv():
    n = collections.Counter(r["wave"] for r in csv.DictReader(open(ROOT / "data" / "national_waves.csv", encoding="utf-8", newline="")))
    return [n["1"], n["2"], n["3"]]


def waves_code():
    import national
    a, b, c = (len(national.rows_through(k)) for k in (1, 2, 3))
    return [a, b - a, c - b]


def nat_runs():
    return conn().execute("select sample_size from runs where snapshot_label='NAT_20261031'").fetchone()[0]


def nat_obs():
    return conn().execute("select count(distinct domain) from observations where snapshot_label='NAT_20261031'").fetchone()[0]


def nat_wave1_csv():
    return sum(1 for r in csv.DictReader(open(ROOT / "data" / "national_waves.csv", encoding="utf-8", newline="")) if r["wave"] == "1")


LIVE_ON = r"^LIVE_REQUESTS_ENABLED\s*=\s*True\b"


def gate_head():
    return bool(re.search(LIVE_ON, git("show", "HEAD:src/config.py"), re.M))


def gate_origin():
    git("fetch", "-q", "origin")
    return bool(re.search(LIVE_ON, git("show", "origin/main:src/config.py"), re.M))


def gate_raw():
    return bool(re.search(LIVE_ON, http("https://raw.githubusercontent.com/CarrollUniversityCS/patch-watch/main/src/config.py"), re.M))


def gate_file():
    return bool(re.search(LIVE_ON, (SRC / "config.py").read_text(encoding="utf-8"), re.M))


def gate_import():
    import config
    return bool(config.LIVE_REQUESTS_ENABLED)


def gate_hub():
    hits = sorted((ROOT / "logs" / "hub" / "checks").glob("*_prerun.json"))
    if not hits:
        raise Unavailable("no pre-run check")
    d = json.load(open(hits[-1], encoding="utf-8"))
    for r in d["results"]:
        if r.get("name", "").startswith("Gate A flag"):
            return "True" in r.get("detail", "")
    raise Unavailable("no Gate A line in the pre-run check")


# ---- suppression audit of the 2026-10-26 report, as first committed and as reprinted
STATES = ("EXPOSED", "EOL", "AMBIGUOUS", "PATCHED", "OPAQUE", "NO_PHP", "UNREACHED")
PS, VS = STATES[:5], ("EXPOSED", "PATCHED")
COLS = ("units", *STATES, "P", "V")


def _old_report() -> str:
    return git("show", "57f7aa7:reports/analysis_weekly_2026-10-26_php2shell.md").replace("\r\n", "\n")


def _new_report() -> str:
    return (ROOT / "reports" / "analysis_weekly_2026-10-26_php2shell.md").read_text(encoding="utf-8").replace("\r\n", "\n")


def _rq0_tables(text: str):
    out = []
    for part in text.split("### RQ0")[1:]:
        tabs, cur = [], []
        for ln in part.split("### RQ1")[0].splitlines():
            if ln.startswith("|"):
                cur.append([c.strip() for c in ln.strip("|").split("|")])
            elif cur:
                tabs.append(cur)
                cur = []
        if cur:
            tabs.append(cur)
        out.append(tabs)
    return out


def _scipy_counts(text: str) -> list[int]:
    try:
        import numpy as np
        from scipy.optimize import Bounds, LinearConstraint, milp
    except ImportError:
        raise Unavailable("scipy is not installed")
    counts = []
    for tabs in _rq0_tables(text):
        live = [r for r in tabs[0][2:] if r[0] != "baseline"]
        rows = {"point": live[-1][2:12], **{"s:" + r[0]: r[1:11] for r in tabs[1][2:]}}
        names, lb, ub, tok = [], [], [], {}
        for r, toks in rows.items():
            anyrow = r != "point" and toks[0] == "<10"
            for c, t in zip(COLS, toks):
                lo, hi = (int(t),) * 2 if t.isdigit() else (1, 9) if t == "<10" else (0, 9) if anyrow else (10, 100000)
                names.append(f"{r}|{c}"); lb.append(lo); ub.append(hi); tok[f"{r}|{c}"] = t
        idx = {n: i for i, n in enumerate(names)}
        eqs = []
        for r in rows:
            eqs.append({f"{r}|units": 1, **{f"{r}|{s}": -1 for s in STATES}})
            eqs.append({f"{r}|P": 1, **{f"{r}|{s}": -1 for s in PS}})
            eqs.append({f"{r}|V": 1, **{f"{r}|{s}": -1 for s in VS}})
        for c in COLS:
            eqs.append({f"point|{c}": 1, **{f"{r}|{c}": -1 for r in rows if r != "point"}})
        A = np.zeros((len(eqs), len(names)))
        for i, e in enumerate(eqs):
            for k, v in e.items():
                A[i, idx[k]] = v
        kw = dict(constraints=LinearConstraint(A, 0, 0), bounds=Bounds(lb, ub), integrality=np.ones(len(names)))
        n = 0
        for nm in names:
            if tok[nm] != "<10":
                continue
            c = np.zeros(len(names)); c[idx[nm]] = 1
            if round(milp(c, **kw).fun) == round(-milp(-c, **kw).fun):
                n += 1
        counts.append(n)
    return counts


def _project_counts(text: str) -> list[int]:
    import analyze
    out = []
    parts = text.split("### RQ0")[1:]
    for part in parts:
        block = "### RQ0" + part.split("### RQ1")[0] + "\n### RQ1\n"
        out.append(len(analyze.audit_rq0_text(block)))
    return out


def rq0_scipy():
    return {"first_committed": _scipy_counts(_old_report()), "reprinted": _scipy_counts(_new_report())}


def rq0_project():
    return {"first_committed": _project_counts(_old_report()), "reprinted": _project_counts(_new_report())}


# ---- Lean
LEAN_FILES = ("Suppression.lean", "Pooling.lean", "Bounds.lean", "Schedule.lean", "PinnedRef.lean")


def lean_compile():
    for f in LEAN_FILES[:4]:
        r = run_lean([f])
        if r.returncode or r.stderr.strip() or "error" in r.stdout:
            return False
    return run_lean(["--run", "PinnedRef.lean"], stdin="").returncode == 0


def lean_axioms():
    d = lean_dir()
    names = {"Suppression.lean": ["interval_lemma", "pinned_iff", "not_determined"], "Pooling.lean": ["finalPools_large", "finalPools_total"],
             "Bounds.lean": ["tipping"], "Schedule.lean": ["burst_observes_all_21", "plan_observes_none_21"]}
    for f, thms in names.items():
        r = lean_text((d / f).read_text(encoding="utf-8") + "\n" + "\n".join(f"#print axioms PatchWatch.{t}" for t in thms))
        out = r.stdout + r.stderr
        if r.returncode or "sorryAx" in out or out.count("axioms") + out.count("does not depend") < len(thms):
            return False
    return True


def lean_source_scan():
    d = lean_dir()
    return all("sorry" not in re.sub(r"/-.*?-/", "", (d / f).read_text(encoding="utf-8"), flags=re.S) for f in LEAN_FILES)


def tip_formula():
    x, N = 32, 191
    return [(a * N - b * x - 1) // b for a, b in ((1, 2), (2, 5), (1, 4))]


def tip_brute():
    x, N, m = 32, 191, 148
    return [max(y for y in range(m + 1) if b * (x + y) < a * N) for a, b in ((1, 2), (2, 5), (1, 4))]


def tip_lean():
    d = lean_dir()
    r = lean_text((d / "Bounds.lean").read_text(encoding="utf-8") +
                  "\n#eval [(1 * 191 - 2 * 32 - 1) / 2, (2 * 191 - 5 * 32 - 1) / 5, (1 * 191 - 4 * 32 - 1) / 4]\n")
    if r.returncode:
        raise Unavailable("lean evaluation failed")
    return [int(x) for x in re.findall(r"\d+", r.stdout.strip())]


WINDOWS = (3, 7, 14, 21)


def sched_python():
    sys.path.insert(0, str(ROOT / "scripts"))
    import schedule_coverage as sc
    return {str(w): [round(sc.coverage(w, 3, False) * 69), round(sc.coverage(w, 3, True) * 69)] for w in WINDOWS}


def sched_independent():
    plan = set(range(13)) | {19, 26, 43, 58, 88}                    # days since 2026-10-23, from the plan text
    out = {}
    for w in WINDOWS:
        plain = sum(1 for a in range(13, 82) if sum(1 for d in plan if a <= d <= a + w) >= 3)
        burst = sum(1 for a in range(13, 82) if sum(1 for d in plan | set(range(a + 1, a + 8)) if a <= d <= a + w) >= 3)
        out[str(w)] = [plain, burst]
    return out


def sched_lean():
    d = lean_dir()
    evals = "\n".join(f"#eval (PatchWatch.observed {w} (fun _ => PatchWatch.plan), "
                      f"PatchWatch.observed {w} (fun a => (PatchWatch.plan ++ PatchWatch.burst a).eraseDups))" for w in WINDOWS)
    r = lean_text((d / "Schedule.lean").read_text(encoding="utf-8") + "\n" + evals + "\n")
    if r.returncode:
        raise Unavailable("lean evaluation failed")
    nums = [int(x) for x in re.findall(r"\d+", r.stdout)]
    return {str(w): nums[2 * i:2 * i + 2] for i, w in enumerate(WINDOWS)}


def _pin_cases():
    import analyze
    rng = random.Random(20261101)
    sup = analyze.Suppressor()
    cases = []
    for _ in range(6000):
        cells = [rng.choice(["<10", "§"] + [str(rng.randint(0, 40)) for _ in range(3)]) for _ in range(rng.randint(1, 7))]
        cases.append((cells, rng.randint(0, 120)))
    for _ in range(4000):
        vals = [rng.choice([0, 0, 1, 2, 3, 5, 8, 9, 10, 11, 15, 25, 40, 100]) for _ in range(rng.randint(1, 8))]
        cases.append((sup.row(vals), sum(vals)))
    return cases


def pin_python():
    import analyze
    return hashlib.sha256("".join("1" if analyze._pinned(c, t, 10) else "0" for c, t in _pin_cases()).encode()).hexdigest()[:16]


def pin_lean():
    cases = _pin_cases()
    inp = "\n".join(f"{t} 10 " + " ".join("S" if x == "§" else x for x in c) for c, t in cases) + "\n"
    r = run_lean(["--run", "PinnedRef.lean"], stdin=inp)
    out = r.stdout.split()
    if len(out) != len(cases) or r.returncode:
        raise Unavailable("lean reference did not run")
    return hashlib.sha256("".join(out).encode()).hexdigest()[:16]


def _csv_rows(text: str) -> int:
    return len(list(csv.reader(io.StringIO(text, newline="")))) - 1


def registry_github():
    base = "https://api.github.com/repositories/362891993/commits?path=current-full.csv&per_page=1&until=2022-01-29T23:59:59Z"
    sha = json.loads(http(base))[0]["sha"]
    return _csv_rows(http(f"https://raw.githubusercontent.com/cisagov/dotgov-data/{sha}/current-full.csv"))


def registry_wayback():
    return _csv_rows(http("https://web.archive.org/web/20220130144423id_/https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv"))


def tests_pytest():
    r = subprocess.run([str(ROOT / ".venv" / "Scripts" / "python.exe"), "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        "--deselect", "tests/test_fetch_rules.py::test_gate_a_is_closed_in_this_checkout"],
                       cwd=str(ROOT), capture_output=True, text=True, timeout=900)
    m = re.search(r"(\d+) passed", r.stdout)
    if not m or r.returncode:
        return f"failed: {r.stdout[-200:]}"
    return int(m.group(1))


def tests_hub():
    hits = sorted((ROOT / "logs" / "hub" / "checks").glob("*_prerun.json"))
    d = json.load(open(hits[-1], encoding="utf-8"))
    for r in d["results"]:
        if r.get("name") == "Test suite":
            return int(re.search(r"(\d+) passed", r["detail"]).group(1))
    raise Unavailable("no test line in the pre-run check")


# --------------------------------------------------------------------------------------------------------- claims
CLAIMS = [
    ("C01", "Design", "Every Wisconsin run covers the same {v} domains.",
     [("runs table sample_size", "database: runs", wi_sample_runs), ("distinct domains observed per run", "database: observations", wi_sample_obs),
      ("registry-derived frame file", "file: data/wi_frame.csv", wi_sample_frame)]),
    ("C02", "Design", "The Wisconsin plus comparison frame holds {v} domains.",
     [("frame file rows", "file: data/wi_frame.csv", frame_total_file), ("sum of run sample sizes", "database: runs", frame_total_runs),
      ("first-written analysis report header", "file: reports/analysis_weekly_2026-10-26", frame_total_report)]),
    ("C03", "Design", "Every request identifies the study with the User-Agent {v}.",
     [("code constant", "code: src/config.py", ua_config), ("stored with each run", "database: runs", ua_db),
      ("run report header", "file: reports/run_*", ua_report)]),
    ("C04", "Design", "No domain receives more than 3 budget-charged first requests per run (within cap: {v}).",
     [("configured cap", "code: src/config.py", cap_config), ("request ledger CSV files", "files: data/ledger_*.csv", cap_csv),
      ("request ledger table", "database: request_ledger", cap_db)]),
    ("C05", "Design", "Since 2026-10-28 every Wisconsin run started at {v} UTC.",
     [("run start times", "database: runs", start_db), ("first request time per run", "files: data/ledger_*.csv", start_ledger),
      ("run report start lines", "files: reports/run_*", start_reports)]),
    ("C06", "State", "Wisconsin snapshots exist for exactly these dates: {v}.",
     [("runs table", "database: runs", dates_db), ("run reports", "files: reports/run_*", dates_reports),
      ("request ledgers", "files: data/ledger_*.csv", dates_ledger)]),
    ("C07", "State", "On the latest Wisconsin snapshot the class counts are {v}.",
     [("observation rows", "database: observations", classes_obs), ("current class per domain", "database: domains", classes_domains),
      ("run report class table", "file: reports/run_*", classes_report)]),
    ("C08", "Findings", "Between the 2026-10-24 and 2026-10-26 Wisconsin snapshots {v} domains moved to PATCHED_UPSTREAM.",
     [("compare the two observation sets", "database: observations", trans_obs), ("recorded class-change events between those two runs", "database: patch_events", trans_events)]),
    ("C09", "Design", "The national frame is split into waves of {v} names.",
     [("wave metadata", "file: data/national_waves_meta.json", waves_meta), ("wave column of the names file", "file: data/national_waves.csv", waves_csv),
      ("wave loader in the code", "code: src/national.py", waves_code)]),
    ("C10", "State", "National wave 1 ran on 2026-10-31 over {v} domains.",
     [("run record", "database: runs", nat_runs), ("distinct domains observed", "database: observations", nat_obs),
      ("wave 1 rows in the names file", "file: data/national_waves.csv", nat_wave1_csv)]),
    ("C11", "Safety", "The committed code keeps live requests switched off (live flag in the committed config: {v}).",
     [("HEAD", "git: local commit", gate_head), ("origin/main", "git: remote ref", gate_origin), ("raw file on GitHub", "web: raw.githubusercontent", gate_raw)]),
    ("C12", "Safety", "The collector's working copy has live requests switched on (flag: {v}).",
     [("source file", "file: src/config.py", gate_file), ("imported module", "code: config import", gate_import),
      ("pre-run check written by the scheduler", "file: logs/hub/checks", gate_hub)]),
    ("C13", "Findings", "Joint audit of the RQ0 tables (hidden cells recoverable, per region block) for the report as first committed and as reprinted: {v}.",
     [("SciPy integer programming", "tool: SciPy milp", rq0_scipy), ("project exact audit", "code: src/analyze + src/disclosure", rq0_project)]),
    ("C14", "Method", "The Lean files check with no gaps (no sorry, no sorryAx): {v}.",
     [("compile each file", "tool: lean", lean_compile), ("axiom listing of the key theorems", "tool: lean #print axioms", lean_axioms),
      ("source scan outside comments", "files: lean/*.lean", lean_source_scan)]),
    ("C15", "Findings", "Tipping counts (largest hidden-patched count keeping the share below 50%, 40%, 25%): {v}.",
     [("closed form", "arithmetic: formula", tip_formula), ("exhaustive search", "arithmetic: enumeration", tip_brute), ("Lean evaluation", "tool: lean #eval", tip_lean)]),
    ("C16", "Findings", "Arrival days (of 69) with at least 3 snapshots in the window, plan versus plan plus 7-day burst, by window length: {v}.",
     [("project script", "code: scripts/schedule_coverage.py", sched_python), ("independent recount", "code: day-number recount in this script", sched_independent),
      ("Lean evaluation", "tool: lean #eval", sched_lean)]),
    ("C17", "Method", "The Python suppression check and the Lean reference agree on 10,000 test rows (output fingerprint {v}).",
     [("Python _pinned", "code: src/analyze.py", pin_python), ("Lean PinnedRef", "tool: lean --run", pin_lean)]),
    ("C18", "Method", "The public .gov registry list had {v} domains on 2022-01-29/30.",
     [("GitHub history of dotgov-data", "web: github", registry_github), ("Internet Archive capture", "web: archive.org", registry_wayback)]),
]
TEST_CLAIM = ("C19", "Method", "The full test suite passes: {v} tests (one test that must fail while live requests are on is excluded).",
              [("fresh pytest run", "tool: pytest now", tests_pytest), ("scheduler's own pre-run run", "file: logs/hub/checks", tests_hub)])


def evaluate(claim):
    cid, section, template, probes = claim
    results = []
    for name, origin, fn in probes:
        try:
            results.append((name, origin, fn(), None))
        except Unavailable as e:
            results.append((name, origin, None, f"unavailable: {e}"))
        except Exception as e:                          # noqa: BLE001
            results.append((name, origin, None, f"error: {type(e).__name__}: {str(e)[:80]}"))
    ok = [r for r in results if r[3] is None]
    broken = [r for r in results if r[3] is not None and not r[3].startswith("unavailable")]
    values = {json.dumps(r[2], sort_keys=True, default=str) for r in ok}
    origins = {r[1] for r in ok}
    verified = len(ok) >= 2 and len(origins) >= 2 and len(values) == 1 and not broken
    return verified, results, (ok[0][2] if ok else None)


def fmt(v) -> str:
    return json.dumps(v, sort_keys=True, default=str) if not isinstance(v, str) else v


HEADER = """# Source of truth: the Patch Watch experiment

This file is the log of what the experiment does and what has been established about it. It is append-only.

**Rule for entries.** A statement is written here only when at least two probes with different origins (a different table,
file, tool or independent implementation) returned the same value in the same run of `scripts/sot_verify.py`, and no probe
disagreed or failed. A probe that could not run (a missing tool, no network) is shown as "not run" and does not count.
A statement with fewer than two working probes is not written. Nothing here is argued from memory or from a summary: every
value below was recomputed when its block was written. To re-check, run `python -X utf8 scripts/sot_verify.py --check`
(it exits 1 if a previously logged statement no longer holds).

**What counts as different origins.** Examples: the runs table versus the observations table versus the request ledger
file versus the written report; the code constant versus the committed copy on GitHub; a Python result versus a Lean
evaluation of the same quantity. Two probes that read the same file in the same way do not count.

**Scope.** Aggregates only. No domain name, address or per-domain row appears here. Ideas, plans and opinions live elsewhere
(`docs/EVALUATION.md`, `docs/proposed/`), because they cannot be verified this way.
"""


def main(argv: list[str]) -> int:
    claims = list(CLAIMS) + ([TEST_CLAIM] if "--tests" in argv else [])
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    lines = [f"\n## Verification run {stamp}\n"]
    verified_ids, rejected = [], []
    for claim in claims:
        verified, results, value = evaluate(claim)
        cid, section, template, _ = claim
        if not verified:
            rejected.append((cid, [(r[0], r[3] or fmt(r[2])) for r in results]))
            continue
        verified_ids.append(cid)
        lines.append(f"### {cid} ({section}) VERIFIED\n\n{template.format(v=fmt(value))}\n")
        lines.append("| probe | origin | value |\n|---|---|---|")
        for name, origin, v, err in results:
            lines.append(f"| {name} | {origin} | " + (f"`{fmt(v)[:90]}` |" if err is None else f"not run ({err}) |"))
        lines.append("")
    lines.append(f"Statements verified in this run: {', '.join(verified_ids) if verified_ids else 'none'}.\n")
    block = "\n".join(lines)
    for cid, info in rejected:
        print(f"NOT LOGGED {cid}: {info}", file=sys.stderr)
    if "--check" in argv:
        last = DOC.read_text(encoding="utf-8").split("## Verification run")[-1] if DOC.exists() else ""
        before = set(re.findall(r"### (C\d+)", last))
        attempted = {c[0] for c in claims}                 # a claim not run this time (the test suite without --tests) is not a failure
        failed = sorted((before & attempted) - set(verified_ids))
        print("still verified:", sorted(before & set(verified_ids)), "failed now:", failed,
              "not re-run:", sorted(before - attempted))
        return 1 if failed else 0
    if "--dry" in argv:
        print(block)
        return 0
    text = DOC.read_text(encoding="utf-8") if DOC.exists() else HEADER
    DOC.write_text(text.rstrip() + "\n" + block, encoding="utf-8")
    print(f"logged {len(verified_ids)} statements; not logged: {[c for c, _ in rejected]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
