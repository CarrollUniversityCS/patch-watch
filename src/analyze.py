"""Stage 7: every pre-registered outcome in docs/analysis_plan.md §7, from the database.

Reads `data/study.db` (live `observations` + archived `baseline_observations`) and the
frame CSV, and writes ONE markdown report of aggregate tables. The tables in the paper
are this file's output, not hand-copied numbers.

Disclosure (plan §8): by default every count of 1-9 is printed as "<10", every share
whose numerator is suppressed is hidden, and complementary suppression ("§") is
applied wherever a suppressed cell could be recovered from its row total. Vendors and
ASNs are never named. `--unsuppressed` writes the PI's working copy under data/
(gitignored), never under reports/.

Everything is RE-CLASSIFIED from the stored headers, not read from the stored class,
so a classifier fix applies to old rows too and `--event` can re-read the same
headers against another release.

Run:
    python src/analyze.py --frame data/wi_frame.csv --label WI_d14
    python src/analyze.py --frame data/wi_frame.csv --event cve_2024_4577 --label hist
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import classify as classify_mod
import config
import db
import detect
import hosting
import support_status
import versions

# ------------------------------------------------------------------ analysis states (§5)
STATES = ("EXPOSED", "EOL", "AMBIGUOUS", "PATCHED", "OPAQUE", "NO_PHP", "UNREACHED")
# Entity rule (§2): first state in this order wins across an entity's domains, so an
# entity is PATCHED only when none of its domains is exposed, EOL or ambiguous.
PRECEDENCE = {s: i for i, s in enumerate(STATES)}
CLASS_TO_STATE = {
    "PATCHED_UPSTREAM": "PATCHED",
    "VULNERABLE_BY_VERSION": "EXPOSED",
    "EOL_UNFIXED": "EOL",
    "POSSIBLY_BACKPORTED": "AMBIGUOUS",
    "UNPARSEABLE": "AMBIGUOUS",
    "PHP_VERSION_HIDDEN": "OPAQUE",
    "NO_PHP_EVIDENCE": "NO_PHP",
    "NO_RESPONSE": "UNREACHED",
    "NOT_MEASURED": "UNREACHED",
}
P_STATES = ("EXPOSED", "EOL", "AMBIGUOUS", "PATCHED", "OPAQUE")
# Pre-registered primary endpoint (plan §7.0): Wisconsin, entity unit, A(d) at the last
# live point no later than day 14, and the never-patched count at the last observation.
PRIMARY_DAY = 14
# Contingency (plan §7.0): below this many cohort entities the Wisconsin RQ2/RQ3 results
# are descriptive only, the median is not reported, and the pooled cohort is shown too.
MIN_COHORT = 30
V_STATES = ("EXPOSED", "PATCHED")

# PHP2Shell: first observed exploitation. Archived captures from this moment on are
# not "before" anything (plan §3).
BASELINE_CUTOFF = {"php2shell": "2026-10-17T00:00:00Z"}
SUPPRESS_BELOW = 10


@dataclass(frozen=True)
class Scenario:
    """One pre-registered analysis variant (§7.7). The default is the primary analysis."""
    name: str = "primary"
    backport_as: str = "AMBIGUOUS"          # or PATCHED / EXPOSED
    unit: str = "entity"                    # entity | domain | ip | asn
    exclude_cert_error: bool = False
    exclude_off_domain: bool = False
    server_comment_off: bool = False


SENSITIVITY = (
    Scenario("1a backport counted as patched", backport_as="PATCHED"),
    Scenario("1b backport counted as exposed", backport_as="EXPOSED"),
    Scenario("2 domain is the unit", unit="domain"),
    Scenario("3 cert-error domains excluded", exclude_cert_error=True),
    Scenario("4 off-domain redirects excluded", exclude_off_domain=True),
    Scenario("5 server-comment deviation off", server_comment_off=True),
    Scenario("6a host cluster (IP) is the unit", unit="ip"),
    Scenario("6b host cluster (ASN) is the unit", unit="asn"),
)


# ------------------------------------------------------------------ data
@dataclass
class Reading:
    domain: str
    point: str                 # "baseline" or a run id
    day: float                 # days from the event's t0
    verdict: classify_mod.Verdict
    ip: str | None
    cert_error: bool = False
    off_domain: bool = False


@dataclass
class Frame:
    rows: dict[str, dict[str, str]]                      # domain -> frame row
    entity_stratum: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | str) -> "Frame":
        import pipeline           # load_sample applies the tribal-nation exclusion
        rows = {r["domain"]: r for r in pipeline.load_sample(path)}
        by_entity: dict[str, Counter] = defaultdict(Counter)
        for r in rows.values():
            ent = r.get("entity_id") or f"{r.get('state', '')}:{r['domain']}"
            r["entity_id"] = ent
            by_entity[ent][r.get("stratum") or "unknown"] += 1
        f = cls(rows)
        for ent, c in by_entity.items():
            # An election office shares an organization with its city or county; the
            # entity is reported under the government's own stratum (§2).
            non_el = Counter({k: v for k, v in c.items() if k != "Election office"})
            f.entity_stratum[ent] = (non_el or c).most_common(1)[0][0]
        return f


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_from(t0: str, ts: str | None) -> float | None:
    a, b = _parse_ts(t0), _parse_ts(ts)
    return None if a is None or b is None else (b - a).total_seconds() / 86400.0


def _reclassify(row: sqlite3.Row | dict, event: versions.PatchEvent) -> classify_mod.Verdict:
    get = (lambda k: row[k] if k in row.keys() else None) if isinstance(row, sqlite3.Row) \
        else row.get
    return classify_mod.classify({
        "status_code": get("status_code"),
        "error_type": get("error_type"),
        "skipped_reason": get("skipped_reason"),
        "headers": json.loads(get("headers_json") or "{}"),
        "php_hints": json.loads(get("php_hints_json") or "{}"),
        "cert_error": bool(get("cert_error")),
    }, event=event)


def load_live(conn: sqlite3.Connection, frame: Frame, event: versions.PatchEvent,
              include_mock: bool = False) -> tuple[list[Reading], list[dict[str, Any]]]:
    """Live readings from trustworthy runs. A run whose ledger audit failed is not
    analysed (docs/OPERATIONS.md); a run halted by the kill switch is, because its
    unsent domains are already NOT_MEASURED."""
    runs = []
    for r in conn.execute("SELECT * FROM runs ORDER BY started_at_utc"):
        mock = (r["notes"] or "").startswith("mock") or '"mock": true' in (r["config_json"] or "")
        if r["kill_switch"] == "audit_violation" or (mock and not include_mock):
            continue
        runs.append(dict(r))
    keep = {r["run_id"] for r in runs}
    out = []
    for o in conn.execute("SELECT * FROM observations ORDER BY started_at_utc"):
        if o["run_id"] not in keep or o["domain"] not in frame.rows:
            continue
        out.append(Reading(o["domain"], o["run_id"], days_from(event.t0_utc, o["started_at_utc"]) or 0.0,
                           _reclassify(o, event), o["resolved_ip"],
                           bool(o["cert_error"]), bool(o["redirect_off_domain"])))
    return out, runs


def load_baseline(conn: sqlite3.Connection, frame: Frame, event: versions.PatchEvent,
                  crawls: Iterable[str] | None = None) -> tuple[list[Reading], dict[str, Any]]:
    """Latest archived capture per domain before the cutoff (PHP2Shell: first
    exploitation; other events: their t0)."""
    if not conn.execute("SELECT name FROM sqlite_master WHERE name='baseline_observations'").fetchone():
        return [], {"available": False}
    cutoff = BASELINE_CUTOFF.get(event.key, event.t0_utc)
    q = "SELECT * FROM baseline_observations"
    rows = [r for r in conn.execute(q) if r["domain"] in frame.rows
            and (crawls is None or r["crawl_id"] in set(crawls))]
    asked = {r["domain"] for r in rows}
    best: dict[str, sqlite3.Row] = {}
    late = 0
    for r in rows:
        if not r["captured"]:
            continue
        if (r["warc_date_utc"] or "") >= cutoff:
            late += 1
            continue
        if r["domain"] not in best or r["warc_date_utc"] > best[r["domain"]]["warc_date_utc"]:
            best[r["domain"]] = r
    readings = [Reading(d, "baseline", days_from(event.t0_utc, r["warc_date_utc"]) or 0.0,
                        _reclassify(r, event), r["warc_ip"]) for d, r in best.items()]
    return readings, {"available": True, "domains_asked": len(asked),
                      "domains_with_pre_cutoff_capture": len(best),
                      "captures_on_or_after_cutoff": late, "cutoff": cutoff}


def load_historical(conn: sqlite3.Connection, frame: Frame, event: versions.PatchEvent) -> list[dict]:
    """Per crawl, every capture re-read against `event` (plan §7.8)."""
    if not conn.execute("SELECT name FROM sqlite_master WHERE name='baseline_observations'").fetchone():
        return []
    per: dict[str, list[Reading]] = defaultdict(list)
    for r in conn.execute("SELECT * FROM baseline_observations WHERE captured=1"):
        if r["domain"] in frame.rows:
            per[r["crawl_id"]].append(Reading(r["domain"], r["crawl_id"],
                                              days_from(event.t0_utc, r["warc_date_utc"]) or 0.0,
                                              _reclassify(r, event), r["warc_ip"]))
    return [{"crawl": c, "readings": rs} for c, rs in sorted(per.items())]


# ------------------------------------------------------------------ states and units
def state_of(v: classify_mod.Verdict, sc: Scenario) -> str:
    cls = v.cls
    if sc.server_comment_off and v.detail.get("distro_evidence") == "server_comment" and v.version:
        if v.fixed_version is None:
            cls = "EOL_UNFIXED"
        else:
            cls = "PATCHED_UPSTREAM" if v.version >= v.fixed_version else "VULNERABLE_BY_VERSION"
    if cls == "POSSIBLY_BACKPORTED":
        return sc.backport_as
    return CLASS_TO_STATE[cls]


def unit_key(r: Reading, frame: Frame, sc: Scenario, asn: hosting.AsnTable | None,
             first_ip: dict[str, str]) -> str | None:
    if sc.unit == "domain":
        return r.domain
    if sc.unit == "entity":
        return frame.rows[r.domain]["entity_id"]
    ip = first_ip.get(r.domain)
    if sc.unit == "ip":
        return f"ip:{ip}" if ip else f"solo:{r.domain}"
    if sc.unit == "asn":
        a = asn.lookup(ip) if asn and ip else None
        return f"as:{a}" if a else f"solo:{r.domain}"
    raise ValueError(sc.unit)


def unit_states(readings: list[Reading], frame: Frame, sc: Scenario,
                asn: hosting.AsnTable | None = None) -> dict[str, dict[str, str]]:
    """point -> unit -> state, after the scenario's exclusions and the entity rule."""
    return unit_states_and_map(readings, frame, sc, asn)[0]


def unit_states_and_map(readings: list[Reading], frame: Frame, sc: Scenario,
                        asn: hosting.AsnTable | None = None
                        ) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    """unit_states() plus the domain -> unit map it used."""
    drop: set[str] = set()
    if sc.exclude_cert_error:
        drop |= {r.domain for r in readings if r.cert_error}
    if sc.exclude_off_domain:
        drop |= {r.domain for r in readings if r.off_domain}
    first_ip: dict[str, str] = {}
    for r in sorted(readings, key=lambda r: (r.point == "baseline", r.day)):
        if r.ip and r.domain not in first_ip:
            first_ip[r.domain] = r.ip
    out: dict[str, dict[str, str]] = defaultdict(dict)
    dom2unit: dict[str, str] = {}
    for r in readings:
        if r.domain in drop:
            continue
        k = unit_key(r, frame, sc, asn, first_ip)
        dom2unit[r.domain] = k
        s = state_of(r.verdict, sc)
        cur = out[r.point].get(k)
        if cur is None or PRECEDENCE[s] < PRECEDENCE[cur]:
            out[r.point][k] = s
    return out, dom2unit


def flapping_units(readings: list[Reading], dom2unit: dict[str, str]) -> set[str]:
    """Flapping is judged per DOMAIN (an entity with two domains on two versions is
    not a flapper) and then charged to the unit that domain belongs to."""
    seqs: dict[str, list] = defaultdict(list)
    for r in sorted(readings, key=lambda r: r.day):
        v = r.verdict.version
        seqs[r.domain].append(".".join(map(str, v)) if v else None)
    return {dom2unit[d] for d, seq in seqs.items()
            if d in dom2unit and detect.is_flapping(seq)}


def point_days(readings: list[Reading]) -> dict[str, float]:
    by: dict[str, list[float]] = defaultdict(list)
    for r in readings:
        by[r.point].append(r.day)
    return {p: sorted(ds)[len(ds) // 2] for p, ds in by.items()}


# ------------------------------------------------------------------ outcomes
def visibility(states: dict[str, str]) -> dict[str, int]:
    c = Counter(states.values())
    out = {s: c.get(s, 0) for s in STATES}
    out["P"] = sum(out[s] for s in P_STATES)
    out["V"] = sum(out[s] for s in V_STATES)
    out["units"] = len(states)
    return out


@dataclass
class Cohort:
    members: list[str]
    first_point: dict[str, str]
    curve: list[dict[str, Any]]
    intervals: list[tuple[float, float]]
    hid_without_patching: int
    flapping_excluded: int
    late_visible: int


def cohort_analysis(by_point: dict[str, dict[str, str]], days: dict[str, float],
                    flapping: set[str] | None = None) -> Cohort:
    """§7.3/§7.4. Cohort = units EXPOSED at their first observation (baseline if any)."""
    order = sorted(by_point, key=lambda p: days[p])
    live = [p for p in order if p != "baseline"]
    first: dict[str, str] = {}
    for p in order:
        for u in by_point[p]:
            first.setdefault(u, p)
    flapping = flapping or set()
    cohort = sorted(u for u, p in first.items()
                    if by_point[p][u] == "EXPOSED" and u not in flapping)
    exposed_first_flappers = sum(1 for u in flapping
                                 if u in first and by_point[first[u]][u] == "EXPOSED")
    late_visible = sum(1 for u, p in first.items() if by_point[p][u] not in V_STATES
                       and any(by_point[q].get(u) in V_STATES for q in order))

    curve = []
    for p in live:
        c = Counter(by_point[p].get(u, "ABSENT") for u in cohort if days[p] >= days[first[u]])
        row = {"point": p, "day": days[p], "cohort": sum(c.values()),
               "patched": c["PATCHED"], "exposed": c["EXPOSED"], "went_dark": c["OPAQUE"],
               "went_ambiguous": c["AMBIGUOUS"] + c["EOL"],
               "unreached": c["UNREACHED"] + c["NO_PHP"] + c["ABSENT"]}
        row["denominator"] = row["patched"] + row["exposed"]
        curve.append(row)

    intervals = []
    hid = 0
    for u in cohort:
        seq = [(days[p], by_point[p][u]) for p in order if u in by_point[p]]
        last_exposed = None
        right = float("inf")
        for d, s in seq:
            if s == "PATCHED":
                right = d
                break
            if s == "EXPOSED":
                last_exposed = d
        if last_exposed is None:
            continue
        intervals.append((last_exposed, right))
        if right == float("inf") and seq and seq[-1][1] == "OPAQUE":
            hid += 1
    return Cohort(cohort, {u: first[u] for u in cohort}, curve, intervals, hid,
                  exposed_first_flappers, late_visible)


def turnbull(intervals: list[tuple[float, float]], iters: int = 5000,
             tol: float = 1e-10) -> list[tuple[float, float]]:
    """Self-consistency NPMLE for interval-censored (L, R] times. Returns the CDF as
    [(t, F(t))] at each finite support point. Right-censored = (L, inf]."""
    if not intervals:
        return []
    support = sorted({r for _, r in intervals if r != float("inf")}) + [float("inf")]
    alpha = [[1.0 if l < s <= r else 0.0 for s in support] for l, r in intervals]
    p = [1.0 / len(support)] * len(support)
    n = len(intervals)
    for _ in range(iters):
        new = [0.0] * len(support)
        for row in alpha:
            denom = sum(a * q for a, q in zip(row, p))
            if denom <= 0:
                continue
            for j, a in enumerate(row):
                if a:
                    new[j] += a * p[j] / denom / n
        if max(abs(a - b) for a, b in zip(new, p)) < tol:
            p = new
            break
        p = new
    cdf, acc = [], 0.0
    for s, q in zip(support, p):
        if s == float("inf"):
            break
        acc += q
        cdf.append((s, acc))
    return cdf


# ------------------------------------------------------------------ disclosure
class Suppressor:
    def __init__(self, on: bool = True, below: int = SUPPRESS_BELOW):
        self.on, self.below = on, below

    def hidden(self, n: int) -> bool:
        return self.on and 0 < n < self.below

    def row(self, values: list[int], total_shown: bool = True) -> list[str]:
        """Primary + complementary suppression across one row of disjoint counts."""
        out = [("<10" if self.hidden(v) else str(v)) for v in values]
        if self.on and total_shown and sum(self.hidden(v) for v in values) == 1:
            rest = [(v, i) for i, v in enumerate(values) if v > 0 and not self.hidden(v)]
            if rest:
                out[min(rest)[1]] = "§"
        return out

    def share(self, num: int, den: int) -> str:
        if den == 0:
            return "–"
        if self.on and (self.hidden(num) or self.hidden(den - num) or den < self.below):
            return "§"
        return f"{100.0 * num / den:.0f}%"

    def count(self, n: int) -> str:
        return "<10" if self.hidden(n) else str(n)


# ------------------------------------------------------------------ report
def _table(head: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + \
           ["| " + " | ".join(r) + " |" for r in rows]


def provenance(asn_path: Path | None = None, frame_meta: dict | None = None) -> str:
    """Code commit, frame hash and ASN-table hash, so a reader can tie every table to
    the exact inputs and the pre-registered implementation (plan §7.0)."""
    import hashlib
    import subprocess
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=config.ROOT,
                                capture_output=True, text=True, timeout=5).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "src"], cwd=config.ROOT,
                               capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit, dirty = "unknown", ""
    asn = (hashlib.sha256(Path(asn_path).read_bytes()).hexdigest()[:16]
           if asn_path and Path(asn_path).exists() else "not loaded")
    fr = (frame_meta or {}).get("frame_csv_sha256", "unknown")[:16]
    return (f"- provenance: code `{commit or 'unknown'}`{' (src/ MODIFIED since commit)' if dirty else ''}"
            f"; frame sha256 `{fr}`; ASN table sha256 `{asn}`")


def build_report(conn: sqlite3.Connection, frame: Frame, event: versions.PatchEvent, *,
                 sup: Suppressor, asn: hosting.AsnTable | None = None,
                 include_mock: bool = False, frame_meta: dict | None = None,
                 label: str = "", asn_path: Path | None = None) -> str:
    live, runs = load_live(conn, frame, event, include_mock=include_mock)
    base, base_info = load_baseline(conn, frame, event)
    readings = base + live
    days = point_days(readings)
    regions = sorted({r.get("region") or "all" for r in frame.rows.values()})
    L: list[str] = [f"# Analysis {label or ''} - {event.title}".rstrip(), ""]
    L += [f"- event t0: `{event.t0_utc}`; generated {db.utc_now_iso()}",
          f"- frame: {len(frame.rows)} domains, {len(set(frame.entity_stratum))} entities; "
          f"regions: {', '.join(regions)}",
          f"- live runs analysed: {len(runs)}"
          + (" (INCLUDING MOCK RUNS - not study data)" if include_mock else ""),
          f"- archived baseline: {json.dumps(base_info)}",
          "- tribal nations' domains are not measured (PI decision D1)"
          + (f"; excluded: {json.dumps((frame_meta or {}).get('excluded_counts', {}).get('tribal_nations_by_decision_D1', {}))}"
             if frame_meta else ""),
          f"- disclosure: {'counts 1-9 shown as <10, complementary suppression marked §' if sup.on else 'UNSUPPRESSED - PI only, never publish'}",
          "- vendors, ASNs and hosting providers are never named",
          provenance(asn_path, frame_meta), ""]
    if not readings:
        L.append("No readings yet.")
        return "\n".join(L) + "\n"

    primary = Scenario()
    for region in regions:
        reg_frame = frame if region == "all" else region_frame(frame, region)
        reg_readings = [r for r in readings if r.domain in reg_frame.rows]
        if not reg_readings:
            continue
        by_point, d2u = unit_states_and_map(reg_readings, reg_frame, primary)
        L += [f"## Region: {region}", ""]
        L += _rq0(by_point, days, reg_frame, reg_readings, sup)
        L += _rq1(by_point, base_info, reg_frame, sup, reg_readings)
        co = cohort_analysis(by_point, days, flapping_units(reg_readings, d2u))
        if region in ("wisconsin", "all"):
            L += _primary(co, sup, readings, frame, days)
        L += _rq23(co, sup)
        L += _rq4(reg_readings, reg_frame, days, asn, sup)
        L += _sensitivity(reg_readings, reg_frame, days, asn, sup)
    L += _rq6(frame, readings, days, sup)
    L += _unsupported(conn, frame, runs, sup)
    L += _platforms(conn, frame, runs, sup)
    L += _election(conn, frame, runs, sup)
    L += _historical(conn, frame, sup)
    return "\n".join(L) + "\n"


def _rq0(by_point, days, frame, readings, sup) -> list[str]:
    L = ["### RQ0 - measurability (entities)", ""]
    head = ["point", "day", "units", *STATES, "P", "V", "V/P"]
    rows = []
    for p in sorted(by_point, key=lambda p: days[p]):
        v = visibility(by_point[p])
        cells = sup.row([v[s] for s in STATES])
        rows.append([p, f"{days[p]:.1f}", str(v["units"]), *cells, sup.count(v["P"]),
                     sup.count(v["V"]), sup.share(v["V"], v["P"])])
    L += _table(head, rows) + [""]
    live_pts = [p for p in by_point if p != "baseline"]
    if live_pts:
        last = max(live_pts, key=lambda p: days[p])
        L += [f"By stratum at the latest live point (`{last}`):", ""]
        strat: dict[str, dict[str, str]] = defaultdict(dict)
        for u, s in by_point[last].items():
            strat[frame.entity_stratum.get(u, "unknown")][u] = s
        rows = []
        for name in sorted(strat):
            v = visibility(strat[name])
            if v["units"] < SUPPRESS_BELOW and sup.on:
                rows.append([name, "<10", *(["§"] * (len(STATES) + 3))])
                continue
            rows.append([name, str(v["units"]), *sup.row([v[s] for s in STATES]),
                         sup.count(v["P"]), sup.count(v["V"]), sup.share(v["V"], v["P"])])
        L += _table(["stratum", "units", *STATES, "P", "V", "V/P"], rows) + [""]
        off = sum(1 for r in readings if r.point == last and r.off_domain)
        cert = sum(1 for r in readings if r.point == last and r.cert_error)
        L += [f"Domains at `{last}` redirecting off-domain (front door only classified): "
              f"{sup.count(off)}; with certificate errors: {sup.count(cert)}.", ""]
    return L


def _rq1(by_point, base_info, frame, sup, readings=()) -> list[str]:
    L = ["### RQ1 - exposure before disclosure (archived)", ""]
    if "baseline" not in by_point:
        return L + ["No pre-cutoff archived captures in this region.", ""]
    v = visibility(by_point["baseline"])
    ages = sorted(-r.day for r in readings if r.point == "baseline")
    if ages:
        L += [f"Capture age before t0 (days): median {ages[len(ages) // 2]:.0f}, "
              f"oldest {ages[-1]:.0f}.", ""]
    n_ent = len(set(frame.entity_stratum) & {frame.rows[d]["entity_id"] for d in frame.rows})
    L += [f"Entities with a pre-cutoff capture: {sup.count(v['units'])} of {n_ent} "
          f"(coverage {sup.share(v['units'], n_ent)}; NOT a random subset - CC favours "
          f"larger, linked sites).", ""]
    L += _table(["", *STATES, "P", "V", "EXPOSED among V"],
                [["baseline", *sup.row([v[s] for s in STATES]), sup.count(v["P"]),
                  sup.count(v["V"]), sup.share(v["EXPOSED"], v["V"])]]) + [""]
    return L


def primary_endpoint(co: Cohort) -> dict[str, Any]:
    """§7.0. A(d) at the last live point with whole day <= PRIMARY_DAY, and the number of
    cohort entities never observed patched by the last observation."""
    at = [c for c in co.curve if int(c["day"] // 1) <= PRIMARY_DAY]
    c = at[-1] if at else None
    return {"cohort": len(co.members), "point": c["point"] if c else None,
            "day": c["day"] if c else None,
            "patched": c["patched"] if c else None,
            "denominator": c["denominator"] if c else None,
            "never_patched": sum(1 for _, r in co.intervals if r == float("inf")),
            "contingency": len(co.members) < MIN_COHORT}


def _primary(co: Cohort, sup: Suppressor, readings: list[Reading], frame: Frame,
             days: dict[str, float]) -> list[str]:
    pe = primary_endpoint(co)
    L = ["### Primary endpoint (pre-registered, plan §7.0)", ""]
    if pe["point"] is None:
        return L + ["No live point on or before day 14 yet.", ""]
    L += [f"A({PRIMARY_DAY}) = {sup.share(pe['patched'], pe['denominator'])} "
          f"({sup.count(pe['patched'])} of {sup.count(pe['denominator'])} still-visible cohort "
          f"entities patched at `{pe['point']}`, day {pe['day']:.1f}); cohort "
          f"{sup.count(pe['cohort'])}; never observed patched by the last observation: "
          f"{sup.count(pe['never_patched'])}.", ""]
    if pe["contingency"]:
        # every region's readings against the whole frame: one pooled entity cohort
        bp, d2u = unit_states_and_map(readings, frame, Scenario())
        pco = cohort_analysis(bp, days, flapping_units(readings, d2u))
        ppe = primary_endpoint(pco)
        L += [f"**Contingency rule applies** (Wisconsin cohort < {MIN_COHORT}): Wisconsin "
              f"results are descriptive only and no median is reported. Pooled cohort across "
              f"all regions: {sup.count(ppe['cohort'])}, A({PRIMARY_DAY}) = "
              f"{sup.share(ppe['patched'] or 0, ppe['denominator'] or 0)}.", ""]
    return L


def _rq23(co: Cohort, sup: Suppressor) -> list[str]:
    L = ["### RQ2 - adoption among entities exposed when first seen", "",
         f"Cohort: {sup.count(len(co.members))} entities. Flapping entities excluded: "
         f"{sup.count(co.flapping_excluded)}. Became visible only later (reported, not in "
         f"cohort): {sup.count(co.late_visible)}.", ""]
    rows = []
    for c in co.curve:
        rows.append([c["point"], f"{c['day']:.1f}", str(c["cohort"]),
                     *sup.row([c["patched"], c["exposed"], c["went_dark"],
                               c["went_ambiguous"], c["unreached"]]),
                     sup.share(c["patched"], c["denominator"])])
    L += _table(["point", "day", "cohort", "patched", "still exposed", "went dark",
                 "went ambiguous", "unreached", "A(d)"], rows) + [""]
    L += ["### RQ3 - time to patch (Turnbull NPMLE, interval-censored)", ""]
    cdf = turnbull(co.intervals)
    still = sum(1 for _, r in co.intervals if r == float("inf"))
    if cdf:
        L += _table(["day <=", "F(t)"], [[f"{t:.1f}", f"{f:.2f}"] for t, f in cdf]) + [""]
        med = next((t for t, f in cdf if f >= 0.5), None)
        if len(co.members) < MIN_COHORT:
            L.append(f"Median not reported: cohort below {MIN_COHORT} (plan §7.0 contingency).")
        else:
            L.append(f"Median time to patch: {'not reached' if med is None else f'<= {med:.1f} days'}.")
    L += [f"Never observed patched (right-censored; includes cohort entities that later went "
          f"dark, ambiguous or unreachable): {sup.count(still)}. "
          f"Hid the version instead of patching (exposed -> opaque, never patched): "
          f"{sup.count(co.hid_without_patching)}.", ""]
    return L


def _rq4(readings, frame, days, asn, sup) -> list[str]:
    L = ["### RQ4 - shared hosting", ""]
    live = [r for r in readings if r.point != "baseline"]
    if not live:
        return L + ["No live readings yet.", ""]
    first = min({r.point for r in live}, key=lambda p: days[p])
    php = {r.domain for r in live if r.point == first
           and CLASS_TO_STATE[r.verdict.cls] in P_STATES}
    ent_ip: dict[str, str] = {}
    for r in live:
        if r.point == first and r.domain in php and r.ip:
            ent_ip.setdefault(frame.rows[r.domain]["entity_id"], r.ip)
    rows = []
    c = hosting.concentration(ent_ip.values())
    rows.append(["IP", str(c["clusters"]), sup.count(c["largest_cluster"]),
                 f"{100 * c['share_in_clusters_ge5']:.0f}%", f"{c['effective_independent']:.1f}"])
    if asn:
        c2 = hosting.concentration(f"as:{asn.lookup(ip)}" if asn.lookup(ip) else None
                                   for ip in ent_ip.values())
        rows.append(["ASN", str(c2["clusters"]), sup.count(c2["largest_cluster"]),
                     f"{100 * c2['share_in_clusters_ge5']:.0f}%", f"{c2['effective_independent']:.1f}"])
    L += [f"PHP-evidence entities at `{first}`: {sup.count(len(ent_ip))}.", ""]
    L += _table(["cluster key", "clusters", "largest", "in clusters >=5",
                 "effective independent servers"], rows) + [""]
    return L


def _sensitivity(readings, frame, days, asn, sup) -> list[str]:
    L = ["### Sensitivity analyses (§7.7) - A(d) at the latest live point", ""]
    rows = []
    for sc in (Scenario(),) + SENSITIVITY:
        if sc.unit == "asn" and asn is None:
            rows.append([sc.name, "–", "–", "–", "ASN table not loaded"])
            continue
        by_point, d2u = unit_states_and_map(readings, frame, sc, asn)
        co = cohort_analysis(by_point, days, flapping_units(readings, d2u))
        if not co.curve:
            rows.append([sc.name, sup.count(len(co.members)), "–", "–", "no live points"])
            continue
        c = co.curve[-1]
        rows.append([sc.name, sup.count(len(co.members)), sup.count(c["patched"]),
                     sup.share(c["patched"], c["denominator"]), ""])
    L += _table(["scenario", "cohort", "patched", "A(latest)", "note"], rows) + [""]
    return L


def region_frame(frame: Frame, region: str) -> Frame:
    return Frame({d: r for d, r in frame.rows.items() if (r.get("region") or "all") == region},
                 frame.entity_stratum)


def curve_by_day(readings: list[Reading], frame: Frame, days: dict[str, float],
                 sc: Scenario) -> tuple[int, dict[int, dict[str, Any]]]:
    """Cohort size and the A(d) curve keyed by whole day from t0. Wisconsin and the
    comparison states are separate snapshots (minutes apart), so curves are matched on
    the day, not on the run; the last point of a day stands for that day."""
    by_point, d2u = unit_states_and_map(readings, frame, sc)
    co = cohort_analysis(by_point, days, flapping_units(readings, d2u))
    out: dict[int, dict[str, Any]] = {}
    for c in co.curve:
        out[int(c["day"] // 1)] = c
    return len(co.members), out


def _rq6(frame: Frame, readings: list[Reading], days: dict[str, float],
         sup: Suppressor) -> list[str]:
    """§7.9: Wisconsin vs. the comparison states on matched days. Descriptive."""
    regions = {r.get("region") for r in frame.rows.values()}
    if not {"wisconsin", "comparison"} <= regions:
        return []
    live = [r for r in readings if r.point != "baseline"]
    parts = {reg: [r for r in live if frame.rows[r.domain].get("region") == reg]
             for reg in ("wisconsin", "comparison")}
    if not all(parts.values()):
        return ["## RQ6 - Wisconsin vs. comparison states", "",
                "Needs live readings from both regions.", ""]
    L = ["## RQ6 - Wisconsin vs. comparison states (descriptive, matched day)", "",
         "A(d) = patched / (patched + still exposed) in each region's cohort. The difference "
         "is in percentage points. Entity rows are the primary analysis; host-cluster rows "
         "guard against one provider's upgrade standing in for many entities. No test of "
         "significance is reported here (plan §7.9).", ""]
    for sc in (Scenario(), Scenario("host cluster (IP)", unit="ip")):
        res = {reg: curve_by_day(parts[reg], region_frame(frame, reg), days, sc)
               for reg in parts}
        rows = []
        for day in sorted(set(res["wisconsin"][1]) | set(res["comparison"][1])):
            cells, shares = [], []
            for reg in ("wisconsin", "comparison"):
                c = res[reg][1].get(day)
                if c is None:
                    cells += ["–", "–"]
                    shares.append(None)
                    continue
                sh = sup.share(c["patched"], c["denominator"])
                cells += [sup.count(c["denominator"]), sh]
                shares.append(100.0 * c["patched"] / c["denominator"]
                              if sh.endswith("%") else None)
            if any(res[reg][1].get(day) is None for reg in ("wisconsin", "comparison")):
                diff = "–"
            else:
                diff = f"{shares[0] - shares[1]:+.0f}" if None not in shares else "§"
            rows.append([str(day), *cells, diff])
        L += [f"**Unit: {'entity' if sc.unit == 'entity' else 'host cluster (IP)'}**; cohorts: "
              f"Wisconsin {sup.count(res['wisconsin'][0])}, comparison "
              f"{sup.count(res['comparison'][0])}.", ""]
        L += _table(["day", "WI denominator", "WI A(d)", "comparison denominator",
                     "comparison A(d)", "WI - comparison (pp)"], rows) + [""]
    return L


UNSUPPORTED_PRODUCTS = ("php", "apache", "nginx", "openssl")


def _unsupported(conn, frame: Frame, runs: list[dict[str, Any]], sup: Suppressor) -> list[str]:
    """EXPLORATORY, not pre-registered (see the exploratory notes): of the sites that
    show a product version in their headers, the share on a branch its maker no longer
    fixes, judged by the pinned endoflife.date table on each snapshot's own date. Counts
    only. Distro-labelled builds are counted apart: their vendor may still patch them."""
    import inventory                       # late: inventory imports this module

    from_cfg = lambda r: (json.loads(r.get("config_json") or "{}") or {}).get("region")  # noqa: E731
    regions = sorted({r.get("region") for r in frame.rows.values() if r.get("region")})
    L: list[str] = []
    for region in regions:
        reg_frame = region_frame(frame, region)
        types = {d: (row.get("stratum") or row.get("domain_type") or "Unknown")
                 for d, row in reg_frame.rows.items()}
        rows, latest = [], None
        for r in runs:
            try:
                if from_cfg(r) != region:
                    continue
            except ValueError:
                continue
            inv = inventory.aggregate_conn(conn, r["run_id"], only_domains=reg_frame.rows, types=types)
            if not inv.answering:
                continue
            latest = inv
            for p in UNSUPPORTED_PRODUCTS:
                c = inv.by_product.get(p)
                if c and (c.placed or c.eol_distro):
                    rows.append([inv.as_of, p, sup.count(c.disclosed), sup.count(c.placed),
                                 sup.count(c.eol), sup.share(c.eol, c.placed),
                                 sup.count(c.eol_distro)])
        if not rows:
            continue
        info = support_status.snapshot_info()
        L += [f"## Exploratory: unsupported software among version-showing sites - {region}", "",
              "NOT pre-registered. `placed` = sites whose headers give a version we can place "
              "on a branch, with no package-suffix ambiguity; `unsupported` = of those, on a "
              "branch past its maker's end of life on the snapshot date. "
              f"Support dates: endoflife.date, pinned {info['retrieved_on']}. IIS is not "
              "tracked. Sites that show no version are outside this table; see the coverage "
              "figure before reading a share.", ""]
        L += _table(["snapshot (UTC date)", "product", "version shown", "placed",
                     "unsupported", "share", "distro-labelled on EOL branch"], rows) + [""]
        if latest is not None:
            pub = latest.public(sup)["by_type"]
            trows = []
            for t, d in pub.items():
                for p in UNSUPPORTED_PRODUCTS:
                    cell = d.get(p)
                    if cell and cell["unsupported_basis"] not in ("0",):
                        trows.append([t, p, cell["unsupported_basis"], cell["unsupported"],
                                      cell["unsupported_share"]])
            if trows:
                L += [f"Latest snapshot ({latest.as_of}) by entity type:", ""]
                L += _table(["entity type", "product", "placed", "unsupported", "share"], trows) + [""]
    return L


ELECTION_DAY = "2026-11-03"
ELECTION_STRATUM = "Election office"


def _election(conn, frame: Frame, runs: list[dict[str, Any]], sup: Suppressor) -> list[str]:
    """EXPLORATORY, not pre-registered: the Election office stratum around the
    2026-11-03 midterm. A table is printed ONLY if every cell in it is large enough to show; if any
    snapshot has a hidden cell the whole table is replaced by one line, because a partial table of a
    small stratum is how a single office gets identified."""
    import inventory                       # late: inventory imports this module

    L: list[str] = []
    for region in sorted({r.get("region") for r in frame.rows.values() if r.get("region")}):
        reg_frame = region_frame(frame, region)
        doms = {d for d, row in reg_frame.rows.items() if row.get("stratum") == ELECTION_STRATUM}
        if not doms:
            continue
        rows, tiny = [], False
        for r in runs:
            try:
                if (json.loads(r.get("config_json") or "{}") or {}).get("region") != region:
                    continue
            except ValueError:
                continue
            inv = inventory.aggregate_conn(conn, r["run_id"], only_domains=doms)
            if not inv.answering:
                continue
            php = inv.by_product.get("php")
            cells = [inv.answering, php.named if php else 0, php.placed if php else 0, php.eol if php else 0]
            if sup.on and any(sup.hidden(c) for c in cells[:3]):
                tiny = True
            when = "before" if inv.as_of < ELECTION_DAY else "on or after"
            rows.append([inv.as_of, when, *[str(c) for c in cells]])
        if not rows:
            continue
        L += [f"## Exploratory: election-office domains around {ELECTION_DAY} - {region}", "",
              "NOT pre-registered. The stratum is small, so the table is shown only when every count in it "
              "can be shown; otherwise it is withheld whole.", ""]
        if tiny:
            L += ["Too few election-office domains with a placeable PHP version to report in this region; "
                  "nothing is shown.", ""]
        else:
            L += _table(["snapshot (UTC date)", "relative to election day", "answering", "show PHP",
                         "version placeable", "on an unsupported branch"], rows) + [""]
    return L


def _platforms(conn, frame: Frame, runs: list[dict[str, Any]], sup: Suppressor) -> list[str]:
    """EXPLORATORY, not pre-registered: who is behind the homepage. Software
    classes get generic labels; other server tokens are 'platform 1', 'platform 2' by size.
    Vendors are never named (plan §8, decision D5). Latest snapshot per region."""
    import platforms                       # late: platforms imports this module

    L: list[str] = []
    for region in sorted({r.get("region") for r in frame.rows.values() if r.get("region")}):
        reg_frame = region_frame(frame, region)
        latest = None
        for r in runs:
            try:
                if (json.loads(r.get("config_json") or "{}") or {}).get("region") != region:
                    continue
            except ValueError:
                continue
            latest = r
        if latest is None:
            continue
        t = platforms.aggregate_conn(conn, latest["run_id"], only_domains=reg_frame.rows)
        if not t.answering:
            continue
        pub = platforms.public(t, sup)
        L += [f"## Exploratory: platform and hosting concentration - {region}", "",
              f"NOT pre-registered. Snapshot {pub['as_of']}; {pub['answering']} answering domains. Vendors "
              "are never named: platforms are ranked by size. Hosting figures group sites by the "
              "address they resolved to and keep only group sizes.", ""]
        L += _table(["web server or edge, by class", "domains", "share"],
                    [[c, v["n"], v["share"]] for c, v in pub["by_category"].items()]) + [""]
        if pub["by_platform"]:
            L += _table(["server platform (largest first)", "domains", "share"],
                        [[p["platform"], p["n"], p["share"]] for p in pub["by_platform"]]) + [""]
        h = pub["hosting"]
        L += [f"- platform concentration (Herfindahl, 0 to 1): {pub['platform_hhi']}",
              f"- domains sharing a resolved address with another domain: {h['domains_sharing_an_address']} "
              f"({h['share_sharing_an_address']}); largest single address: {h['largest_address_share']}; "
              f"address-level Herfindahl: {h['address_hhi']}", ""]
        if pub["php_by_category"]:
            L += ["PHP sites with a placeable version, by class (unsupported = branch PHP no longer fixes):", ""]
            L += _table(["class", "placed", "unsupported", "share"],
                        [[c, v["placed"], v["unsupported"], v["unsupported_share"]]
                         for c, v in pub["php_by_category"].items()]) + [""]
    return L


def _historical(conn, frame, sup) -> list[str]:
    ev = versions.CVE_2024_4577
    per = load_historical(conn, frame, ev)
    per = [p for p in per if p["crawl"].startswith("CC-MAIN-2024")]
    if not per:
        return []
    L = [f"## Historical benchmark - {ev.title}", "",
         "Archived captures only; entity level; the share of version-visible entities at "
         "or above the fix, crawl by crawl. Measures ADOPTION, not exposure.", ""]
    rows = []
    for p in per:
        st = unit_states(p["readings"], frame, Scenario())
        v = visibility(next(iter(st.values()), {}))
        d = sorted(r.day for r in p["readings"])
        rows.append([p["crawl"], f"{d[len(d) // 2]:.0f}", sup.count(v["V"]),
                     sup.count(v["PATCHED"]), sup.share(v["PATCHED"], v["V"])])
    L += _table(["crawl", "median day from fix", "V", "patched", "patched among V"], rows) + [""]
    return L


# ------------------------------------------------------------------ cli
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="analyze.py", description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=str(config.DB_PATH))
    ap.add_argument("--frame", default=str(config.DATA_DIR / "wi_frame.csv"))
    ap.add_argument("--frame-meta", default=str(config.DATA_DIR / "wi_frame_meta.json"))
    ap.add_argument("--event", default=versions.PHP2SHELL.key, choices=sorted(versions.EVENTS))
    ap.add_argument("--asn-table", default=str(hosting.ASN_TABLE_PATH))
    ap.add_argument("--label", default="")
    ap.add_argument("--unsuppressed", action="store_true",
                    help="PI working copy under data/ (never reports/)")
    ap.add_argument("--include-mock", action="store_true",
                    help="analyse loopback mock runs (pipeline rehearsal only)")
    args = ap.parse_args(argv)

    event = versions.get_event(args.event)
    frame = Frame.load(args.frame)
    meta = json.loads(Path(args.frame_meta).read_text(encoding="utf-8")) \
        if Path(args.frame_meta).exists() else None
    asn = hosting.AsnTable.load(args.asn_table) if Path(args.asn_table).exists() else None
    conn = db.connect(args.db)
    sup = Suppressor(on=not args.unsuppressed)
    text = build_report(conn, frame, event, sup=sup, asn=asn, include_mock=args.include_mock,
                        frame_meta=meta, label=args.label, asn_path=Path(args.asn_table))
    name = f"analysis_{args.label or 'adhoc'}_{event.key}"
    out = (config.DATA_DIR / f"{name}_UNSUPPRESSED.md") if args.unsuppressed \
        else (config.REPORTS_DIR / f"{name}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
