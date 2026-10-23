"""Stage 4b: change detection between consecutive observations of one domain.

`events_between()` is a pure function over two observation-shaped mappings so it
can be unit-tested without a database or a network. `detect_changes()` is the
sqlite driver around it.

Why flapping is separated from upgrades
---------------------------------------
The brief asks for `version_decrease or flip (possible load balancer or backend
variance)`. Both look identical in a pair of observations: a version that went
down. They mean opposite things for a patch-latency study. A rollback is rare; a
round-robin pool of half-patched backends is common, and it would show up as a
drop on the next snapshot and a rise on the one after.

So a *return to the earlier value* (A -> B -> A) is reported as `version_flip`,
not `version_decrease`, and `is_flapping()` marks a domain whose version alternates
over at least four observations. Stage 7 counts true upgrades only among domains
that are not flapping, and reports both numbers.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

# An observation as the pipeline and the analysts both hold it: either a sqlite3.Row
# straight out of db.py or a dict from a CSV/JSON export. _get() reads either.
RowLike = Any

import classify
import db
from versions import fixed_for_branch

EVENT_TYPES = (
    "version_increase",
    "version_decrease",
    "version_flip",
    "class_change",
    "header_disappeared",
    "header_appeared",
)

# The class names have exactly one source of truth: classify.CLASSES.
NO_RESPONSE = classify.CLASSES[0]

_Visible = tuple[int, int, int]


def norm_version(raw: Any) -> _Visible | None:
    """'8.3.36' -> (8, 3, 36). None when nothing is visible or it does not parse.

    observations.php_version is written by db.insert_observation from
    classify.Verdict.as_dict(): a normalized dotted triple with the distro
    package suffix already stripped, or NULL when no version was visible. A
    trailing suffix is tolerated and dropped anyway so a hand-built test row
    cannot sneak a string comparison into the ranking below.
    Integer tuples compare correctly where '8.4.9' > '8.4.27' as strings.
    """
    if raw is None:
        return None
    if isinstance(raw, (tuple, list)):
        parts = [str(x) for x in raw]
    elif isinstance(raw, str):
        raw = raw.strip()
        if not raw:
            return None
        parts = raw.split("-")[0].split("+")[0].split("~")[0].split(".")
    else:
        return None
    out: list[int] = []
    for part in parts[:3]:
        if not part.isdigit():
            return None
        out.append(int(part))
    if not out:
        return None
    while len(out) < 3:
        out.append(0)
    return (out[0], out[1], out[2])


def _get(row: Any, key: str) -> Any:
    """Read a column from an sqlite3.Row or a plain dict interchangeably."""
    if isinstance(row, Mapping):
        return row.get(key)
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


def _v(row: Any) -> _Visible | None:
    return norm_version(_get(row, "php_version"))


def backend_key(row: Any) -> tuple[str, str]:
    """(final host, resolved ip) — the coarse 'which backend answered' identity."""
    url = _get(row, "final_url") or ""
    ip = _get(row, "resolved_ip") or ""
    host = url.split("/")[2].split(":")[0].lower() if "://" in url else ""
    return (host, ip)


def _event(cur: Any, event_type: str, prev: Any, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    detail = {
        "from_run_id": _get(prev, "run_id"),
        "to_run_id": _get(cur, "run_id"),
        "from_started_at_utc": _get(prev, "started_at_utc"),
        "to_started_at_utc": _get(cur, "started_at_utc"),
        "from_backend": list(backend_key(prev)),
        "to_backend": list(backend_key(cur)),
        "backend_changed": backend_key(prev) != backend_key(cur),
    }
    if extra:
        detail.update(extra)
    return {
        "domain": _get(cur, "domain"),
        "event_type": event_type,
        "detected_at_utc": _get(cur, "started_at_utc"),
        "from_class": _get(prev, "class"),
        "to_class": _get(cur, "class"),
        "from_version": _get(prev, "php_version"),
        "to_version": _get(cur, "php_version"),
        "from_run_id": _get(prev, "run_id"),
        "to_run_id": _get(cur, "run_id"),
        "detail_json": json.dumps(detail, sort_keys=True),
    }


def is_flapping(version_seq: Iterable[str | None], min_length: int = 4) -> bool:
    """True when ANY window of `min_length` consecutive readings alternates A,B,A,B.

    Input is the ordered sequence of parsed version strings ('' or None when no
    version was visible). Only fully-visible readings participate; the sequence is
    compacted first so '8.3.35, None, 8.3.35, 8.3.36' is not called a flap.

    The scan is windowed, not whole-sequence, on purpose. A domain that reported
    8.3.30 for six weeks and only then starts alternating 8.3.35/8.3.36 — the exact
    signature of a half-patched backend joining a rotation — IS flapping. Requiring
    the entire history to alternate would call it steady and then count every one of
    its bounces as a genuine upgrade in Stage 7.

    `min_length` is the window size, and alternation is unexpressible below 3
    readings: A,B is a change, A,B,A is a flap. A 2-reading window has no index `i`
    with `i+2` in range, so its "every pair repeats" test is vacuously true and would
    call every domain with two identical readings a flapper — which, wired to
    `flapping_domains(min_length=2)`, would suppress the entire Stage 7 upgrade count.
    Hence the floor below rather than a clamp, so a caller asking for 2 is refused
    loudly by behaviour and by test rather than silently getting 3.
    """
    vals = [v for v in (norm_version(x) for x in version_seq) if v is not None]
    if min_length < 3 or len(vals) < min_length:
        return False

    def alternates(window: list[tuple[int, int, int]]) -> bool:
        # every third reading repeats the one before it: A,B,A,B...
        if len(window) < 3:
            return False
        return all(window[i] == window[i + 2] and window[i] != window[i + 1]
                   for i in range(len(window) - 2))

    return any(alternates(vals[start:start + min_length])
               for start in range(len(vals) - min_length + 1))


def events_between(prev: "RowLike", cur: "RowLike",
                   history: "Iterable[RowLike] | None" = None) -> list[dict[str, Any]]:
    """All events implied by two consecutive observations of one domain.

    `prev`/`cur`/`history` entries may be sqlite3.Row or plain dicts — this module
    reads columns through _get() so it stays usable from both the capture pipeline
    and ad-hoc analysis notebooks. Two contracts worth stating because getting them
    backwards silently changes event TYPES, not just counts:

    * `history` is the domain's readings strictly OLDER than `cur`, oldest first,
      and must NOT include `cur` itself. The flap test looks at `history[-2]`, so a
      caller that appends the current reading reports a flip as a decrease.
    * `history=None` means "no prior context". A bare A->B drop with nothing before
      it is reported as version_decrease, not version_flip: "it went down" is what
      the two readings actually show, and calling it a flip needs a third reading.
    """
    out: list[dict[str, Any]] = []
    prev_cls, cur_cls = _get(prev, "class"), _get(cur, "class")
    pv, cv = _v(prev), _v(cur)

    if prev_cls != cur_cls:
        out.append(_event(cur, "class_change", prev,
                          {"note": "one class changed between snapshots"}))

    responded = cur_cls != NO_RESPONSE
    if pv is not None and cv is None and responded:
        out.append(_event(cur, "header_disappeared", prev,
                          {"note": "version string no longer visible; may be a patch, a "
                                   "config mitigation, or simply hiding"}))
    if pv is None and cv is not None:
        out.append(_event(cur, "header_appeared", prev,
                          {"note": "version string became visible"}))

    if pv is not None and cv is not None and pv != cv:
        seq = [v for v in (norm_version(_get(h, "php_version")) for h in (history or []))
               if v is not None]
        # A -> B -> A: the current value equals the value from two readings ago.
        if len(seq) >= 2 and seq[-2] == cv and cv != pv:
            out.append(_event(cur, "version_flip", prev,
                              {"note": "value returned to the earlier reading; backend "
                                       "variance or rollback, not counted as an upgrade"}))
        elif cv > pv:
            fixed = fixed_for_branch((cv[0], cv[1]))
            out.append(_event(cur, "version_increase", prev,
                              {"branch_has_official_fix": fixed is not None,
                               # Was `fixed is None or cv >= fixed`, which is vacuously
                               # TRUE on every branch with no published fix — 8.1.90 ->
                               # 8.1.91 would report "now at or above fixed" beside
                               # "no official fix exists". Nothing is proven when there
                               # is no fixed version to be at or above; say False.
                               "now_at_or_above_fixed": fixed is not None and cv >= fixed,
                               "note": "version rose between snapshots"}))
        else:
            out.append(_event(cur, "version_decrease", prev,
                              {"note": "lower version than the previous snapshot"}))
    return out


def detect_changes(conn, run_id: str) -> list[dict[str, Any]]:
    """Compare each domain's observation in this run to the one that came BEFORE it.

    "Before" means before in time, not merely adjacent in the history list.
    db.observation_history() is chronological, so taking prior[-1] of a list that
    still contains NEWER rows compares this snapshot forward against the future and
    emits reversed events — a real upgrade read back as a version_decrease. That
    happens whenever detection re-runs over an older snapshot: a crash mid-capture,
    a backfill, or simply auditing a week of runs after the fact. Because events are
    keyed on run ids, the reversed rows would land in `events` beside the correct
    ones and quietly corrupt the Stage 7 upgrade counts. db.prior_observation() is
    the single-row form of the same `started_at_utc <` rule; this is its list twin.

    Known limits, stated rather than hidden. `limit=13` is not the flap lookback and
    does not need to be: the A->B->A rule in events_between() only reads the two
    readings before the current one, so 13 is generous (flapping_domains() is the
    caller that wants a long window, and asks for its own). And the `started_at_utc <`
    filter assumes per-observation timestamps strictly increase between runs —
    fetch.py stamps each observation with utc_now_iso(), so two snapshots captured
    inside the same second would compare equal and the earlier row would drop out,
    making the later one look like a first sighting with no events. Unreachable at one
    snapshot a day, and the reason backfills must not re-use a run id.
    """
    events: list[dict[str, Any]] = []
    rows = conn.execute(
        "SELECT * FROM observations WHERE run_id=? ORDER BY domain", (run_id,)).fetchall()
    for cur in rows:
        cur_ts = cur["started_at_utc"] or ""
        history = db.observation_history(conn, cur["domain"], limit=13)
        prior = [h for h in history
                 if h["run_id"] != run_id and (h["started_at_utc"] or "") < cur_ts]
        if not prior:
            continue
        events.extend(events_between(prior[-1], cur, history=prior))
    return events


def flapping_domains(conn, run_id: str | None = None, min_length: int = 4) -> list[str]:
    """Domains whose visible version alternates. Needs >= min_length visible readings.

    `run_id` selects WHICH DOMAINS are asked about, not the history window: the verdict
    always uses the domain's full stored history (up to `limit=50` readings, ~7 weeks of
    daily snapshots), so a domain that only began alternating in later snapshots is still
    reported. There is no "as of this run" promise here — detect_changes() is the
    point-in-time function. Callers wanting a historical cut must filter the sequence
    themselves.
    """
    q = "SELECT DISTINCT domain FROM observations"
    args: tuple = ()
    if run_id:
        q += " WHERE run_id=?"
        args = (run_id,)
    out = []
    for row in conn.execute(q, args):
        hist = db.observation_history(conn, row["domain"], limit=50)
        if is_flapping([h["php_version"] for h in hist], min_length=min_length):
            out.append(row["domain"])
    return sorted(out)
