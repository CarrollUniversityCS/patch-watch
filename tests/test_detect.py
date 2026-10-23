"""Stage-4b change-detection tests: `src/detect.py`.

Two layers, deliberately kept apart:

* `events_between()` / `norm_version()` / `is_flapping()` / `backend_key()` are
  pure functions over mappings, so most of this file hands them hand-built
  observation dicts and asserts on the returned events.
* `detect_changes()` / `flapping_domains()` are the sqlite drivers, so those get
  a real database under `tmp_path`, written through `db.insert_run` +
  `db.insert_observation` with verdicts produced by the real Stage-3 classifier.

No sockets, no `fetch.py`: the classifier is fed synthetic header dicts exactly
like `tests/test_classify.py` does, which keeps the (class, php_version) pairs in
these observations consistent with what the pipeline could actually have written.

The test that gives this module its reason to exist is
`test_small_numbered_upgrade_is_an_increase_not_a_decrease`: '8.4.9' > '8.4.27'
as strings, so a string compare calls the single most important real-world
upgrade (8.4.9 -> 8.4.27, the Oct-2026 PHP2Shell fix) a rollback.

One convention worth knowing before reading the flip tests: `detect_changes()`
passes `history=prior`, i.e. the ordered prior observations *including* `prev`
as the last element (src/detect.py:193-197). The flip rule at src/detect.py:169
then reads `history[-2]` = "the value two readings ago". A history that stops
before `prev` silently degrades a flip into a decrease.
"""

from __future__ import annotations

import json

import pytest

import classify
import db
import detect
from detect import (EVENT_TYPES, NO_RESPONSE, backend_key, detect_changes,
                    events_between, flapping_domains, is_flapping, norm_version)

# Class names, spelled once. Taken from classify.CLASSES so a rename cannot drift.
NO_PHP = classify.CLASSES[1]
HIDDEN = classify.CLASSES[2]
PATCHED = classify.CLASSES[3]
VULN = classify.CLASSES[4]
EOL = classify.CLASSES[5]
BACKPORTED = classify.CLASSES[6]

# The columns events_between() returns, and the keys it puts in detail_json.
EVENT_COLUMNS = ("domain", "event_type", "detected_at_utc", "from_class", "to_class",
                 "from_version", "to_version", "from_run_id", "to_run_id", "detail_json")
DETAIL_KEYS = ("from_run_id", "to_run_id", "from_started_at_utc", "to_started_at_utc",
               "from_backend", "to_backend", "backend_changed")


# ------------------------------------------------------------------ row builders
def row(run_id, cls, php_version, *, domain="example.gov", ts="2026-10-22T00:00:00Z",
        ip="10.0.0.1", final_url=None):
    """A minimal observation mapping: only the columns detect.py reads."""
    return {
        "domain": domain, "run_id": run_id, "started_at_utc": ts, "class": cls,
        "php_version": php_version, "resolved_ip": ip,
        "final_url": final_url or f"https://{domain}/",
    }


def prior(*versions):
    """History for events_between(), oldest first, last element == prev.

    Invisible readings are expressed as None and unparsable values as strings,
    exactly as they arrive from observations.php_version.
    """
    return [row(f"run_{i}", VULN if v else HIDDEN, v) for i, v in enumerate(versions)]


def classify_input(xpb=None, server=None, status=200, error_type=None, php_hints=None):
    """The observation dict src/classify.py consumes, from fake header values."""
    headers: dict[str, list[str]] = {}
    if xpb is not None:
        headers["x-powered-by"] = [xpb]
    if server is not None:
        headers["server"] = [server]
    return {"status_code": status, "error_type": error_type, "headers": headers,
            "php_hints": dict(php_hints or {}), "redirect_off_domain": False,
            "cert_error": False}


def verdict(**kw):
    """A real Verdict.as_dict() - the shape db.insert_observation demands."""
    return classify.classify(classify_input(**kw)).as_dict()


def obs_row(run_id, domain, started_at_utc, *, ip="10.0.0.1", status=200, error_type=None):
    """The fetch-side half of one observation (the db.OBS_COLUMNS subset we set)."""
    return {"run_id": run_id, "snapshot_label": run_id, "domain": domain,
            "started_at_utc": started_at_utc, "https_or_http": "https",
            "requested_url": f"https://{domain}/", "final_url": f"https://{domain}/",
            "status_code": status, "error_type": error_type, "resolved_ip": ip,
            "sends": 1, "latency_ms": 42}


def types(events):
    """Event types in emission order - the shape almost every assertion needs."""
    return [e["event_type"] for e in events]


def one(events, event_type):
    matches = [e for e in events if e["event_type"] == event_type]
    assert len(matches) == 1, f"expected exactly one {event_type!r} in {types(events)}"
    return matches[0]


def detail(event):
    return json.loads(event["detail_json"])


def assert_event_shape(event):
    """Column set, valid detail_json, and the cross-run bookkeeping every event carries."""
    assert set(event) == set(EVENT_COLUMNS), sorted(event)
    assert event["event_type"] in EVENT_TYPES
    d = detail(event)                          # req: detail_json is always valid JSON
    assert set(d) >= set(DETAIL_KEYS), sorted(d)
    assert isinstance(d["backend_changed"], bool)
    for key in ("from_backend", "to_backend"):
        assert isinstance(d[key], list) and len(d[key]) == 2
    if event["from_run_id"] and event["to_run_id"]:
        assert d["from_run_id"] == event["from_run_id"]
        assert d["to_run_id"] == event["to_run_id"]
        assert d["to_started_at_utc"] == event["detected_at_utc"]


# ------------------------------------------------------------- database fixtures
def make_conn(tmp_path, name="detect.sqlite"):
    conn = db.connect(tmp_path / name)
    db.init_db(conn)
    return conn


def add_run(conn, run_id, started_at_utc):
    db.insert_run(conn, {"run_id": run_id, "snapshot_label": run_id.replace("_", "-"),
                         "started_at_utc": started_at_utc, "finished_at_utc": None,
                         "sample_size": len(run_id), "attempted": 4, "responded": 4,
                         "errors": 0, "sends": 4, "kill_switch": None,
                         "user_agent": "CarrollPHPStudy/0.1", "config_json": "{}",
                         "notes": "test fixture"})


def build_runs(conn, *runs):
    """Insert (run_id, date, {domain: spec}) tuples in order.

    Each spec is classify kwargs plus optional ip. Timestamps are unique per row
    because db.observation_history() ranks by started_at_utc, not by id.
    """
    for run_id, day, specs in runs:
        add_run(conn, run_id, f"{day}T00:00:00Z")
        for i, (domain, spec) in enumerate(sorted(specs.items())):
            spec = dict(spec)
            ip = spec.pop("ip", "10.0.0.1")
            db.insert_observation(conn,
                                  obs_row(run_id, domain, f"{day}T12:{i:02d}:00Z", ip=ip),
                                  verdict(**spec))
    conn.commit()


# domain -> headers, per snapshot. Read across the three runs as one story:
#   a.gov  upgrades, then falls back to the run_1 value  -> increase, then flip
#   b.gov  never moves                                    -> no events at all
#   c.gov  stops advertising its version                  -> header_disappeared
#   d.gov  was dead, now answers patched                  -> header_appeared
#   e.gov  8.3.36 -> 8.3.35 -> 8.3.34                     -> two genuine decreases
#   f.gov  first seen in run_2                            -> no prior, no events
#   g.gov  8.4.9 -> 8.4.27                                -> the string-compare trap
RUN_1 = ("run_1", "2026-10-21", {
    "a.gov": dict(xpb="PHP/8.3.35"),
    "b.gov": dict(xpb="PHP/8.3.35"),
    "c.gov": dict(xpb="PHP/8.3.35"),
    "d.gov": dict(status=None, error_type="timeout"),
    "e.gov": dict(xpb="PHP/8.3.36"),
    "g.gov": dict(xpb="PHP/8.4.9"),
})
RUN_2 = ("run_2", "2026-10-22", {
    "a.gov": dict(xpb="PHP/8.3.36", ip="10.0.0.2"),
    "b.gov": dict(xpb="PHP/8.3.35"),
    "c.gov": dict(xpb="PHP", php_hints={"phpsessid_in_body": True}),
    "d.gov": dict(xpb="PHP/8.4.27"),
    "e.gov": dict(xpb="PHP/8.3.35"),
    "f.gov": dict(xpb="PHP/8.3.35"),
    "g.gov": dict(xpb="PHP/8.4.27"),
})
RUN_3 = ("run_3", "2026-10-23", {
    "a.gov": dict(xpb="PHP/8.3.35"),
    "b.gov": dict(xpb="PHP/8.3.35"),
    "e.gov": dict(xpb="PHP/8.3.34"),
})

EXPECTED_RUN_2 = {
    "a.gov": ["class_change", "version_increase"],
    "c.gov": ["class_change", "header_disappeared"],
    "d.gov": ["class_change", "header_appeared"],
    "e.gov": ["class_change", "version_decrease"],
    "g.gov": ["class_change", "version_increase"],
}
EXPECTED_RUN_3 = {
    "a.gov": ["class_change", "version_flip"],
    "e.gov": ["version_decrease"],
}


# ============================================================= norm_version
# Everything the crawler can put in observations.php_version, plus the shapes a
# hand-built row or a distro package release can smuggle in.
@pytest.mark.parametrize("raw, want", [
    ("8.3.36", (8, 3, 36)),
    ("8.3.35", (8, 3, 35)),
    ("8.4.27", (8, 4, 27)),
    ("8.4.9", (8, 4, 9)),
    ("8.10.0", (8, 10, 0)),
    ("8.2.100", (8, 2, 100)),
    ("  8.3.36  ", (8, 3, 36)),                    # whitespace is stripped, not fatal
    ("8.2.7-1~deb12u1", (8, 2, 7)),                # Debian package release
    ("8.1.2-1ubuntu2.20", (8, 1, 2)),              # Ubuntu
    ("8.3.20+deb.sury.org~bookworm", (8, 3, 20)),  # sury, '+' form
    ("8.5.12-1.el9_7", (8, 5, 12)),                # EL
    ("8.4", (8, 4, 0)),                            # partial -> patch .0
    ("8", (8, 0, 0)),
    ("8.3.36.1", (8, 3, 36)),                      # anything past the triple is dropped
    ("8.3.36-8.3.37", (8, 3, 36)),                 # '-' splits first: no negative rank
])
def test_norm_version_parses_visible_version_strings(raw, want):
    assert norm_version(raw) == want


@pytest.mark.parametrize("raw", [
    None, "", "   ", "beta", "8.x.36", "x.y.z", "PHP/8.3.36", "-1.2.3",
    "8.-1.2", 8.3, 8, True, {"php_version": "8.3.36"}, [8, "x", 36], (8, None, 36),
])
def test_norm_version_returns_none_when_nothing_is_rankable(raw):
    """Unparseable or absent -> None, so it can never be ranked either way.

    The float/int cases matter: `8.3` is a plausible JSON-decoded accident and a
    float has no business comparing against a version tuple.
    """
    assert norm_version(raw) is None


def test_norm_version_accepts_tuple_and_list_input():
    assert norm_version((8, 3, 36)) == (8, 3, 36)
    assert norm_version([8, 3, 36]) == (8, 3, 36)
    assert norm_version((8, 3)) == (8, 3, 0)
    assert norm_version([8]) == (8, 0, 0)
    assert norm_version((8, 3, 36, "rc")) == (8, 3, 36)
    assert norm_version(("8", "3", "36")) == (8, 3, 36)


@pytest.mark.parametrize("lo, hi", [
    ("8.4.9", "8.4.27"),      # the PHP2Shell jump on the 8.4 branch
    ("8.9.0", "8.10.0"),      # minor rolls past 9
    ("8.2.99", "8.2.100"),    # patch rolls past 99
    ("8.3.9", "8.3.10"),
])
def test_integer_tuples_rank_where_strings_do_not(lo, hi):
    """THE TRAP, stated directly: string order is the opposite of version order."""
    assert lo > hi, f"premise broken: {lo!r} > {hi!r} as strings"
    lo_v, hi_v = norm_version(lo), norm_version(hi)
    assert lo_v is not None and hi_v is not None
    assert hi_v > lo_v
    assert lo_v < hi_v
    assert lo_v != hi_v


def test_distro_suffix_cannot_smuggle_a_string_comparison():
    """A raw package release string still ranks as its upstream numbers."""
    assert norm_version("8.4.27-1~deb13u1") == (8, 4, 27)
    deb, bare = norm_version("8.4.27-1~deb13u1"), norm_version("8.4.9")
    assert deb is not None and bare is not None and deb > bare
    ubuntu, older = norm_version("8.2.100-1ubuntu2"), norm_version("8.2.99-1ubuntu2")
    assert ubuntu is not None and older is not None and ubuntu > older


# ============================================================= module constants
def test_no_response_constant_is_classifies_first_class():
    assert NO_RESPONSE == classify.CLASSES[0] == "NO_RESPONSE"


def test_event_types_are_the_six_documented_names():
    assert set(EVENT_TYPES) == {"version_increase", "version_decrease", "version_flip",
                                "class_change", "header_disappeared", "header_appeared"}


# ============================================================= backend_key
@pytest.mark.parametrize("r, want", [
    ({"final_url": "https://www.city.gov/index.php", "resolved_ip": "198.1.2.3"},
     ("www.city.gov", "198.1.2.3")),
    ({"final_url": "https://WWW.CITY.GOV/A/B", "resolved_ip": "198.1.2.3"},
     ("www.city.gov", "198.1.2.3")),                        # host is case-folded
    ({"final_url": "http://127.0.0.1:8451/case/vuln8335", "resolved_ip": "127.0.0.1"},
     ("127.0.0.1", "127.0.0.1")),                           # :port is dropped
    ({"final_url": "https://a.gov", "resolved_ip": ""}, ("a.gov", "")),
    ({"final_url": "", "resolved_ip": "9.9.9.9"}, ("", "9.9.9.9")),
    ({"final_url": "not a url", "resolved_ip": "9.9.9.9"}, ("", "9.9.9.9")),  # no scheme
    ({"final_url": None, "resolved_ip": None}, ("", "")),
    ({}, ("", "")),
])
def test_backend_key_is_host_and_ip(r, want):
    assert backend_key(r) == want


def test_backend_key_moved_by_ip_only_still_reads_as_a_different_backend():
    """Round-robin pool: same URL, another address -> the flip evidence lives here."""
    a = row("run_1", VULN, "8.3.35", ip="10.0.0.1")
    b = row("run_2", VULN, "8.3.35", ip="10.0.0.2")
    assert backend_key(a) != backend_key(b)
    same_host = row("run_2", VULN, "8.3.35", final_url="https://example.gov/other.php",
                    ip="10.0.0.1")
    assert backend_key(a) == backend_key(same_host)


# ============================================================= events_between
@pytest.mark.parametrize("lo, hi", [
    ("8.4.9", "8.4.27"),
    ("8.9.0", "8.10.0"),
    ("8.2.99", "8.2.100"),
])
def test_small_numbered_upgrade_is_an_increase_not_a_decrease(lo, hi):
    """End-to-end version of the trap: 8.4.9 -> 8.4.27 must never read as a rollback."""
    events = events_between(row("run_1", PATCHED, lo), row("run_2", PATCHED, hi))
    assert types(events) == ["version_increase"], f"{lo} -> {hi} produced {types(events)}"
    assert "version_decrease" not in types(events)
    assert "version_flip" not in types(events)


@pytest.mark.parametrize("hi, lo", [("8.4.27", "8.4.9"), ("8.10.0", "8.9.0"),
                                    ("8.2.100", "8.2.99")])
def test_the_reverse_pair_is_a_decrease_not_an_increase(hi, lo):
    events = events_between(row("run_1", PATCHED, hi), row("run_2", PATCHED, lo))
    assert types(events) == ["version_decrease"]


def test_vulnerable_to_patched_emits_both_events_and_the_fix_flags():
    """8.3.35 VULNERABLE_BY_VERSION -> 8.3.36 PATCHED_UPSTREAM is the headline event.

    It is both a class change and a version increase: Stage 7 counts the upgrade,
    the reporting counts the class move, so neither may imply the other.
    """
    prev, cur = row("run_1", VULN, "8.3.35"), row("run_2", PATCHED, "8.3.36")
    events = events_between(prev, cur)
    assert types(events) == ["class_change", "version_increase"]

    inc = one(events, "version_increase")
    assert detail(inc)["branch_has_official_fix"] is True
    assert detail(inc)["now_at_or_above_fixed"] is True

    for event in events:
        assert event["domain"] == "example.gov"
        assert event["from_class"] == VULN and event["to_class"] == PATCHED
        assert event["from_version"] == "8.3.35" and event["to_version"] == "8.3.36"
        assert event["from_run_id"] == "run_1" and event["to_run_id"] == "run_2"
        assert event["detected_at_utc"] == cur["started_at_utc"]
        assert_event_shape(event)


@pytest.mark.parametrize("branch, lo, hi", [
    ("8.2", "8.2.34", "8.2.35"),
    ("8.3", "8.3.35", "8.3.36"),
    ("8.4", "8.4.26", "8.4.27"),
    ("8.5", "8.5.11", "8.5.12"),
])
def test_crossing_the_published_fix_is_an_official_fix(branch, lo, hi):
    """Every branch in versions.FIXED_RELEASES, at the exact boundary."""
    events = events_between(row("run_1", VULN, lo), row("run_2", PATCHED, hi))
    assert types(events) == ["class_change", "version_increase"]
    assert detail(one(events, "version_increase"))["branch_has_official_fix"] is True


@pytest.mark.parametrize("lo, hi, cls", [
    ("8.1.90", "8.1.91", EOL),          # EOL branch: PHP will never ship a fixed 8.1
    ("7.4.33", "7.4.34", EOL),
    ("8.6.0", "8.6.1", PATCHED),        # newer than any known-vulnerable branch
])
def test_upgrade_on_a_branch_with_no_official_fix_is_flagged(lo, hi, cls):
    """branch_has_official_fix False AND now_at_or_above_fixed False.

    The second flag used to read `fixed is None or cv >= fixed`, which is vacuously TRUE
    whenever the branch has no published fix — so 8.1.90 -> 8.1.91 came out saying
    "no official fix exists" and "now at or above the fixed version" in the same
    detail_json. There is nothing to be at or above, so the honest answer is False.
    Fixed in src/detect.py events_between(); both flags now agree.
    """
    events = events_between(row("run_1", cls, lo), row("run_2", cls, hi))
    assert types(events) == ["version_increase"]
    d = detail(one(events, "version_increase"))
    assert d["branch_has_official_fix"] is False
    assert d["now_at_or_above_fixed"] is False


def test_class_change_alone_when_the_ranked_version_is_unchanged():
    """8.3.35 bare vs 8.3.35-1~deb13u1: same php_version, different class.

    A backport changes the interpretation, not the number, so exactly one event
    must fire and no version event may accompany it.
    """
    prev, cur = row("run_1", VULN, "8.3.35"), row("run_2", BACKPORTED, "8.3.35")
    events = events_between(prev, cur)
    assert types(events) == ["class_change"]
    assert detail(events[0])["note"] == "one class changed between snapshots"


@pytest.mark.parametrize("cls, ver", [(VULN, "8.3.35"), (HIDDEN, None),
                                      (NO_PHP, None), (NO_RESPONSE, None),
                                      (PATCHED, "8.10.0")])
def test_identical_observations_produce_no_events(cls, ver):
    r = row("run_1", cls, ver)
    assert events_between(r, dict(r)) == []
    assert events_between(r, row("run_2", cls, ver)) == []


def test_return_to_the_earlier_value_is_a_flip_not_a_decrease():
    """A -> B -> A is backend variance, and it must not be booked as a rollback."""
    history = prior("8.3.35", "8.3.36")            # last element IS prev
    events = events_between(row("run_2", VULN, "8.3.36"), row("run_3", VULN, "8.3.35"),
                            history=history)
    assert types(events) == ["version_flip"]
    assert "version_decrease" not in types(events)
    assert "backend variance" in detail(events[0])["note"]


def test_history_must_exclude_the_current_reading_or_a_flip_degrades_to_a_decrease():
    """The contract this argument has: prior readings only, oldest first, prev LAST.

    The flip branch compares history[-2] with the current value (src/detect.py:169),
    so a history that also contains `cur` shifts the two-back lookup onto `prev`
    itself and the A,B,A return is silently reported as a rollback.
    `detect_changes()` builds exactly the stops-at-prev form; every other caller in
    these tests uses prior() for the same reason.
    """
    prev, cur = row("run_2", VULN, "8.3.36"), row("run_3", VULN, "8.3.35")
    assert types(events_between(prev, cur, history=prior("8.3.35", "8.3.36"))) == \
        ["version_flip"]
    assert types(events_between(prev, cur,
                                history=prior("8.3.35", "8.3.36", "8.3.35"))) == \
        ["version_decrease"]


def test_flip_wins_even_when_the_class_moved_at_the_same_time():
    """8.3.36 PATCHED -> 8.3.35 VULN after having been 8.3.35: flip + class_change."""
    events = events_between(row("run_2", PATCHED, "8.3.36"), row("run_3", VULN, "8.3.35"),
                            history=prior("8.3.35", "8.3.36"))
    assert types(events) == ["class_change", "version_flip"]
    assert "version_decrease" not in types(events)


@pytest.mark.parametrize("history", [
    None,                                                    # first comparison ever
    prior("8.3.35"),                                         # only one prior reading
    prior("8.3.36", "8.3.35"),                               # steady rollback: 36->35->34
    prior("8.3.33", "8.3.35"),                               # never saw 8.3.34 before
    prior("8.3.33", "8.3.33", "8.3.35"),                     # plateau at a third value
])
def test_a_genuine_one_way_drop_is_a_decrease(history):
    """Nothing in the history shows 8.3.34 coming back, so this reads as a rollback."""
    events = events_between(row("run_2", VULN, "8.3.35"), row("run_3", VULN, "8.3.34"),
                            history=history)
    assert types(events) == ["version_decrease"]
    assert detail(events[0])["note"] == "lower version than the previous snapshot"


def test_invisible_and_unparsable_history_entries_do_not_create_a_flip():
    """History is compacted to rankable readings before the two-back lookup."""
    # 8.3.35, hidden, 8.3.36 -> visible [35, 36]: the return to 35 IS a flip.
    events = events_between(row("run_2", VULN, "8.3.36"), row("run_3", VULN, "8.3.35"),
                            history=prior("8.3.35", None, "8.3.36"))
    assert types(events) == ["version_flip"]
    # 8.3.35, garbage, 8.3.36 -> the garbage drops out the same way.
    events = events_between(row("run_2", VULN, "8.3.36"), row("run_3", VULN, "8.3.35"),
                            history=prior("8.3.35", "nonsense", "8.3.36"))
    assert types(events) == ["version_flip"]
    # A single visible reading in the history cannot support a two-back comparison.
    events = events_between(row("run_2", VULN, "8.3.36"), row("run_3", VULN, "8.3.35"),
                            history=prior(None, "8.3.35", None))
    assert types(events) == ["version_decrease"]


@pytest.mark.parametrize("cur_cls", [HIDDEN, NO_PHP, BACKPORTED])
def test_header_disappears_when_the_version_stops_being_visible(cur_cls):
    """The patch-or-hiding ambiguity is preserved, not resolved, by an event."""
    events = events_between(row("run_1", VULN, "8.3.35"), row("run_2", cur_cls, None))
    assert "header_disappeared" in types(events)
    assert "version_increase" not in types(events)
    assert "version_decrease" not in types(events)
    assert "version_flip" not in types(events)
    assert events[0]["event_type"] == "class_change"     # VULN -> something else
    d = detail(one(events, "header_disappeared"))
    assert "may be a patch" in d["note"]
    for event in events:
        assert_event_shape(event)


def test_header_disappeared_still_fires_when_the_class_does_not_change():
    """VULNERABLE_BY_VERSION -> VULNERABLE_BY_VERSION is impossible from one classifier,
    but the disappeared-header event must not depend on class_change."""
    events = events_between(row("run_1", VULN, "8.3.35"), row("run_2", VULN, None))
    assert types(events) == ["header_disappeared"]


@pytest.mark.parametrize("cur_ver", [None, "8.3.35"])
def test_a_dead_site_is_not_reported_as_hiding_its_header(cur_ver):
    """NO_RESPONSE means we got nothing to read; that is not a header disappearance."""
    events = events_between(row("run_1", VULN, "8.3.35"),
                            row("run_2", NO_RESPONSE, cur_ver))
    assert "header_disappeared" not in types(events)
    assert types(events) == ["class_change"]


@pytest.mark.parametrize("prev_cls, prev_ver, cur_cls", [
    (HIDDEN, None, PATCHED),
    (NO_PHP, None, VULN),
    (VULN, None, PATCHED),      # php_version NULL even though a class was assigned
])
def test_header_appears_when_the_version_becomes_visible(prev_cls, prev_ver, cur_cls):
    events = events_between(row("run_1", prev_cls, prev_ver),
                            row("run_2", cur_cls, "8.3.36"))
    assert "header_appeared" in types(events)
    assert "version_increase" not in types(events)     # nothing to rank the other side of
    assert "version_decrease" not in types(events)
    assert detail(one(events, "header_appeared"))["note"] == "version string became visible"


def test_header_appeared_without_a_class_change_is_a_lone_event():
    events = events_between(row("run_1", HIDDEN, None), row("run_2", HIDDEN, "8.3.36"))
    assert types(events) == ["header_appeared"]


def test_events_between_reads_sqlite_rows_and_dicts_identically(tmp_path):
    """_get() has to serve db.snapshot_classes() rows and test dicts alike."""
    conn = make_conn(tmp_path)
    build_runs(conn, RUN_1)
    stored = conn.execute("SELECT * FROM observations WHERE domain='c.gov'").fetchone()
    as_dict = dict(stored)
    cur = row("run_2", PATCHED, "8.3.36")
    from_row = events_between(stored, cur)
    from_dict = events_between(as_dict, cur)
    assert types(from_row) == types(from_dict) == ["class_change", "version_increase"]
    assert from_row[0]["detail_json"] == from_dict[0]["detail_json"]
    assert from_row[0]["from_class"] == VULN
    # A projection that lacks the column reads as "no version", not KeyError/IndexError.
    thin = conn.execute("SELECT domain, run_id FROM observations WHERE domain='c.gov'").fetchone()
    assert backend_key(thin) == ("", "")
    # NULL class/version on a projection degrade to "unknown -> visible", not a crash.
    assert types(events_between(thin, row("run_2", VULN, "8.3.36"))) == [
        "class_change", "header_appeared"]


# ============================================================= detail_json
@pytest.mark.parametrize("prev, cur, history", [
    (row("r1", VULN, "8.3.35"), row("r2", PATCHED, "8.3.36"), None),
    (row("r1", PATCHED, "8.3.36"), row("r2", VULN, "8.3.35"), prior("8.3.35", "8.3.36")),
    (row("r1", VULN, "8.2.99"), row("r2", VULN, "8.2.100"), None),
    (row("r1", VULN, "8.1.90"), row("r2", VULN, "8.1.91"), None),
    (row("r1", VULN, "8.3.35"), row("r2", HIDDEN, None), None),
    (row("r1", HIDDEN, None), row("r2", PATCHED, "8.3.36"), None),
    (row("r1", VULN, "8.3.35"), row("r2", NO_RESPONSE, None), None),
    (row("r1", VULN, "8.3.36"), row("r2", VULN, "8.3.34"), prior("8.3.35", "8.3.36")),
])
def test_every_event_detail_json_is_valid_and_shaped(prev, cur, history):
    events = events_between(prev, cur, history=history)
    assert events, "fixture scenario must produce at least one event to inspect"
    for event in events:
        assert_event_shape(event)


def test_backend_changed_flag_follows_the_resolved_ip():
    """Same version, another address -> the detail says which backend answered."""
    moved = events_between(row("r1", VULN, "8.3.35", ip="10.0.0.1"),
                           row("r2", PATCHED, "8.3.36", ip="10.0.0.2"))
    assert len(moved) == 2
    for event in moved:
        d = detail(event)
        assert d["backend_changed"] is True
        assert d["from_backend"] == ["example.gov", "10.0.0.1"]
        assert d["to_backend"] == ["example.gov", "10.0.0.2"]

    held = events_between(row("r1", VULN, "8.3.35", ip="10.0.0.1"),
                          row("r2", PATCHED, "8.3.36", ip="10.0.0.1"))
    assert [detail(e)["backend_changed"] for e in held] == [False, False]

    # A different host answering the same domain (redirect off-site) also counts.
    redirected = events_between(row("r1", VULN, "8.3.35"),
                                row("r2", VULN, "8.3.36", final_url="https://cdn.gov/"))
    assert all(detail(e)["backend_changed"] is True for e in redirected)


def test_a_backend_move_alone_emits_no_event():
    """Same version, same class, new IP: interesting context, not an event."""
    assert events_between(row("r1", VULN, "8.3.35", ip="10.0.0.1"),
                          row("r2", VULN, "8.3.35", ip="10.0.0.9")) == []


# ============================================================= is_flapping
@pytest.mark.parametrize("seq, want, why", [
    (["8.3.35", "8.3.36", "8.3.35", "8.3.36"], True, "A,B,A,B over four readings"),
    (["8.3.35", "8.3.36", "8.3.35", "8.3.36", "8.3.35"], True, "five readings"),
    (["8.3.35", "8.3.36", None, "8.3.35", "8.3.36"], True, "the gap drops out, 4 visible"),
    (["8.3.35", "8.3.36", "8.3.35"], False, "only three visible readings"),
    (["8.3.35", "8.3.36", None, "8.3.35"], False, "three visible after compaction"),
    (["8.3.35", None, "8.3.36", "8.3.37", "8.3.35"], False, "not alternating once compacted"),
    (["8.3.35", "8.3.36", "8.3.35", "8.4.0"], False, "fourth reading breaks the pattern"),
    (["8.3.35", "8.3.36", "8.3.37", "8.3.38"], False, "monotone: adoption, not variance"),
    (["8.3.35"] * 6, False, "one value repeated is not alternation"),
    ([], False, "empty"),
    ([None] * 6, False, "nothing visible at all"),
    (["8.3.35", "garbage", "8.3.36", "8.3.35", "8.3.36"], True, "unparsable drops out"),
    (["8.3.35-1~deb12u1", "8.3.36", "8.3.35", "8.3.36"], True, "suffix normalised first"),
    (["8.4.9", "8.4.27", "8.4.9", "8.4.27"], True, "the trap: string order would tie them"),
])
def test_is_flapping_table(seq, want, why):
    assert is_flapping(seq) is want, why


def test_flapping_is_scanned_per_window_not_over_the_whole_sequence():
    """A backend pool that JOINS the rotation late is still flapping.

    Steady for a month, then A,B,A,B: the steady prefix must not hide the flap,
    because Stage 7 uses this predicate to keep backend variance out of the "true
    upgrade" counts and a missed flap silently inflates them. The mirror case stays
    False - one bounce and then stability is a real change, not variance.
    """
    assert is_flapping(["8.3.30", "8.3.35", "8.3.36", "8.3.35", "8.3.36"]) is True
    assert is_flapping(["8.3.35", "8.3.36", "8.3.37", "8.3.36", "8.3.37"]) is True
    assert is_flapping(["8.3.35", "8.3.36", "8.3.36", "8.3.36"]) is False
    assert is_flapping(["8.3.35", "8.3.36", "8.3.36", "8.3.36", "8.3.37"]) is False


@pytest.mark.parametrize("seq, min_length, want", [
    (["8.3.35", "8.3.36", "8.3.35"], 3, True),      # explicit knob, three visible
    (["8.3.35", "8.3.36", "8.3.35"], 4, False),     # the default demands more evidence
    (["8.3.35", "8.3.36", "8.3.35", "8.3.36"], 6, False),
    (["8.3.35", "8.3.36"] * 3, 6, True),
    (["8.3.35", "8.3.36"] * 4, 8, True),
    (["8.3.30", "8.3.35", "8.3.36", "8.3.35", "8.3.36"], 4, True),   # window at the end
    (["8.3.30", "8.3.35", "8.3.36", "8.3.35", "8.3.36"], 5, False),  # prefix blocks five
    (["8.3.35", "8.3.35"], 2, False),      # the vacuous-window case, see below
    (["8.3.35", "8.3.36"] * 4, 2, False),  # a real flap, but 2 cannot PROVE one
    (["8.3.35", "8.3.36", "8.3.35"], 1, False),
])
def test_is_flapping_min_length_knob(seq, min_length, want):
    assert is_flapping(seq, min_length=min_length) is want


def test_min_length_below_three_cannot_prove_a_flap():
    """Regression, found by child A on 2026-10-23: a 2-reading window was vacuously
    'alternating', and I wrote that bug while fixing a different one.

    `all(...)` over `range(len(window) - 2)` is True for a 2-long window because there is
    no index i with i+2 in range. So with min_length=2, EVERY domain with two or more
    visible readings was called a flapper - including one that reported 8.3.35 twice and
    never moved. Verified before the fix: is_flapping(['8.3.35','8.3.35'], min_length=2)
    returned True.

    Blast radius if anyone had passed 2: Stage 7 uses this predicate to keep backend
    variance out of the 'true upgrade' counts, so every domain would have been discarded
    as noise and the study would have reported zero upgrades for the whole year. Latent
    only because every caller so far uses the default of 4.

    The fix floors at 3 instead of clamping 2 up to 3: alternation needs A,B,A to be
    distinguishable from a single change, so 'no flap provable' is the honest answer to
    a 2-reading window, and silently reading the caller's 2 as 3 would hide the mistake.
    """
    assert is_flapping(["8.3.35", "8.3.35"], min_length=2) is False
    assert is_flapping(["8.3.35", "8.3.36"], min_length=2) is False
    assert is_flapping(["8.3.35", "8.3.36", "8.3.35", "8.3.36"], min_length=2) is False
    assert is_flapping(["8.3.35", "8.3.36", "8.3.35"], min_length=0) is False
    # the same sequence at the smallest provable window IS a flap
    assert is_flapping(["8.3.35", "8.3.36", "8.3.35"], min_length=3) is True


def test_is_flapping_counts_visible_readings_not_rows():
    """Six rows, four of them visible and alternating -> flapping."""
    seq = [None, "8.3.35", "8.3.36", None, "8.3.35", "8.3.36"]
    assert is_flapping(seq) is True
    assert is_flapping(seq, min_length=5) is False


# ============================================================= detect_changes
def test_the_first_run_produces_no_events(tmp_path):
    """Nothing to compare against: run_1 is the baseline, not a wall of changes."""
    conn = make_conn(tmp_path)
    build_runs(conn, RUN_1)
    assert detect_changes(conn, "run_1") == []
    assert conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == len(RUN_1[2])


def test_second_run_events_by_domain(tmp_path):
    """One real sqlite file, two real runs, every event type the story implies."""
    conn = make_conn(tmp_path)
    build_runs(conn, RUN_1, RUN_2)

    events = detect_changes(conn, "run_2")
    by_domain: dict[str, list[str]] = {}
    for event in events:
        by_domain.setdefault(event["domain"], []).append(event["event_type"])
    assert by_domain == EXPECTED_RUN_2, f"got {by_domain}"

    # Domains with nothing to report stay out of the result entirely.
    assert "b.gov" not in by_domain and "f.gov" not in by_domain
    assert [e["domain"] for e in events] == sorted(e["domain"] for e in events)

    # The trap, end to end through the database driver.
    g = [e for e in events if e["domain"] == "g.gov"]
    assert "version_increase" in types(g) and "version_decrease" not in types(g)
    assert detail(one(g, "version_increase"))["branch_has_official_fix"] is True

    # a.gov answered from another address in run_2 (see RUN_2's ip).
    a_inc = one([e for e in events if e["domain"] == "a.gov"], "version_increase")
    assert detail(a_inc)["backend_changed"] is True
    assert a_inc["from_run_id"] == "run_1" and a_inc["to_run_id"] == "run_2"
    assert a_inc["detected_at_utc"].startswith("2026-10-22")

    for event in events:
        assert_event_shape(event)
        json.loads(event["detail_json"])       # req: valid JSON for every event

    # Re-detecting the same run is stable, and every row is insertable verbatim.
    assert types(detect_changes(conn, "run_2")) == types(events)
    assert db.insert_events(conn, events) == len(events)
    assert db.insert_events(conn, events) == 0          # UNIQUE guard, idempotent
    assert conn.execute("SELECT COUNT(*) FROM patch_events").fetchone()[0] == len(events)


def test_third_run_separates_a_flip_from_a_rollback(tmp_path):
    """a.gov returns to its run_1 value (flip); e.gov keeps falling (decrease).

    This is also the proof that detect_changes() passes `history` correctly: the
    flip branch reads history[-2], so the argument must stop at prev and must not
    contain the current reading (see src/detect.py's `started_at_utc < cur_ts` filter).
    """
    conn = make_conn(tmp_path)
    build_runs(conn, RUN_1, RUN_2, RUN_3)

    events = detect_changes(conn, "run_3")
    by_domain: dict[str, list[str]] = {}
    for event in events:
        by_domain.setdefault(event["domain"], []).append(event["event_type"])
    assert by_domain == EXPECTED_RUN_3, f"got {by_domain}"

    flip = one(events, "version_flip")
    assert flip["domain"] == "a.gov"
    assert flip["from_version"] == "8.3.36" and flip["to_version"] == "8.3.35"
    assert flip["from_run_id"] == "run_2" and flip["to_run_id"] == "run_3"
    # run_2 answered from the second backend (RUN_2's ip), run_3 from the first again:
    # the move is recorded beside the flip, which is exactly the pool signature.
    assert detail(flip)["backend_changed"] is True

    drop = one(events, "version_decrease")
    assert drop["domain"] == "e.gov"
    assert drop["from_version"] == "8.3.35" and drop["to_version"] == "8.3.34"
    assert detail(drop)["backend_changed"] is False
    for event in events:
        assert_event_shape(event)


def test_a_domain_observed_once_is_never_reported_as_changed(tmp_path):
    conn = make_conn(tmp_path)
    build_runs(conn, RUN_1, RUN_2)
    # f.gov exists only in run_2: no prior row, so no events, even though it is
    # classified VULNERABLE_BY_VERSION like its neighbours.
    assert [e for e in detect_changes(conn, "run_2") if e["domain"] == "f.gov"] == []
    assert conn.execute("SELECT COUNT(*) FROM observations WHERE domain='f.gov'").fetchone()[0] == 1


def test_detect_changes_on_an_unknown_run_is_empty(tmp_path):
    conn = make_conn(tmp_path)
    build_runs(conn, RUN_1, RUN_2)
    assert detect_changes(conn, "run_99") == []


def test_re_running_an_older_snapshot_never_compares_forward(tmp_path):
    """A snapshot is compared with the observation BEFORE it in time, never after.

    Regression guard for src/detect.py:205-216: `prior` now filters on
    started_at_utc < the current row's, not merely run_id != this one. Without that
    filter, re-running detection over run_1 while run_2 exists compared run_1 against
    its own FUTURE and emitted six reversed events - an upgrade booked as a rollback,
    keyed on run ids so it sat beside the correct rows in patch_events.
    """
    conn = make_conn(tmp_path)
    build_runs(conn, RUN_1, RUN_2)
    assert detect_changes(conn, "run_1") == []      # still the baseline, run_2 exists
    run_2_events = detect_changes(conn, "run_2")
    assert run_2_events

    build_runs(conn, RUN_3)                          # two snapshots of history behind it
    assert detect_changes(conn, "run_1") == []
    again = detect_changes(conn, "run_2")

    def key(events):
        return [(e["domain"], e["event_type"], e["from_version"], e["to_version"],
                 e["from_run_id"], e["to_run_id"]) for e in events]

    assert key(again) == key(run_2_events), "detection is not stable as runs accumulate"
    assert all(e["from_run_id"] == "run_1" and e["to_run_id"] == "run_2"
               for e in again)


# ============================================================= flapping_domains
FLAP_SEQ = {
    # 8.3.35 / 8.3.36 on every snapshot: a pool of half-patched backends.
    "flap.gov": ["PHP/8.3.35", "PHP/8.3.36", "PHP/8.3.35", "PHP/8.3.36", "PHP/8.3.35"],
    # steady adoption, never returns: an upgrade, not a flap.
    "up.gov": ["PHP/8.3.35", "PHP/8.3.35", "PHP/8.3.36", "PHP/8.3.36", "PHP/8.3.37"],
    # alternating, but only three visible readings in its whole history.
    "short.gov": ["PHP/8.3.35", "PHP/8.3.36", "PHP/8.3.35", None, None],
    # visible [35, 35, 36, 35] once the gap drops out: not A,B,A,B.
    "gap.gov": ["PHP/8.3.35", None, "PHP/8.3.35", "PHP/8.3.36", "PHP/8.3.35"],
    # one move and then it settles: the alternation fails from the second window on.
    "settle.gov": ["PHP/8.3.35", "PHP/8.3.36", "PHP/8.3.36", "PHP/8.3.36", "PHP/8.3.36"],
}
FLAP_DAYS = ["2026-10-21", "2026-10-22", "2026-10-23", "2026-10-24", "2026-10-25"]
TIMEOUT = "TIMEOUT"   # sentinel: the snapshot ran, the domain never answered


def runs_from(seq_by_domain, days=FLAP_DAYS):
    """Turn {domain: [value per run]} into build_runs() arguments.

    None means "no observation row for that run at all"; TIMEOUT means a row whose
    class is NO_RESPONSE and whose php_version is NULL.
    """
    out = []
    for i, day in enumerate(days):
        specs = {}
        for domain, vals in seq_by_domain.items():
            v = vals[i]
            if v is None:
                continue
            specs[domain] = ({"status": None, "error_type": "timeout"} if v == TIMEOUT
                             else {"xpb": v})
        out.append((f"run_{i + 1}", day, specs))
    return tuple(out)


@pytest.fixture()
def flap_db(tmp_path):
    """Five snapshots: one true flapper, four domains that must not be reported."""
    conn = make_conn(tmp_path, "flap.sqlite")
    build_runs(conn, *runs_from(FLAP_SEQ))
    return conn


def test_flapping_domains_lists_only_the_flapper(flap_db):
    assert flapping_domains(flap_db) == ["flap.gov"]


@pytest.mark.parametrize("run_id, expected", [
    ("run_1", ["flap.gov"]),
    ("run_4", ["flap.gov"]),     # short.gov is gone by now, and never flapped
    ("run_5", ["flap.gov"]),
    ("run_99", []),              # a run that never happened has no candidates
])
def test_flapping_domains_run_id_filter(flap_db, run_id, expected):
    assert flapping_domains(flap_db, run_id=run_id) == expected


@pytest.mark.parametrize("min_length, expected", [
    (4, ["flap.gov"]),
    (5, ["flap.gov"]),           # flap.gov has exactly five visible readings
    (6, []),                     # one reading short of the bar
    (2, []),                     # below 3 proves nothing; used to report ALL FIVE domains
])
def test_flapping_domains_honours_min_length(flap_db, min_length, expected):
    assert flapping_domains(flap_db, min_length=min_length) == expected


def test_flapping_domains_treats_a_timeout_row_as_an_invisible_reading(tmp_path):
    """A snapshot that never answered leaves a NULL, not a break in the flap."""
    conn = make_conn(tmp_path, "gaps.sqlite")
    seq = {"hidden.gov": ["PHP/8.3.35", "PHP/8.3.36", TIMEOUT, "PHP/8.3.35", "PHP/8.3.36"]}
    build_runs(conn, *runs_from(seq))
    hist = db.observation_history(conn, "hidden.gov")
    assert [h["php_version"] for h in hist] == ["8.3.35", "8.3.36", None, "8.3.35", "8.3.36"]
    assert [h["class"] for h in hist][2] == NO_RESPONSE
    assert flapping_domains(conn) == ["hidden.gov"]


def test_flapping_domains_run_id_selects_candidates_but_not_the_history(tmp_path):
    """run_id narrows which domains are asked about; the flap test still sees every
    reading the domain has, including ones recorded after that run (src/detect.py:210).

    late.gov is not in run_1 at all, and in run_2 it has a single visible reading -
    it is reported for both because the sequence used is its whole history.
    """
    conn = make_conn(tmp_path, "late.sqlite")
    seq = {"early.gov": ["PHP/8.3.35", "PHP/8.3.36", "PHP/8.3.35", "PHP/8.3.36",
                         "PHP/8.3.35", "PHP/8.3.36"],
           "late.gov": [None, "PHP/8.5.11", "PHP/8.5.12", "PHP/8.5.11", "PHP/8.5.12",
                        "PHP/8.5.11"]}
    build_runs(conn, *runs_from(seq, FLAP_DAYS + ["2026-10-26"]))
    assert flapping_domains(conn) == ["early.gov", "late.gov"]
    assert flapping_domains(conn, run_id="run_1") == ["early.gov"]
    assert flapping_domains(conn, run_id="run_6") == ["early.gov", "late.gov"]


def test_flapping_domains_catches_a_pool_that_joined_the_rotation_late(tmp_path):
    """The window rule end to end: steady for the first snapshots, A,B,A,B after."""
    conn = make_conn(tmp_path, "joiner.sqlite")
    seq = {"late-pool.gov": ["PHP/8.3.30", "PHP/8.3.30", "PHP/8.3.35", "PHP/8.3.36",
                             "PHP/8.3.35", "PHP/8.3.36"],
           "steady-then-settled.gov": ["PHP/8.3.30", "PHP/8.3.36", "PHP/8.3.36",
                                       "PHP/8.3.36", "PHP/8.3.36", "PHP/8.3.37"]}
    build_runs(conn, *runs_from(seq, FLAP_DAYS + ["2026-10-26"]))
    assert flapping_domains(conn) == ["late-pool.gov"]


# ============================================================= helper self-checks
def test_the_obs_helper_only_writes_real_columns():
    """If db.OBS_COLUMNS changes, this fails before a confusing sqlite error does."""
    assert set(obs_row("run_1", "example.gov", "2026-10-22T00:00:00Z")) <= set(db.OBS_COLUMNS)
    assert set(verdict(xpb="PHP/8.3.35")) == {
        "class", "reason", "php_version", "php_version_tuple", "php_version_string",
        "php_version_source", "php_branch", "fixed_version", "at_or_above_fixed",
        "distro_suffix", "distro_family", "php_evidence", "php_evidence_features",
        "header_conflict", "classify_detail"}


def test_verdict_helper_matches_the_classifier_output():
    v = verdict(xpb="PHP/8.3.35")
    assert v["class"] == VULN and v["php_version"] == "8.3.35" and v["fixed_version"] == "8.3.36"
    hidden = verdict(xpb="PHP", php_hints={"phpsessid_in_body": True})
    assert hidden["class"] == HIDDEN and hidden["php_version"] is None
    dead = verdict(status=None, error_type="timeout")
    assert dead["class"] == NO_RESPONSE and dead["php_version"] is None
    assert norm_version(dead["php_version"]) is None
