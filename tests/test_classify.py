"""Stage-3 classifier unit tests, driven from the mock_server CASES table.

Everything here is pure function calls: no sockets, no network. The rig's
fidelity on the wire is proven separately in test_mock_server.py.

Each table case is classified from a `case_to_obs()` observation built out of
its CaseSpec: header names lower-cased, values grouped into ordered lists,
duplicates preserved (exactly the shape the crawler hands the classifier).
"""

from __future__ import annotations

import pytest

from classify import CLASSES, classify, parse_php_token
from mock_server import CASES, CaseSpec


# ------------------------------------------------------------------ obs builder
def case_to_obs(spec: CaseSpec, **overrides) -> dict:
    """Turn a CaseSpec into the observation dict src/classify.py expects.

    Header names are lower-cased; values for the same name are kept in a list
    in wire order. A synthesised Location (spec.location not already present
    in spec.headers) is appended last, mirroring what the mock server emits.
    """
    headers: dict[str, list[str]] = {}
    for name, value in spec.headers:
        headers.setdefault(name.lower(), []).append(value)
    if spec.location is not None and "location" not in headers:
        headers["location"] = [spec.location]
    obs = {
        "status_code": spec.status,
        "error_type": None,
        "headers": headers,
        "php_hints": {},
        "redirect_off_domain": False,
        "cert_error": False,
    }
    obs.update(overrides)
    return obs


def verdict_for(case_name: str, **overrides):
    return classify(case_to_obs(CASES[case_name], **overrides))


# ------------------------------------------------------------- expected table
# cls is mandatory; the rest are asserted only where listed.
# reason_has: every substring must appear in Verdict.reason.
# detail_has: subset-match against Verdict.detail.
# evidence_has: every entry must appear in Verdict.evidence.
EXPECTED: dict[str, dict] = {
    # ---- versions we can rank
    "vuln8335": dict(cls="VULNERABLE_BY_VERSION", version=(8, 3, 35),
                     version_source="x-powered-by", fixed_version=(8, 3, 36),
                     at_or_above_fixed=False, header_conflict=False, php_evidence=True,
                     reason_has=["8.3.35 < fixed 8.3.36", "no distro package suffix"]),
    "patched8336": dict(cls="PATCHED_UPSTREAM", version=(8, 3, 36),
                        version_source="x-powered-by", fixed_version=(8, 3, 36),
                        at_or_above_fixed=True,
                        reason_has=["8.3.36 >= fixed release 8.3.36"]),
    "patched_exact8512": dict(cls="PATCHED_UPSTREAM", version=(8, 5, 12),
                              at_or_above_fixed=True, fixed_version=(8, 5, 12),
                              reason_has=["8.5.12 >= fixed release 8.5.12"]),
    "patched_newbranch": dict(cls="PATCHED_UPSTREAM", version=(8, 6, 0),
                              fixed_version=None, at_or_above_fixed=True,
                              reason_has=["newer than the newest branch"]),
    # ---- PHP present, version absent
    "hidden_cookie": dict(cls="PHP_VERSION_HIDDEN", version=None, php_evidence=True,
                          evidence_has=["phpsessid_cookie"],
                          reason_has=["no version"]),
    "hidden_bare_xpb": dict(cls="PHP_VERSION_HIDDEN", evidence_has=["x_powered_by_php"],
                            reason_has=["no version"]),
    "multi_set_cookie": dict(cls="PHP_VERSION_HIDDEN", evidence_has=["phpsessid_cookie"]),
    "body_hint": dict(cls="NO_PHP_EVIDENCE",   # hint NOT applied -> table row
                      reason_has=["no PHP indicator"]),
    # ---- distro suffix / distro-labelled server
    "ubuntu_suffix": dict(cls="POSSIBLY_BACKPORTED", version=(8, 1, 2),
                          distro_family="ubuntu", fixed_version=None,
                          at_or_above_fixed=None,
                          detail_has={"distro_evidence": "version_suffix", "eol_branch": True},
                          reason_has=["EOL branch 8.1", "ubuntu", "distro package suffix"]),
    "debian_suffix": dict(cls="POSSIBLY_BACKPORTED", version=(8, 2, 7),
                          distro_family="debian", fixed_version=(8, 2, 35),
                          at_or_above_fixed=False,
                          detail_has={"distro_evidence": "version_suffix", "suffix_ambiguous": True},
                          reason_has=["8.2.7 < fixed 8.2.35", "debian"]),
    "sury_suffix": dict(cls="POSSIBLY_BACKPORTED", version=(8, 3, 20),
                        distro_family="sury",
                        detail_has={"distro_evidence": "version_suffix"},
                        reason_has=["-> sury"]),
    "rhel_comment": dict(cls="POSSIBLY_BACKPORTED", version=(8, 0, 30),
                         distro_family="el",
                         detail_has={"distro_evidence": "server_comment", "eol_branch": True},
                         reason_has=["EOL branch 8.0"]),
    # ---- EOL branches with no distro evidence
    "eol81": dict(cls="EOL_UNFIXED", version=(8, 1, 9), fixed_version=None,
                  at_or_above_fixed=None,
                  reason_has=["branch 8.1 is at or below 8.1", "no official fixed"]),
    "eol74": dict(cls="EOL_UNFIXED", version=(7, 4, 33),
                  reason_has=["branch 7.4"]),
    # ---- garbage
    "garbage_word": dict(cls="UNPARSEABLE", version=None,
                         version_string="eight-point-three", version_source="x-powered-by",
                         php_evidence=True, reason_has=["unparseable", "eight-point-three"]),
    "garbage_major_only": dict(cls="UNPARSEABLE", version_string="8",
                               reason_has=["major version"]),
    # ---- no PHP at all
    "no_php": dict(cls="NO_PHP_EVIDENCE", php_evidence=False,
                   reason_has=["no PHP indicator"]),
    "iis_nophp": dict(cls="NO_PHP_EVIDENCE", reason_has=["no PHP indicator"]),
    "no_content": dict(cls="NO_PHP_EVIDENCE", reason_has=["HTTP 204"]),
    "status_503": dict(cls="NO_PHP_EVIDENCE", reason_has=["HTTP 503"]),
    "status_403": dict(cls="NO_PHP_EVIDENCE", reason_has=["HTTP 403"]),
    # ---- conflicting header reads (classifier prefers X-Powered-By)
    "conflict_headers": dict(cls="PATCHED_UPSTREAM", version=(8, 3, 36),
                             version_source="x-powered-by", header_conflict=True,
                             detail_has={"other_reads": ["server:8.3.35"], "conflict": True},
                             reason_has=["8.3.36 >= fixed release 8.3.36"]),
    "two_xpb_values": dict(cls="VULNERABLE_BY_VERSION", version=(8, 3, 35),
                           header_conflict=True,
                           detail_has={"other_reads": ["x-powered-by:8.4.26"]},
                           reason_has=["8.3.35 < fixed 8.3.36"]),
    # ---- redirects (classifier is status-agnostic; Location is ignored)
    "crossdomain_redirect": dict(cls="VULNERABLE_BY_VERSION", version=(8, 3, 35)),
    "same_domain_redirect": dict(cls="NO_PHP_EVIDENCE"),
    "same_domain_final": dict(cls="PATCHED_UPSTREAM", version=(8, 4, 27),
                              at_or_above_fixed=True, fixed_version=(8, 4, 27),
                              reason_has=["8.4.27 >= fixed release 8.4.27"]),
    "redirect_loop": dict(cls="NO_PHP_EVIDENCE"),
    # ---- statuses / transport shapes (class pinned: classifier does not gate on status)
    "status_429": dict(cls="VULNERABLE_BY_VERSION", version=(8, 3, 35)),
    "slow_short": dict(cls="VULNERABLE_BY_VERSION", version=(8, 3, 35)),
    "slow_35s": dict(cls="VULNERABLE_BY_VERSION", version=(8, 3, 35)),
    "big_body": dict(cls="VULNERABLE_BY_VERSION", version=(8, 2, 34),
                     fixed_version=(8, 2, 35), at_or_above_fixed=False,
                     reason_has=["8.2.34 < fixed 8.2.35"]),
    "https_bad_cert": dict(cls="VULNERABLE_BY_VERSION", version=(8, 3, 35)),
    "http_only_case": dict(cls="VULNERABLE_BY_VERSION", version=(8, 4, 26),
                           fixed_version=(8, 4, 27)),
}


def test_table_covers_every_case():
    assert set(EXPECTED) == set(CASES), "CASES table and EXPECTED table drifted apart"


def test_table_covers_seven_of_eight_classes():
    # NO_RESPONSE cannot come from a served case; it is covered by edge tests below.
    got = {e["cls"] for e in EXPECTED.values()}
    assert set(CLASSES) - got == {"NO_RESPONSE"}


@pytest.mark.parametrize("case_name", sorted(EXPECTED))
def test_case_classifies_as_pinned(case_name):
    exp = EXPECTED[case_name]
    v = verdict_for(case_name)
    assert v.cls == exp["cls"], f"{case_name}: {v.cls!r} (reason: {v.reason})"
    for field in ("version", "version_source", "distro_family", "header_conflict",
                  "fixed_version", "at_or_above_fixed", "php_evidence", "version_string"):
        if field in exp:
            assert getattr(v, field) == exp[field], f"{case_name}.{field}"
    for frag in exp.get("reason_has", []):
        assert frag in v.reason, f"{case_name}: reason {v.reason!r} lacks {frag!r}"
    for key, want in exp.get("detail_has", {}).items():
        assert v.detail.get(key) == want, f"{case_name}: detail[{key!r}]={v.detail.get(key)!r}"
    for ev in exp.get("evidence_has", []):
        assert ev in v.evidence, f"{case_name}: evidence {v.evidence} lacks {ev!r}"
    assert v.cls in CLASSES and v.reason


# ------------------------------------------------------------------ per-case twists
def test_body_hint_flag_decides_the_class():
    """Same served bytes; the crawler's php_hints flip the class."""
    hidden = verdict_for("body_hint", php_hints={"link_or_action_has_php": True})
    assert hidden.cls == "PHP_VERSION_HIDDEN"
    assert "php_href_or_action" in hidden.evidence
    plain = verdict_for("body_hint", php_hints={"link_or_action_has_php": False})
    assert plain.cls == "NO_PHP_EVIDENCE"


def test_cert_error_flag_recorded_but_does_not_change_class():
    v = verdict_for("https_bad_cert", cert_error=True)
    assert v.cls == "VULNERABLE_BY_VERSION"
    h = verdict_for("hidden_cookie", cert_error=True)
    assert h.cls == "PHP_VERSION_HIDDEN" and h.detail["cert_error"] is True


def test_sury_family_wins_over_debian_marker_order():
    """'+deb.sury.org' contains 'deb'; family lookup must not call it debian."""
    v = verdict_for("sury_suffix")
    assert v.distro_family == "sury"
    assert v.distro_family != "debian"


def test_two_xpb_values_first_wins_actual_behaviour():
    """Documented behaviour: with two X-Powered-By values the FIRST parses as the
    chosen read (lowest/earliest wins), the second lands in other_reads, and the
    response is flagged as a header conflict rather than silently merged."""
    v = verdict_for("two_xpb_values")
    assert v.version == (8, 3, 35) and v.header_conflict is True
    assert v.detail["other_reads"] == ["x-powered-by:8.4.26"]


def test_as_dict_roundtrip():
    d = verdict_for("vuln8335").as_dict()
    assert d["class"] == "VULNERABLE_BY_VERSION"
    assert d["php_version"] == "8.3.35"
    assert d["php_version_tuple"] == [8, 3, 35]
    assert d["fixed_version"] == "8.3.36"
    assert d["header_conflict"] is False


# ------------------------------------------------------------------ pure-string edges
def _obs(xpb=None, server=None, status=200, **ov):
    headers: dict[str, list[str]] = {}
    if xpb is not None:
        headers["x-powered-by"] = [xpb]
    if server is not None:
        headers["server"] = [server]
    base = {"status_code": status, "error_type": None, "headers": headers,
            "php_hints": {}, "redirect_off_domain": False, "cert_error": False}
    base.update(ov)
    return base


def test_integer_tuple_ranking_8_10_beats_8_9():
    """A string compare gets this exactly backwards; the classifier must not."""
    assert "8.10.2" < "8.9.9"          # lexicographic trap, documented
    hi = parse_php_token("8.10.2", "x-powered-by")
    lo = parse_php_token("8.9.9", "x-powered-by")
    assert hi.version > lo.version
    v_hi = classify(_obs(xpb="PHP/8.10.2"))
    v_lo = classify(_obs(xpb="PHP/8.9.9"))
    assert v_hi.cls == v_lo.cls == "PATCHED_UPSTREAM"   # both on future branches
    assert v_hi.version == (8, 10, 2) and v_lo.version == (8, 9, 9)


def test_branch_minor_ranking_inside_supported_branch():
    # 8.2.10 > 8.2.9 numerically even though "8.2.10" < "8.2.9" as strings.
    assert parse_php_token("8.2.10", "x-powered-by").version > \
        parse_php_token("8.2.9", "x-powered-by").version
    assert classify(_obs(xpb="PHP/8.2.10")).version == (8, 2, 10)


def test_boundary_just_below_and_exactly_fixed_82():
    below = classify(_obs(xpb="PHP/8.2.34"))
    assert below.cls == "VULNERABLE_BY_VERSION"
    assert below.at_or_above_fixed is False and below.fixed_version == (8, 2, 35)
    exact = classify(_obs(xpb="PHP/8.2.35"))
    assert exact.cls == "PATCHED_UPSTREAM"
    assert exact.at_or_above_fixed is True
    above = classify(_obs(xpb="PHP/8.2.36"))
    assert above.cls == "PATCHED_UPSTREAM"


def test_empty_header_values_are_no_evidence():
    assert classify(_obs(xpb="")).cls == "NO_PHP_EVIDENCE"
    assert classify(_obs(server="")).cls == "NO_PHP_EVIDENCE"
    assert classify(_obs(headers={"x-powered-by": [""], "server": ["", ""]})).cls == "NO_PHP_EVIDENCE"


def test_aspnet_powered_by_is_no_php():
    v = classify(_obs(xpb="ASP.NET"))
    assert v.cls == "NO_PHP_EVIDENCE"
    assert v.php_evidence is False


def test_missing_status_is_no_response():
    v = classify(_obs(xpb="PHP/8.3.35", status=None))
    assert v.cls == "NO_RESPONSE"
    assert "no status code" in v.reason


@pytest.mark.parametrize("err", ["timeout", "connect_refused", "dns_error", "read_error"])
def test_error_types_are_no_response(err):
    v = classify(_obs(xpb="PHP/8.3.35", error_type=err))
    assert v.cls == "NO_RESPONSE"
    assert err in v.reason


def test_error_type_ok_is_not_no_response():
    assert classify(_obs(xpb="PHP/8.3.35", error_type="ok")).cls == "VULNERABLE_BY_VERSION"
    assert classify(_obs(xpb="PHP/8.3.35", error_type="")).cls == "VULNERABLE_BY_VERSION"


# ---------------------------------------------------------- precedence, one per rule
def test_precedence_no_response_beats_version():
    assert classify(_obs(xpb="PHP/8.3.35", status=None)).cls == "NO_RESPONSE"


def test_precedence_suffix_beats_eol():
    """8.1 is EOL, but a distro package suffix outranks EOL_UNFIXED."""
    v = verdict_for("ubuntu_suffix")
    assert v.cls == "POSSIBLY_BACKPORTED" and v.detail["eol_branch"] is True
    bare = classify(_obs(xpb="PHP/8.1.2"))          # same branch, no suffix
    assert bare.cls == "EOL_UNFIXED"


def test_precedence_suffix_beats_vulnerable():
    v = verdict_for("debian_suffix")
    assert v.cls == "POSSIBLY_BACKPORTED"
    bare = classify(_obs(xpb="PHP/8.2.7"))          # same number, no suffix
    assert bare.cls == "VULNERABLE_BY_VERSION"


def test_precedence_unparseable_beats_hidden():
    """A PHPSESSID cookie is PHP evidence, but a broken version slot outranks HIDDEN."""
    v = classify(_obs(headers={"x-powered-by": ["PHP/eight-point-three"],
                               "set-cookie": ["PHPSESSID=abc; path=/"]}))
    assert v.cls == "UNPARSEABLE"


def test_precedence_parsed_version_beats_unparseable():
    """Server header garbage does not veto a parseable X-Powered-By read."""
    v = classify({"status_code": 200, "error_type": None,
                  "headers": {"x-powered-by": ["PHP/8.3.36"],
                              "server": ["Apache PHP/nonsense"]},
                  "php_hints": {}, "redirect_off_domain": False, "cert_error": False})
    assert v.cls == "PATCHED_UPSTREAM" and v.version == (8, 3, 36)


def test_precedence_x_powered_by_chosen_over_server():
    v = verdict_for("conflict_headers")
    assert v.version_source == "x-powered-by" and v.version == (8, 3, 36)


def test_server_header_alone_can_carry_the_version():
    v = classify(_obs(server="Apache/2.4.62 PHP/8.4.27"))
    assert v.cls == "PATCHED_UPSTREAM" and v.version_source == "server"


def test_partial_version_treated_as_dot_zero():
    v = classify(_obs(xpb="PHP/8.3"))
    assert v.cls == "VULNERABLE_BY_VERSION" and v.version == (8, 3, 0)
    assert v.detail["partial_version"] is True
    assert "patch number absent" in v.detail["note"]


def test_space_separated_php_token_parses():
    v = classify(_obs(xpb="PHP 8.5.12"))
    assert v.cls == "PATCHED_UPSTREAM" and v.version == (8, 5, 12)


def test_phpsessid_body_marker_counts_as_hidden():
    v = classify(_obs(server="nginx/1.27.4", php_hints={"phpsessid_in_body": True}))
    assert v.cls == "PHP_VERSION_HIDDEN"
    assert "phpsessid_body_marker" in v.evidence
