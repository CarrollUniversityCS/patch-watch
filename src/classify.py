"""Stage 3 classifier: one PHP version reading, eight classes, one class per
observation, always with a reason string.

Design rules (read before changing anything):

* Versions are compared as INTEGER TUPLES, never as strings. `8.10.2 > 8.9.9`.
* A distro package suffix means the version number no longer tracks the upstream
  release. php.net said distro/LTS vendors got the patches *in advance* and that
  the popular volunteer repo rpms.remirepo.net would have *no update on release
  day* -- so a suffix is evidence of a possible fix, never proof of one. That is
  why POSSIBLY_BACKPORTED outranks both EOL_UNFIXED and VULNERABLE_BY_VERSION.
* Absence of a version is not safety. PHP_VERSION_HIDDEN is not PATCHED.
* Nothing here looks up a distro security advisory. The pilot only sizes the
  ambiguity; resolving it is a later stage.
* Ambiguous input is classified and logged, never guessed at (brief rule 9).

Class precedence, first match wins:
  1 NO_RESPONSE          connection/timeout/non-HTTP failure
  2 <version parsed>     PATCHED_UPSTREAM | POSSIBLY_BACKPORTED |
                         EOL_UNFIXED | VULNERABLE_BY_VERSION
  3 UNPARSEABLE          a version-shaped token exists but will not parse
  4 PHP_VERSION_HIDDEN   PHP evidence, no version anywhere
  5 NO_PHP_EVIDENCE      responded, nothing indicates PHP
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from versions import (
    FIXED_RELEASES,
    SUFFIX_DISTRO_FAMILIES,
    fixed_for_branch,
    is_eol_branch,
    is_newer_branch,
)

CLASSES: tuple[str, ...] = (
    "NO_RESPONSE",
    "NO_PHP_EVIDENCE",
    "PHP_VERSION_HIDDEN",
    "PATCHED_UPSTREAM",
    "VULNERABLE_BY_VERSION",
    "EOL_UNFIXED",
    "POSSIBLY_BACKPORTED",
    "UNPARSEABLE",
)

# Class order used for reporting, most-severe-unknown first.
CLASS_ORDER: tuple[str, ...] = (
    "VULNERABLE_BY_VERSION",
    "POSSIBLY_BACKPORTED",
    "EOL_UNFIXED",
    "PATCHED_UPSTREAM",
    "PHP_VERSION_HIDDEN",
    "NO_PHP_EVIDENCE",
    "UNPARSEABLE",
    "NO_RESPONSE",
)

# `PHP/<ver>` or `PHP <ver>` inside an X-Powered-By or Server header value.
_PHP_TOKEN_RE = re.compile(r"php[\s/]*v?([^\s;,)\]]*)", re.IGNORECASE)
_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$", re.DOTALL)
# Something that looks like a package release suffix rather than a bare version.
_SUFFIX_RE = re.compile(r"^[-+~.]")


def _tup(major: str, minor: str | None, patch: str | None) -> tuple[int, int, int]:
    return (int(major), int(minor or 0), int(patch or 0))


@dataclass
class VersionRead:
    """One parsed PHP version taken from one header."""

    raw: str                       # the whole token as it appeared, e.g. "8.2.7-1~deb12u1"
    version: tuple[int, int, int] | None
    suffix: str                    # package/release suffix, "" when absent
    source: str                    # "x-powered-by" | "server"
    partial: bool = False          # patch number was absent in the string
    parsed: bool = True
    note: str = ""

    @property
    def branch(self) -> tuple[int, int] | None:
        return self.version[:2] if self.version else None


def parse_php_token(token: str, source: str) -> VersionRead | None:
    """Parse the version slot after a `PHP` marker. Returns None when the header
    mentions PHP but carries no version slot at all (-> hidden)."""
    token = (token or "").strip()
    if token == "":
        return None
    m = _VERSION_RE.match(token)
    if not m:
        return VersionRead(raw=token, version=None, suffix="", source=source, parsed=False,
                           note="version-shaped slot present but no leading digits")
    major, minor, patch, rest = m.group(1), m.group(2), m.group(3), (m.group(4) or "")
    if minor is None:
        # "PHP/8" or "PHP/x" garbage; a bare major is not a version we can rank.
        return VersionRead(raw=token, version=None, suffix="", source=source, parsed=False,
                           note=f"only a major version present ({token!r}); cannot rank a branch")
    return VersionRead(
        raw=token,
        version=_tup(major, minor, patch),
        suffix=rest,
        source=source,
        partial=(patch is None),
        parsed=True,
        note=("patch number absent, treated as .0" if patch is None else ""),
    )


def _family_from(hay: str) -> str | None:
    hay = hay.lower()
    for family, markers in SUFFIX_DISTRO_FAMILIES:
        if any(mk in hay for mk in markers):
            return family
    return None


def distro_family(version_read: VersionRead, server_comment: str = "") -> str | None:
    """Family if either evidence path fires; use distro_family_source() for both."""
    fam, _ = distro_family_source(version_read, server_comment)
    return fam


def distro_family_source(version_read: VersionRead, server_comment: str = "") -> tuple[str | None, str | None]:
    """Return (family, evidence_source) where evidence_source is one of:

    "version_suffix"  the PHP version itself carries a package release token
                      (8.2.7-1~deb12u1, 8.1.2-1ubuntu2.20, 8.3.20+deb.sury.org~...)
    "server_comment"  the version is bare but the Server header names a Linux
                      distribution (Apache/2.4.37 (Red Hat Enterprise Linux))
    None              no distro evidence

    Both mean the same thing for our purposes: the version string does not track
    an upstream PHP release, so "below fixed" does not license a vulnerability
    claim. The mission brief defines POSSIBLY_BACKPORTED on the version suffix
    only; the "server_comment" path is the SAFER READING deviation, documented in
    docs/analysis_plan.md. A bare-below-fixed version on a distro-labelled
    web server stays out of VULNERABLE_BY_VERSION.
    """
    fam = _family_from(version_read.suffix or "")
    if fam:
        return fam, "version_suffix"
    # An unrecognised but clearly-package-release suffix (-1, +20230101, ~1) is still ambiguity.
    if _SUFFIX_RE.match(version_read.suffix or ""):
        return "unknown_package_suffix", "version_suffix"
    fam = _family_from(server_comment or "")
    if fam:
        return fam, "server_comment"
    return None, None


def _header_values(headers: dict[str, list[str]] | None, name: str) -> list[str]:
    if not headers:
        return []
    return list(headers.get(name.lower(), []))


def _read_versions(headers: dict[str, list[str]] | None) -> tuple[list[VersionRead], list[VersionRead]]:
    """Return (parsed_reads, unparsed_reads) across the two header sources.

    X-Powered-By is preferred because the PHP core emits it; `Server` carries PHP
    only when mod_php appends its own token. Multiple values for one header name
    are all considered (a fronting proxy may add its own).
    """
    parsed: list[VersionRead] = []
    unparsed: list[VersionRead] = []
    for source, hdr in (("x-powered-by", "x-powered-by"), ("server", "server")):
        for value in _header_values(headers, hdr):
            for m in _PHP_TOKEN_RE.finditer(value):
                read = parse_php_token(m.group(1), source)
                if read is None:
                    continue                    # PHP mentioned, no version slot -> evidence only
                (parsed if read.parsed else unparsed).append(read)
    return parsed, unparsed


@dataclass
class Verdict:
    cls: str
    reason: str
    version: tuple[int, int, int] | None = None
    version_string: str | None = None
    version_source: str | None = None
    branch: tuple[int, int] | None = None
    fixed_version: tuple[int, int, int] | None = None
    at_or_above_fixed: bool | None = None
    distro_suffix: str = ""
    distro_family: str | None = None
    php_evidence: bool = False
    evidence: tuple[str, ...] = field(default_factory=tuple)
    header_conflict: bool = False
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "class": self.cls,
            "reason": self.reason,
            "php_version": ".".join(map(str, self.version)) if self.version else None,
            "php_version_tuple": list(self.version) if self.version else None,
            "php_version_string": self.version_string,
            "php_version_source": self.version_source,
            "php_branch": ".".join(map(str, self.branch)) if self.branch else None,
            "fixed_version": ".".join(map(str, self.fixed_version)) if self.fixed_version else None,
            "at_or_above_fixed": self.at_or_above_fixed,
            "distro_suffix": self.distro_suffix,
            "distro_family": self.distro_family,
            "php_evidence": self.php_evidence,
            "php_evidence_features": list(self.evidence),
            "header_conflict": self.header_conflict,
            "classify_detail": self.detail,
        }


def _php_evidence(headers: dict[str, list[str]] | None, php_hints: dict[str, Any] | None) -> tuple[bool, tuple[str, ...]]:
    hints = php_hints or {}
    ev: list[str] = []
    if _header_values(headers, "x-powered-by"):
        if any("php" in v.lower() for v in _header_values(headers, "x-powered-by")):
            ev.append("x_powered_by_php")
    cookie_blob = " ; ".join(_header_values(headers, "set-cookie")).lower()
    if "phpsessid" in cookie_blob:
        ev.append("phpsessid_cookie")
    if hints.get("link_or_action_has_php"):
        ev.append("php_href_or_action")
    if hints.get("phpsessid_in_body"):
        ev.append("phpsessid_body_marker")
    return (bool(ev), tuple(ev))


def classify(obs: dict[str, Any]) -> Verdict:
    """Assign exactly one class to one observation record.

    Expected keys: status_code, error_type, headers (dict[str, list[str]],
    lower-cased keys), php_hints (dict), redirect_off_domain, cert_error.
    """
    error_type = obs.get("error_type")
    status = obs.get("status_code")
    headers = obs.get("headers") or {}

    # ---- 1. NO_RESPONSE: never reached the HTTP layer, or timed out.
    if error_type and error_type not in ("ok", ""):
        return Verdict("NO_RESPONSE", f"request failed before a usable HTTP response: {error_type}",
                       detail={"error_type": error_type})
    if status is None:
        return Verdict("NO_RESPONSE", "no status code recorded", detail={"error_type": "no_status"})

    has_ev, evidence = _php_evidence(headers, obs.get("php_hints"))
    parsed, unparsed = _read_versions(headers)

    # ---- 2. A version we can rank.
    if parsed:
        # Multiple sources disagree -> almost certainly a load balancer or more
        # than one backend. Classify on X-Powered-By (PHP's own emission) and
        # flag it; change detection treats this as flap evidence, not an upgrade.
        chosen = next((p for p in parsed if p.source == "x-powered-by"), parsed[0])
        others = [p for p in parsed if p is not chosen]
        conflict = any(o.version != chosen.version for o in others)

        branch = chosen.branch
        fixed = fixed_for_branch(branch) if branch else None
        server_comment = " ".join(_header_values(headers, "server"))
        family, family_src = distro_family_source(chosen, server_comment=server_comment)
        base = dict(
            version=chosen.version,
            version_string=chosen.raw,
            version_source=chosen.source,
            branch=branch,
            distro_suffix=chosen.suffix,
            distro_family=family,
            php_evidence=True,
            evidence=evidence or ("parsed_version",),
            header_conflict=conflict,
        )
        detail: dict[str, Any] = {"chosen_raw": chosen.raw, "partial": chosen.partial, "note": chosen.note}
        if family_src:
            detail["distro_evidence"] = family_src
        if others:
            detail["other_reads"] = [f"{o.source}:{o.raw}" for o in others]
        if conflict:
            detail["conflict"] = True
        if chosen.partial:
            detail["partial_version"] = True

        if is_newer_branch(branch):
            return Verdict("PATCHED_UPSTREAM",
                           f"branch {'.'.join(map(str, branch))} is newer than the newest branch with a "
                           f"known-vulnerable release (8.5); no vulnerable release of this branch exists",
                           fixed_version=None, at_or_above_fixed=True, **{**base, "detail": detail})
        if fixed is None:
            # <= 8.1: no official fixed release exists for this branch.
            if family:
                return Verdict("POSSIBLY_BACKPORTED",
                               f"EOL branch {'.'.join(map(str, branch))} with a distro package suffix "
                               f"({chosen.suffix!r} -> {family}); vendor may have backported, PHP project will not release",
                               at_or_above_fixed=None, **{**base, "detail": {**detail, "eol_branch": True}})
            return Verdict("EOL_UNFIXED",
                           f"branch {'.'.join(map(str, branch))} is at or below 8.1: no official fixed "
                           f"release from the PHP project (source-backport branches exist for 7.4-8.1, so a "
                           f"from-source patch here is invisible to header inspection)",
                           at_or_above_fixed=None, **{**base, "detail": detail})

        at_or_above = chosen.version >= fixed
        detail["fixed"] = ".".join(map(str, fixed))
        if at_or_above:
            return Verdict("PATCHED_UPSTREAM",
                           f"{'.'.join(map(str, chosen.version))} >= fixed release {'.'.join(map(str, fixed))} "
                           f"for branch {'.'.join(map(str, branch))}",
                           fixed_version=fixed, at_or_above_fixed=True, **{**base, "detail": detail})
        if family:
            return Verdict("POSSIBLY_BACKPORTED",
                           f"{'.'.join(map(str, chosen.version))} < fixed {'.'.join(map(str, fixed))} but the "
                           f"version carries a distro package suffix ({chosen.suffix!r} -> {family}); "
                           f"backport cannot be resolved from headers alone",
                           fixed_version=fixed, at_or_above_fixed=False,
                           **{**base, "detail": {**detail, "suffix_ambiguous": True}})
        return Verdict("VULNERABLE_BY_VERSION",
                       f"{'.'.join(map(str, chosen.version))} < fixed {'.'.join(map(str, fixed))} for branch "
                       f"{'.'.join(map(str, branch))}, no distro package suffix",
                       fixed_version=fixed, at_or_above_fixed=False, **{**base, "detail": detail})

    # ---- 3. A version-shaped token that refused to parse.
    if unparsed:
        bad = unparsed[0]
        return Verdict("UNPARSEABLE",
                       f"PHP version slot present but unparseable: {bad.raw!r} ({bad.note})",
                       version_string=bad.raw, version_source=bad.source,
                       php_evidence=True, evidence=evidence or ("unparseable_version_slot",),
                       detail={"raw": bad.raw, "all_unparsed": [u.raw for u in unparsed]})

    # ---- 4. PHP is there, the version is not.
    if has_ev:
        return Verdict("PHP_VERSION_HIDDEN",
                       "PHP indicators present but no version in X-Powered-By or Server "
                       "(expose_php=Off, header stripped by a proxy, or PHP-FPM behind a "
                       "server that does not advertise it); absence of a version is NOT evidence of safety",
                       php_evidence=True, evidence=evidence,
                       detail={"cert_error": bool(obs.get("cert_error"))})

    # ---- 5. Answered, nothing about PHP.
    return Verdict("NO_PHP_EVIDENCE",
                   f"HTTP {status} response with no PHP indicator in headers or body hints",
                   php_evidence=False, detail={"status_code": status})


def class_counts(verdicts: Iterable[Verdict]) -> dict[str, int]:
    out = {c: 0 for c in CLASSES}
    for v in verdicts:
        out[v.cls] = out.get(v.cls, 0) + 1
    return out
