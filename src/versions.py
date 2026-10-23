"""Single source of truth: PHP2Shell fixed-version table.

VERIFIED 2026-10-22 against the primary source (php.net security advisory,
news archive entry 2026-10-21-5), cross-checked against CERT-EU SA 2026-018,
WatchGuard WGSA-2026-0032 and Tenable's PHP2Shell FAQ. Nothing in the mission
brief's reference table needed correcting; the brief's Oct-21-2026 date and the
four fixed releases are right.

Two additions the brief did not have, both relevant to classification:
  * PHP published *source-backport branches* for 7.4 / 8.0 / 8.1 (no official
    releases, no version-number change). A host patched from those branches
    still reports an old version string -> it lands in EOL_UNFIXED.
  * Distro/LTS vendors received the patches in ADVANCE ("Linux distributions
    and LTS vendors received the patches in advance, so check your vendor for
    updated packages", php.net advisory 2026-10-21-5). Vendors ship on their own
    schedules, so a distro-looking suffix is evidence of a *possible* fix, never
    evidence of a fix. (An earlier version of this docstring attributed a
    remirepo release-day warning to the PHP project; php.net says no such thing,
    checked 2026-10-23, and the claim is withdrawn.)

Do not import pandas/numpy here; this module is read by the classifier, the
reporter and the tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field as _field

# ---------------------------------------------------------------- disclosure clock
# The PHP project scheduled the release for 14:00 UTC on 2026-10-21 and shipped
# it early; CERT-EU logs 13:30 UTC. t0 is genuinely uncertain by ~30 min.
T0_SCHEDULED_UTC = "2026-10-21T14:00:00Z"
T0_PUBLISHED_UTC = "2026-10-21T13:30:00Z"   # CERT-EU SA 2026-018
# Operational t0 used for "day 1" arithmetic: the later of the two, i.e. the
# earliest moment every observer agrees the fixed code was downloadable.
T0_UTC = T0_SCHEDULED_UTC

T0_NOTES = {
    "vulnerability_existence_became_public": "2026-10-20 (leak ahead of coordinated disclosure)",
    "first_observed_exploitation": "2026-10-17 (Amazon Threat Intelligence MadPot; before disclosure)",
    "cve_records": ["CVE-2026-109618", "CVE-2026-109619"],
    "ghsa": {"CVE-2026-109618": "GHSA-w8hw-w9fx-j79w", "CVE-2026-109619": "GHSA-6wmf-4rv5-p3rp"},
    "cvss_v4": "9.2 (Critical) for both",
    "highest_risk_deployment": "Apache mod_php (exploitable before any application code runs)",
}

# ---------------------------------------------------------------- fixed releases
# branch -> minimum fixed upstream release, as an integer tuple.
FIXED_RELEASES: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

# Releases immediately preceding the security release. Context for reading a
# pre-disclosure baseline (e.g. Common Crawl); NOT used in classification.
PRIOR_RELEASES: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 2): (8, 2, 34),
    (8, 3): (8, 3, 35),
    (8, 4): (8, 4, 26),
    (8, 5): (8, 5, 11),
}
PRIOR_RELEASES_DATE = "2026-09-25"  # per mission brief; not re-verified from php.net

# Branches with no official fixed release. Anything <= this ceiling is EOL_UNFIXED
# unless it carries a distro package suffix (-> POSSIBLY_BACKPORTED).
SUPPORTED_BRANCHES: tuple[tuple[int, int], ...] = ((8, 2), (8, 3), (8, 4), (8, 5))
EOL_BRANCH_CEILING: tuple[int, int] = (8, 1)

BRANCH_EOL_DATES = {
    (8, 2): "2026-12-31",   # php.net: 8.2 reaches EOL 31 Dec 2026, no further releases
}

# PHP 8.6 and any future branch number: no known-vulnerable release exists, so
# "at or above fixed" is vacuously true -> PATCHED_UPSTREAM.
def fixed_for_branch(branch: tuple[int, int, int] | tuple[int, int]) -> tuple[int, int, int] | None:
    """Minimum fixed release for `branch`, or None if the branch has no official fix."""
    key = (int(branch[0]), int(branch[1]))
    return FIXED_RELEASES.get(key)


# ---------------------------------------------------------------- distro suffixes
# Package-release tokens that mean "this version string does not track upstream".
# ORDER MATTERS: '+deb.sury.org' contains 'deb', so sury must be tested first.
# Marker matching is case-insensitive substring search over the version suffix and
# the Server header's parenthesised comment.
SUFFIX_DISTRO_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sury", ("sury",)),                                   # ondrej/php PPA + deb.sury.org
    ("ubuntu", ("ubuntu",)),                               # e.g. 8.1.2-1ubuntu2.20 (incl. PHP 8.3 backported to 22.04)
    ("debian", ("deb12", "deb13", "deb11", "~deb", "deb.sury", "debian")),  # e.g. 8.2.7-1~deb12u1
    ("el", (".el7", ".el8", ".el9", ".el10", "el9_", "el8_", "remi", "rhel", "red hat", "redhat", "centos", "alma", "rocky")),
    ("amazon", ("amzn", "amazon linux",)),                 # advisory: Amazon Linux had no fix on day 1
    ("suse", ("suse", "lp15", "lp42", "opensus")),
    ("alpine", ("alpine", "-r0", "-r1", "-r2", "-r3")),
)


def is_newer_branch(branch: tuple[int, int]) -> bool:
    """True for branches above the newest known-supported one (8.5): count as patched."""
    newest = max(SUPPORTED_BRANCHES)
    return tuple(branch) > newest


def is_eol_branch(branch: tuple[int, int]) -> bool:
    """True for 8.1 and older (and 7.x, 5.x)."""
    return tuple(branch) <= EOL_BRANCH_CEILING


SOURCES = [
    "https://www.php.net/archive/2026.php#2026-10-21-5  (primary; verified 2026-10-22)",
    "https://cert.europa.eu/publications/security-advisories/2026-018",
    "https://psirt.watchguard.com/WGSA-2026-0032",
    "https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote",
    "https://www.php.net/releases/ (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35)",
]

STUDY_NAME = "PHP2Shell patch-adoption pilot"
CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")


# ---------------------------------------------------------------- events
# A patch EVENT is one fixed-version table plus the clock and branch-support facts
# that were true when it happened. The study classifies against PHP2SHELL by
# default; the other events exist so the same classifier can read archived
# (Common Crawl) headers against a different release and measure how this
# population USUALLY adopts a security fix (docs/analysis_plan.md §3, §7.8).
@dataclass(frozen=True)
class PatchEvent:
    key: str
    title: str
    t0_utc: str
    fixed_releases: dict = _field(default_factory=dict)   # (maj, min) -> (maj, min, patch)
    eol_ceiling: tuple = (8, 1)                            # branches <= this have no fix
    published: bool = True
    # Pre-release builds of a NEWER branch that already carry the fix, as
    # {(maj, min): ("RC", n)} meaning RCn and later. Anything else pre-release
    # on a newer branch is unrankable, not patched.
    prerelease_fixed: dict = _field(default_factory=dict)
    note: str = ""
    sources: tuple = ()

    @property
    def newest_supported(self) -> tuple[int, int]:
        return max(self.fixed_releases)

    def fixed_for_branch(self, branch) -> tuple[int, int, int] | None:
        return self.fixed_releases.get((int(branch[0]), int(branch[1])))

    def is_newer_branch(self, branch) -> bool:
        return tuple(branch[:2]) > self.newest_supported

    def is_eol_branch(self, branch) -> bool:
        return tuple(branch[:2]) <= self.eol_ceiling


PHP2SHELL = PatchEvent(
    key="php2shell",
    title="PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
    t0_utc=T0_UTC,
    fixed_releases=dict(FIXED_RELEASES),
    eol_ceiling=EOL_BRANCH_CEILING,
    # php.net 2026-10-21: "PHP 8.6.0 RC4 ... contains the fixes for two critical
    # vulnerabilities". RC1-RC3 predate the fix.
    prerelease_fixed={(8, 6): ("RC", 4)},
    sources=tuple(SOURCES),
)

# Historical benchmark, used ONLY on archived headers. CVE-2024-4577 (PHP-CGI
# argument injection) was exploitable only on Windows PHP-CGI in some locales, so
# this event measures how fast the population ADOPTS a critical security release,
# not how exposed it was. Fixed 2024-06-06 in 8.3.8 / 8.2.20 / 8.1.29; 8.0 was
# already EOL. Verify against php.net/ChangeLog-8.php before the plan is frozen.
CVE_2024_4577 = PatchEvent(
    key="cve_2024_4577",
    title="CVE-2024-4577 (PHP-CGI argument injection), adoption benchmark",
    t0_utc="2024-06-06T00:00:00Z",
    fixed_releases={(8, 1): (8, 1, 29), (8, 2): (8, 2, 20), (8, 3): (8, 3, 8)},
    eol_ceiling=(8, 0),
    note="Adoption benchmark only; exposure required Windows PHP-CGI.",
    sources=("https://www.php.net/ChangeLog-8.php",),
)

# Pre-committed second threshold (docs/analysis_plan.md §5.2). php.net 2026-10-23:
# the CVE-2026-115560 fix ships in the next regular release, not yet published.
# Fill fixed_releases and set published=True by a dated deviation-log entry.
CVE_2026_115560 = PatchEvent(
    key="cve_2026_115560",
    title="CVE-2026-115560 (session upload progress), secondary threshold T2",
    t0_utc="",
    fixed_releases={},
    published=False,
    note="Unpublished: classifying against it raises.",
    sources=("https://www.php.net/archive/2026.php",),
)

EVENTS: dict[str, PatchEvent] = {e.key: e for e in (PHP2SHELL, CVE_2024_4577, CVE_2026_115560)}


def get_event(key: str | None) -> PatchEvent:
    ev = EVENTS[key or PHP2SHELL.key]
    if not ev.published or not ev.fixed_releases:
        raise ValueError(f"event {ev.key!r} has no published fixed releases yet; "
                         "add them by a dated entry in docs/analysis_plan.md §12")
    return ev
