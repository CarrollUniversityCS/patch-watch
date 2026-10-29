"""Repository guards: the pre-registration is frozen, and published text names no domain or person.

These run in CI and locally. They need no data directory; the frame check runs only where the
frame file exists (the collecting machine) and is skipped elsewhere.
"""

from __future__ import annotations

import csv
import hashlib
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# docs/analysis_plan.md is the pre-registration. Its section 12 deviation log may only grow by the
# PI's own dated entries; any other edit must fail here. Update this hash ONLY together with a dated
# row in section 12, in the same commit, by the PI. Line endings are normalised so Windows and
# Linux checkouts agree. Recorded 2026-10-29 from origin/main (identical bytes).
ANALYSIS_PLAN_SHA256 = "0700a23f3ebe68e8bc75815e8c999a4b8d8b4c87a97399ea49bd5fcfeda56048"

# Federal and reference hosts that may be named in public text. Anything else ending in .gov is a
# potential study subject and must not appear in docs/, dashboard/ or the README.
ALLOWED_GOV_HOSTS = {"www.cisa.gov", "cisa.gov", "www.federalregister.gov", "www.census.gov", "census.gov",
                     "doit.maryland.gov", "nvd.nist.gov", "www.nist.gov", "example.gov", "yourdomain.gov"}
ALLOWED_EMAILS = {"jforden@carrollu.edu"}

PUBLIC_TEXT = [p for pattern in ("docs/**/*.md", "docs/**/*.json", "dashboard/*.md", "dashboard/*.json", "README.md")
               for p in ROOT.glob(pattern)]


def normalised_bytes(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def test_analysis_plan_is_unchanged():
    assert hashlib.sha256(normalised_bytes(ROOT / "docs" / "analysis_plan.md")).hexdigest() == ANALYSIS_PLAN_SHA256


@pytest.mark.parametrize("path", PUBLIC_TEXT, ids=lambda p: str(p.relative_to(ROOT)))
def test_public_text_names_no_government_domain(path):
    text = path.read_text(encoding="utf-8", errors="replace").lower()
    hosts = set(re.findall(r"\b[a-z0-9][a-z0-9.-]*\.gov\b", text))
    stray = {h for h in hosts if h not in ALLOWED_GOV_HOSTS and h != "non-.gov"
             and not h.endswith(".cisa.gov") and h not in (".gov",)}
    assert not stray, f"{path.name} names {sorted(stray)}"


@pytest.mark.parametrize("path", PUBLIC_TEXT, ids=lambda p: str(p.relative_to(ROOT)))
def test_public_text_contains_no_stray_email_address(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    emails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
    stray = {e for e in emails if e.lower() not in ALLOWED_EMAILS and not e.lower().endswith("@example.org")
             and not e.lower().endswith("@example.com")}
    assert not stray, f"{path.name} contains email-shaped text: {sorted(stray)}"


def test_the_built_dashboard_names_no_government_domain():
    html = (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8").lower()
    hosts = set(re.findall(r"\b[a-z0-9][a-z0-9.-]*\.gov\b", html))
    assert hosts <= ALLOWED_GOV_HOSTS, sorted(hosts - ALLOWED_GOV_HOSTS)


def test_no_frame_domain_appears_in_public_text():
    frame = ROOT / "data" / "frame_full.csv"
    main_frame = ROOT.parents[2] / "data" / "frame_full.csv"        # the main checkout, from a worktree
    path = next((p for p in (frame, main_frame) if p.exists()), None)
    if path is None:
        pytest.skip("the registry frame is not on this machine")
    with open(path, newline="", encoding="utf-8") as fh:
        domains = {r["domain"].lower() for r in csv.DictReader(fh) if r.get("domain")}
    blob = " ".join(p.read_text(encoding="utf-8", errors="replace").lower() for p in PUBLIC_TEXT)
    blob += (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8").lower()
    # Whole host names only: "sa.gov" is a substring of "cisa.gov" and means nothing there.
    hosts = set(re.findall(r"(?<![a-z0-9.-])[a-z0-9][a-z0-9.-]*\.gov(?![a-z0-9-])", blob))
    found = sorted(h for h in hosts if h in domains and h not in ALLOWED_GOV_HOSTS)
    assert not found, f"{len(found)} frame domains appear in public text"


def test_no_database_or_domain_list_is_tracked():
    import subprocess
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split("\n")
    bad = [f for f in out if re.search(r"\.(db|sqlite3?|db-wal|db-shm)$", f)
           or re.search(r"(^|/)(frame|wi_frame|frame_full|pilot_sample)\.csv$", f)]
    assert not bad, bad


def test_live_requests_stay_off_in_this_checkout_of_the_code():
    # The Gate A flag is edited by hand on the collecting machine only and never committed.
    src = (ROOT / "src" / "config.py").read_text(encoding="utf-8")
    assert re.search(r"^LIVE_REQUESTS_ENABLED\s*=\s*False\b", src, re.M) or \
        re.search(r"^LIVE_REQUESTS_ENABLED\s*=\s*True\b", src, re.M), "the flag must be a plain assignment"
    import subprocess
    head = subprocess.run(["git", "show", "HEAD:src/config.py"], cwd=ROOT, capture_output=True, text=True).stdout
    assert re.search(r"^LIVE_REQUESTS_ENABLED\s*=\s*False\b", head, re.M), "a COMMITTED config must keep the gate shut"


def test_the_tests_workflow_asks_for_no_secrets_or_write_access():
    y = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    assert "secrets." not in y and "contents: read" in y and "write" not in y.split("permissions:")[1].split("concurrency")[0]


def test_no_csv_file_is_tracked():
    import subprocess
    out = subprocess.run(["git", "ls-files", "*.csv"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    assert not out, out


def test_the_public_notice_says_headers_and_the_resolved_address_are_kept():
    text = (ROOT / "docs" / "project_page.md").read_text(encoding="utf-8")
    keep = text[text.index("# What we keep"):text.index("# Who runs it")]
    for needle in ("response headers", "address the name resolved to", "never by the name of a hosting company"):
        assert needle in keep, needle
    assert "A small record" not in keep
