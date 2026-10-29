"""Vulnerability intake: read the exploited-vulnerability feeds, PROPOSE how measurable
each entry is, and never act on the proposal.

Intake and first-pass triage of public vulnerability data. The four-question test is applied as far as public
data allows:

  Q1  Is the product visible in response headers or the homepage?   (keyword + CPE)
  Q2  Does the fix change the version string it shows?              (known for a few products)
  Q3  Is the product common in the .gov frame?                      (header-inventory counts)
  Q4  Does a detector pass the test matrix?                         (always "unknown": a person
      and the Docker matrix decide)

Everything here is a PROPOSAL. Nothing in this module edits dashboard/catalog.json, enables
a scan, or touches the study database. The tiers are the dashboard's (dashboard.TIERS); a
proposal is never "live": only a person approves that (Gate A, plan freeze).

Network: exactly one function, `fetch_text`, reaches out, to an allow-list of public data
feeds, never to a .gov host or any host of the study frame. Everything else takes parsed
data, so tests run offline.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
CVELIST_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve}.json"
VULNRICHMENT_URL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{bucket}/{cve}.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cves}"
VULNCHECK_ENV = "VULNCHECK_API_KEY"          # a stub: never called here

ALLOWED_HOSTS = frozenset({"raw.githubusercontent.com", "api.first.org"})

# ------------------------------------------------------------------ keyword tiers
# Kept identical to the first pass in scripts/kev_triage.py, which now imports these.
A_PATTERNS = [r'\bphp\b', r'apache.*http', r'http server', r'\bnginx', r'\biis\b', r'internet information services',
     r'tomcat', r'drupal', r'wordpress', r'joomla', r'magento', r'adobe commerce', r'liferay', r'sitecore',
     r'telerik', r'sharepoint', r'craft cms', r'\bstruts', r'coldfusion', r'\.net framework', r'asp\.net',
     r'jquery', r'kentico', r'umbraco', r'progress sitefinity', r'cpanel', r'plesk', r'webmin', r'openssl']
B_PATTERNS = [r'fortios', r'fortigate', r'fortiweb', r'fortimanager', r'fortiproxy', r'fortisiem', r'forticlient ems', r'fortivoice',
     r'connect secure', r'policy secure', r'pulse', r'ivanti', r'epmm', r'mobileiron', r'netscaler', r'citrix adc', r'citrix gateway',
     r'pan-os', r'globalprotect', r'sonicwall', r'\bsma\b', r'\basa\b', r'firepower', r'ios xe', r'adaptive security', r'big-ip', r'f5',
     r'exchange', r'zimbra', r'roundcube', r'moveit', r'goanywhere', r'confluence', r'jira', r'bitbucket', r'gitlab', r'jenkins',
     r'vcenter', r'esxi', r'horizon', r'workspace one', r'connectwise', r'screenconnect', r'solarwinds', r'n-able', r'kaseya',
     r'check point', r'quantum security', r'zyxel', r'draytek', r'mikrotik', r'qnap', r'synology', r'd-link', r'netgear', r'tp-link',
     r'weblogic', r'e-business suite', r'peoplesoft', r'sap netweaver', r'jfrog', r'langflow', r'crushftp', r'wing ftp', r'arista', r'velocloud',
     r'veeam', r'commvault', r'cyberark', r'beyondtrust', r'array networks', r'sophos', r'barracuda', r'owa', r'outlook web', r'plex']

TIER_A, TIER_B, TIER_C = "A_homepage_stack", "B_edge_or_server_product", "C_client_or_local"

# Products the inventory reports (src/inventory.PRODUCTS) and the words that name them in KEV.
INVENTORY_PRODUCTS = {
    "php": (r"\bphp\b",),
    "apache": (r"apache.*http", r"http server"),
    "nginx": (r"\bnginx",),
    "iis": (r"\biis\b", r"internet information services"),
    "openssl": (r"openssl",),
    "wordpress": (r"wordpress",),
}
# Products whose upstream release changes the version string a server shows (Q2 = yes).
# Distro backports still break this for Apache, nginx and PHP: see inventory "rankable".
VERSION_STRING_CHANGES = frozenset({"php", "apache", "nginx", "openssl"})


def tier_keyword(vendor: str, product: str) -> str:
    t = f"{vendor} {product}".lower()
    if any(re.search(p, t) for p in A_PATTERNS):
        return TIER_A
    if any(re.search(p, t) for p in B_PATTERNS):
        return TIER_B
    return TIER_C


# ------------------------------------------------------------------ network (the only one)
def _host_ok(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return urlparse(url).scheme == "https" and host in ALLOWED_HOSTS and not host.endswith(".gov")


def fetch_text(url: str, cache_dir: Path | str, timeout: float = 30.0) -> str | None:
    """GET a public data feed, cached on disk by URL. Returns None on any failure; a missing
    record is data, not an error. Refuses any host not on the allow-list."""
    if not _host_ok(url):
        raise ValueError(f"refusing to fetch {url!r}: host is not an allowed public feed")
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    f = cache / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".json")
    if f.exists():
        return f.read_text(encoding="utf-8")
    req = urllib.request.Request(url, headers={"User-Agent": "patch-watch-intake (research; see repo)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 (allow-listed)
            body = r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    f.write_text(body, encoding="utf-8")
    return body


# ------------------------------------------------------------------ parsers (pure)
def load_kev(obj: dict[str, Any] | str) -> dict[str, Any]:
    """Normalise the KEV JSON: a catalog header and a list of entries sorted by date."""
    data = _as_dict(json.loads(obj) if isinstance(obj, str) else obj)
    vulns = []
    for v in _as_list(data.get("vulnerabilities")):
        if not isinstance(v, dict) or not isinstance(v.get("cveID"), str) or not v["cveID"]:
            continue
        vulns.append({
            "cve": v["cveID"], "vendor": _s(v.get("vendorProject")), "product": _s(v.get("product")),
            "name": _s(v.get("vulnerabilityName")), "added": _s(v.get("dateAdded")),
            "due": _s(v.get("dueDate")), "ransomware": _s(v.get("knownRansomwareCampaignUse")),
        })
    vulns.sort(key=lambda r: (r["added"], r["cve"]))
    return {"version": data.get("catalogVersion", ""), "released": data.get("dateReleased", ""),
            "count": len(vulns), "entries": vulns}


def record_bucket(cve: str) -> tuple[str, str] | None:
    """('2024', '4xxx') for CVE-2024-4577, the directory scheme cvelistV5 uses."""
    m = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve)
    if not m:
        return None
    return m.group(1), f"{int(m.group(2)) // 1000}xxx"


def record_urls(cve: str) -> tuple[str, str] | None:
    b = record_bucket(cve)
    if not b:
        return None
    kw = {"year": b[0], "bucket": b[1], "cve": cve}
    return CVELIST_URL.format(**kw), VULNRICHMENT_URL.format(**kw)


_CPE_RE = re.compile(r"^cpe:2\.3:([aho]):([^:]*):([^:]*):")


def extract_cpes(*records: dict[str, Any] | None) -> list[tuple[str, str, str]]:
    """(part, vendor, product) from CPE strings in CNA and ADP containers of CVE records."""
    out: set[tuple[str, str, str]] = set()

    def walk(aff: Any) -> None:
        for a in _as_list(aff):
            for c in _as_list(a.get("cpes") if isinstance(a, dict) else None):
                m = _CPE_RE.match(c) if isinstance(c, str) else None
                if m:
                    out.add((m.group(1), m.group(2).lower(), m.group(3).lower()))
    for rec in records:
        cont = _as_dict(_as_dict(rec).get("containers"))
        walk(_as_dict(cont.get("cna")).get("affected"))
        for adp in _as_list(cont.get("adp")):
            walk(_as_dict(adp).get("affected"))
    return sorted(out)


def _s(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_list(x: Any) -> list:
    return x if isinstance(x, list) else []


def _as_dict(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def extract_ssvc(rec: dict[str, Any] | None) -> dict[str, str]:
    """CISA's SSVC decision points (Exploitation, Automatable, Technical Impact), if present. A record of
    any other shape gives an empty result, never an exception."""
    res: dict[str, str] = {}
    for adp in _as_list(_as_dict(_as_dict(rec).get("containers")).get("adp")):
        for m in _as_list(_as_dict(adp).get("metrics")):
            o = _as_dict(_as_dict(m).get("other"))
            if o.get("type") == "ssvc":
                for opt in _as_list(_as_dict(o.get("content")).get("options")):
                    res.update({str(k): str(v) for k, v in _as_dict(opt).items()})
    return res


def parse_epss(text: str | None) -> dict[str, float]:
    try:
        rows = json.loads(text or "{}").get("data", [])
        return {r["cve"]: float(r["epss"]) for r in rows}
    except (ValueError, KeyError, TypeError, AttributeError):
        return {}


# ------------------------------------------------------------------ the four-question test
# A plugin, theme or helper library for a platform is not the platform: its version is not
# in a response header, and a fix to it does not change the platform's version string.
_NOT_THE_PLATFORM = re.compile(r"plugin|theme|extension|addon|add-on|phpmailer|phpunit|phpmyadmin|"
                               r"wp2|squared|proxy plug-in", re.I)


def inventory_product(vendor: str, product: str) -> str | None:
    t = f"{vendor} {product}".lower()
    if _NOT_THE_PLATFORM.search(t) or vendor.strip().lower() == "oracle":
        return None
    for key, pats in INVENTORY_PRODUCTS.items():
        if any(re.search(p, t) for p in pats):
            return key
    return None


def adjust_with_cpe(tier: str, cpes: Iterable[tuple[str, str, str]]) -> tuple[str, str]:
    """Refine a keyword tier with what the CVE record says the product is. Returns
    (tier, note). A CPE can promote an unmatched product to the appliance tier (hardware or
    operating system images are not a homepage stack), and nothing here ever promotes to A."""
    cpes = list(cpes)
    parts = {c[0] for c in cpes}
    if tier == TIER_C and "h" in parts:
        return TIER_B, "CPE names hardware: an appliance, not a homepage stack"
    return tier, ""


def four_question(entry: dict[str, Any], tier: str,
                  frame_named: dict[str, int] | None = None) -> dict[str, str]:
    """Q1-Q4 for one entry. `frame_named` is aggregate inventory counts only
    ({'php': 198, ...}); with it absent Q3 is 'unknown'."""
    prod = inventory_product(entry["vendor"], entry["product"])
    q1 = {TIER_A: "yes", TIER_B: "maybe", TIER_C: "no"}[tier]
    q2 = "yes" if prod in VERSION_STRING_CHANGES else ("unknown" if q1 != "no" else "n/a")
    if prod and frame_named is not None and prod in frame_named:
        n = frame_named[prod]
        q3 = "yes" if n >= 30 else "some" if n >= 10 else "rare"
    elif q1 == "no":
        q3 = "n/a"
    else:
        q3 = "unknown"
    return {"q1_visible": q1, "q2_version_changes": q2, "q3_common_in_frame": q3,
            "q4_detector_passes": "unknown"}


def propose(entry: dict[str, Any], tier: str, q: dict[str, str]) -> tuple[str, str]:
    """(proposed dashboard tier, reason). Never 'live' and never 'awaiting_fix'."""
    if q["q1_visible"] == "no":
        return "not_measurable", "Client or local software: it leaves no passive fingerprint in a web response."
    if q["q1_visible"] == "maybe":
        return "untriaged", ("Edge or server product: whether its version shows on a public homepage "
                             "needs a per-product check (Q1 undecided).")
    if q["q3_common_in_frame"] == "rare":
        return "archive_only", ("Homepage-visible, but rare in the frame; archived captures may be enough "
                                "and live requests are not justified (Q3).")
    if q["q2_version_changes"] == "yes":
        return "validating", ("Homepage-visible and the fix changes the version string; a detector must "
                              "pass the test matrix before any scan (Q4 open).")
    return "untriaged", "Homepage-visible, but whether the fix changes the shown version is unknown (Q2)."


# ------------------------------------------------------------------ census and sample
def build_rows(kev: dict[str, Any], cpe_by_cve: dict[str, list[tuple[str, str, str]]] | None = None,
               epss: dict[str, float] | None = None,
               frame_named: dict[str, int] | None = None) -> list[dict[str, Any]]:
    rows = []
    for e in kev["entries"]:
        tier = tier_keyword(e["vendor"], e["product"])
        note = ""
        cpes = (cpe_by_cve or {}).get(e["cve"])
        if cpes:
            tier, note = adjust_with_cpe(tier, cpes)
        q = four_question(e, tier, frame_named)
        proposed, reason = propose(e, tier, q)
        rows.append({**e, "tier": tier, "cpe_note": note, "has_cpe": bool(cpes),
                     "epss": (epss or {}).get(e["cve"]), **q, "proposed_tier": proposed, "reason": reason})
    return rows


def census_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    by_tier = Counter(r["tier"] for r in rows)
    by_proposed = Counter(r["proposed_tier"] for r in rows)
    by_year: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        by_year[r["added"][:4]][r["tier"]] += 1
    return {"n": n, "by_tier": dict(by_tier), "by_proposed": dict(by_proposed),
            "by_year": {y: dict(c) for y, c in sorted(by_year.items())},
            "with_cpe": sum(r["has_cpe"] for r in rows)}


def stratified_sample(rows: list[dict[str, Any]], size: int = 120, seed: int = 20261029) -> list[dict[str, Any]]:
    """`size` entries spread evenly over (tier, year-bucket) strata, seeded so the same input
    gives the same sample. Strata smaller than their share contribute everything they have
    and the remainder is spread over the rest."""
    def bucket(r: dict[str, Any]) -> tuple[str, str]:
        y = int(r["added"][:4]) if r["added"][:4].isdigit() else 0
        return r["tier"], ("2021-22" if y <= 2022 else "2023-24" if y <= 2024 else "2025-26")
    strata: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in sorted(rows, key=lambda r: r["cve"]):
        strata[bucket(r)].append(r)
    rng = random.Random(seed)
    for v in strata.values():
        rng.shuffle(v)
    keys = sorted(strata)
    picked: list[dict[str, Any]] = []
    quota = {k: 0 for k in keys}
    remaining = min(size, len(rows))
    active = list(keys)
    while remaining > 0 and active:
        share = max(1, remaining // len(active))
        nxt = []
        for k in active:
            take = min(share, len(strata[k]) - quota[k], remaining)
            quota[k] += take
            remaining -= take
            if quota[k] < len(strata[k]):
                nxt.append(k)
            if remaining == 0:
                break
        active = nxt
    for k in keys:
        picked += strata[k][:quota[k]]
    return sorted(picked, key=lambda r: (r["tier"], r["added"], r["cve"]))
