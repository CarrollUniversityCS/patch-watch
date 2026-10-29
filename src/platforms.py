"""Platform and hosting concentration (exploratory).

Who actually runs the web server behind a .gov homepage: a self-run Apache or nginx, an edge
network in front of it, a site-builder service, or one vendor's stack shared by many
governments? If a few platforms front most sites, patch speed is partly their decision, and one
platform's flaw is correlated risk across many governments.

Named `platforms` (not `platform`) on purpose: a module called `platform` here would shadow
the standard library's whenever `src/` is first on the import path.

Rules (docs/analysis_plan.md §8, decision D5):

* Counts only. Nothing per domain leaves this module; IP addresses are grouped and then only
  cluster SIZES are kept.
* Vendors are NOT named. Software classes get generic labels ("edge network", "self-run web
  server"); other server tokens are shown as "platform 1", "platform 2" ... in order of size.
  `NAME_VENDORS` (default False) exists so the PI can change that after sign-off; it is not
  switched on anywhere, and a test fails if the default changes.
* Counts of 1-9 print as "<10" (the project's suppression), and platforms with fewer than ten
  sites are folded into "other platforms" before any ranking is shown.
"""

from __future__ import annotations

import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

import inventory
from analyze import SUPPRESS_BELOW, Suppressor

NAME_VENDORS = False          # decision D5 belongs to the PI; never enabled here

SELF_RUN = "self-run web server"
EDGE = "edge network in front"
BUILDER = "hosted site builder"
MICROSOFT = "Microsoft web stack"
OTHER = "other or unidentified"
NO_HEADER = "no identifying server header"
CATEGORIES = (SELF_RUN, MICROSOFT, EDGE, BUILDER, OTHER, NO_HEADER)

# Software classes, matched on the Server header token and on a few telltale headers. These
# are software names in CODE; results use the generic labels above.
_EDGE_TOKENS = ("cloudflare", "akamaighost", "akamainetworkstorage", "cloudfront", "fastly", "sucuri",
                "incapsula", "imperva", "stackpath", "azure front door", "bigip", "big-ip", "netscaler",
                "barracuda", "awselb", "envoy")
_EDGE_HEADERS = ("cf-ray", "x-amz-cf-id", "x-amz-cf-pop", "x-akamai-transformed", "x-sucuri-id",
                 "x-iinfo", "x-azure-ref", "x-fastly-request-id", "x-served-by")
_BUILDER_TOKENS = ("squarespace", "pepyaka", "weebly", "wix", "shopify", "godaddy website builder")
_MICROSOFT_TOKENS = ("microsoft-iis", "microsoft-httpapi")
_SELF_RUN_TOKENS = ("apache", "nginx", "litespeed", "openresty", "caddy", "lighttpd", "tomcat",
                    "jetty", "gunicorn", "kestrel", "varnish")
_TOKEN_RE = re.compile(r"^\s*([A-Za-z0-9_.\-+ ]+?)(?:/[^\s(]*)?(?:\s*\(.*)?\s*$")


def server_token(headers: Any) -> str:
    """Lower-case product token of the first Server value, version and comment removed:
    'Apache/2.4.58 (Ubuntu)' -> 'apache'. '' when there is no Server header."""
    h = inventory._norm_headers(headers)
    for v in h.get("server", []):
        m = _TOKEN_RE.match(v)
        tok = (m.group(1) if m else v).strip().lower()
        tok = re.sub(r"\s+", " ", tok)
        if tok:
            return tok[:40]
    return ""


def platform_of(headers: Any) -> tuple[str, str]:
    """(generic category, token). The token is used for concentration counts and is never
    printed unless NAME_VENDORS is on."""
    h = inventory._norm_headers(headers)
    tok = server_token(h)
    if any(t in tok for t in _BUILDER_TOKENS):
        return BUILDER, tok
    if any(t in tok for t in _EDGE_TOKENS) or any(k in h for k in _EDGE_HEADERS):
        return EDGE, tok or "(edge headers only)"
    if any(t in tok for t in _MICROSOFT_TOKENS) or any("asp.net" in v.lower() for v in h.get("x-powered-by", [])):
        return MICROSOFT, tok or "microsoft-iis"
    if any(t in tok for t in _SELF_RUN_TOKENS):
        return SELF_RUN, tok
    if tok:
        return OTHER, tok
    return NO_HEADER, ""


# ------------------------------------------------------------------ aggregation
@dataclass
class PlatformTable:
    answering: int = 0
    by_category: Counter = field(default_factory=Counter)
    by_token: Counter = field(default_factory=Counter)
    ip_cluster_sizes: list[int] = field(default_factory=list)       # sizes only, never addresses
    php_by_category: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    as_of: str = ""


def hhi(counts: Iterable[int]) -> float | None:
    """Herfindahl-Hirschman index of a set of counts, 0 to 1. None for an empty set."""
    c = [n for n in counts if n > 0]
    total = sum(c)
    if not total:
        return None
    return sum((n / total) ** 2 for n in c)


_PHP_RANKED = {"PATCHED_UPSTREAM": "patched", "VULNERABLE_BY_VERSION": "exposed", "EOL_UNFIXED": "eol"}


def aggregate_conn(conn: sqlite3.Connection, run_id: str | None = None, region: str = "wisconsin", *,
                   only_domains: Iterable[str] | None = None) -> PlatformTable:
    conn.row_factory = sqlite3.Row
    run = run_id or inventory.latest_run(conn, region)
    t = PlatformTable()
    if run is None:
        return t
    t.as_of = inventory.run_date(conn, run)
    keep = set(only_domains) if only_domains is not None else None
    ips: Counter = Counter()
    for row in conn.execute(
            "SELECT domain, class, status_code, headers_json, headers_raw_json, resolved_ip "
            "FROM observations WHERE run_id = ?", (run,)):
        if keep is not None and row["domain"] not in keep:
            continue
        if row["class"] is not None:
            if row["class"] in inventory.ANSWERED_EXCLUDE:
                continue
        elif row["status_code"] is None:
            continue
        t.answering += 1
        headers = inventory._load_json(row["headers_json"]) or inventory._load_json(row["headers_raw_json"])
        cat, tok = platform_of(headers)
        t.by_category[cat] += 1
        if tok:
            t.by_token[tok] += 1
        if row["resolved_ip"]:
            ips[row["resolved_ip"]] += 1
        st = _PHP_RANKED.get(row["class"])
        if st:
            t.php_by_category[cat][st] += 1
    t.ip_cluster_sizes = sorted(ips.values(), reverse=True)
    return t


def public(t: PlatformTable, sup: Suppressor | None = None, name_vendors: bool | None = None) -> dict[str, Any]:
    """Suppressed tables as strings. Platforms under the threshold fold into 'other platforms'."""
    sup = sup or Suppressor()
    named = NAME_VENDORS if name_vendors is None else name_vendors
    out: dict[str, Any] = {"answering": sup.count(t.answering), "as_of": t.as_of}
    cells = sup.row([t.by_category.get(c, 0) for c in CATEGORIES])     # primary + complementary
    out["by_category"] = {c: {"n": cells[i], "share": "§" if cells[i] == "§"
                              else sup.share(t.by_category.get(c, 0), t.answering)}
                          for i, c in enumerate(CATEGORIES)}
    big = [(tok, n) for tok, n in sorted(t.by_token.items(), key=lambda kv: (-kv[1], kv[0])) if n >= SUPPRESS_BELOW]
    rest = sum(n for n in t.by_token.values()) - sum(n for _, n in big)
    while sup.on and 0 < rest < SUPPRESS_BELOW and big:      # a lone small remainder could be recovered
        rest += big.pop()[1]
    plats = []
    for i, (tok, n) in enumerate(big, 1):
        plats.append({"platform": tok if named else f"platform {i}", "n": sup.count(n),
                      "share": sup.share(n, t.answering)})
    if rest:
        plats.append({"platform": "other platforms", "n": sup.count(rest), "share": sup.share(rest, t.answering)})
    out["by_platform"] = plats
    show = t.answering >= SUPPRESS_BELOW or not sup.on
    h = hhi(t.by_token.values())
    out["platform_hhi"] = round(h, 3) if (h is not None and show) else "§"
    sizes = t.ip_cluster_sizes
    shared = sum(s for s in sizes if s >= 2)
    out["hosting"] = {
        "addresses": sup.count(len(sizes)),
        "domains_sharing_an_address": sup.count(shared),
        "share_sharing_an_address": sup.share(shared, sum(sizes)),
        "largest_address_share": sup.share(sizes[0], sum(sizes)) if sizes and sizes[0] >= SUPPRESS_BELOW else "§",
        "address_hhi": round(hhi(sizes) or 0, 3) if (sizes and show) else "§",
    }
    php = {}
    for c in CATEGORIES:
        d = t.php_by_category.get(c)
        if not d:
            continue
        placed = sum(d.values())
        php[c] = {"placed": sup.count(placed), "unsupported": sup.count(d["eol"]),
                  "unsupported_share": sup.share(d["eol"], placed)}
    out["php_by_category"] = php
    return out
