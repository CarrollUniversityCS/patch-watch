"""Header inventory: which software do stored response headers reveal, and how well?

Coverage reporting and unsupported-software reporting both start from the
same question: of the sites that answered, how many name a product, how many give a
version, and how many give a version we can rank. This module answers it from headers
the crawler ALREADY stored. It sends no request and never writes to the database.

Rules (docs/analysis_plan.md §8, hard rule 7):

* Nothing leaves this module per domain. `parse_headers` works on one header dict;
  `aggregate` returns counts only, and `Inventory.public()` applies the project's
  suppression (counts 1-9 print as "<10", shares are hidden when a cell is hidden).
* A version string is evidence of a version string. Apache and nginx on a Linux
  distribution carry backported fixes under an old number, so a distro-labelled build is
  counted as "disclosed" but never as "rankable" (same rule as `classify.py`).
* Absence of a version is not safety, and it is not a finding either: it lowers the
  coverage figure and nothing else.

Run (read-only; give it a COPY of the database when in doubt):

    python -X utf8 src/inventory.py --db data/study.db --region wisconsin
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import classify
import support_status
from analyze import SUPPRESS_BELOW, Suppressor

# Products reported by name. Names of SOFTWARE (not of vendors that host sites) are
# fine here; hosting providers and platforms are handled elsewhere and stay unnamed.
PRODUCTS: tuple[str, ...] = ("php", "apache", "nginx", "iis", "openssl", "litespeed", "wordpress")

# Header patterns. "(?<![\w-])" keeps Apache-Coyote (Tomcat), Apache-HttpClient and
# "openresty" from being read as the products they merely resemble.
_NAME_RES: dict[str, re.Pattern[str]] = {
    "apache": re.compile(r"(?<![\w-])apache(?![\w-])(?:/(?P<tok>[^\s;,()]+))?", re.I),
    "nginx": re.compile(r"(?<![\w-])nginx(?![\w-])(?:/(?P<tok>[^\s;,()]+))?", re.I),
    "iis": re.compile(r"(?<![\w-])microsoft-iis(?![\w-])(?:/(?P<tok>[^\s;,()]+))?", re.I),
    "openssl": re.compile(r"(?<![\w-])openssl(?![\w-])(?:/(?P<tok>[^\s;,()]+))?", re.I),
    "litespeed": re.compile(r"(?<![\w-])litespeed(?![\w-])(?:/(?P<tok>[^\s;,()]+))?", re.I),
}
_WP_GENERATOR_RE = re.compile(r"wordpress\s*/?\s*(?P<tok>\d[^\s;,()]*)?", re.I)
_COMMENT_RE = re.compile(r"\(([^)]*)\)")

# Entity types with fewer domains than this are folded into "Other" before reporting.
ANSWERED_EXCLUDE = frozenset({"NO_RESPONSE", "NOT_MEASURED"})


@dataclass(frozen=True)
class ProductRead:
    """What the headers of one domain say about one product."""

    product: str
    named: bool = True                 # the product is named (evidence)
    raw: str = ""                      # version token as it appeared, "" when absent
    version: tuple[int, int, int] | None = None
    partial: bool = False              # 2.4 but no patch number
    suffix: str = ""
    distro_family: str | None = None
    source: str = ""

    @property
    def disclosed(self) -> bool:
        """Any version number at all, ranked or not."""
        return self.version is not None or self.partial

    @property
    def rankable(self) -> bool:
        """A full version we can compare to a fixed release: three numbers and no
        package-suffix ambiguity."""
        return self.version is not None and self.distro_family is None

    @property
    def branch(self) -> tuple[int, int] | None:
        if self.version is not None:
            return self.version[:2]
        if self.partial:
            m = re.match(r"(\d+)\.(\d+)", self.raw)
            if m:
                return (int(m.group(1)), int(m.group(2)))
        return None

    @property
    def status_version(self) -> tuple[int, ...] | None:
        """The most specific version the headers give, for a support-status lookup."""
        return self.version if self.version is not None else self.branch


def _norm_headers(headers: Any) -> dict[str, list[str]]:
    """Accept the stored shapes: {name: [values]}, {name: value}, or [[name, value], ...]."""
    out: dict[str, list[str]] = {}
    if not headers:
        return out
    items: Iterable[Any]
    if isinstance(headers, dict):
        items = headers.items()
    elif isinstance(headers, (list, tuple)):
        items = [(p[0], p[1]) for p in headers if isinstance(p, (list, tuple)) and len(p) == 2]
    else:
        return out
    for k, v in items:
        if not isinstance(k, str):
            continue
        vals = v if isinstance(v, (list, tuple)) else [v]
        out.setdefault(k.lower(), []).extend(str(x) for x in vals if x is not None)
    return out


def _comment_text(server_values: list[str]) -> str:
    return " ".join(m.group(1) for v in server_values for m in _COMMENT_RE.finditer(v))


def _read_from_token(product: str, tok: str | None, source: str, comment: str) -> ProductRead:
    if not tok:
        return ProductRead(product=product, source=source)
    # Reuse the PHP classifier's token parser: it already refuses to turn "2.4" into
    # "2.4.0" and keeps the package suffix separate.
    r = classify.parse_php_token(tok, source)
    if r is None:
        return ProductRead(product=product, source=source)
    fam = None
    if r.parsed or r.partial:
        fam, _ = classify.distro_family_source(r, comment)
    return ProductRead(product=product, raw=r.raw, version=r.version, partial=r.partial,
                       suffix=r.suffix, distro_family=fam, source=source)


def _rank(r: ProductRead) -> int:
    return (3 if r.rankable else 2 if r.version is not None else 1 if r.partial else 0)


def parse_headers(headers: Any) -> dict[str, ProductRead]:
    """Product -> best read for ONE response's headers. Never raises on odd input."""
    h = _norm_headers(headers)
    server = h.get("server", [])
    powered = h.get("x-powered-by", [])
    comment = _comment_text(server)
    found: dict[str, ProductRead] = {}

    def keep(r: ProductRead) -> None:
        old = found.get(r.product)
        if old is None or _rank(r) > _rank(old):
            found[r.product] = r

    # PHP: the classifier's own reader, so the two can never disagree.
    parsed, unparsed = classify._read_versions(h)
    for vr in parsed:
        fam, _ = classify.distro_family_source(vr, comment)
        keep(ProductRead("php", raw=vr.raw, version=vr.version, suffix=vr.suffix,
                         distro_family=fam, source=vr.source))
    for vr in unparsed:
        keep(ProductRead("php", raw=vr.raw, partial=vr.partial, suffix=vr.suffix, source=vr.source))
    if "php" not in found:
        php_named = any(re.search(r"(?<![\w-])php(?![\w-])", v, re.I) for v in server + powered)
        if php_named:
            keep(ProductRead("php", source="x-powered-by"))

    for src_name, values in (("server", server), ("x-powered-by", powered)):
        for value in values:
            for product, rx in _NAME_RES.items():
                for m in rx.finditer(value):
                    keep(_read_from_token(product, m.group("tok"), src_name, comment))

    # WordPress: only what the headers carry. A generator header may name a version; the
    # REST discovery link or pingback header is evidence without one. Nothing is fetched.
    for v in h.get("x-generator", []) + h.get("x-powered-by", []):
        wm = _WP_GENERATOR_RE.search(v)
        if wm:
            keep(_read_from_token("wordpress", wm.group("tok"), "x-generator", comment))
    link = " ".join(h.get("link", []))
    if "api.w.org" in link or "wp-json" in link or "xmlrpc.php" in " ".join(h.get("x-pingback", [])):
        keep(ProductRead("wordpress", source="link"))
    return found


# ---------------------------------------------------------------- aggregation
@dataclass
class Counts:
    answering: int = 0
    named: int = 0
    disclosed: int = 0
    rankable: int = 0
    distro: int = 0
    # Support status. `placed` = sites with no package-suffix ambiguity whose
    # branch the pinned table can place on the snapshot's date; `eol` and `security_only`
    # are subsets of it. `eol_distro` counts distro-labelled builds on an end-of-life
    # upstream branch: reported separately because the vendor may still patch them.
    placed: int = 0
    eol: int = 0
    security_only: int = 0
    eol_distro: int = 0

    def add(self, r: ProductRead | None, as_of: str | None = None) -> None:
        self.answering += 1
        if r is None:
            return
        self.named += 1
        self.disclosed += r.disclosed
        self.rankable += r.rankable
        self.distro += r.distro_family is not None
        if as_of and r.status_version is not None:
            st = support_status.status(r.product, r.status_version, as_of)
            if r.distro_family is not None:
                self.eol_distro += st == support_status.END_OF_LIFE
            elif st != support_status.UNKNOWN:
                self.placed += 1
                self.eol += st == support_status.END_OF_LIFE
                self.security_only += st == support_status.SECURITY_ONLY

    def merge(self, other: "Counts") -> None:
        for f in ("answering", "named", "disclosed", "rankable", "distro",
                  "placed", "eol", "security_only", "eol_distro"):
            setattr(self, f, getattr(self, f) + getattr(other, f))


@dataclass
class Inventory:
    """Counts only. `by_product[p]` is all answering domains; `by_type[t][p]` splits by
    the registry's entity type. Raw counts stay in memory; use `public()` to print."""

    attempted: int = 0
    answering: int = 0
    by_product: dict[str, Counts] = field(default_factory=dict)
    by_type: dict[str, dict[str, Counts]] = field(default_factory=dict)
    type_sizes: dict[str, int] = field(default_factory=dict)
    as_of: str = ""

    def funnel(self, product: str) -> dict[str, int]:
        c = self.by_product.get(product, Counts())
        return {"attempted": self.attempted, "answering": self.answering, "named": c.named,
                "disclosed": c.disclosed, "rankable": c.rankable}

    def public(self, sup: Suppressor | None = None) -> dict[str, Any]:
        """Aggregate tables as strings, suppressed. Entity types with fewer than the
        suppression threshold answering domains are folded into 'Other' first, and the
        fold is recomputed so 'Other' itself is suppressed when small."""
        sup = sup or Suppressor()
        out: dict[str, Any] = {
            "attempted": sup.count(self.attempted),
            "answering": sup.count(self.answering),
            "products": {},
            "by_type": {},
        }
        for p, c in self.by_product.items():
            out["products"][p] = {
                "named": sup.count(c.named),
                "disclosed": sup.count(c.disclosed),
                "rankable": sup.count(c.rankable),
                "distro_labelled": sup.count(c.distro),
                "disclosure_rate": sup.share(c.disclosed, c.answering),
                "rankable_rate": sup.share(c.rankable, c.answering),
                "unsupported": sup.count(c.eol),
                "unsupported_basis": sup.count(c.placed),
                "unsupported_share": sup.share(c.eol, c.placed),
                "unsupported_distro_labelled": sup.count(c.eol_distro),
            }
        folded: dict[str, dict[str, Counts]] = {}
        sizes: Counter[str] = Counter()
        for t, per in self.by_type.items():
            n = max((c.answering for c in per.values()), default=0)
            key = t if n >= SUPPRESS_BELOW else "Other"
            tgt = folded.setdefault(key, {})
            sizes[key] += n
            for p, c in per.items():
                tgt.setdefault(p, Counts()).merge(c)
        for t, per in sorted(folded.items()):
            out["by_type"][t] = {
                "answering": sup.count(sizes[t]),
                **{p: {"disclosed": sup.count(c.disclosed),
                       "rankable": sup.count(c.rankable),
                       "disclosure_rate": sup.share(c.disclosed, c.answering),
                       "unsupported": sup.count(c.eol),
                       "unsupported_basis": sup.count(c.placed),
                       "unsupported_share": sup.share(c.eol, c.placed)}
                   for p, c in per.items()},
            }
        return out


def _open_ro(db_path: Path | str) -> sqlite3.Connection:
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def latest_run(conn: sqlite3.Connection, region: str = "wisconsin") -> str | None:
    rows = conn.execute(
        "SELECT run_id FROM runs WHERE json_extract(config_json,'$.region') = ? "
        "AND finished_at_utc IS NOT NULL AND (kill_switch IS NULL OR kill_switch = '') "
        "ORDER BY started_at_utc DESC LIMIT 1", (region,)).fetchone()
    return rows["run_id"] if rows else None


def aggregate(db_path: Path | str, run_id: str | None = None, region: str = "wisconsin") -> Inventory:
    """Counts for ONE run. Opens the database read-only; reads headers, class and the
    domain's registry type, and returns no per-domain information."""
    conn = _open_ro(db_path)
    try:
        return aggregate_conn(conn, run_id, region)
    finally:
        conn.close()


def run_date(conn: sqlite3.Connection, run_id: str) -> str:
    row = conn.execute("SELECT started_at_utc FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    return (row[0] or "")[:10] if row else ""


def aggregate_conn(conn: sqlite3.Connection, run_id: str | None = None,
                   region: str = "wisconsin", *, only_domains: Iterable[str] | None = None,
                   types: dict[str, str] | None = None) -> Inventory:
    """`aggregate` for an open connection (the analysis already has one). Support status
    is judged on the run's own start date, not today's.

    `only_domains` keeps just those domains (the frame, tribal nations excluded);
    `types` maps a domain to the reporting type to group by instead of the registry's."""
    keep = set(only_domains) if only_domains is not None else None
    conn.row_factory = sqlite3.Row
    run = run_id or latest_run(conn, region)
    inv = Inventory()
    if run is None:
        return inv
    inv.as_of = run_date(conn, run)
    rows = conn.execute(
        "SELECT o.domain AS dom, o.class AS cls, o.status_code AS sc, o.headers_json AS hj, "
        "o.headers_raw_json AS hr, "
        "o.php_evidence AS php_ev, COALESCE(d.domain_type, 'Unknown') AS dtype "
        "FROM observations o LEFT JOIN domains d ON d.domain = o.domain "
        "WHERE o.run_id = ?", (run,)).fetchall()
    for row in rows:
        if keep is not None and row["dom"] not in keep:
            continue
        inv.attempted += 1
        if row["cls"] is not None:
            if row["cls"] in ANSWERED_EXCLUDE:
                continue
        elif row["sc"] is None:
            continue
        inv.answering += 1
        headers = _load_json(row["hj"]) or _load_json(row["hr"])
        reads = parse_headers(headers)
        if row["php_ev"] and "php" not in reads:
            # The crawler also saw PHP in the page markup or cookies (no version).
            reads["php"] = ProductRead("php", source="body")
        t = (types or {}).get(row["dom"]) or row["dtype"] or "Unknown"
        inv.type_sizes[t] = inv.type_sizes.get(t, 0) + 1
        for p in PRODUCTS:
            inv.by_product.setdefault(p, Counts()).add(reads.get(p), inv.as_of)
            inv.by_type.setdefault(t, {}).setdefault(p, Counts()).add(reads.get(p), inv.as_of)
    return inv


def _load_json(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def format_table(pub: dict[str, Any]) -> str:
    lines = [f"attempted {pub['attempted']}, answering {pub['answering']}", "",
             "| product | named | version shown | rankable | distro-labelled | shown % | rankable % | unsupported of placed |",
             "|---|---|---|---|---|---|---|---|"]
    for p, v in pub["products"].items():
        lines.append(f"| {p} | {v['named']} | {v['disclosed']} | {v['rankable']} | "
                     f"{v['distro_labelled']} | {v['disclosure_rate']} | {v['rankable_rate']} | "
                     f"{v['unsupported']} of {v['unsupported_basis']} ({v['unsupported_share']}) |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Aggregate header inventory (read-only, counts only).")
    ap.add_argument("--db", required=True, help="path to a study database (opened read-only)")
    ap.add_argument("--region", default="wisconsin")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--json", action="store_true", help="print the suppressed tables as JSON")
    args = ap.parse_args(argv)
    if not Path(args.db).exists():
        print(f"error: database not found: {args.db}", file=sys.stderr)
        return 2
    try:
        inv = aggregate(args.db, args.run_id, args.region)
    except sqlite3.Error as e:
        print(f"error: cannot read database: {e}", file=sys.stderr)
        return 2
    pub = inv.public()
    print(json.dumps(pub, indent=2) if args.json else format_table(pub))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
