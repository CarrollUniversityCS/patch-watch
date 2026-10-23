"""Archived baseline from Common Crawl (docs/analysis_plan.md §3, §7.2, §7.8).

PASSIVE BY CONSTRUCTION. This module talks to exactly two hosts, Common Crawl's URL
index and its public data bucket, and nothing else: `CCClient` refuses any other host
before a socket opens. No request ever goes to a government domain. What it reads is
what CC's own crawler recorded when it fetched a homepage: the archived HTTP status
and response headers (including X-Powered-By and Server), the archived server IP, and
the capture time. Those are classified by the SAME classifier as live snapshots.

Two uses:
  * the PHP2Shell "before" (crawls CC-MAIN-2026-39 / -43; the analysis keeps only
    captures with WARC-Date before first exploitation, 2026-10-17);
  * the historical adoption benchmark (2024 crawls around CVE-2024-4577), so the paper
    can say how fast this population USUALLY adopts a critical release.

Etiquette: one request at a time, at least `min_interval` seconds apart, exponential
backoff on 429/5xx/timeouts, every response cached under data/cc_cache/ so a re-run
never re-asks. The index server is shared and fragile (it returned 504s on
2026-10-23); be patient with it. For very large frames, CC's columnar index via
Athena is the polite alternative and produces the same (filename, offset, length).

Run:
    python src/baseline_cc.py collect --frame data/wi_frame.csv --crawls 2026
    python src/baseline_cc.py collect --frame data/wi_frame.csv --crawls 2024 --limit 25
    python src/baseline_cc.py coverage --db data/study.db
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sqlite3
import sys
import time
import zlib
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import quote, urlparse

import httpx

import classify as classify_mod
import config
import db
from fetch import add_headers, derive_body_hints

CC_INDEX = "https://index.commoncrawl.org"
CC_DATA = "https://data.commoncrawl.org"
ALLOWED_HOSTS = frozenset({"index.commoncrawl.org", "data.commoncrawl.org"})

CRAWL_SETS = {
    # PHP2Shell baseline. Captures on/after 2026-10-17 are kept but analysed separately.
    "2026": ("CC-MAIN-2026-34", "CC-MAIN-2026-39", "CC-MAIN-2026-43"),
    # CVE-2024-4577 (fixed 2024-06-06): two crawls before, four after.
    "2024": ("CC-MAIN-2024-18", "CC-MAIN-2024-22", "CC-MAIN-2024-26",
             "CC-MAIN-2024-30", "CC-MAIN-2024-33", "CC-MAIN-2024-38"),
}

CACHE_DIR = config.DATA_DIR / "cc_cache"

SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline_observations (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id              TEXT NOT NULL,
    domain                TEXT NOT NULL,
    captured              INTEGER NOT NULL,        -- 0 = CC holds no homepage capture
    candidates            INTEGER,
    capture_url           TEXT,
    cdx_timestamp         TEXT,
    warc_date_utc         TEXT,
    warc_ip               TEXT,
    status_code           INTEGER,
    headers_json          TEXT,
    php_hints_json        TEXT,
    warc_filename         TEXT,
    warc_offset           INTEGER,
    warc_length           INTEGER,
    class                 TEXT,                    -- PHP2Shell event; re-derive others
    php_version           TEXT,
    classify_detail_json  TEXT,
    collected_at_utc      TEXT,
    UNIQUE(crawl_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_base_domain ON baseline_observations(domain);
"""


def init_schema(conn: sqlite3.Connection) -> None:
    db.init_db(conn)
    conn.executescript(SCHEMA)


# --------------------------------------------------------------------------- client
class CCClient:
    """The only network surface in this module. Common Crawl hosts only."""

    def __init__(self, cache_dir: Path = CACHE_DIR, min_interval: float = 1.5,
                 max_retries: int = 6, http: httpx.Client | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.cache_dir = Path(cache_dir)
        self.min_interval = min_interval
        self.max_retries = max_retries
        self.http = http or httpx.Client(headers={"User-Agent": config.USER_AGENT},
                                         timeout=httpx.Timeout(90.0, connect=20.0))
        self.sleep = sleep
        self._last = 0.0

    @staticmethod
    def check_host(url: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        if host not in ALLOWED_HOSTS:
            raise PermissionError(f"baseline_cc may only contact Common Crawl, not {host!r}")

    def _cache_path(self, url: str, rng: str | None) -> Path:
        key = hashlib.sha256(f"{url}|{rng or ''}".encode()).hexdigest()
        return self.cache_dir / key[:2] / key

    def get(self, url: str, *, byte_range: tuple[int, int] | None = None) -> tuple[int, bytes]:
        """(status, body). 404 is a real answer ("no captures") and is cached too."""
        self.check_host(url)
        rng = f"bytes={byte_range[0]}-{byte_range[1]}" if byte_range else None
        cp = self._cache_path(url, rng)
        if cp.exists():
            blob = cp.read_bytes()
            return int(blob[:3]), blob[4:]
        delay = 4.0
        for attempt in range(self.max_retries + 1):
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                self.sleep(wait)
            self._last = time.monotonic()
            try:
                r = self.http.get(url, headers={"Range": rng} if rng else None)
                status, body = r.status_code, r.content
            except httpx.TransportError:
                status, body = 0, b""
            if status in (200, 206, 404):
                cp.parent.mkdir(parents=True, exist_ok=True)
                cp.write_bytes(f"{status:03d}\n".encode() + body)
                return status, body
            if attempt < self.max_retries:
                self.sleep(min(delay, 120.0))
                delay *= 2
        raise RuntimeError(f"Common Crawl kept failing for {url} (last status {status})")

    def lookup(self, crawl: str, host: str) -> list[dict[str, Any]]:
        url = f"{CC_INDEX}/{crawl}-index?url={quote(host + '/', safe='/')}&output=json"
        status, body = self.get(url)
        if status == 404:
            return []
        out = []
        for line in body.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if line.startswith("{"):
                out.append(json.loads(line))
        return out

    def fetch_record(self, cap: dict[str, Any]) -> bytes:
        off, length = int(cap["offset"]), int(cap["length"])
        status, body = self.get(f"{CC_DATA}/{cap['filename']}", byte_range=(off, off + length - 1))
        if status not in (200, 206):
            raise RuntimeError(f"WARC range fetch returned {status}")
        return gzip.decompress(body)


# --------------------------------------------------------------------------- parsing
def is_homepage(url: str) -> bool:
    p = urlparse(url)
    return p.path in ("", "/") and not p.query


def pick_homepage(captures: Iterable[dict[str, Any]]) -> tuple[dict[str, Any] | None, int]:
    """One capture per (crawl, domain): 200 over 3xx over anything else, then https,
    then the apex host, then the earliest timestamp. Deterministic on ties."""
    homes = [c for c in captures if is_homepage(c.get("url", ""))
             and c.get("filename") and c.get("offset") is not None]
    if not homes:
        return None, 0

    def rank(c):
        st = str(c.get("status", ""))
        host = urlparse(c["url"]).hostname or ""
        return (0 if st == "200" else 1 if st.startswith("3") else 2,
                0 if c["url"].startswith("https://") else 1,
                1 if host.startswith("www.") else 0,
                c.get("timestamp", ""), c["url"])
    return sorted(homes, key=rank)[0], len(homes)


def _split_block(data: bytes) -> tuple[list[str], bytes]:
    head, _, rest = data.partition(b"\r\n\r\n")
    return head.decode("iso-8859-1").split("\r\n"), rest


def parse_warc_response(record: bytes) -> dict[str, Any]:
    """WARC response record -> archived status, headers, capture metadata, body hints.

    The body is inspected for the same php hints the live crawler derives, capped at
    the same 64 KiB, and then dropped: archived page content is not stored either.
    """
    warc_lines, payload = _split_block(record)
    if not warc_lines or not warc_lines[0].startswith("WARC/"):
        raise ValueError("not a WARC record")
    warc = {}
    for ln in warc_lines[1:]:
        k, _, v = ln.partition(":")
        warc[k.strip().lower()] = v.strip()
    if warc.get("warc-type") != "response":
        raise ValueError(f"WARC-Type is {warc.get('warc-type')!r}, not response")
    http_lines, body = _split_block(payload)
    parts = http_lines[0].split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    raw = []
    for ln in http_lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            raw.append([k.strip(), v.strip()])
    headers: dict[str, list[str]] = {}
    add_headers(headers, raw)
    body = body[: config.MAX_BODY_BYTES]
    enc = " ".join(headers.get("content-encoding", [])).lower()
    if "gzip" in enc or "deflate" in enc:
        try:
            body = zlib.decompressobj(47).decompress(body, config.MAX_BODY_BYTES)
        except zlib.error:
            body = b""
    hints = derive_body_hints(body)
    del body
    return {"status_code": status, "headers": headers, "php_hints": hints,
            "warc_date_utc": warc.get("warc-date"), "warc_ip": warc.get("warc-ip-address"),
            "target_uri": warc.get("warc-target-uri")}


# --------------------------------------------------------------------------- collect
def collect(conn: sqlite3.Connection, client: CCClient, domains: list[str],
            crawls: Iterable[str], *, progress: Callable[[str], None] = lambda s: None) -> dict[str, int]:
    """Resumable: a (crawl, domain) pair already in the table is never re-asked."""
    init_schema(conn)
    tally = {"captured": 0, "no_capture": 0, "skipped_existing": 0, "errors": 0}
    for crawl in crawls:
        done = {r[0] for r in conn.execute(
            "SELECT domain FROM baseline_observations WHERE crawl_id=?", (crawl,))}
        for i, dom in enumerate(domains):
            if dom in done:
                tally["skipped_existing"] += 1
                continue
            try:
                caps = client.lookup(crawl, dom) + client.lookup(crawl, f"www.{dom}")
                cap, n = pick_homepage(caps)
                row: dict[str, Any] = {"crawl_id": crawl, "domain": dom, "captured": 0,
                                       "candidates": n, "collected_at_utc": db.utc_now_iso()}
                if cap is not None:
                    rec = parse_warc_response(client.fetch_record(cap))
                    v = classify_mod.classify({**rec, "error_type": None})
                    vd = v.as_dict()
                    row.update({
                        "captured": 1, "capture_url": cap["url"],
                        "cdx_timestamp": cap.get("timestamp"),
                        "warc_date_utc": rec["warc_date_utc"], "warc_ip": rec["warc_ip"],
                        "status_code": rec["status_code"],
                        "headers_json": json.dumps(rec["headers"]),
                        "php_hints_json": json.dumps(rec["php_hints"]),
                        "warc_filename": cap["filename"], "warc_offset": int(cap["offset"]),
                        "warc_length": int(cap["length"]), "class": vd["class"],
                        "php_version": vd["php_version"],
                        "classify_detail_json": json.dumps(vd["classify_detail"]),
                    })
                    tally["captured"] += 1
                else:
                    tally["no_capture"] += 1
                cols = ", ".join(row)
                conn.execute(f"INSERT INTO baseline_observations({cols}) VALUES("
                             + ", ".join(f":{c}" for c in row) + ")", row)
                conn.commit()
            except (RuntimeError, ValueError, OSError) as exc:
                tally["errors"] += 1
                progress(f"{crawl} {dom}: {type(exc).__name__}: {exc}")
            if i % 50 == 0:
                progress(f"{crawl}: {i}/{len(domains)} {tally}")
    return tally


def coverage(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT crawl_id, COUNT(*) AS asked, SUM(captured) AS captured, "
        "MIN(warc_date_utc) AS first_capture, MAX(warc_date_utc) AS last_capture "
        "FROM baseline_observations GROUP BY crawl_id ORDER BY crawl_id").fetchall()


def main(argv: list[str] | None = None) -> int:
    import pipeline      # load_sample applies the tribal-nation exclusion

    ap = argparse.ArgumentParser(prog="baseline_cc.py", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--frame", default=str(config.DATA_DIR / "wi_frame.csv"))
    c.add_argument("--crawls", default="2026",
                   help="a set name (2026, 2024) or comma-separated crawl ids")
    c.add_argument("--db", default=str(config.DB_PATH))
    c.add_argument("--limit", type=int)
    c.add_argument("--region", default="", help="only rows of this frame region")
    v = sub.add_parser("coverage")
    v.add_argument("--db", default=str(config.DB_PATH))
    args = ap.parse_args(argv)

    conn = db.connect(args.db)
    init_schema(conn)
    if args.command == "coverage":
        for r in coverage(conn):
            print(dict(r))
        return 0
    rows = pipeline.load_sample(args.frame)
    if args.region:
        rows = [r for r in rows if r.get("region") == args.region]
    domains = [r["domain"] for r in rows][: args.limit or None]
    crawls = CRAWL_SETS.get(args.crawls) or tuple(s.strip() for s in args.crawls.split(",") if s.strip())
    tally = collect(conn, CCClient(), domains, crawls, progress=lambda s: print(s, flush=True))
    print(json.dumps(tally))
    return 0


if __name__ == "__main__":
    sys.exit(main())
