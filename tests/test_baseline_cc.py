"""Common Crawl baseline collector (src/baseline_cc.py). No network: httpx.MockTransport."""

from __future__ import annotations

import gzip
import json

import httpx
import pytest

import baseline_cc
import db


def warc_record(*, status=200, headers=(("X-Powered-By", "PHP/8.3.35"),), body=b"<html></html>",
                uri="https://a.gov/", date="2026-09-20T10:00:00Z", ip="192.0.2.10",
                warc_type="response") -> bytes:
    http = f"HTTP/1.1 {status} OK\r\n".encode() + b"".join(
        f"{k}: {v}\r\n".encode() for k, v in headers) + b"\r\n" + body
    warc = (f"WARC/1.0\r\nWARC-Type: {warc_type}\r\nWARC-Date: {date}\r\n"
            f"WARC-Target-URI: {uri}\r\nWARC-IP-Address: {ip}\r\n"
            f"Content-Length: {len(http)}\r\n\r\n").encode()
    return gzip.compress(warc + http + b"\r\n\r\n")


def cdx(url, status="200", ts="20260920100000", filename="crawl/a.warc.gz", offset=0, length=10):
    return {"url": url, "status": status, "timestamp": ts, "filename": filename,
            "offset": str(offset), "length": str(length)}


def make_client(tmp_path, routes, seen=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        for match, resp in routes:
            if match(request):
                return resp(request) if callable(resp) else resp
        return httpx.Response(404, text="")
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return baseline_cc.CCClient(cache_dir=tmp_path / "cache", min_interval=0, http=http,
                                sleep=lambda s: None)


# --------------------------------------------------------------------------- safety
def test_client_refuses_anything_but_common_crawl(tmp_path):
    client = make_client(tmp_path, [])
    for url in ("https://a.gov/", "http://example.com/x", "https://index.commoncrawl.org.evil.net/"):
        with pytest.raises(PermissionError):
            client.get(url)


def test_collect_never_requests_a_government_host(tmp_path):
    seen: list[str] = []
    rec = warc_record()
    routes = [
        (lambda r: r.url.host == "index.commoncrawl.org" and "url=a.gov" in str(r.url),
         httpx.Response(200, text=json.dumps(cdx("https://a.gov/", length=len(rec))) + "\n")),
        (lambda r: r.url.host == "data.commoncrawl.org", httpx.Response(206, content=rec)),
    ]
    conn = db.connect(tmp_path / "s.db")
    baseline_cc.collect(conn, make_client(tmp_path, routes, seen), ["a.gov"], ["CC-MAIN-2026-39"])
    assert seen and all(httpx.URL(u).host in baseline_cc.ALLOWED_HOSTS for u in seen)


# --------------------------------------------------------------------------- parsing
def test_warc_response_is_parsed_and_body_dropped():
    out = baseline_cc.parse_warc_response(gzip.decompress(warc_record(
        body=b'<form action="/login.php">')))
    assert out["status_code"] == 200
    assert out["headers"]["x-powered-by"] == ["PHP/8.3.35"]
    assert out["warc_ip"] == "192.0.2.10" and out["warc_date_utc"].startswith("2026-09-20")
    assert out["php_hints"]["link_or_action_has_php"] is True
    assert "body" not in out


def test_non_response_record_is_rejected():
    with pytest.raises(ValueError):
        baseline_cc.parse_warc_response(gzip.decompress(warc_record(warc_type="request")))


def test_pick_homepage_prefers_200_https_apex_earliest():
    caps = [
        cdx("http://a.gov/", ts="20260901"),
        cdx("https://www.a.gov/", ts="20260902"),
        cdx("https://a.gov/", status="301", ts="20260903"),
        cdx("https://a.gov/", ts="20260905"),
        cdx("https://a.gov/", ts="20260904"),
        cdx("https://a.gov/about", ts="20260801"),            # not a homepage
        cdx("https://a.gov/?q=1", ts="20260801"),             # not a homepage
    ]
    best, n = baseline_cc.pick_homepage(caps)
    assert best["url"] == "https://a.gov/" and best["timestamp"] == "20260904"
    assert n == 5


# --------------------------------------------------------------------------- collect
def test_collect_classifies_records_no_capture_and_is_resumable(tmp_path):
    rec = warc_record(headers=(("X-Powered-By", "PHP/8.3.35"), ("Server", "Apache")))
    calls = {"index": 0}

    def index(r):
        calls["index"] += 1
        if "url=a.gov" in str(r.url):
            return httpx.Response(200, text=json.dumps(cdx("https://a.gov/", length=len(rec))))
        return httpx.Response(404)
    routes = [(lambda r: r.url.host == "index.commoncrawl.org", index),
              (lambda r: r.url.host == "data.commoncrawl.org", httpx.Response(206, content=rec))]
    conn = db.connect(tmp_path / "s.db")
    client = make_client(tmp_path, routes)
    tally = baseline_cc.collect(conn, client, ["a.gov", "b.gov"], ["CC-MAIN-2026-39"])
    assert tally == {"captured": 1, "no_capture": 1, "skipped_existing": 0, "errors": 0}
    rows = {r["domain"]: r for r in conn.execute("SELECT * FROM baseline_observations")}
    assert rows["a.gov"]["class"] == "VULNERABLE_BY_VERSION"
    assert rows["a.gov"]["warc_ip"] == "192.0.2.10"
    assert rows["b.gov"]["captured"] == 0 and rows["b.gov"]["class"] is None

    before = calls["index"]
    again = baseline_cc.collect(conn, client, ["a.gov", "b.gov"], ["CC-MAIN-2026-39"])
    assert again["skipped_existing"] == 2 and calls["index"] == before


def test_retries_then_caches(tmp_path):
    hits = {"n": 0}

    def flaky(r):
        hits["n"] += 1
        return httpx.Response(504) if hits["n"] < 3 else httpx.Response(200, text="")
    client = make_client(tmp_path, [(lambda r: True, flaky)])
    assert client.lookup("CC-MAIN-2026-39", "a.gov") == []
    assert hits["n"] == 3
    client.lookup("CC-MAIN-2026-39", "a.gov")
    assert hits["n"] == 3, "second ask is served from the cache"


def test_gives_up_loudly(tmp_path):
    client = make_client(tmp_path, [(lambda r: True, httpx.Response(503))])
    client.max_retries = 2
    with pytest.raises(RuntimeError):
        client.lookup("CC-MAIN-2026-39", "a.gov")
