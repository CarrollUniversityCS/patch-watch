"""Fidelity tests for the mock rig itself.

Everything downstream (crawler tests, the pilot's numbers) trusts these canned
responses, so the rig must prove: header names/casing/order on the wire exactly
as configured, repeated headers preserved, empty-body semantics for 204, the
300 KB body really being 300 KB, the delay path really delaying, TLS only
completing with verification disabled, the dead port really refusing, and
8455 really having no TLS listener.

Loopback only. No internet. slow_35s is deliberately never requested here (its
classification is pinned in test_classify.py; 35 s does not belong in a suite).
"""

from __future__ import annotations

import socket
import ssl
import time

import httpx
import pytest

from mock_server import CASES, DEAD_PORT, HTTPS_PORT, HTTP_ONLY_PORT, HTTP_PORT

# Requested cases: everything except the 35-second one.
FETCHED = sorted(n for n in CASES if n != "slow_35s")

# Appended automatically by the handler after the configured headers (never before).
# Compared case-folded, because httpx lower-cases names on parse.
_AUTO = {"location", "content-type", "content-length"}


def case_url(stack, name, base=None):
    return f"{base or stack.base}/case/{name}"


def raw_response(port: int, path: str, read_body_limit: int = 1 << 20) -> bytes:
    """One HTTP/1.1 request over a raw socket; returns the full response bytes.

    httpx lower-cases header names on parse, so header-CASE fidelity can only
    be verified at this level.
    """
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                     f"Connection: close\r\n\r\n".encode())
        buf = b""
        while len(buf) < read_body_limit:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf


def raw_header_lines(response_bytes: bytes) -> list[tuple[str, str]]:
    head = response_bytes.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
    out = []
    for line in head.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        out.append((name, value.strip()))
    return out


# ------------------------------------------------------- header fidelity on the wire
@pytest.mark.parametrize("name", FETCHED)
def test_headers_exact_order_case_and_values(mock_stack, name):
    """Names (case-folded; httpx lower-cases on parse), ORDER and VALUES match
    the config exactly. Original casing is proven per-line over a raw socket in
    test_wire_header_case_is_verbatim; values are what the classifier reads."""
    spec = CASES[name]
    r = httpx.get(case_url(mock_stack, name), timeout=10)
    assert r.status_code == spec.status
    observed = [(n.lower(), v) for n, v in r.headers.multi_items()]
    n = len(spec.headers)
    assert observed[:n] == [(ln.lower(), lv) for ln, lv in spec.headers], \
        (name, observed[:n], spec.headers)
    for extra_name, _ in observed[n:]:
        assert extra_name in _AUTO, f"{name}: unexpected extra header {extra_name!r}"


# Cases chosen to cover: original casing, repeated names, parenthetical comments.
WIRE_CASES = ["hidden_cookie", "conflict_headers", "two_xpb_values",
              "status_429", "multi_set_cookie", "ubuntu_suffix"]


@pytest.mark.parametrize("name", WIRE_CASES)
def test_wire_header_case_is_verbatim(mock_stack, name):
    spec = CASES[name]
    lines = raw_header_lines(raw_response(HTTP_PORT, f"/case/{name}"))
    configured = list(spec.headers)
    assert lines[:len(configured)] == configured  # exact bytes: name case + order


def test_header_case_survives_as_configured(mock_stack):
    """Readable spot-check: 'Server' before 'Set-Cookie', capitals intact, on :8451."""
    lines = raw_header_lines(raw_response(HTTP_PORT, "/case/hidden_cookie"))
    assert lines[0] == ("Server", "nginx/1.27.4")
    assert lines[1] == ("Set-Cookie", "PHPSESSID=7f3a9c2b4d1e6f0a; path=/")


def test_multiple_set_cookie_headers_preserved(mock_stack):
    r = httpx.get(case_url(mock_stack, "multi_set_cookie"), timeout=10)
    cookies = r.headers.get_list("set-cookie")
    assert cookies == [
        "PHPSESSID=0d1e2f3a4b5c6d7e; path=/; HttpOnly",
        "_ga=GA1.3.111.222222222; Path=/; Max-Age=94608000",
    ]
    values = [v for n, v in r.headers.multi_items() if n.lower() == "set-cookie"]
    assert values == cookies  # order preserved on the raw line list too


def test_two_x_powered_by_lines_preserved(mock_stack):
    r = httpx.get(case_url(mock_stack, "two_xpb_values"), timeout=10)
    assert r.headers.get_list("x-powered-by") == ["PHP/8.3.35", "PHP/8.4.26"]


# ------------------------------------------------------------------ body semantics
def test_no_content_has_no_body_and_no_content_length(mock_stack):
    r = httpx.get(case_url(mock_stack, "no_content"), timeout=10)
    assert r.status_code == 204
    assert r.content == b""
    assert "content-length" not in {n.lower() for n in r.headers.keys()}


def test_big_body_really_is_300000_bytes(mock_stack):
    r = httpx.get(case_url(mock_stack, "big_body"), timeout=30)
    assert r.status_code == 200
    assert len(r.content) == 300000
    assert r.content.count(b"A") == 300000
    assert r.headers["content-length"] == "300000"


def test_delay_path_really_delays(mock_stack):
    """slow_short sleeps 0.5 s. slow_35s would prove the same thing for 35 s.

    Absolute wall-clock bounds are not usable here: the mock rig is a Python
    ThreadingHTTPServer shared by the whole session (fixture scope=session), and when
    this test runs inside the full suite a plain HTTPS round trip measured 1.96 s -
    TLS handshake plus scheduling, not the delay path. A first version of this test
    asserted `fast < 0.4` and failed 1 in 4 full-suite runs for exactly that reason.

    So measure the claim instead of the ceiling: sample the fast path and keep the
    MINIMUM (a floor is stable under load; a mean is not), then require the delay case
    to cost the baseline plus the sleep it is supposed to have taken.
    """
    def timed(case: str) -> float:
        t0 = time.monotonic()
        r = httpx.get(case_url(mock_stack, case), timeout=10)
        assert r.status_code == 200
        return time.monotonic() - t0

    baseline = min(timed("vuln8335") for _ in range(3))
    elapsed = timed("slow_short")
    assert elapsed >= 0.4, f"delay path returned in {elapsed:.2f}s"
    assert elapsed - baseline >= 0.35, (
        f"delay path added only {elapsed - baseline:.2f}s over a {baseline:.2f}s baseline"
    )


# ---------------------------------------------------------------------- listeners
def test_plain_http_listeners_all_serve_the_same_case(mock_stack):
    ref = httpx.get(case_url(mock_stack, "vuln8335"), timeout=10)
    for base in (mock_stack.http_only_base,):
        r = httpx.get(case_url(mock_stack, "vuln8335", base=base), timeout=10)
        assert r.status_code == ref.status_code
        assert list(r.headers.multi_items()) == list(ref.headers.multi_items())
    with httpx.Client(verify=False, timeout=10) as c:
        r = c.get(case_url(mock_stack, "vuln8335", base=mock_stack.https_base))
        assert r.status_code == 200
        assert r.headers["X-Powered-By"] == "PHP/8.3.35"


def test_tls_endpoint_works_only_with_verification_disabled(mock_stack):
    with httpx.Client(verify=False, timeout=10) as c:
        r = c.get(case_url(mock_stack, "https_bad_cert", base=mock_stack.https_base))
        assert r.status_code == 200
        assert r.headers.get_list("x-powered-by") == ["PHP/8.3.35"]
    with pytest.raises(httpx.ConnectError):          # untrusted self-signed chain
        httpx.get(case_url(mock_stack, "https_bad_cert", base=mock_stack.https_base),
                  timeout=10)


def test_http_only_listener_rejects_tls_handshake(mock_stack):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with pytest.raises(OSError):                     # ssl.SSLError (wrong version) or reset
        with socket.create_connection(("127.0.0.1", HTTP_ONLY_PORT), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost"):
                pass


def test_dead_port_refuses_connection(mock_stack):
    """Nothing listens on 8459. On this Windows box a refused loopback connect
    surfaces as ConnectionRefusedError only after ~2 s (and can tip into a
    timeout under load), so any connection failure proves the point."""
    assert mock_stack.dead_port == DEAD_PORT
    with pytest.raises((ConnectionRefusedError, TimeoutError, OSError)):
        with socket.create_connection(("127.0.0.1", DEAD_PORT), timeout=6):
            pass
    with pytest.raises(httpx.TransportError):
        httpx.get(f"http://127.0.0.1:{DEAD_PORT}/case/vuln8335", timeout=6)


def test_robots_txt_on_every_listener(mock_stack):
    bases = [mock_stack.base, mock_stack.http_only_base]
    for url in bases:
        r = httpx.get(url + "/robots.txt", timeout=10)
        assert r.status_code == 200
        assert "User-agent: CarrollPHPStudy" in r.text
        assert "Disallow:" in r.text
    with httpx.Client(verify=False, timeout=10) as c:
        r = c.get(mock_stack.https_base + "/robots.txt")
        assert r.status_code == 200 and "CarrollPHPStudy" in r.text


def test_unknown_case_is_404(mock_stack):
    r = httpx.get(mock_stack.base + "/case/not_a_real_case", timeout=10)
    assert r.status_code == 404
    r = httpx.get(mock_stack.base + "/elsewhere", timeout=10)
    assert r.status_code == 404


# ------------------------------------------------------------------- redirects
def test_crossdomain_redirect_is_served_verbatim(mock_stack):
    r = httpx.get(case_url(mock_stack, "crossdomain_redirect"),
                  follow_redirects=False, timeout=10)
    assert r.status_code == 302
    assert r.headers["location"] == "https://cdn-elsewhere.example/landing"
    assert r.headers["x-powered-by"] == "PHP/8.3.35"


def test_same_domain_redirect_chain_resolves(mock_stack):
    r = httpx.get(case_url(mock_stack, "same_domain_redirect"),
                  follow_redirects=True, timeout=10)
    assert r.status_code == 200
    assert r.headers["x-powered-by"] == "PHP/8.4.27"
    assert len(r.history) == 1


def test_redirect_loop_loops(mock_stack):
    with pytest.raises(httpx.TooManyRedirects):
        httpx.get(case_url(mock_stack, "redirect_loop"),
                  follow_redirects=True, timeout=10)


# ------------------------------------------------------------------ statuses
def test_kill_switch_statuses_and_bodies(mock_stack):
    r = httpx.get(case_url(mock_stack, "status_429"), timeout=10)
    assert r.status_code == 429
    assert r.headers["retry-after"] == "120"
    assert r.headers["x-powered-by"] == "PHP/8.3.35"
    for name in ("status_503", "status_403"):
        r = httpx.get(case_url(mock_stack, name), timeout=10)
        assert r.status_code == CASES[name].status


# --------------------------------------------------------------------- contract
def test_stack_attributes_and_url_for(mock_stack):
    assert mock_stack.base == "http://127.0.0.1:8451"
    assert mock_stack.https_base == "https://127.0.0.1:8452"
    assert mock_stack.http_only_base == "http://127.0.0.1:8455"
    assert mock_stack.dead_port == 8459
    assert (HTTP_PORT, HTTPS_PORT, HTTP_ONLY_PORT, DEAD_PORT) == (8451, 8452, 8455, 8459)
    assert mock_stack.url_for("vuln8335") == "http://127.0.0.1:8451/case/vuln8335"
    assert mock_stack.url_for("https_bad_cert", tls=True) == \
        "https://127.0.0.1:8452/case/https_bad_cert"
    with pytest.raises(KeyError):
        mock_stack.url_for("nope")


def test_case_table_shape(mock_stack):
    """Every CaseSpec carries the documented attributes with sane types."""
    for name, spec in CASES.items():
        assert spec.name == name
        assert isinstance(spec.status, int) and 100 <= spec.status < 600
        assert isinstance(spec.headers, list)
        assert all(isinstance(h, tuple) and len(h) == 2 for h in spec.headers)
        assert isinstance(spec.body, bytes)
        assert spec.location is None or isinstance(spec.location, str)
        assert isinstance(spec.delay_s, float)


def test_stack_restart_roundtrip():
    """MockStack.start()/stop() must be re-entrant (session fixture is not the only user)."""
    from mock_server import MockStack
    s = MockStack(http_port=8461, https_port=8462, http_only_port=8465, dead_port=8469)
    s.start()
    try:
        r = httpx.get(s.base + "/case/vuln8335", timeout=10)
        assert r.status_code == 200
    finally:
        s.stop()
    s.start()
    try:
        r = httpx.get(s.base + "/case/eol74", timeout=10)
        assert r.status_code == 200
    finally:
        s.stop()
