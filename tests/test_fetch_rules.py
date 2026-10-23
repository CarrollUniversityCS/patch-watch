"""Rule-by-rule tests for `src/fetch.py` — the module that enforces the brief's hard
rules 1-8 and Gate A.

Loopback only. Every target is `127.0.0.1`, addressed either through the shared deck in
`tests/mock_server.py` or through one small in-file recorder that captures the headers we
actually put on the wire. No real name is ever resolved and no real agency server is ever
contacted; a test that tried would be refused by `ApprovedSet` before the socket opens.

Two conventions worth knowing before editing:

* One `asyncio.run()` per `Crawler`. `Crawler` holds a `Semaphore`, an `IPBudget`
  `Condition` and a `KillSwitch` `Lock`, and an asyncio primitive cannot be awaited from
  two different event loops. Helpers here therefore run a whole scenario in one loop.
* Redirect hops are ledger rows but NOT budget charges. `Budget.take()` is called once per
  phase (https, unverified retry, http fallback), so `MAX_SENDS_PER_DOMAIN = 3` counts
  phases while the ledger counts requests. Several tests below pin that distinction
  deliberately, because it is the thing a future reader is most likely to "fix".
"""

from __future__ import annotations

import asyncio
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import config
import fetch

HOST = "127.0.0.1"
DECK_TIMEOUTS = (2.0, 4.0)


# --------------------------------------------------------------------------- helpers
def deck_crawler(stack, case: str, *, domains=("probe.gov",), base: str | None = None,
                 **kw) -> fetch.Crawler:
    """A Crawler aimed at one deck case, addressed as an approved fake domain."""
    root = base or stack.base
    kw.setdefault("url_for", lambda d: f"{root}/case/{case}")
    kw.setdefault("test_hosts", [HOST])
    kw.setdefault("timeouts", DECK_TIMEOUTS)
    return fetch.Crawler(list(domains), **kw)


def fetch_one(crawler: fetch.Crawler, domain: str = "probe.gov") -> fetch.Observation:
    return crawler_loop(crawler, [domain])[0]


def crawler_loop(crawler: fetch.Crawler, domains: list[str]) -> list[fetch.Observation]:
    return asyncio.run(crawler.fetch_many(domains))


def ledger_row(domain="a.gov", url="https://a.gov/", phase="https", status=200,
               error=None, hop=0) -> dict:
    return {"run_id": "r1", "ts_utc": "2026-10-23T00:00:00.000Z", "domain": domain,
            "method": "GET", "url": url, "phase": phase, "redirect_hop": hop,
            "status_code": status, "error_type": error}


# --------------------------------------------------------------------- recorder server
def start_recorder():
    """Fresh single-host server that records request headers and peak in-flight count.

    Returns (server, thread, state). Port 0, so it can never collide with the deck
    listeners or with a mock server another process left behind.
    """
    state = {"hits": [], "inflight": 0, "peak": 0}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with lock:
                state["inflight"] += 1
                state["peak"] = max(state["peak"], state["inflight"])
                state["hits"].append((self.path, {k.lower(): v
                                                  for k, v in self.headers.items()}))
            try:
                self._respond()
            finally:
                with lock:
                    state["inflight"] -= 1

        def _respond(self):
            if self.path.startswith("/sleep"):
                time.sleep(0.25)
            if self.path.startswith("/setcookie_then_redirect"):
                self.send_response(302)
                self.send_header("Set-Cookie", "SESS=deadbeef; Path=/")
                self.send_header("Location", "/landing")
                self.send_header("Content-Length", "0")
                state["set_cookie_sent"] = True
                self.end_headers()
                return
            body = b"<html><body>php info card</body></html>"
            self.send_response(200)
            self.send_header("X-Powered-By", "PHP/8.3.35")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):    # silence per-request stderr noise
            pass

    server = ThreadingHTTPServer((HOST, 0), Handler)
    server.daemon_threads = True
    state["port"] = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, state


@pytest.fixture
def recorder():
    server, thread, state = start_recorder()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def recorder_crawler(state, *, domains=("probe.gov",), path="/plain", **kw):
    port = state["port"]
    kw.setdefault("url_for", lambda d: f"http://{HOST}:{port}{path}")
    kw.setdefault("test_hosts", [HOST])
    kw.setdefault("timeouts", DECK_TIMEOUTS)
    return fetch.Crawler(list(domains), **kw)


# ========================================================================= rule 1
def test_rule1_subdomain_matches_approved_root():
    a = fetch.ApprovedSet(["agency.gov"])
    assert a.allows("agency.gov")
    assert a.allows("WWW.Agency.GOV.")          # case and trailing dot normalised
    assert a.allows("maps.agency.gov")


def test_rule1_lookalike_suffix_is_not_approved():
    a = fetch.ApprovedSet(["agency.gov"])
    assert not a.allows("agency.gov.evil.example")   # suffix attack: different root
    assert not a.allows("notagency.gov")
    assert not a.allows("")


def test_rule1_check_raises_for_a_foreign_host():
    a = fetch.ApprovedSet(["agency.gov"])
    with pytest.raises(fetch.RegistrableDomainError):
        a.check("evil.example", phase="seed")
    with pytest.raises(fetch.RegistrableDomainError):
        a.check("", phase="seed")


def test_rule1_refusal_is_logged_in_plain_words(caplog):
    """Hard rule 1 wants refusals ON the record, not just in an exception."""
    import logging
    a = fetch.ApprovedSet(["agency.gov"])
    with caplog.at_level(logging.WARNING, logger="patchwatch.fetch"):
        with pytest.raises(fetch.RegistrableDomainError):
            a.check("cdn-elsewhere.example", phase="redirect")
    text = caplog.text
    assert "REFUSING redirect: cdn-elsewhere.example" in text
    assert "hard rule 1" in text


def test_rule1_seed_host_outside_the_list_never_opens_a_socket():
    """`approved.check()` runs at src/fetch.py:539, before `_resolve` and before the
    httpx client makes a request, so a lookalike host costs us nothing but a log line."""
    led = fetch.Ledger()
    crawler = fetch.Crawler(["agency.gov"],
                            url_for=lambda d: "https://never-resolve-this.invalid/",
                            test_hosts=[HOST], timeouts=DECK_TIMEOUTS, ledger=led)
    obs = crawler_loop(crawler, ["agency.gov"])[0]
    assert "RegistrableDomainError" in (obs.error_type or ""), obs.error_type
    assert obs.sends == 0
    assert led.rows == [], "a refused seed host must not reach the ledger: nothing was sent"


# ========================================================================= rule 2
def test_rule2_offdomain_redirect_is_recorded_and_not_followed(mock_stack):
    led = fetch.Ledger()
    crawler = deck_crawler(mock_stack, "crossdomain_redirect", ledger=led)
    obs = fetch_one(crawler)
    assert obs.redirect_off_domain is True
    assert obs.status_code == 302
    assert obs.final_url.endswith("/case/crossdomain_redirect")
    assert obs.redirect_chain and obs.redirect_chain[0]["to"] == \
        "https://cdn-elsewhere.example/landing"
    # the whole point: the foreign host appears in the chain, never in the ledger
    assert [r["url"] for r in led.rows] == [obs.final_url]
    assert not any("cdn-elsewhere" in r["url"] for r in led.rows)
    assert obs.sends == 1


def test_rule2_samedomain_redirect_is_followed(mock_stack):
    crawler = deck_crawler(mock_stack, "same_domain_redirect")
    obs = fetch_one(crawler)
    assert obs.status_code == 200
    assert len(obs.redirect_chain) == 1
    assert obs.final_url.endswith("/case/same_domain_final")
    assert obs.headers["x-powered-by"] == ["PHP/8.4.27"]
    assert obs.sends == 1, "a redirect hop rides inside one phase and is not a new charge"


def test_rule2_redirect_chain_length_is_bounded(mock_stack):
    led = fetch.Ledger()
    crawler = deck_crawler(mock_stack, "redirect_loop", ledger=led)
    obs = fetch_one(crawler)
    assert obs.error_type == "redirect_limit"
    assert len(led.rows) <= config.MAX_REDIRECTS + 1
    assert obs.sends == 1


def test_rule2_body_is_capped_and_never_stored(mock_stack):
    crawler = deck_crawler(mock_stack, "big_body")
    obs = fetch_one(crawler)
    assert obs.body_length_read == config.MAX_BODY_BYTES
    assert not hasattr(obs, "body") and not hasattr(obs, "html")
    assert "body" not in obs.as_row()


def test_rule2_dead_port_gets_exactly_one_http_fallback(mock_stack):
    led = fetch.Ledger()
    crawler = fetch.Crawler(["probe.gov"],
                            url_for=lambda d: f"https://{HOST}:{mock_stack.dead_port}/",
                            test_hosts=[HOST], timeouts=(1.0, 2.0), ledger=led)
    obs = fetch_one(crawler)
    assert obs.sends == 2, "rule 2 allows one https try and one plain-http try, no more"
    assert obs.https_or_http == "http"
    # MockStack.dead_port is deliberately UNBOUND (tests/mock_server.py:9). On this
    # Windows host that surfaces as a connect timeout rather than a refused socket;
    # src/fetch.py:573 treats both as "could not connect" and falls back exactly once.
    assert obs.error_type in ("connect_error", "timeout"), obs.error_type
    assert [r["phase"] for r in led.rows] == ["https", "http_fallback"]


def test_rule2_dns_failure_does_not_trigger_a_fallback():
    """A second doomed lookup against the same name would be avoidable traffic."""
    led = fetch.Ledger()
    dead = "no-such-host-here.invalid"
    crawler = fetch.Crawler([dead], url_for=lambda d: f"https://{d}/",
                            test_hosts=[HOST], timeouts=(1.0, 2.0), ledger=led)
    obs = fetch_one(crawler, dead)
    assert obs.error_type == "dns_error"
    assert obs.sends == 1, "budget charged, but only one phase was ever attempted"
    assert led.rows == [], "DNS failure returns before any request, so it logs nothing"


def test_rule2_cert_failure_gets_one_unverified_retry_and_no_more(mock_stack):
    crawler = deck_crawler(mock_stack, "vuln8335", base=mock_stack.https_base)
    obs = fetch_one(crawler)
    assert obs.cert_error is True, "broken TLS is a finding in its own right; the flag survives"
    assert obs.status_code == 200, "headers were still readable on the unverified retry"
    assert obs.sends == 2, "https + one unverified retry, and no third send"
    assert obs.https_or_http == "https"


def test_rule2_budget_object_refuses_a_fourth_phase():
    async def main():
        b = fetch.Budget()
        got = [await b.take("a.gov", p) for p in ("https", "https_unverified", "http_fallback")]
        with pytest.raises(RuntimeError):
            await b.take("a.gov", "one_too_many")
        return got, b.count("a.gov")
    got, count = asyncio.run(main())
    assert got == [1, 2, 3]
    assert count == config.MAX_SENDS_PER_DOMAIN == 3


def test_rule2_no_cookie_state_carries_into_the_next_request(recorder):
    """The deck cannot prove this one, because it never sets a cookie and redirects.

    This test found a real defect on 2026-10-23: `AsyncClient(cookies=None)` only starts
    the jar empty — httpx extracts `Set-Cookie` into `client.cookies` after EVERY
    response, so a cookie from hop 1 rode into hop 2 inside the same domain visit,
    against hard rule 2 and this module's own "deliberately no Cookie header, ever".
    Fixed at src/fetch.py:455 with `client.cookies.clear()`.

    Two hits prove the redirect really was followed and `set_cookie_sent` proves the
    server really offered a cookie, so the absence below is a result and not a vacuity.
    """
    crawler = recorder_crawler(recorder, path="/setcookie_then_redirect")
    obs = fetch_one(crawler)
    assert len(recorder["hits"]) == 2, "the same-host redirect should have been followed"
    assert obs.final_url.endswith("/landing")
    assert recorder.get("set_cookie_sent"), "the server must actually have set a cookie"
    assert obs.redirect_chain[0]["status"] == "302"
    for path, headers in recorder["hits"]:
        assert "cookie" not in headers, f"we sent a Cookie header on {path}"


# ========================================================================= rule 4
def test_rule4_429_backs_off_without_retrying(mock_stack):
    led = fetch.Ledger()
    crawler = deck_crawler(mock_stack, "status_429", ledger=led)
    obs = fetch_one(crawler)
    assert obs.status_code == 429
    assert obs.backoff is True
    assert obs.sends == 1 and len(led.rows) == 1, "rule 4: never retry a rate limit in-run"


def test_rule4_503_backs_off_without_retrying(mock_stack):
    crawler = deck_crawler(mock_stack, "status_503")
    obs = fetch_one(crawler)
    assert obs.status_code == 503 and obs.backoff is True and obs.sends == 1


def test_rule4_ipbudget_never_allows_two_in_flight_for_one_ip():
    async def main():
        ips = fetch.IPBudget(max_per_ip=1)
        events = []

        async def worker(n):
            await ips.acquire("127.0.0.1")
            events.append(("down", n))
            await asyncio.sleep(0.02)
            events.append(("up", n))
            await ips.release("127.0.0.1")

        await asyncio.gather(*(worker(i) for i in range(4)))
        depth = peak = 0
        for kind, _ in events:
            depth += 1 if kind == "down" else -1
            peak = max(peak, depth)
        return peak, len(events)
    peak, n_events = asyncio.run(main())
    assert n_events == 8
    assert peak == 1, "one concurrent request per IP is hard rule 4, not a suggestion"


def test_rule4_crawler_holds_one_request_per_ip_in_practice(recorder):
    """Deck jitter staggers starts, so this asserts the invariant, not the overlap;
    the overlap mechanism itself is pinned by the unit test above."""
    crawler = recorder_crawler(recorder, domains=("a.gov", "b.gov", "c.gov", "d.gov"),
                              path="/sleep")
    obs = crawler_loop(crawler, ["a.gov", "b.gov", "c.gov", "d.gov"])
    assert len(recorder["hits"]) == 4
    assert all(o.status_code == 200 for o in obs)
    assert recorder["peak"] <= 1


# ========================================================================= rule 5
def test_rule5_blocklisted_domain_is_skipped_without_traffic(mock_stack):
    led = fetch.Ledger()
    crawler = deck_crawler(mock_stack, "vuln8335", domains=["gone.gov"],
                           blocklist={"gone.gov"}, ledger=led)
    obs = fetch_one(crawler, "gone.gov")
    assert obs.skipped_reason == "blocklisted"
    assert obs.sends == 0
    assert led.rows == []


def test_rule5_blocklist_file_parsing(tmp_path):
    p = tmp_path / "blocklist.txt"
    p.write_text("# opt-outs\n\n  Foo.Gov.  # trailing comment\nbar.gov\n",
                 encoding="utf-8")
    assert fetch.load_blocklist(p) == {"foo.gov", "bar.gov"}
    assert fetch.load_blocklist(tmp_path / "absent.txt") == set()


def test_rule5_blocklist_is_matched_after_case_folding(mock_stack):
    crawler = deck_crawler(mock_stack, "vuln8335", domains=["GONE.gov"],
                           blocklist={"gone.gov"})
    obs = fetch_one(crawler, "gone.gov")
    assert obs.skipped_reason == "blocklisted"


# ========================================================================= rule 6
def test_rule6_what_counts_as_bad_traffic():
    assert fetch.KillSwitch.bad(403, None) is True
    assert fetch.KillSwitch.bad(429, None) is True
    assert fetch.KillSwitch.bad(500, None) is True
    assert fetch.KillSwitch.bad(503, None) is True
    assert fetch.KillSwitch.bad(200, None) is False
    assert fetch.KillSwitch.bad(404, None) is False
    assert fetch.KillSwitch.bad(None, "timeout") is False, \
        "a timeout is our network, not their objection; counting it would halt on us"


def test_rule6_rolling_window_trips_above_the_ratio(tmp_path):
    async def main():
        ks = fetch.KillSwitch(window=10, ratio=0.10, abuse_flag=tmp_path / "none.flag")
        for i in range(10):
            await ks.record(503 if i < 2 else 200, None)
        return ks
    assert asyncio.run(main()).tripped is True


def test_rule6_rolling_window_stays_closed_at_the_ratio(tmp_path):
    async def main():
        ks = fetch.KillSwitch(window=10, ratio=0.10, abuse_flag=tmp_path / "none.flag")
        for i in range(10):
            await ks.record(503 if i < 1 else 200, None)
        return ks
    ks = asyncio.run(main())
    assert ks.tripped is False, "10% of 10 is not MORE than 10%"


def test_rule6_window_does_not_trip_before_it_is_full(tmp_path):
    async def main():
        ks = fetch.KillSwitch(window=50, ratio=0.10, abuse_flag=tmp_path / "none.flag")
        for _ in range(3):
            await ks.record(503, None)
        return ks
    assert asyncio.run(main()).tripped is False


def test_rule6_abuse_marker_needs_the_magic_words(tmp_path):
    quiet = tmp_path / "quiet.flag"
    quiet.write_text("just a note about something else", encoding="utf-8")
    ks_quiet = fetch.KillSwitch(abuse_flag=quiet)
    ks_quiet.check_external()
    assert ks_quiet.tripped is False, \
        "an unrelated file named abuse.flag must not be able to halt the study by accident"

    loud = tmp_path / "abuse.flag"
    loud.write_text("ABUSE_COMPLAINT automated scanning, stop now", encoding="utf-8")
    ks = fetch.KillSwitch(abuse_flag=loud)
    ks.check_external()
    assert ks.tripped is True
    assert "abuse/complaint marker" in (ks.reason or "")


def test_rule6_absent_marker_does_not_trip(tmp_path):
    ks = fetch.KillSwitch(abuse_flag=tmp_path / "never-written.flag")
    ks.check_external()
    assert ks.tripped is False


def test_rule6_tripped_switch_stops_the_domains_after_it(mock_stack, tmp_path):
    led = fetch.Ledger()
    ks = fetch.KillSwitch(abuse_flag=tmp_path / "none.flag")
    ks.tripped_reason = "kill switch: test"
    crawler = deck_crawler(mock_stack, "vuln8335", domains=["a.gov", "b.gov"],
                           kill_switch=ks, ledger=led)
    out = crawler_loop(crawler, ["a.gov", "b.gov"])
    assert all(o.error_type == "halted" for o in out)
    assert led.rows == [], "a halted run sends nothing at all"


# ========================================================================= rule 7
def test_rule7_send_over_the_phase_cap_is_a_finding():
    rows = [ledger_row(phase=p) for p in
            ("https", "https_unverified", "http_fallback", "fourth_phase")]
    problems = fetch.audit_ledger(rows, {"a.gov": 4}, {"a.gov"})
    assert any("budget violation: a.gov made 4 sends" in p for p in problems)


def test_rule7_ledger_row_on_a_foreign_host_is_a_finding():
    rows = [ledger_row(url="https://cdn-elsewhere.example/landing")]
    problems = fetch.audit_ledger(rows, {"a.gov": 1}, {"a.gov"})
    assert any("non-approved host" in p for p in problems)


def test_rule7_more_ledger_phases_than_charges_is_a_finding():
    rows = [ledger_row(phase="https"), ledger_row(phase="http_fallback", url="http://a.gov/")]
    problems = fetch.audit_ledger(rows, {"a.gov": 1}, {"a.gov"})
    assert any("did not approve" in p for p in problems)


def test_rule7_fewer_phases_than_charges_is_not_a_finding():
    """Budget charges before the request; a DNS failure never writes a row."""
    rows = [ledger_row(phase="https")]
    assert fetch.audit_ledger(rows, {"a.gov": 2}, {"a.gov"}) == []


def test_rule7_redirect_hops_do_not_break_the_audit():
    rows = [ledger_row(phase="https", hop=0, status=302),
            ledger_row(phase="https", hop=1)]
    assert fetch.audit_ledger(rows, {"a.gov": 1}, {"a.gov"}) == []


def test_rule7_a_clean_mock_run_audits_clean(mock_stack):
    led = fetch.Ledger()
    crawler = deck_crawler(mock_stack, "vuln8335",
                           domains=["a.gov", "b.gov", "c.gov"], ledger=led)
    out = crawler_loop(crawler, ["a.gov", "b.gov", "c.gov"])
    roots = {fetch.registrable_root(HOST)} | {fetch.registrable_root(d)
                                              for d in ("a.gov", "b.gov", "c.gov")}
    counts = {o.domain: o.sends for o in out}
    assert led.rows, "the audit has to be run against real rows to mean anything"
    assert fetch.audit_ledger(led.rows, counts, roots) == []


# ========================================================================= rule 8
def test_rule8_user_agent_identifies_the_study_and_the_contact(recorder):
    crawler = recorder_crawler(recorder)
    fetch_one(crawler)
    sent = recorder["hits"][0][1]
    assert sent["user-agent"] == config.USER_AGENT
    assert config.CONTACT_EMAIL in sent["user-agent"]
    assert "http" in sent["user-agent"], "a UA without a URL is not a contactable identity"


def test_rule8_request_headers_carry_no_cookies_by_construction():
    crawler = fetch.Crawler(["a.gov"], test_hosts=[HOST])
    headers = crawler._request_headers()
    assert "Cookie" not in headers and "cookie" not in headers
    assert headers["User-Agent"] == config.USER_AGENT


# ========================================================================= Gate A
def test_gate_a_is_closed_in_this_checkout():
    assert config.LIVE_REQUESTS_ENABLED is False, \
        "if you are flipping this to True in a commit, stop and open Gate A on purpose"


def test_gate_a_refuses_live_without_the_marker(monkeypatch):
    monkeypatch.setattr(config, "LIVE_REQUESTS_ENABLED", False)
    monkeypatch.delenv(config.GATE_MARKER_ENV, raising=False)
    with pytest.raises(fetch.GateClosed):
        fetch.assert_live_allowed()


def test_gate_a_marker_alone_opens_live_traffic(monkeypatch):
    """Documented reality, not an endorsement: the gate is an OR (src/fetch.py:93).

    One stray `export PATCHWATCH_GATE_A=APPROVED` in a shell profile is enough to
    authorise live traffic with no code change. See
    reports/STATUS_GATE_A_2026-10-23.md for the decision this is waiting on.
    """
    monkeypatch.setattr(config, "LIVE_REQUESTS_ENABLED", False)
    monkeypatch.setenv(config.GATE_MARKER_ENV, "approved")   # matched case-insensitively
    fetch.assert_live_allowed()


def test_gate_a_still_refuses_a_placeholder_identity(monkeypatch):
    monkeypatch.setenv(config.GATE_MARKER_ENV, "APPROVED")
    monkeypatch.setattr(config, "USER_AGENT", "Study (+[PROJECT_URL]; [CONTACT_EMAIL])")
    with pytest.raises(fetch.GateClosed):
        fetch.assert_live_allowed()


def test_gate_a_mock_mode_bypasses_the_gate_by_design(monkeypatch):
    monkeypatch.delenv(config.GATE_MARKER_ENV, raising=False)
    monkeypatch.setattr(config, "LIVE_REQUESTS_ENABLED", False)
    fetch.assert_live_allowed(allow_loopback_only=True)
