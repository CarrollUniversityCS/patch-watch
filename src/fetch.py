"""Stage 2: the only module in this project that talks to a government domain.

Everything the mission brief's hard rules demand is enforced HERE, in code, not
in a comment:

  rule 1  passive only         one ordinary GET for "/" ; no payload, no path
                               guessing, no port scanning; a domain that is not
                               on the approved list cannot be requested at all
                               (ApprovedSet check runs before the socket opens)
  rule 2  request budget       MAX_SENDS_PER_DOMAIN cap, <=3 redirects, redirect
                               containment by registrable root of the FIRST url,
                               one http fallback only when https could not
                               connect, one unverified retry only on a TLS
                               verification failure, 64 KiB body cap, body never
                               stored, cookies never stored and never resent
  rule 3  identity             fixed User-Agent, no browser spoofing
  rule 4  rate limits          20 workers, 1 in flight per resolved IP, 100-500 ms
                               jitter, 10 s connect / 20 s total, no retry on 429/503
  rule 5  opt-out              blocklist re-read at run start, skipped domains recorded
  rule 6  kill switch          rolling window of 50 phase outcomes (redirect hops
                               are not separate entries): trips above 10% 429/5xx
                               (overload) or above 30% 401/403 (blocked broadly);
                               or if logs/abuse.flag appears (re-read before every
                               domain); or if the ledger audit finds a budget
                               violation
  rule 8  human gate           refuses to run unless GATE A is marked APPROVED and
                               the User-Agent carries no [PLACEHOLDER]

Test-only escape hatch: `url_for` maps a domain to a URL so the crawler can be
driven against the loopback mock server stack. It never relaxes any check above;
the approved-domain set and the redirect containment root are still enforced.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import socket
import ssl
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import urljoin, urlparse

import httpx

import config

# Refusals and halts have to be visible while a run is happening, not only in the
# database afterwards: hard rule 1 asks for a `REFUSING <phase>: <host>` line, and
# the abuse-file halt is the other thing an operator needs to see the moment it
# lands. pipeline.py attaches this to logs/capture.log (UTF-8) so the em dash in
# rule 1's literal wording cannot trip a cp1252 console.
log = logging.getLogger("patchwatch.fetch")


# --------------------------------------------------------------------------- clock
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _date_str(iso: str) -> str:
    return iso[:10]


# --------------------------------------------------------------------------- gate
class GateClosed(RuntimeError):
    """Raised when live traffic is requested before Gate A."""


class KillSwitchTripped(RuntimeError):
    """Raised when hard rule 6 fires; the run stops immediately."""


class RegistrableDomainError(ValueError):
    """Raised when a request would leave the approved domain set (hard rule 1).

    Only the SEED url and same-root hops can raise this. A redirect to a foreign
    registrable domain is not an error: rule 2 says record the Location and do not
    follow it, which is handled in the redirect loop.
    """


def assert_live_allowed(allow_loopback_only: bool = False) -> None:
    """Hard rule 8. Live requests need the env marker AND a filled-in UA."""
    if allow_loopback_only:
        return
    marker = os.environ.get(config.GATE_MARKER_ENV, "")
    if not (config.LIVE_REQUESTS_ENABLED and marker.strip().upper() == "APPROVED"):
        raise GateClosed(
            "GATE A is not open. No request will be sent to any government domain. "
            f"The operator must reply 'GATE A APPROVED', set "
            "LIVE_REQUESTS_ENABLED=True in src/config.py, and run with "
            f"{config.GATE_MARKER_ENV}=APPROVED."
        )
    if "[PROJECT_URL]" in config.USER_AGENT or "[CONTACT_EMAIL]" in config.USER_AGENT:
        raise GateClosed("User-Agent still contains placeholders; fill in PROJECT_URL and CONTACT_EMAIL.")


# --------------------------------------------------------------------------- targets
def registrable_root(host: str) -> str:
    """Last two labels of a hostname; used only to decide redirect containment.

    Our population is second-level .gov domains, so the last-two-label rule is
    exact here. A non-exact match can only ever make us FOLLOW LESS, which is the
    safe direction (a host on someone else's suffix is treated as off-domain).
    """
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    if _is_ip_literal(host):
        return host
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _is_ip_literal(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except (OSError, ValueError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (OSError, ValueError):
        return False


def load_blocklist(path: Path | None = None) -> set[str]:
    """Hard rule 5. One domain per line; # comments and blanks ignored.

    Also reads the sibling `<name>.local.txt` (e.g. blocklist.local.txt). That is
    where blocklist.txt itself tells operators to put real opt-outs, because the list
    of who opted out is a disclosure and the local file is gitignored. Before
    2026-10-23 that file was never read, so an opt-out recorded exactly as instructed
    was silently ignored.
    """
    p = Path(path or config.BLOCKLIST_PATH)
    out: set[str] = set()
    for f in (p, p.with_name(p.stem + ".local" + p.suffix)):
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            d = line.split("#", 1)[0].strip().lower().rstrip(".")
            if d:
                out.add(d)
    return out


class ApprovedSet:
    """Hard rule 1: nothing outside the approved list may be contacted.

    `extra_hosts` is an explicit, opt-in allowlist for the loopback mock rig, since
    `url_for` points a domain at 127.0.0.1 in tests. It never widens redirect
    containment, which is enforced separately against the first URL's root.
    """

    def __init__(self, domains: Iterable[str], extra_hosts: Iterable[str] = ()):
        self.domains = {d.strip().lower().rstrip(".") for d in domains if d.strip()}
        self.extra_hosts = {h.strip().lower().rstrip(".") for h in extra_hosts if h.strip()}
        self.roots = {registrable_root(d) for d in self.domains if d}

    def allows(self, host: str) -> bool:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return False
        if host in self.domains or host in self.extra_hosts:
            return True
        return registrable_root(host) in self.roots

    def check(self, host: str, *, phase: str) -> None:
        host = (host or "").strip().lower()
        if not host:
            log.warning("REFUSING %s: empty host - not on approved list (hard rule 1)", phase)
            raise RegistrableDomainError(f"REFUSING {phase}: empty host")
        if self.allows(host):
            return
        # Hard rule 1 says a refusal is LOGGED, in these words. The exception carries
        # the same text so it survives into obs.error_type if anything catches it.
        log.warning("REFUSING %s: %s — not on approved list (hard rule 1)", phase, host)
        raise RegistrableDomainError(
            f"REFUSING {phase}: host {host!r} is not on the approved list (hard rule 1)")


# --------------------------------------------------------------------------- kill switch
class KillSwitch:
    """Rule 6. Two trips over one rolling window of the most recent phase outcomes.

    * overload: more than `ratio` (10%) of the window are 429 or 5xx - the signals that
      we might be adding load;
    * block: more than `block_ratio` (30%) of the window are 401/403 - our crawler is
      being refused broadly, which needs a human to look before anything else is sent.

    403 used to count toward the overload trip. Edge firewalls (Cloudflare, Akamai)
    answer a non-browser client with 403 on first contact; at that base rate the
    combined 10% rule halted the first real Wisconsin snapshot with no load signal at
    all (plan §12, 2026-10-23). A refusal is honoured where it happens - the site is
    NOT_MEASURED and not asked again that day - and only a broad pattern stops the run.
    """

    def __init__(self, window: int | None = None, ratio: float | None = None,
                 abuse_flag: Path | None = None, block_ratio: float | None = None):
        self.window = window or config.KILL_ROLLING_WINDOW
        self.ratio = ratio or config.KILL_TRIP_RATIO
        self.block_ratio = block_ratio or config.KILL_BLOCK_RATIO
        self.abuse_flag = Path(abuse_flag or config.ABUSE_FLAG_PATH)
        self._recent: deque[bool] = deque(maxlen=self.window)
        self._blocked: deque[bool] = deque(maxlen=self.window)
        self.tripped_reason: str | None = None
        self.lock = asyncio.Lock()

    @staticmethod
    def bad(status: int | None, error_type: str | None) -> bool:
        """Overload signal: 429 or any 5xx. A timeout is our network, not their load."""
        if status in config.KILL_STATUS_CODES:
            return True
        if status is not None and status >= 500:
            return True
        return False

    @staticmethod
    def blocked(status: int | None) -> bool:
        """Refusal signal: 401/403."""
        return status in config.KILL_BLOCK_STATUS_CODES

    async def record(self, status: int | None, error_type: str | None) -> None:
        async with self.lock:
            self._recent.append(self.bad(status, error_type))
            self._blocked.append(self.blocked(status))
            if len(self._recent) < self.window:
                return
            n = len(self._recent)
            share = sum(self._recent) / n
            blocked = sum(self._blocked) / n
            if share > self.ratio:
                self.tripped_reason = (
                    f"kill switch (overload): {share:.0%} of the last {n} outcomes were "
                    f"429/5xx (threshold {self.ratio:.0%})")
            elif blocked > self.block_ratio:
                self.tripped_reason = (
                    f"kill switch (block rate): {blocked:.0%} of the last {n} outcomes were "
                    f"401/403 (threshold {self.block_ratio:.0%}) - the crawler is being "
                    f"refused broadly; find out why before sending anything else")
            if self.tripped_reason:
                self._recent.clear()
                self._blocked.clear()

    def check_external(self) -> None:
        """Rule 6, second trigger: an operator-written abuse/complaint marker.

        Matched on CONTENT (config.KILL_ABUSE_MARKER) so an empty or unrelated file
        cannot stop a run by accident. Only the first line, truncated, is echoed.
        """
        if self.tripped:
            return
        try:
            if not self.abuse_flag.exists():
                return
            text = self.abuse_flag.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        if config.KILL_ABUSE_MARKER in text.upper():
            first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
            self.tripped_reason = (
                f"kill switch: abuse/complaint marker in {self.abuse_flag} (hard rule 6): "
                f"{first[:160]!r}")

    @property
    def tripped(self) -> bool:
        return self.tripped_reason is not None

    @property
    def reason(self) -> str | None:
        return self.tripped_reason


# --------------------------------------------------------------------------- budget
@dataclass
class Budget:
    """Rule 2 send accounting, per domain per snapshot."""

    # 1 https primary + 1 http fallback + 1 unverified TLS retry. Redirect hops ride
    # inside a chain and are counted by MAX_REDIRECTS, not against this cap.
    cap: int = config.MAX_SENDS_PER_DOMAIN
    _counts: dict[str, int] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def take(self, domain: str, phase: str) -> int:
        async with self._lock:
            n = self._counts.get(domain, 0)
            if n >= self.cap:
                raise RuntimeError(f"request budget exhausted for {domain} at phase {phase} "
                                   f"(cap {self.cap}) - refusing to send")
            self._counts[domain] = n + 1
            return n + 1

    def count(self, domain: str) -> int:
        return self._counts.get(domain, 0)


class IPBudget:
    """Rule 4: one concurrent request per resolved IP."""

    def __init__(self, max_per_ip: int = config.MAX_PER_IP):
        self.max_per_ip = max_per_ip
        self._inflight: dict[str, int] = {}
        self._cond = asyncio.Condition()

    async def acquire(self, ip: str) -> None:
        async with self._cond:
            while self._inflight.get(ip, 0) >= self.max_per_ip:
                await self._cond.wait()
            self._inflight[ip] = self._inflight.get(ip, 0) + 1

    async def release(self, ip: str) -> None:
        async with self._cond:
            self._inflight[ip] = max(0, self._inflight.get(ip, 0) - 1)
            self._cond.notify_all()


# --------------------------------------------------------------------------- observation
@dataclass
class Observation:
    """One row of the observations table. Field list comes from brief Stage 2."""

    domain: str
    run_id: str
    snapshot_label: str
    started_at_utc: str
    https_or_http: str = ""
    requested_url: str = ""
    final_url: str = ""
    status_code: int | None = None
    redirect_chain: list[dict[str, str]] = field(default_factory=list)
    redirect_off_domain: bool = False
    resolved_ip: str | None = None
    headers: dict[str, list[str]] = field(default_factory=dict)
    headers_raw: list[list[str]] = field(default_factory=list)
    cert_error: bool = False
    error_type: str | None = None
    latency_ms: int | None = None
    body_length_read: int = 0
    php_hints: dict[str, bool] = field(default_factory=dict)
    sends: int = 0
    backoff: bool = False
    skipped_reason: str | None = None

    def as_row(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "run_id": self.run_id,
            "snapshot_label": self.snapshot_label,
            "started_at_utc": self.started_at_utc,
            "https_or_http": self.https_or_http,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "redirect_chain_json": json.dumps(self.redirect_chain),
            "redirect_off_domain": int(self.redirect_off_domain),
            "resolved_ip": self.resolved_ip,
            "headers_json": json.dumps({k: v for k, v in self.headers.items()}),
            "headers_raw_json": json.dumps(self.headers_raw),
            "cert_error": int(self.cert_error),
            "error_type": self.error_type,
            "latency_ms": self.latency_ms,
            "body_length_read": self.body_length_read,
            "php_hints_json": json.dumps(self.php_hints),
            "sends": self.sends,
            "backoff": int(self.backoff),
            "skipped_reason": self.skipped_reason,
        }


def add_headers(target: dict[str, list[str]], items: Iterable[Sequence[str]]) -> None:
    """Lower-case keyed, order-preserving, multiple values kept (never merged)."""
    for pair in items:
        name, value = pair[0], pair[1]
        target.setdefault(name.lower(), []).append(value)


_LINK_PHP_RE = re.compile(rb"""(?:href|action)\s*=\s*["'][^"']*\.php""", re.IGNORECASE)
_PHP_ANY_RE = re.compile(rb"\.php", re.IGNORECASE)
_PHPSESSID_RE = re.compile(rb"phpsessid", re.IGNORECASE)


def derive_body_hints(body: bytes) -> dict[str, bool]:
    """Body is inspected here and then discarded. Nothing returns the bytes."""
    sessid = bool(_PHPSESSID_RE.search(body))
    return {
        "link_or_action_has_php": bool(_LINK_PHP_RE.search(body)),
        "php_marker_any": bool(_PHP_ANY_RE.search(body)),
        # the classifier reads phpsessid_in_body; the alias keeps both spellings valid
        "phpsessid_in_body": sessid,
        "phpsessid_body_marker": sessid,
    }


# --------------------------------------------------------------------------- crawler
class Crawler:
    def __init__(self, approved_domains: Iterable[str], *, blocklist: set[str] | None = None,
                 run_id: str = "test", snapshot_label: str = "test",
                 url_for: Callable[[str], str] | None = None,
                 test_hosts: Iterable[str] = (),
                 max_concurrency: int = config.MAX_CONCURRENCY,
                 kill_switch: KillSwitch | None = None,
                 ledger: "Ledger | None" = None,
                 timeouts: tuple[float, float] | None = None):
        self.approved = ApprovedSet(approved_domains, extra_hosts=test_hosts)
        self.blocklist = {d.lower() for d in (blocklist or set())}
        self.run_id = run_id
        self.snapshot_label = snapshot_label
        self.url_for = url_for or (lambda d: f"https://{d}/")
        self.sem = asyncio.Semaphore(max_concurrency)
        self.ips = IPBudget()
        self.budget = Budget()
        self.kill = kill_switch or KillSwitch()
        self.ledger = ledger
        self.connect_timeout, self.total_timeout = timeouts or (
            config.CONNECT_TIMEOUT_S, config.TOTAL_TIMEOUT_S)
        self.resolved_cache: dict[str, str] = {}
        self._stopped = asyncio.Event()

    # -- helpers ------------------------------------------------------------
    def _request_headers(self) -> dict[str, str]:
        return {
            "User-Agent": config.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            # deliberately no Cookie header, ever (rule 2)
        }

    async def _resolve(self, host: str) -> str | None:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return None
        if not infos:
            return None
        return str(infos[0][4][0])

    async def _jitter(self) -> None:
        await asyncio.sleep(random.uniform(config.JITTER_MIN_S, config.JITTER_MAX_S))

    # -- one scheme attempt, including the redirect chain -------------------
    async def _attempt(self, client: httpx.AsyncClient, domain: str, url: str,
                       phase: str, obs: Observation) -> Observation:
        """Follow at most MAX_REDIRECTS hops, all inside the first URL's root."""
        root0 = registrable_root(urlparse(url).hostname or "")
        current = url
        self.approved.check(urlparse(current).hostname or "", phase=phase)
        for hop in range(config.MAX_REDIRECTS + 1):
            ip = await self._resolve(urlparse(current).hostname or "")
            if ip is None:
                obs.error_type = "dns_error"
                return obs
            self.resolved_cache[domain] = ip
            obs.resolved_ip = ip
            await self.ips.acquire(ip)
            t0 = time.monotonic()
            try:
                async with client.stream("GET", current, headers=self._request_headers(),
                                         follow_redirects=False) as resp:
                    raw = [[str(n), str(v)] for n, v in resp.headers.multi_items()]
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) >= config.MAX_BODY_BYTES:
                            break
                    body_len = min(len(body), config.MAX_BODY_BYTES)
                    status = resp.status_code
                if self.ledger:
                    await self.ledger.record(self.run_id, domain, current, phase, hop, status, None)
                obs.latency_ms = int((time.monotonic() - t0) * 1000)
                obs.final_url = current
                obs.status_code = status
                obs.headers_raw = raw
                obs.headers = {}
                add_headers(obs.headers, raw)
                obs.php_hints.update(derive_body_hints(bytes(body)))
                obs.body_length_read = body_len
                del body  # rule 2: never store bodies
                # Rule 2 also says no session state. `cookies=None` at construction only
                # starts the jar empty: httpx calls `client.cookies.extract_cookies(resp)`
                # on EVERY response (httpx/_client.py, 0.28.1), so a Set-Cookie on one
                # same-domain redirect hop would ride into the next request. Drop it.
                client.cookies.clear()

                if status in (429, 503):
                    obs.backoff = True           # rule 4: do not retry in this snapshot
                    return obs
                if 300 <= status < 400:
                    loc = obs.headers.get("location", [None])[-1]
                    obs.redirect_chain.append({"hop": str(hop), "from": current,
                                               "to": loc or "", "status": str(status)})
                    if not loc:
                        obs.error_type = "redirect_no_location"
                        return obs
                    nxt = urljoin(current, loc)
                    nxt_host = (urlparse(nxt).hostname or "").lower()
                    if registrable_root(nxt_host) != root0:
                        # Rule 2: record the Location value, do not follow. No request is
                        # sent and this is NOT an error - off-domain redirects are a
                        # reported feature of the population, not a safety violation.
                        # It IS logged: hard rule 1 wants the refusal on the record, and
                        # "we saw a redirect off the approved root and did not take it"
                        # is a finding, not a silence.
                        log.warning("REFUSING %s: %s — not on approved list (hard rule 1)",
                                    "redirect", nxt_host)
                        obs.redirect_off_domain = True
                        obs.final_url = current
                        return obs
                    # Belt and braces: a same-root hop must still sit in the approved set.
                    self.approved.check(nxt_host, phase="redirect")
                    if hop >= config.MAX_REDIRECTS:
                        obs.error_type = "redirect_limit"
                        return obs
                    current = nxt
                    continue
                return obs
            except httpx.TimeoutException as exc:
                if self.ledger:
                    await self.ledger.record(self.run_id, domain, current, phase, hop, None, "timeout")
                obs.latency_ms = int((time.monotonic() - t0) * 1000)
                obs.error_type = "timeout"
                obs.final_url = current
                return obs
            except httpx.ConnectError as exc:
                # Distinguish "TLS certificate could not be verified" (rule 2 allows one
                # unverified retry, to read the headers) from a plain connection failure
                # (rule 2 allows one plain-http fallback). Getting this wrong would hide
                # which sites have broken TLS, so check the exception chain, not a string.
                if _is_cert_failure(exc):
                    obs.cert_error = True
                    obs.error_type = "cert_error"
                    if self.ledger:
                        await self.ledger.record(self.run_id, domain, current, phase, hop, None, "cert_error")
                    return obs
                if self.ledger:
                    await self.ledger.record(self.run_id, domain, current, phase, hop, None, "connect_error")
                obs.error_type = "connect_error"
                obs.final_url = current
                return obs
            except (httpx.RemoteProtocolError, httpx.ReadError, httpx.ProtocolError) as exc:
                if self.ledger:
                    await self.ledger.record(self.run_id, domain, current, phase, hop, None, "connect_error")
                obs.error_type = "connect_error"
                obs.final_url = current
                return obs
            finally:
                await self.ips.release(ip)
        obs.error_type = "redirect_limit"
        return obs

    # -- public: one domain, full rule-2 sequence ---------------------------
    async def fetch(self, domain: str) -> Observation:
        domain = domain.strip().lower().rstrip(".")
        obs = Observation(domain=domain, run_id=self.run_id, snapshot_label=self.snapshot_label,
                          started_at_utc=utc_now_iso())
        if domain in self.blocklist:
            obs.skipped_reason = "blocklisted"
            obs.error_type = "skipped_blocklist"
            return obs
        # Rule 6, second trigger, re-read per domain: an operator who drops the abuse
        # flag mid-run stops every request not yet sent, not just the next run
        # (audit C5). One stat() per domain is nothing next to a network request.
        self.kill.check_external()
        if self.kill.tripped:
            obs.skipped_reason = "halted_by_kill_switch"
            obs.error_type = "halted"
            return obs
        async with self.sem:
            self.kill.check_external()
            if self._stopped.is_set() or self.kill.tripped:
                obs.skipped_reason = "halted_by_kill_switch"
                obs.error_type = "halted"
                return obs
            await self._jitter()
            seed_url = self.url_for(domain)
            obs.requested_url = seed_url
            self.approved.check(urlparse(seed_url).hostname or "", phase="seed")

            async with httpx.AsyncClient(timeout=httpx.Timeout(
                    self.total_timeout, connect=self.connect_timeout),
                    http2=False, verify=True, cookies=None) as client:
                # 1) https primary
                try:
                    send_no = await self.budget.take(domain, "https")
                except RuntimeError as exc:
                    obs.error_type = "budget_exhausted"
                    obs.skipped_reason = str(exc)
                    return obs
                obs.sends = send_no
                obs.https_or_http = "https"
                obs = await self._attempt(client, domain, seed_url, "https", obs)
                await self.kill.record(obs.status_code, obs.error_type)

                # 2) TLS verification failure -> one retry with verification off, https only
                if obs.cert_error and not obs.headers_raw:
                    try:
                        send_no = await self.budget.take(domain, "https_unverified")
                        obs.sends = send_no
                        # Clear the phase-1 error before the retry, exactly as the http
                        # fallback does below. Left set, a retry that READ the headers
                        # was still classified NO_RESPONSE, which defeated the whole
                        # point of this phase (audit C1). cert_error stays True.
                        obs.error_type = None
                        async with httpx.AsyncClient(timeout=httpx.Timeout(
                                self.total_timeout, connect=self.connect_timeout),
                                http2=False, verify=False, cookies=None) as insecure:
                            obs = await self._attempt(insecure, domain, seed_url, "https_unverified", obs)
                        obs.cert_error = True   # keep the flag: it was a cert problem
                        await self.kill.record(obs.status_code, obs.error_type)
                    except Exception as exc:                    # pragma: no cover
                        obs.error_type = f"unverified_retry_failed: {type(exc).__name__}"

                # 3) https could not connect -> exactly one plain-http fallback (rule 2).
                #    DNS failure is excluded on purpose: http would fail the same way and a
                #    second doomed lookup is avoidable traffic.
                connect_failed = (obs.error_type in ("connect_error", "timeout")
                                  and not obs.headers_raw)
                if connect_failed:
                    http_url = _to_http(seed_url)
                    if http_url != seed_url:
                        try:
                            send_no = await self.budget.take(domain, "http_fallback")
                            obs.sends = send_no
                        except RuntimeError:
                            return obs
                        obs.https_or_http = "http"
                        prev_error = obs.error_type
                        obs.error_type = None
                        obs = await self._attempt(client, domain, http_url, "http_fallback", obs)
                        if obs.error_type is None and obs.status_code is None:
                            obs.error_type = prev_error
                        await self.kill.record(obs.status_code, obs.error_type)
            if self.kill.tripped:
                self._stopped.set()
            return obs

    async def fetch_many(self, domains: list[str]) -> list[Observation]:
        """Fetch every domain, one failure per domain, never one failure for all.

        `return_exceptions=True` is the whole point. Plain gather cancels the
        remaining tasks the moment one raises, and by then requests have already
        gone out to other agencies' servers - so a single malformed response would
        cost us a partial run with traffic sent and no observations written, and no
        ledger to account for it. A domain that blows up comes back as an
        observation carrying the exception type instead.
        """
        results = await asyncio.gather(*(self.fetch(d) for d in domains),
                                       return_exceptions=True)
        out: list[Observation] = []
        for domain, res in zip(domains, results):
            if isinstance(res, BaseException):
                obs = Observation(domain=domain, run_id=self.run_id,
                                  snapshot_label=self.snapshot_label,
                                  started_at_utc=utc_now_iso())
                # The type is the useful part; a message can carry a URL, and this
                # record is exported.
                obs.error_type = f"crawler_error: {type(res).__name__}"
                obs.skipped_reason = None
                out.append(obs)
            else:
                out.append(res)
        return out


def _is_cert_failure(exc: BaseException) -> bool:
    """True when the failure is TLS certificate verification, not connectivity.

    Checked on the exception chain first (httpx wraps the ssl error); the message
    is a documented fallback because anyio can flatten the chain on some platforms.
    A false positive here would mislabel a dead site as a cert problem and would
    suppress the http fallback, so both signals are reported in the ledger either way.
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ssl.SSLCertVerificationError):
            return True
        if isinstance(cur, ssl.SSLError) and getattr(cur, "verify_code", 0):
            return True
        cur = cur.__cause__ or cur.__context__
    text = str(exc).upper()
    return "CERTIFICATE_VERIFY_FAILED" in text or "CERTIFICATE_VALIDATE" in text


def _to_http(url: str) -> str:
    p = urlparse(url)
    if p.scheme != "https":
        return url
    port = f":{p.port}" if p.port and p.port != 443 else ""
    return f"http://{p.hostname}{port}{p.path or '/' }"


# --------------------------------------------------------------------------- ledger
class Ledger:
    """Every network request actually sent. Rule 2 is auditable only if this exists."""

    def __init__(self):
        self.rows: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def record(self, run_id: str, domain: str, url: str, phase: str,
                     redirect_hop: int, status: int | None, error_type: str | None) -> None:
        async with self._lock:
            self.rows.append({
                "run_id": run_id, "ts_utc": utc_now_iso(), "domain": domain,
                "method": "GET", "url": url, "phase": phase, "redirect_hop": redirect_hop,
                "status_code": status, "error_type": error_type,
            })

    def violations(self, cap: int = 3) -> list[str]:
        """Loose sanity check on raw row counts: a domain that appears more than
        `cap x (MAX_REDIRECTS + 1)` times means something is looping.

        NOT a substitute for `audit_ledger()` below, and never call it "the
        rule-2 audit": this counts LEDGER ROWS, and a redirect hop is a row inside a
        phase that the budget counter never charges, so the ceiling here (12) is
        deliberately far above the 3 send phases rule 2 allows. The budget is
        enforced per phase by `Budget.take()` (src/fetch.py:546, 559, 579) and audited
        against the ledger by `audit_ledger()`.
        """
        out = []
        per_domain: dict[str, int] = {}
        for r in self.rows:
            per_domain[r["domain"]] = per_domain.get(r["domain"], 0) + 1
        for d, n in per_domain.items():
            if n > cap * (config.MAX_REDIRECTS + 1):
                out.append(f"{d}: {n} sends exceeds budget cap x redirect allowance ({cap*(config.MAX_REDIRECTS+1)})")
        return out


def audit_ledger(ledger_rows: list[dict[str, Any]], budget_counts: dict[str, int],
                 approved_roots: set[str]) -> list[str]:
    """Rule 6, third trigger: refuse to call a run trustworthy if the ledger
    cannot be shown to match rule 2.

    Three independent checks, because trusting the counter to audit the counter
    proves nothing:

    * no domain charged more sends than rule 2 allows;
    * every host the ledger recorded an ATTEMPT against sits in an approved root.
      Off-domain redirects are not ledger rows at all (src/fetch.py:451 refuses them before
      any request goes out and records them in `redirect_chain`), so a row here is
      traffic we really put on the wire, or tried to;
    * the ledger's own view of how many phases a domain used agrees with the Budget
      counter that authorised them. More phases in the ledger than in the counter
      means a send happened that rule 2 never approved. FEWER is expected and is
      not a finding: `Budget.take()` charges before the request, and a domain whose
      DNS lookup fails returns at src/fetch.py:407-410 without ever recording a row.
    """
    problems: list[str] = []
    cap = config.MAX_SENDS_PER_DOMAIN
    for d, n in sorted(budget_counts.items()):
        if n > cap:
            problems.append(f"budget violation: {d} made {n} sends (cap {cap})")

    sent_phases: dict[str, set[str]] = {}
    for r in ledger_rows:
        host = (urlparse(r["url"]).hostname or "").lower()
        if not host:
            problems.append(f"ledger row without a host: {r}")
            continue
        if registrable_root(host) not in approved_roots and host not in approved_roots:
            problems.append(f"ledger row contacted a non-approved host: {host} ({r['url']})")
        sent_phases.setdefault(r["domain"], set()).add(r["phase"])

    for d, phases in sorted(sent_phases.items()):
        charged = budget_counts.get(d, 0)
        if len(phases) > charged:
            problems.append(
                f"{d}: ledger records {len(phases)} sent phase(s) {sorted(phases)} but the "
                f"budget counter authorised {charged} - a send happened that rule 2 did not approve")
    return problems
