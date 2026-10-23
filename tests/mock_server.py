"""Dependency-free mock server stack for the patch-watch crawler/classifier tests.

Stdlib only (http.server + ssl + threading). Three loopback listeners plus one
port that is deliberately dead:

    http://127.0.0.1:8451   all cases, TLS not involved           (MockStack.base)
    https://127.0.0.1:8452  same cases over self-signed TLS       (MockStack.https_base)
    http://127.0.0.1:8455   same cases, plain HTTP only           (MockStack.http_only_base)
    127.0.0.1:8459          nothing listens -- dead-port control  (MockStack.dead_port)

Routes: GET /case/<name> for every entry in CASES, and /robots.txt.

The handler emits the configured header tuples in exactly the configured order
and original case, via send_response_only + send_header, so header-name casing,
ordering, and repeated headers (two X-Powered-By, two Set-Cookie) are faithful
on the wire. After the configured headers the server appends, in this order,
only what it must: a synthesised ``Location`` (when the spec sets .location but
has no Location in .headers), ``Content-Type: text/html; charset=utf-8``, and
``Content-Length`` (the last two omitted for 204, per RFC 9110).

TLS cert: a self-signed localhost certificate is generated into tests/fixtures/
at first use (openssl if on PATH, otherwise the `cryptography` package). The
cert is deliberately NOT trusted -- that is the point of case https_bad_cert.

Run standalone to poke it by hand:

    .venv/Scripts/python.exe tests/mock_server.py

serves until Ctrl-C and prints the port map.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"
HTTP_PORT = 8451
HTTPS_PORT = 8452
HTTP_ONLY_PORT = 8455
DEAD_PORT = 8459  # nothing ever listens here

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
CERT_FILE = FIXTURES_DIR / "cert.pem"
KEY_FILE = FIXTURES_DIR / "key.pem"
CERT_DAYS = 30
CERT_REGENERATE_AFTER_S = 25 * 86400  # refresh before the 30-day expiry bites

ROBOTS_BODY = (
    b"User-agent: CarrollPHPStudy\n"
    b"Disallow:\n"
    b"\n"
    b"User-agent: *\n"
    b"Disallow:\n"
)

# Set by ensure_cert(): "openssl", "cryptography", or "reused".
CERT_BACKEND: str | None = None


# --------------------------------------------------------------------------- cases
@dataclass
class CaseSpec:
    """One canned response. `headers` is emitted on the wire in exactly this
    order, with exactly this name casing; repeated names are allowed."""

    name: str
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    location: str | None = None
    delay_s: float = 0.0


_HTML_OK = b"<html><body><h1>Mock page</h1></body></html>"
_NO_PHP_HINT = b"<html><body><h1>Newsroom</h1><p>Plain static page.</p></body></html>"
_PHP_FORM_BODY = (
    b'<html><body><form action="/site/login.php" method="post">'
    b'<input name="user"><input name="pass" type="password"></form></body></html>'
)

CASES: dict[str, CaseSpec] = {}


def _case(name, status, headers=(), body=_HTML_OK, location=None, delay_s=0.0):
    CASES[name] = CaseSpec(name=name, status=status, headers=list(headers),
                           body=body, location=location, delay_s=delay_s)
    return name


# --- versioned PHP headers (expected class under src/classify.py noted per case)
_case("vuln8335", 200, [("Server", "Apache/2.4.62"),
                        ("X-Powered-By", "PHP/8.3.35")])                     # VULNERABLE_BY_VERSION
_case("patched8336", 200, [("Server", "Apache/2.4.62"),
                           ("X-Powered-By", "PHP/8.3.36")])                  # PATCHED_UPSTREAM
_case("patched_exact8512", 200, [("X-Powered-By", "PHP/8.5.12")])            # PATCHED_UPSTREAM, boundary
_case("patched_newbranch", 200, [("X-Powered-By", "PHP/8.6.0")])             # PATCHED_UPSTREAM, future branch
_case("hidden_cookie", 200, [("Server", "nginx/1.27.4"),
                             ("Set-Cookie", "PHPSESSID=7f3a9c2b4d1e6f0a; path=/")],
      body=_NO_PHP_HINT)                                                      # PHP_VERSION_HIDDEN
_case("hidden_bare_xpb", 200, [("X-Powered-By", "PHP")])                     # PHP_VERSION_HIDDEN
_case("ubuntu_suffix", 200, [("Server", "Apache/2.4.52 (Ubuntu)"),
                             ("X-Powered-By", "PHP/8.1.2-1ubuntu2.20")])     # POSSIBLY_BACKPORTED (suffix beats EOL)
_case("debian_suffix", 200, [("Server", "Apache/2.4.62"),
                             ("X-Powered-By", "PHP/8.2.7-1~deb12u1")])       # POSSIBLY_BACKPORTED (suffix beats vulnerable)
_case("sury_suffix", 200, [("X-Powered-By", "PHP/8.3.20+deb.sury.org~bookworm+1")])  # POSSIBLY_BACKPORTED, family sury NOT debian
_case("rhel_comment", 200, [("Server", "Apache/2.4.37 (Red Hat Enterprise Linux)"),
                            ("X-Powered-By", "PHP/8.0.30")])                 # POSSIBLY_BACKPORTED via server_comment
_case("eol81", 200, [("Server", "Apache/2.4.58"),
                     ("X-Powered-By", "PHP/8.1.9")])                         # EOL_UNFIXED
_case("eol74", 200, [("X-Powered-By", "PHP/7.4.33")])                        # EOL_UNFIXED
_case("garbage_word", 200, [("X-Powered-By", "PHP/eight-point-three")])      # UNPARSEABLE
_case("garbage_major_only", 200, [("X-Powered-By", "PHP/8")])                # UNPARSEABLE
_case("no_php", 200, [("Server", "nginx/1.27.4")], body=_NO_PHP_HINT)        # NO_PHP_EVIDENCE
_case("iis_nophp", 200, [("Server", "Microsoft-IIS/10.0")], body=_NO_PHP_HINT)  # NO_PHP_EVIDENCE
_case("body_hint", 200, [("Server", "nginx/1.27.4")],
      body=_PHP_FORM_BODY)                                                    # HIDDEN when hint True, NO_PHP_EVIDENCE when False
_case("conflict_headers", 200, [("Server", "Apache/2.4.62 PHP/8.3.35"),
                                ("X-Powered-By", "PHP/8.3.36")])             # PATCHED_UPSTREAM, header_conflict
_case("two_xpb_values", 200, [("X-Powered-By", "PHP/8.3.35"),
                              ("X-Powered-By", "PHP/8.4.26")])               # first value wins, header_conflict
_case("multi_set_cookie", 200, [("Server", "nginx/1.27.4"),
                                ("Set-Cookie", "PHPSESSID=0d1e2f3a4b5c6d7e; path=/; HttpOnly"),
                                ("Set-Cookie", "_ga=GA1.3.111.222222222; Path=/; Max-Age=94608000")],
      body=_NO_PHP_HINT)                                                      # PHP_VERSION_HIDDEN; proves repeated headers

# --- redirects (the classifier never sees Location; the crawler contract does)
_case("crossdomain_redirect", 302, [("X-Powered-By", "PHP/8.3.35")],
      body=b"", location="https://cdn-elsewhere.example/landing")
_case("same_domain_redirect", 302, [], body=b"", location="/case/same_domain_final")
_case("same_domain_final", 200, [("X-Powered-By", "PHP/8.4.27")])            # PATCHED_UPSTREAM
_case("redirect_loop", 302, [], body=b"", location="/case/redirect_loop")

# --- statuses / transport shapes
_case("status_429", 429, [("X-Powered-By", "PHP/8.3.35"), ("Retry-After", "120")],
      body=b"<html><body>Too Many Requests</body></html>")
_case("status_503", 503, [("Server", "nginx/1.27.4")],
      body=b"<html><body>Service Unavailable</body></html>")
_case("status_403", 403, [("Server", "Microsoft-IIS/10.0")],
      body=b"<html><body>Forbidden</body></html>")
_case("slow_35s", 200, [("X-Powered-By", "PHP/8.3.35")], delay_s=35.0)       # crawler total timeout is 20 s
_case("slow_short", 200, [("X-Powered-By", "PHP/8.3.35")], delay_s=0.5)      # suite-safe delay probe
_case("big_body", 200, [("X-Powered-By", "PHP/8.2.34")], body=b"A" * 300000)  # VULNERABLE_BY_VERSION; crawler caps at 64 KiB
_case("no_content", 204, [("Server", "nginx/1.27.4")], body=b"")             # no Content-Length, no body
_case("https_bad_cert", 200, [("X-Powered-By", "PHP/8.3.35")])               # untrusted self-signed chain on :8452
_case("http_only_case", 200, [("X-Powered-By", "PHP/8.4.26")])               # only meaningful on :8455 (no TLS listener)

assert len(CASES) == 33, f"CASES table drifted: {len(CASES)}"


# --------------------------------------------------------------------------- cert
def _cert_is_fresh() -> bool:
    if not (CERT_FILE.exists() and KEY_FILE.exists()):
        return False
    age = time.time() - min(CERT_FILE.stat().st_mtime, KEY_FILE.stat().st_mtime)
    return age < CERT_REGENERATE_AFTER_S


def _gen_with_openssl(openssl_bin: str) -> None:
    subprocess.run(
        [openssl_bin, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "key.pem", "-out", "cert.pem", "-days", str(CERT_DAYS),
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        cwd=str(FIXTURES_DIR), check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _gen_with_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "cryptography"],
                       check=True)
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=CERT_DAYS))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    KEY_FILE.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def ip_address(s: str):
    import ipaddress
    return ipaddress.ip_address(s)


def ensure_cert(force: bool = False) -> str:
    """Create tests/fixtures/{cert,key}.pem if needed. Returns the backend used:
    "openssl", "cryptography", or "reused"."""
    global CERT_BACKEND
    if _cert_is_fresh() and not force:
        CERT_BACKEND = "reused"
        return CERT_BACKEND
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    openssl_bin = shutil.which("openssl")
    if openssl_bin:
        try:
            _gen_with_openssl(openssl_bin)
            CERT_BACKEND = "openssl"
            return CERT_BACKEND
        except subprocess.CalledProcessError:
            pass  # fall through to cryptography
    _gen_with_cryptography()
    CERT_BACKEND = "cryptography"
    return CERT_BACKEND


# --------------------------------------------------------------------------- handler
# Headers the server is allowed to append after the configured ones.
_APPENDED_OK = {"location", "content-type", "content-length"}


def _no_body(spec: CaseSpec) -> CaseSpec:
    """Same response but bodyless (HEAD request)."""
    return CaseSpec(name=spec.name, status=spec.status, headers=list(spec.headers),
                    body=b"", location=spec.location, delay_s=0.0)


class _CaseHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive; we always send exact Content-Length

    def log_message(self, format, *args):  # silence per-request stderr spam
        if os.environ.get("PATCHWATCH_MOCK_VERBOSE"):
            super().log_message(format, *args)

    def _write(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.send_response_only(status)
        for name, value in headers:
            self.send_header(name, value)
        if status not in (204, 304):
            names = {n.lower() for n, _ in headers}
            if "content-type" not in names:
                self.send_header("Content-Type", "text/html; charset=utf-8")
            if "content-length" not in names:
                self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _serve(self, want_body: bool = True) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/robots.txt":
            self._write(200, [("Content-Type", "text/plain; charset=utf-8")], ROBOTS_BODY)
            return
        if path.startswith("/case/"):
            spec = CASES.get(path[len("/case/"):])
            if spec is not None:
                if spec.delay_s:
                    time.sleep(spec.delay_s)
                self._respond(spec if want_body else _no_body(spec))
                return
            self._write(404, [], b"no such case\n")
            return
        self._write(404, [], b"not found\n")

    def _respond(self, spec: CaseSpec) -> None:
        emitted = list(spec.headers)  # configured order and casing, verbatim
        names = {n.lower() for n, _ in emitted}
        if spec.location is not None and "location" not in names:
            emitted.append(("Location", spec.location))
        body = spec.body
        self._write(spec.status, emitted, body)

    def do_GET(self):
        self._serve(want_body=True)

    def do_HEAD(self):
        self._serve(want_body=False)


# --------------------------------------------------------------------------- stack
class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, ssl.SSLError,
                            TimeoutError, OSError)):
            return  # probes poke closed sockets on purpose
        super().handle_error(request, client_address)


class MockStack:
    """Start/stop the three listeners. `.dead_port` is never bound."""

    def __init__(self, host: str = HOST, http_port: int = HTTP_PORT,
                 https_port: int = HTTPS_PORT, http_only_port: int = HTTP_ONLY_PORT,
                 dead_port: int = DEAD_PORT):
        self.host = host
        self.http_port = http_port
        self.https_port = https_port
        self.http_only_port = http_only_port
        self.base = f"http://{host}:{http_port}"
        self.https_base = f"https://{host}:{https_port}"
        self.http_only_base = f"http://{host}:{http_only_port}"
        self.dead_port = dead_port
        self._servers: list[ThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []

    # -- lifecycle
    def start(self) -> "MockStack":
        if self._servers:
            raise RuntimeError("MockStack already started")
        for port, tls in ((self.http_port, False), (self.https_port, True),
                          (self.http_only_port, False)):
            srv = _make_server(port, tls)
            th = threading.Thread(target=srv.serve_forever, name=f"mock-{port}", daemon=True)
            th.start()
            self._servers.append(srv)
            self._threads.append(th)
        # readiness check: live ports must accept before start() returns
        for port in (self.http_port, self.https_port, self.http_only_port):
            deadline = time.time() + 5
            while True:
                try:
                    with socket.create_connection((self.host, port), timeout=0.5):
                        break
                except OSError:
                    if time.time() > deadline:
                        raise RuntimeError(f"mock listener on :{port} never came up")
                    time.sleep(0.05)
        return self

    def stop(self) -> None:
        for srv in self._servers:
            srv.shutdown()
        for srv in self._servers:
            srv.server_close()
        for th in self._threads:
            th.join(timeout=5)
        self._servers.clear()
        self._threads.clear()

    def url_for(self, case_name: str, tls: bool = False) -> str:
        """Full URL of a case on the plain-HTTP listener (or HTTPS with tls=True)."""
        if case_name not in CASES:
            raise KeyError(f"unknown case {case_name!r}")
        base = self.https_base if tls else self.base
        return f"{base}/case/{case_name}"


def _make_server(port: int, tls: bool) -> ThreadingHTTPServer:
    srv = _QuietServer((HOST, port), _CaseHandler)
    if tls:
        ensure_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


# --------------------------------------------------------------------------- standalone
def main() -> int:
    stack = MockStack()
    stack.start()
    backend = CERT_BACKEND or "unknown"
    print("patch-watch mock server stack -- serving, Ctrl-C to stop")
    print("  plain HTTP     : http://127.0.0.1:%d/case/<name>" % HTTP_PORT)
    print("  self-signed TLS: https://127.0.0.1:%d/case/<name>   (cert backend: %s)" % (HTTPS_PORT, backend))
    print("  HTTP only      : http://127.0.0.1:%d/case/<name>    (no TLS listener)" % HTTP_ONLY_PORT)
    print("  dead port      : 127.0.0.1:%d (nothing listens)" % DEAD_PORT)
    print("  robots.txt     : /robots.txt on every listener")
    print("  cases (%d)      : %s" % (len(CASES), ", ".join(sorted(CASES))))
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        stack.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
