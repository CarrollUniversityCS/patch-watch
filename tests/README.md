# tests/ — mock rig + Stage-3 classifier tests

Run everything (no internet needed; loopback 127.0.0.1 only):
    cd C:/Users/jforden/Desktop/repos/patch-watch
    .venv/Scripts/python.exe -m pytest tests/ -q
Poke the rig by hand (serves until Ctrl-C, prints the port map):
    .venv/Scripts/python.exe tests/mock_server.py
Listeners: :8451 plain HTTP, :8452 self-signed HTTPS (cert auto-generated into
tests/fixtures/, gitignored), :8455 HTTP-only (no TLS), :8459 dead on purpose.
Routes: GET /case/<name> and /robots.txt (`User-agent: CarrollPHPStudy`).
Cases (name -> class under src/classify.py; full detail in mock_server.CASES):
vuln8335 VULNERABLE | patched8336, patched_exact8512, patched_newbranch, same_domain_final PATCHED | hidden_cookie, hidden_bare_xpb, multi_set_cookie, body_hint(+php_hints) HIDDEN | ubuntu_suffix, debian_suffix, sury_suffix, rhel_comment POSSIBLY_BACKPORTED | eol81, eol74 EOL_UNFIXED | garbage_word, garbage_major_only UNPARSEABLE | no_php, iis_nophp, no_content, status_503/403, redirects NO_PHP_EVIDENCE | status_429, slow_short, slow_35s, big_body, https_bad_cert, http_only_case, crossdomain_redirect transport/status shapes | conflict_headers, two_xpb_values header conflicts. slow_35s is pinned in test_classify.py only — never fetched in the suite.
