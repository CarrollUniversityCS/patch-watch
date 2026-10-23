# What we measure

Carroll University (Waukesha, Wisconsin) is measuring how quickly nonfederal U.S.
government websites update one piece of software, the PHP scripting language, after a
security fix is published.

We start with the fix released on October 21, 2026 (PHP2Shell, CVE-2026-109618 and
CVE-2026-109619). Site operators are not named or ranked individually. The report is
about the whole group: what share of city, county, tribal, school and special district
sites were already current, and how many updated in the days after the fix.

# What a request from us looks like

One ordinary request for the homepage, over HTTPS, with a tool that identifies itself as
this study. We read the address bar equivalent of `https://yourdomain.gov/` and no other
path on your site. If HTTPS will not connect to your host at all, we make one plain-HTTP
attempt so we can tell "no site here" from "site here, refusing HTTPS" — recorded as an
HTTP attempt either way.

- **We do not look for vulnerable endpoints, and we never send an exploit.** The only
  thing we read is what the server volunteers in its normal response headers.
- **We do not test, probe or attack your site.** No port scanning, no guessed paths, no
  form submissions, no logins, no fuzzing, no malformed input.
- **We do not send cookies** and we do not accept them, so we cannot follow a real
  visitor's session or be logged in as anyone.
- **We read at most the first 64 kilobytes of the homepage**, then discard it. We do not
  store page content, only a short fingerprint of it.
- **Usually one request per domain per day, and at most three.** The extra ones only
  happen when the first told us nothing: one more if your certificate fails verification
  (a second read, without verification, purely so we can tell "unreachable" apart from
  "reached but showing no version"), and one more if HTTPS cannot connect at all (a single
  plain-HTTP try). Three in a day means both of those went wrong. Redirects are counted
  separately: we follow at most three hops within the same site on each try, so a site that
  redirects on every try could see up to twelve requests from us in a day — and the twelve
  only happens on a site that is failing in two ways at once. Never more than one request at a
  time to the same IP address, at most 20 of our requests running at once overall, with a
  random pause of 0.1 to 0.5 seconds between them and a hard 20-second timeout.
- **We identify ourselves.** Every request carries the user agent
  `CarrollPHPStudy/1.0` with the address of this notice — my GitHub profile README,
  `https://github.com/JForden/JForden` — and a contact email in it, so your security team
  can see exactly who called and why. We never pretend to be a browser.

A broken certificate is recorded as such — we never quietly treat it as a normal reading.
A site that returns an error,
a rate-limit response (429) or a server error (5xx) is left alone for the rest of the day.

# What we keep

A small record per domain per day: the domain name, the time, the HTTP status, whether a
PHP version number was visible in the headers, that version string, and which of a few
categories it fell into (up to date with the published fix / older than the fix / no
version visible / not reachable). We also keep a log of every request we sent, so that if
anyone asks what we did, we can answer with the record rather than a description.

Everything stays on a university-controlled machine. We publish counts for groups of
sites. **We do not publish per-site results, and we do not publish a list of sites that
appear vulnerable.**

# Who runs it

Jack Forden, Assistant Professor of Computer Science and AI, Carroll University,
Waukesha, Wisconsin — jforden@carrollu.edu. Notice page: https://github.com/JForden/JForden

# How to be excluded

Email us with your domain and it is removed from measurement, no questions asked, within
24 hours. You do not need to give a reason, prove ownership beyond an address at that
domain, or hear back from us first — the removal happens on the strength of the request
alone. Asking to be removed does not affect the study's results in a way that would be
reported about you.

If you prefer to say no by policy rather than by email, blocking the
`CarrollPHPStudy/1.0` user agent at your firewall or WAF has the same effect, and we
will honour it: a site that refuses us is recorded as "not measured", never as
"vulnerable".
