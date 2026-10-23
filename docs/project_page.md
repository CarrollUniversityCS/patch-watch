# How to opt out

**Email jforden@carrollu.edu with your domain and it is removed from measurement within
24 hours.** You don't need to give a reason or prove anything. The removal happens on
the strength of the request alone, before you hear back from us. Asking to be removed
does not affect the study's results in any way that would be reported about you.

If you would rather say no by policy than by email, block the `CarrollPHPStudy/1.0` user
agent at your firewall or WAF. We honour that too: a site that refuses us is recorded as
"not measured", never as "vulnerable".

# What we measure

Carroll University (Waukesha, Wisconsin) is measuring how quickly Wisconsin local and
state government websites on .gov update one piece of software, the PHP scripting
language, after a security fix is published. Minnesota, Illinois, Michigan and Iowa .gov
sites are included for comparison, so the study can say whether Wisconsin's response was
typical. They receive exactly the same single request a day.

We start with the fix released on October 21, 2026 (PHP2Shell, CVE-2026-109618 and
CVE-2026-109619). Site operators are not named or ranked individually. The report is
about groups: what share of town, village, city, county, state, special-district and
election-office sites were already current, and how many updated in the days and weeks
after the fix. Tribal nations' websites are not measured.

To describe how things stood *before* the fix, we also read Common Crawl's public web
archive. That sends no traffic to your site.

# What a request from us looks like

One ordinary request for your homepage over HTTPS, from a tool that identifies itself as
this study. We request `https://yourdomain.gov/` and no other path on your site. If HTTPS
will not connect to your host at all, we make one plain-HTTP attempt, so we can tell
"no site here" from "site here, refusing HTTPS".

- **We never look for vulnerable endpoints and never send an exploit.** The only thing
  we read is what your server volunteers in its normal response headers.
- **We do not test, probe or attack your site.** No port scanning, no guessed paths, no
  form submissions, no logins, no fuzzing, no malformed input.
- **We do not send cookies,** and we do not keep the ones you set, so we cannot follow a
  visitor's session or be logged in as anyone.
- **We read at most the first 64 kilobytes of the homepage**, then discard it. We do not
  store page content, only a few derived yes/no flags.
- **Usually one request per domain per day, and at most three.** An extra request
  happens only when the first one told us nothing:
  - one more if your certificate fails verification. This is a second read without
    verification, purely to tell "unreachable" apart from "reached but showing no
    version";
  - one more if HTTPS cannot connect at all. This is a single plain-HTTP try.

  Three in a day means both of those went wrong.

  Redirects are counted separately. We follow at most three hops within the same site
  on each try. So a site that redirects on every try could see up to twelve requests
  from us in a day, and that only happens on a site that is failing in two ways at once.

  There is never more than one request at a time to the same IP address, and at most 20
  of our requests run at once overall. Each request waits a random 0.1 to 0.5 seconds
  first and has a hard 20-second timeout.
- **How often (planned):** once a day for about two weeks, then on days 21, 28, 45, 60
  and 90 after the fix, then we stop.
- **We identify ourselves.** Every request carries the user agent
  `CarrollPHPStudy/1.0`, the address of this notice
  (`https://github.com/JForden/JForden`) and a contact email, so your security team can
  see exactly who called and why. We never pretend to be a browser.

A broken certificate is recorded as such. A site that returns an error, a refusal (403),
a rate-limit response (429) or a server error (5xx) is not asked again that day.

# What we keep

A small record per domain per day: the domain name, the time, the HTTP status, whether a
PHP version number was visible in the headers, that version string, and which of a few
categories it fell into (up to date with the published fix / older than the fix / no
version visible / not measured). We also keep a log of every request we sent, so that if
anyone asks what we did, we can answer with the record rather than a description.

Everything stays on a university-controlled machine. We publish counts for groups of
sites, and we hide any count smaller than ten. **We do not publish per-site results,
and we do not publish a list of sites that appear vulnerable.**

# Who runs it

Jack Forden, Assistant Professor of Computer Science and AI, Carroll University,
Waukesha, Wisconsin. Email: **jforden@carrollu.edu**. Notice page:
https://github.com/JForden/JForden

Carroll University's IRB has determined that this is not human-subjects research,
because it observes government web servers, not people.
