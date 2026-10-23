# Inquiry: does this activity need IRB review? (Carroll University)

**From:** Jack Forden, Assistant Professor, Computer Science & AI, Carroll University
**Re:** Request for a determination on a passive web-traffic measurement study
**Status:** Requesting a determination. No live measurement traffic has been sent to any
government website as of the date of this note.

## What the project does

The project measures how quickly nonfederal U.S. government websites (city, county,
tribal, school district, special district and state sites) update the PHP scripting
language after a security fix is published. The first measurement window follows the
fixes released October 21, 2026 for CVE-2026-109618 / CVE-2026-109619.

Method: a single ordinary HTTP GET for each site's homepage, the same request a member of
the public makes by typing the address. The study reads response headers that the server
chooses to send. It records the domain, a timestamp, the HTTP status, whether a PHP
version number was disclosed, and a category derived from that version.

## Why I believe this is not human-subjects research

- The units of observation are **government web servers and software version numbers**,
  not people. No person is identified, contacted, interacted with, or intervened upon.
- No private data is collected. Nothing behind authentication is requested; no forms,
  logins, cookies, sessions or personal information are involved. The only "identifiers"
  are domain names that are already published in a public U.S. government dataset
  (GSA/CISA's list of .gov domains).
- The content of web pages is not retained. Response bodies are read up to 64 KB to look
  for a version string and then discarded; only headers and derived categories are stored.
- The activity is passive and non-intrusive by design: no exploitation, no probing for
  vulnerable endpoints, no port scanning, no load generation (at most 20 concurrent
  requests total, one per IP at a time, with random delays and a 20-second timeout).

## What I would like from you

A determination of whether this activity constitutes human-subjects research requiring
IRB review or exemption, and any conditions you would attach (for example, a public
opt-out page, which is already drafted, or a review by University IT / Information
Security).

## Controls already built into the study

- **Opt-out, honoured within 24 hours**, on a bare email request with no verification,
  plus a public project page that describes the traffic before it starts.
- **Self-identifying traffic**: a custom user agent naming the project, its URL and a
  contact address, so site operators can see who is measuring them.
- **A hard stop**: the pipeline halts itself if more than 10% of a rolling window of 50
  requests returns an error, block or rate-limit response, or if an abuse complaint
  arrives, and an operator can stop all traffic by placing a file on disk.
- **No individual publication**: aggregate group statistics only; per-domain results are
  never published or shared, including any list of sites that appear unpatched.
- **Data locality**: all data stays on a university-controlled machine; the working
  database is not committed to source control.

## Related approvals / capacity

Compute and network egress are covered by existing institutional access; the study's
request volume is on the order of hundreds of homepage requests per day against a sample
of 319 domains drawn from a frame of 15,614 nonfederal .gov domains.

Questions: [CONTACT_EMAIL].
