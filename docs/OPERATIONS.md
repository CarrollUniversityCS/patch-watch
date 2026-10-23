# Operations

How to run this thing, how to stop it, and what each switch actually does. Written for
the person operating it at 07:00 with a complaint email open in another tab.

## Two modes, one gate

| Mode | Command | Touches the internet? |
| --- | --- | --- |
| Mock (default) | `python src/pipeline.py --mock` | **No.** Every domain is pointed at `127.0.0.1` on the loopback rig in `tests/mock_server.py`. No real name is ever resolved. |
| Live | `python src/pipeline.py` | Yes, and it refuses unless Gate A is open. |

**Gate A** is `fetch.assert_live_allowed()` (`src/fetch.py:88`). Read the code before you
trust this paragraph: live requests require both the committed config flag and the
runtime environment marker:

```python
if not (config.LIVE_REQUESTS_ENABLED and marker.strip().upper() == "APPROVED"):
    raise GateClosed(...)
```

Both of these are required to open the gate:

1. `PATCHWATCH_GATE_A=APPROVED` in the environment of the process, **and**
2. `LIVE_REQUESTS_ENABLED = True` in `src/config.py` (a committed code change).

The word must be `APPROVED` after stripping and upper-casing;
`yes`, `true` and `GATE A APPROVED` do not open it. Right now `LIVE_REQUESTS_ENABLED` is
`False`, so live runs refuse and no database is even created, regardless of the marker.
Keep the config flag `False` unless the operator has explicitly decided to open Gate A;
an environment marker alone cannot enable live traffic.

Gate A also checks rule 3 on the way out: a `User-Agent` still containing
`[PROJECT_URL]` or `[CONTACT_EMAIL]` is a refusal, so the identity string has to be
filled in before any live request can happen.

## Running a snapshot

```bash
# mock, 20 domains, throwaway database
.venv/bin/python -X utf8 src/pipeline.py --mock --limit 20 --db data/mock_smoke.db --label SMOKE1

# the real thing, after Gate A (Windows: `set PATCHWATCH_GATE_A=APPROVED`)
export PATCHWATCH_GATE_A=APPROVED
.venv/bin/python -X utf8 scripts/run_snapshot.py --sample data/wi_frame.csv --region wisconsin --label WI_S1
# then, once that has finished cleanly, as its own run
.venv/bin/python -X utf8 scripts/run_snapshot.py --sample data/wi_frame.csv --region comparison --label CMP_S1
```

**Always run the two regions separately and one after the other** (`--region`). Wisconsin
is the primary data and runs first. Never run them at the same time: `pipeline.RunLock`
(`logs/run.lock`) refuses a second live run while one is going, because two processes
would each allow one request per IP, which makes two. If a crash leaves the lock behind,
confirm no run is going and delete it. The comparison states (MN, IL, MI, IA) are a secondary aim. If something goes
wrong in their run (a kill-switch trip, a complaint, the abuse flag), Wisconsin's
readings for the day are already committed and untouched. A complaint from a
comparison-state operator is handled exactly like any other: blocklist it, and drop the
flag if needed.

The Wisconsin study runs on `data/wi_frame.csv` (`src/wi_frame.py build`). Any sample
file is filtered at load: rows whose type or stratum starts with "Tribal" never load
(`config.EXCLUDED_DOMAIN_TYPE_PREFIXES`). Preflight refuses a sample with no type
columns, because then that filter could not be checked.

Useful flags: `--sample` (a different sample CSV), `--blocklist`, `--run-id`,
`--mock-rotate N` (shift the mock deck so a second run in the same database produces
genuine version changes, for exercising the change detector), `--preflight-only` (check
everything and send nothing).

Schedule: `docs/analysis_plan.md` §6. Daily from S1 through day 14, then days 21, 28,
45, 60 and 90 after the fix, at most 22 snapshots. That replaces the national pilot's
"A, then B, no third", subject to the PI's decision D3. `scripts/cron.disabled` carries
the schedule in commented form; it stays commented until Gate A.

The archived baseline (`src/baseline_cc.py`) is not gated, because it never contacts a
government host. It talks to Common Crawl only, enforced by `CCClient.check_host()`. It
is slow by design (one request at a time, at least 1.5 s apart, with backoff), and it is
resumable: re-run the same command after an interruption.

## What a run produces

| Where | What |
| --- | --- |
| `data/study.db` → `runs` | one row per snapshot: start, finish, attempted, responded, errors, sends, kill-switch state |
| `data/study.db` → `observations` | one row per domain per snapshot: status, headers of interest, version, classification, cert/redirect flags |
| `data/study.db` → `request_ledger` | one row per request actually sent, with the phase that authorised it |
| `data/study.db` → `patch_events` | change events against the previous observation of the same domain |
| `data/ledger_<run_id>.csv` | the ledger exported, for attaching to an incident or IRB answer |
| `reports/run_<run_id>.md` | the human-readable run summary, including the safety audit result (in `reports/`, not `logs/`, because `logs/*` is gitignored and this is the durable evidence trail; an `ALERT_<run_id>.md` is written beside it whenever the kill switch or the audit fires) |
| `logs/capture.log` | refusals and halts as they happen (`REFUSING <phase>: <host> — not on approved list (hard rule 1)`) |

The ledger is committed to the database **immediately after the network phase**, before
classification, reporting or change detection run. That ordering is deliberate: the
ledger is the artifact that proves what we sent, so a bug downstream must not be able to
lose it. `fetch_many()` likewise catches per-domain failures instead of letting one
malformed response cancel the other domains' work.

## Stopping it

**Drop a file.** `logs/abuse.flag` (or whatever `PATCHWATCH_ABUSE_FLAG` points at)
containing the marker `ABUSE_COMPLAINT`. It is checked before the run starts (before
any DNS resolution) and again before every domain, so dropping it mid-run stops every
request not yet sent. That per-domain check was added 2026-10-23 (audit C5); before then
the flag was read only at start. Verified behaviour: a run started with the flag present
is refused, nothing is written, and no database file is created. A flag dropped mid-run
turns every remaining domain into `halted` / `NOT_MEASURED` with no request sent
(`tests/test_fetch_rules.py::test_c5_…`).

```bash
echo "ABUSE_COMPLAINT automated scan traffic, stop now" > logs/abuse.flag
```

An opt-out email (to jforden@carrollu.edu) is a two-step action:
1. Put the domain in `blocklist.local.txt`. It is gitignored, because the list of who
   opted out is itself a disclosure, and it is read alongside `blocklist.txt` before
   every run.
2. If the traffic needs to stop *now* rather than at the next snapshot, drop the flag.

## Self-halts (kill switch, hard rule 6)

The run stops itself and says why if:

- more than 10% of a rolling window of 50 phase outcomes are 403, 429 or 5xx. An outcome
  is one per budget-charged phase; redirect hops inside a phase are not separate entries.
  `KillSwitch.bad()` counts `status >= 500`, so 5xx is included;
- an abuse/complaint marker appears on disk;
- the post-run ledger audit cannot be reconciled against rule 2 (see below).

429 and 503 additionally back that host off for the rest of the snapshot rather than
retrying it (rule 4).

## The post-run audit (`audit_ledger`)

Every run re-checks its own traffic after the fact and refuses to certify it if:

1. any domain was charged more sends than `MAX_SENDS_PER_DOMAIN`;
2. any ledger row records a request to a host outside an approved root;
3. the ledger shows more request phases for a domain than the budget counter authorised
   — that is, a send happened that rule 2 never approved.

Fewer phases than charges is normal and is *not* a finding: the counter is charged before
the request, and a domain whose DNS lookup fails never writes a ledger row.

If a run reports `audit_violation`, treat the run as untrustworthy: do not analyse it,
keep the ledger CSV, and read `logs/capture.log` for what it caught.

## Rate and identity limits in force

`MAX_CONCURRENCY` 20 · `MAX_PER_IP` 1 concurrent · `MAX_SENDS_PER_DOMAIN` 3 ·
`MAX_REDIRECTS` 3 (same registrable domain only, otherwise the `Location` value is
recorded and the redirect is **not** followed) · `MAX_BODY_BYTES` 65536, body discarded,
never stored · connect 10 s / total 20 s · jitter 0.1–0.5 s · no `Cookie` header, ever ·
`User-Agent: CarrollPHPStudy/1.0 (+https://github.com/JForden/JForden; jforden@carrollu.edu)`.

**Maintenance trap, learned the hard way on 2026-10-23.** That last-but-one bullet is not
free. `httpx.AsyncClient(cookies=None)` only starts the jar empty — httpx then stores every
`Set-Cookie` it receives onto the client and replays it on the next request from that
client, which here means the next redirect hop. The guard is one line,
`client.cookies.clear()` at `src/fetch.py:455`, and `tests/test_fetch_rules.py`'s
no-cookie test fails if you delete it or if you refactor the crawler to reuse a client
across a cookie-setting response. If you ever swap HTTP libraries, that test is the thing
to port first, because the failure mode is silent and breaks a promise made on the public
page and in the IRB note.

**Request-count promise: settled 2026-10-23, owner decision.** The brief's draft page text
said "at most 2 requests per domain per day". The crawler needs three budget-charged
phases, so the code keeps `MAX_SENDS_PER_DOMAIN = 3` and the public page states three with
the reason. Each phase exists to prevent a specific measurement error: `https` (primary),
`https_unverified` only after a certificate-verification failure that read no headers
(`src/fetch.py:562`) — otherwise a broken chain looks like an unreachable site — and
`http_fallback` only when HTTPS produced no response and the failure was not DNS
(`src/fetch.py:578`) — otherwise an HTTP-only host is recorded as `NO_RESPONSE`, which is
the worst error this study can make. In practice a domain sees one request; two if either
condition fires; three only if both do. If you ever tighten the cap to 2, you are choosing
to call cert-broken or HTTP-only hosts unreachable — then say that on the public page
instead of publishing a number the crawler exceeds.

One caveat the page must keep: **redirect hops are not budget-charged.** A phase can end in
up to `MAX_REDIRECTS` same-domain hops, each its own ledger row, so a redirecting site can
see as many as `3 x (3 + 1) = 12` HTTP requests in a day, which is exactly the ceiling
`Ledger.violations()` audits against. "At most three requests" means three phases; the page
says so in plain words.

**Identity URL: your GitHub profile README, not a hosted site.** `PROJECT_URL` is
`https://github.com/JForden/JForden`, whose profile README is the human-readable notice
page, and that is the address carried in the user agent. There is no separate project site.
So Gate A means: *the notice is published at the URL our own traffic points to, and it reads
like the opt-out page*, not "a project page is live somewhere else".

## Playbooks

**`preflight refused the run`** — read the lines. Empty sample, missing/stub
`blocklist.txt`, Gate A closed, abuse marker present, or an unfilled user agent. Fix the
named thing and re-run; nothing was sent.

**Halts mid-run** — the run row is finished with `kill_switch` set, the ledger is already
committed, and the reason is in `reports/run_*.md` (and `ALERT_*.md`) and `logs/capture.log`. Export the ledger
CSV before doing anything else; that is the record of exactly how far it got.

**"Someone emailed about this study"**:
1. Add the domain to `blocklist.local.txt`.
2. Note the request in `logs/optouts.md`. Never note it in a committed file, and never
   in a report.
3. If it is an abuse complaint, drop the flag too.

Opt-out is honoured on the strength of the request alone. Opted-out domains are
classified `NOT_MEASURED` and never counted as unreachable.

**A crashed run** — the ledger survives (committed early) but the CSV export and summary
happen later, so re-export from the database rather than trusting that a `data/ledger_*.csv`
exists for that run.

## What is *not* proven yet

Everything below has been exercised only against the loopback mock rig. It is written,
tested and refuses to run live, but none of it has yet met a real government web server:

- rule 3/4 behaviour under live conditions (real jitter against real servers, real
  per-IP serialisation across distinct IPs — in mock mode every domain is `127.0.0.1`, so
  the per-IP limit serialises the whole run and does not prove the live case);
- the kill switch's 10%-of-50 rolling window on real traffic;
- the change detector on real version movements (it has been proved against a real SQLite
  database and synthetic observations, including the strictly-earlier-history fix and
  windowed flap detection, but not against a live site's header churn);
- whether enough of the population discloses a PHP version at all (`VISIBILITY = V / P`)
  — which is the pilot's actual research question.
