# Analysis plan: Wisconsin .gov census, PHP2Shell patch adoption

**Status: FROZEN v1.0, 2026-10-23**, by the commit titled `analysis plan v1.0 (frozen)`.
The freeze came before any live request and before any archived (Common Crawl) data was
collected.

- **What is frozen.** This text, plus the implementation in that commit: `src/classify.py`,
  `src/versions.py`, `src/analyze.py`, `src/wi_frame.py`, `src/baseline_cc.py`,
  `src/hosting.py`. Every report prints the code commit it ran from (`provenance:` line).
- **Changing anything after the freeze.** Any change to the plan, or to the code that
  decides a class, a state, a cohort or a table, is a dated entry in §12. The entry says
  what changed, why, and whether any data had been seen when it changed.
- **Status of results.** This file is the study's pre-registration. Results that come
  from analyses not listed here are reported as exploratory.

Design source: `reports/AUDIT_2026-10-23.md`. Items marked **[D#]** are decisions for the
PI (§11). Every section names the code that implements it, so a reader can check the
plan against what actually runs.

---

## 1. Questions

| # | Question | Why it matters |
|---|---|---|
| RQ0 | **Measurability.** What share of Wisconsin .gov entities that run PHP disclose a version the study can rank? (`VISIBILITY = V / P`) | Bounds every other answer. A low value is a result in its own right, not a failure. |
| RQ1 | **Exposure before disclosure.** Before first exploitation (2026-10-17), what share of entities with a visible version ran a release that the fix later superseded? | The "before" half of "how they reacted". |
| RQ2 | **Adoption over time.** Among entities exposed when first observed, what share reached a fixed release by each observation day? | The core reaction curve. |
| RQ3 | **Time to patch.** How is time to patch distributed (interval-censored), and how many entities stayed exposed at the end? | Speed, and the tail. |
| RQ4 | **Who patches.** How much of the reaction is explained by shared hosting? Does adoption differ by entity type? | Small towns rarely patch their own servers, so the paper must not credit or blame the town for a hosting provider's upgrade. |
| RQ5 | **Usual vs. emergency.** How did the same population adopt an earlier critical PHP fix (CVE-2024-4577, June 2024)? | Says whether the PHP2Shell response was unusual. Archived data only. |
| RQ6 | **Wisconsin vs. neighbours** (secondary; D6 decided). Do Minnesota, Illinois, Michigan and Iowa .gov entities differ on RQ1–RQ3? | Makes "Wisconsin was fast or slow" a comparison rather than an adjective. Live data from these weeks cannot be collected later. |

**Not asked, and not claimed:** whether any site is exploitable or compromised; any ranking
or naming of entities, vendors or hosting providers; anything about non-.gov sites.

## 2. Population, frame, units (`src/wi_frame.py`)

**Population.** Nonfederal, non-tribal entities whose .gov domain is registered with
`State = WI` in CISA's public .gov registry.

**Tribal nations are not measured (D1, decided by the PI on 2026-10-23).** Their domains
are dropped when the frame is built, and only their count is recorded: 10 in Wisconsin,
plus 10 MN, 13 MI and 2 IA in the comparison states. As a second guard,
`pipeline.load_sample()` drops any row whose type or stratum starts with "Tribal", so no
sample file, old or new, can put a tribal domain on the wire. Preflight refuses a sample
that has no type columns to check.

**Frame source, pinned.** `cisagov/dotgov-data`, `current-full.csv` at commit
`718c7ac8deb13ee4917d45101ee6a0dd08fb94f2` (published 2026-10-22T11:23:57Z), sha256
`f1bf7313…cddd62`. It has 16,935 rows, which is exactly the registry census the national
frame asserts against. The builder refuses any other bytes. The frame is never rebuilt
from a later registry day. `wi_frame.py verify` re-derives the frame and byte-compares it.

**Frame as built (2026-10-23).** 833 domains, 778 entities; 32 entities hold more than
one domain.

| Reporting stratum | Rule (`Domain type`, `Organization name`) | Domains | Entities |
|---|---|---|---|
| Town | City type; name says Town / Township / "TN OF", or hand override | 351 | 330 |
| Village | City type; name says Village | 183 | 181 |
| City | City type; name says City | 119 | 116 |
| Municipal department/other | City type, none of the above (police, library, utility, court) | 15 | 15 |
| County | County | 61 | 56 |
| State | State or territory | 31 | 10 |
| Special district | Special district | 20 | 20 |
| Election office | any "– Election" type | 53 | 53 |

**Three units, each used for a different job.**
- **Domain**: the unit of measurement. One observation per domain per snapshot.
- **Entity** (`entity_id` = state + normalised `Organization name`): the unit of analysis
  for every primary outcome.
  - *Entity rule:* an entity's state is the first of `EXPOSED > EOL > AMBIGUOUS > PATCHED >
    OPAQUE > NO_PHP > UNREACHED` among its domains. So an entity is PATCHED only when none
    of its domains is exposed, EOL or ambiguous.
  - An election-office domain usually shares its organization with a city or county. The
    entity is reported under the government's own stratum.
- **Host cluster** (resolved IP at the first live observation; ASN as a sensitivity
  check): the unit of dependence. `src/hosting.py`.

**Coverage statement for the paper.** Most Wisconsin local government web presence is
*not* on .gov. School districts use `k12.wi.us` or `.org`, and many towns and villages use
`.wi.us`, `.org` or `.com`. This study describes .gov-registered Wisconsin entities only.

## 3. Data sources

1. **Live snapshots** (§6). `src/pipeline.py` and `src/fetch.py`, under hard rules 1–9,
   unchanged.
2. **Archived captures from Common Crawl** (`src/baseline_cc.py`). No traffic reaches any
   site.
   - **What it contacts.** The client refuses every host except `index.commoncrawl.org`
     and `data.commoncrawl.org`.
   - **What it reads.** For each frame domain and crawl, it picks one homepage capture of
     the apex or `www.` host: status 200 first, then https, then apex, then earliest. It
     fetches that WARC record and parses the archived status, headers and server IP. Then
     it runs the **same classifier** as the live crawler and discards the archived page.
   - **Crawl sets.**
     - `2026` (CC-MAIN-2026-34/-39/-43). The baseline is the latest capture with
       `WARC-Date < 2026-10-17T00:00Z`. Later captures are counted, never used as "before".
     - `2024` (CC-MAIN-2024-18 … -38), for RQ5.
   - **Coverage is partial and not random.** CC favours linked, larger sites. Coverage is
     reported with every baseline number. No baseline is ever imputed. The index server is
     fragile (504s on 2026-10-23), so the collector throttles, backs off, caches, and can
     be resumed.
3. **Registry** (§2), for type, organization and city only. The contact column is not
   loaded into any Wisconsin file.

## 4. Measurement requirements (status at v0.2)

| Finding | Required behaviour | Status |
|---|---|---|
| C1 | A cert-failure site whose headers were read on the unverified retry is classified from those headers, with `cert_error` kept. | **Done.** `fetch.py` clears the phase-1 error before the retry. Test: `test_c1_…`. |
| C2 | A redirect-limit or no-Location response is classified from the response it got, with the note kept in `detail.transport_note`. | **Done.** Test: `test_c2_…`. |
| C3 | `NOT_MEASURED` covers not-asked (blocklist, kill switch, budget), refused (401/403/429) and 5xx responses with no PHP evidence. It is out of every denominator and counted in every table. | **Done.** Tests in `test_classify.py`, `test_c3_…`. |
| C4 | A version with no patch number (`PHP/8.3`) is `UNPARSEABLE`. | **Done.** |
| C5 | The abuse flag is re-read before every domain. | **Done.** Test: `test_c5_…`. |
| C6 | `PHP-FPM` / `phpBB` count as PHP evidence, not as versions. Pre-release 8.6 builds before RC4 are not patched. | **Done.** |
| — | Pinned dependencies | **Done.** `requirements.txt` |
| — | Wisconsin frame built and verified | **Done.** `data/wi_frame.csv` (gitignored) |

## 5. Classification → analysis states

| Analysis state | Classes | Meaning |
|---|---|---|
| `PATCHED` | `PATCHED_UPSTREAM` | Visible upstream version at or above the threshold (§5.2). |
| `EXPOSED` | `VULNERABLE_BY_VERSION` | Visible upstream version below the threshold, no distro evidence. **Exposed by version, not shown to be exploitable** (§10). |
| `EOL` | `EOL_UNFIXED` | Branch ≤ 8.1; no upstream fix. Reported on its own. |
| `AMBIGUOUS` | `POSSIBLY_BACKPORTED`, `UNPARSEABLE` | Version visible but not rankable against upstream. |
| `OPAQUE` | `PHP_VERSION_HIDDEN` | PHP present, no version. **Never counted as patched.** |
| `NO_PHP` | `NO_PHP_EVIDENCE` | A real answer with no PHP indicator. |
| `UNREACHED` | `NO_RESPONSE`, `NOT_MEASURED` | Out of every denominator; counted. |

`P` = PATCHED + EXPOSED + EOL + AMBIGUOUS + OPAQUE. `V` = PATCHED + EXPOSED.

The analysis **re-classifies every stored observation from its stored headers**, both
live and archived. A classifier fix therefore applies to old rows too, and the same
headers can be read against another event.

### 5.1 Server-comment deviation (cited by `src/classify.py`)

The brief defines `POSSIBLY_BACKPORTED` by a distro suffix on the PHP version. This study
also treats a bare version as ambiguous when the `Server` header names a Linux
distribution, because distro builds do not always change the PHP version string. This
makes the study call fewer sites exposed, which is the safe direction. Sensitivity
analysis 5 switches it off.

### 5.2 Fixed-version thresholds (`src/versions.py`, `PatchEvent`)

- **T1 (primary), `php2shell`.** 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, released 2026-10-21.
  Checked against php.net on 2026-10-23. `t0 = 2026-10-21T14:00Z`. PHP 8.6.0 RC4 or later
  counts as patched, because php.net says RC4 carries the fixes. Earlier 8.6
  pre-releases are AMBIGUOUS.
- **T2 (secondary), `cve_2026_115560`.** Pre-committed now. Its fix ships in the next
  regular release. The event exists with `published=False`, so classifying against it
  raises an error until its versions are added by a dated §12 entry. T1 results are never
  restated as T2 results.
- **Benchmark, `cve_2024_4577`.** 8.3.8 / 8.2.20 / 8.1.29, released 2024-06-06; 8.0 was
  EOL. It is used for RQ5 on archived data only. That CVE was exploitable only on Windows
  PHP-CGI, so this measures **adoption** of a critical release, not exposure.
  **Verified 2026-10-23:** the php-src advisory GHSA-3qgc-jrrr-25jv gives patched
  versions 8.3.8 / 8.2.20 / 8.1.29, and php.net's 2024 archive dates all three
  06 Jun 2024.

## 6. Schedule and traffic

**Day `d`** is measured from T1's t0 (2026-10-21T14:00Z).

| Phase | When | Notes |
|---|---|---|
| Archived | Any time | Common Crawl, 2026 and 2024 sets, Wisconsin first, then comparison states. No traffic to sites. |
| Region order | Every snapshot day | **Two separate runs, chained:** Wisconsin at 09:00, then the comparison states as soon as it exits cleanly (`--region`). A kill-switch trip, abuse flag or complaint during the comparison run can never cost a Wisconsin reading. A Wisconsin halt skips that day's comparison run. The runs never overlap, because `pipeline.RunLock` allows one live run at a time; overlap would put two requests on a shared-hosting IP (rule 4). |
| S1 | As soon as Gate A opens | Every day before S1 loses the earliest part of the reaction. |
| Daily | S1 through d = 14 | One snapshot a day, 09:00 America/Chicago. |
| Tapering | d = 21, 28, 45, 60, 90 | |
| Stop | d = 90, or earlier if no Wisconsin entity is EXPOSED for two consecutive snapshots | Both regions stop together, on the Wisconsin schedule. |

At most 22 snapshot days [D3], each with one Wisconsin run and one comparison run.

**Volume.** About 833 homepage requests per Wisconsin snapshot, one per domain in the
normal case, plus 1,961 for the comparison run (MN 621, IL 467, MI 643, IA 230) [D6]. That is
2,794 sites a day in total, but each site still gets the same one request. The hard per-domain
ceiling (3 phases × 4 hops = 12), the kill switch, the per-IP limit and the blocklist are
unchanged.

## 7. Analysis (`src/analyze.py`)

### 7.0 Primary endpoint and contingency (pre-registered)
- **Primary endpoint.** Wisconsin region, entity unit, primary scenario:
  - **A(14)**, computed at the last live point whose whole day from t0 is ≤ 14;
  - the number of cohort entities **never observed patched** by the last observation.

  Both appear first in every report (`analyze.primary_endpoint`). Every other number in
  this plan is secondary.
- **Contingency, fixed now so it cannot be chosen after seeing data.** If the Wisconsin
  cohort (§7.3) has fewer than **30** entities:
  - the Wisconsin RQ2/RQ3 results are reported descriptively, with no Turnbull median;
  - the pooled cohort across Wisconsin and the comparison states is reported alongside;
  - the paper leads with RQ0 (measurability) and RQ4 (hosting).

  The threshold is `analyze.MIN_COHORT`.
- **Provenance.** Every report prints the code commit (flagging uncommitted changes to
  `src/`), the frame's sha256 and the ASN table's sha256. The ASN table
  (`data/ip2asn-v4.tsv.gz`) is downloaded once, before the first analysis, and is not
  replaced afterwards.

One command writes every table below into `reports/analysis_<label>_<event>.md`, with
suppression applied. The paper's tables are generated output.

Runs are filtered before anything is computed:
- a run whose ledger audit failed (`kill_switch = audit_violation`) is excluded;
- a run halted by the kill switch is kept, because its unsent domains are already
  `NOT_MEASURED`;
- mock runs are excluded unless `--include-mock` is given, which is for rehearsal only.

### 7.1 RQ0: measurability
- `P`, `V`, `V/P` and the full state distribution per observation point, plus the same by
  stratum at the latest live point.
- Off-domain redirect and cert-error counts.

### 7.2 RQ1: exposure before disclosure
- The state distribution among entities with a pre-cutoff archived capture.
- Coverage (captured / frame) is always shown alongside it, with the median and oldest
  capture age in days before t0.

### 7.3 RQ2: adoption curve
**Cohort.** Entities EXPOSED at their first observation: the archived baseline if one
exists, otherwise the first live snapshot. The cohort is fixed when it is defined.

**Outcome.** `A(d)` = patched / (patched + still exposed), computed at each live point.

**Separate columns.**
- Transitions to OPAQUE ("went dark"), to AMBIGUOUS or EOL, and to UNREACHED. These are
  never counted as patched.
- Entities that became visible only later. These are counted but not part of the cohort.
- Flapping entities (`detect.is_flapping`, window 4). These are excluded and counted.
  Flapping is judged **per domain**, then charged to the domain's entity, so an entity
  with two steady domains on two versions is not called a flapper.

### 7.4 RQ3: time to patch
- Each cohort entity contributes the interval (last EXPOSED day, first PATCHED day].
  Baseline days are negative.
- The CDF is estimated with the Turnbull NPMLE (self-consistency on the finite right
  endpoints). The median is reported only if the estimate crosses 0.5.
- Entities still exposed at the end are right-censored, and their count is a headline
  figure.
- **"Hid instead of patched"** (EXPOSED → OPAQUE, never PATCHED) is reported as an outcome
  in its own right.

### 7.5 RQ4: hosting and type
- **Host concentration** among PHP-evidence entities at the first live point: the number
  of clusters, the largest cluster, the share in clusters of 5 or more, and the effective
  number of independent servers (`1 / Σ share²`). Reported by IP, and by ASN when a local
  `data/ip2asn-v4.tsv.gz` (iptoasn.com, public) is present.
- **Cluster-level A(d):** sensitivity analyses 6a and 6b.
- **By stratum:** descriptive only, with no significance claims.

### 7.6 Uncertainty
The frame is a census, so there is no sampling error with respect to the frame.
Uncertainty comes from opacity, ambiguity and unreachability, and is expressed by the
§7.7 bounds rather than by confidence intervals. Where a superpopulation rate is wanted,
a Wilson 95% interval may be shown, labelled as such and computed over host clusters.

### 7.7 Sensitivity analyses (all implemented in `analyze.SENSITIVITY`)

| # | Variant |
|---|---|
| 1a / 1b | `POSSIBLY_BACKPORTED` counted as PATCHED / as EXPOSED (bounds) |
| 2 | Domain as the unit |
| 3 | Cert-error domains excluded |
| 4 | Off-domain-redirect domains excluded |
| 5 | Server-comment deviation off |
| 6a / 6b | Host cluster by IP / by ASN as the unit |

A headline is called robust only if its direction holds across all of them.

### 7.8 RQ5: historical benchmark
Archived captures from the 2024 set are re-read against `cve_2024_4577`. For each crawl,
the report gives the entities with a visible version, the number patched, and the share
patched among them, with the crawl's median day from the fix. The PHP2Shell curve
(§7.3) and this curve are shown on the same day axis. They differ in resolution (daily
vs. monthly), and the paper says so.

### 7.9 RQ6: comparison states (secondary; D6 decided 2026-10-23)
Built with `wi_frame.py build --comparison MN,IL,MI,IA` and snapshotted live in separate
runs (§6). The report repeats §7.1–7.7 per region and adds one RQ6 table
(`analyze._rq6`):
- A(d) for each region's own cohort, matched on **whole day from t0**, not on run. The two
  runs are minutes apart, so the same day is the fair match.
- The Wisconsin − comparison difference in percentage points.
- The whole table repeated with the host cluster (IP) as the unit, so one provider's
  upgrade cannot pass for a regional difference.

The comparison is descriptive. If a test is ever reported, it is at cluster level and
labelled exploratory. The comparison states are pooled; per-state results are
exploratory. Small per-state, per-stratum cells would fall under suppression anyway. If Wisconsin-specific alerts
(Wisconsin Cyber Response Team, WI DOA, League of Wisconsin Municipalities, Wisconsin
Counties Association) can be dated from public announcements, the curves are annotated at
those dates. No causal claim is made from them.

## 8. Data handling and disclosure

- Hard rule 7 applies unchanged. Per-domain results go to the PI only.
- **Suppression (implemented in `analyze.Suppressor`).**
  - Counts of 1–9 are shown as `<10`.
  - A share is hidden (`§`) when its numerator, its complement or its denominator would
    expose a count under 10.
  - When a row has exactly one suppressed cell, the smallest other non-zero cell is also
    hidden (`§`), so the suppressed value can't be recovered from the row.
  - A stratum with fewer than 10 entities is shown only as `<10`.
  - `--unsuppressed` writes the PI's copy to `data/`, never to `reports/`.
- **No naming.** No vendor, hosting provider or ASN appears in any report. A test asserts
  that no frame domain or organization name appears in a suppressed report.
- **Coordinated notice before publication [D4].** Send aggregates to the Wisconsin Cyber
  Response Team / WI DOA and to MS-ISAC, and wait at least 30 days before publication.
  No per-domain list goes to anyone without an IRB amendment and a change to the public
  notice.

## 9. Governance before Gate A

1. **IRB: done.** The determination arrived 2026-10-23: not human-subjects research,
   may begin at any time (`docs/IRB_DETERMINATION.md`). Still to do: send the IRB a
   one-paragraph update describing the Wisconsin design, which differs from what they were
   told (that file has the table). Any notification experiment or staff survey needs its
   own application first.
2. **Notice: published 2026-10-23** as the top section of the profile README at
   `PROJECT_URL` (JForden/JForden commit `6e9a5ae`), with the opt-out address
   (jforden@carrollu.edu) first. Source of truth: `docs/project_page.md`. Re-publish
   whenever that file changes. Telling Carroll IT is an informal courtesy, not a
   precondition (§12, 2026-10-23).
3. `scripts/cron.disabled`: updated to the §6 schedule, still commented out.
4. **Open.** Commit the mission brief (the hard-rule text this repo enforces) under
   `docs/`. It is cited throughout the code and is still not in the repo.
5. ~~Re-verify the CVE-2024-4577 versions~~ (done 2026-10-23, §5.2). Freeze this
   plan. Then open Gate A.

## 10. Threats to validity, stated for the paper

- **Version ≠ exploitability.** `session.upload_progress.enabled=0` is an advertised
  partial mitigation, and headers cannot show it. Distro backports keep old version
  strings.
- **Opacity is not random.** Hardened or proxied sites hide versions, and they are
  plausibly better maintained.
- **The front door is not the site.** Off-domain redirects are recorded, not followed.
- **Shared hosting.** One upgrade can move many entities (§7.5).
- **Left-censoring and archive bias.** Patches between t0 and S1 have unknown timing.
  Common Crawl coverage is partial, monthly, and biased toward larger sites.
- **Our traffic is a stimulus.** A self-identifying research user agent may prompt an
  operator to look.
- **Historical comparability.** CVE-2024-4577 affected a narrower configuration and
  arrived in a different year with different staff. RQ5 compares adoption rhythms, not
  like-for-like risk.
- **Coverage.** .gov only, non-tribal, as stated in §2.

## 11. Decisions for the PI

| # | Decision | Status |
|---|---|---|
| D1 | Tribal nations | **Decided 2026-10-23: not measured anywhere.** Excluded in the frame and enforced again at sample load. |
| D2 | National 319-domain pilot | **Decided at freeze: paused.** Its tribal stratum would be dropped at load anyway. |
| D3 | The §6 schedule (up to 22 snapshot days) in place of "A, B, no third" | **Decided at freeze: approved.** The IRB precondition is met. |
| D4 | Pre-publication notice to WI CRT / MS-ISAC, aggregate only, 30-day embargo | **Decided at freeze: yes.** |
| D5 | Suppression threshold | **Decided at freeze: fewer than 10.** |
| D6 | Comparison states | **Decided 2026-10-23: live, as a secondary aim, in separate runs** (§6, §7.9), plus archived data. Reason: the live readings cannot be collected after the fact, and each site's burden is unchanged. |

## 12. Deviation log

| Date | Change | Data seen at the time? | Reason |
|---|---|---|---|
| 2026-10-23 | **Frozen as v1.0.** Pre-freeze drafts v0.1 and v0.2 were written the same day. The freeze added §7.0 (primary endpoint and contingency rule) and turned D2–D5 into decisions. | **No.** No live or archived data had been collected. | Pre-registration before collection. |
| 2026-10-23 | §9 governance only: telling Carroll IT is no longer a Gate A precondition; the PI handles it informally. No effect on any measurement, class, cohort or table. | No. | PI decision. |
| 2026-10-23 | **Checked, no change: bare-domain-only requests.** A DNS-only check of all 2,794 frame domains (no HTTP) found that 7 Wisconsin (0.8%) and 23 comparison (1.2%) domains resolve only at `www.`. They will read as NO_RESPONSE, and the paper states this as a limitation. Also found: 95 Wisconsin (11.4%) and 245 comparison (12.5%) domains resolve at neither name; they are registered but have no website. They are UNREACHED and outside every denominator, and their count is reported. 10 lookups timed out. The crawler is unchanged. | Only a 5-site live smoke test, held in a scratch database and never analysed; no study data. | Fixing it would change the request wording in the public notice and add untested code, for an expected effect of 0–2 cohort entities. |
