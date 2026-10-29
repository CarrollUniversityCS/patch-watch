# Action plan: from KEV to a live government patch dashboard

Written 2026-10-28 (evening, Central). **Not part of the pre-registration.** It turns
`docs/RESEARCH_DIRECTIONS.md` (the pathways and the evidence behind them) into an ordered
build. `analysis_plan.md` v1.0 stays frozen; anything run on PHP2Shell beyond it is
exploratory, and every new event needs its own frozen plan before its data is collected.

Dates after 2026-10-28 are proposals. Items marked **Jack** need you; **Claude** is work I
can do from this repo; **Hermes** is the operator agent under the runbook's limits.

## 1. The loop we are building

> an aggregator says there is an issue → write a test to judge whether we can see it →
> build and validate a detector → approval → scan → after X days, publish the chart

| Stage | What happens | Exists today | To build |
|---|---|---|---|
| 1. Ingress | Pull exploited-vulnerability feeds; rank by likely impact | `scripts/kev_triage.py` (keyword pass over KEV) | `src/intake.py`: KEV (CISA's `cisagov/kev-data` mirror), cvelistV5 hourly deltas, CISA Vulnrichment (CPE, SSVC), VulnCheck KEV (free key) as early warning, EPSS to rank |
| 2. Triage | The four-question candidate test, one verdict plus a reason per entry | A hand-written `dashboard/catalog.json` | `intake.py` writes **proposed** tiers into the catalog; a person approves every change |
| 3. Detector | A `PatchEvent` (fixed versions, branch support) and a classifier path, validated before use | `src/versions.py`, `src/classify.py`, mock rig `tests/mock_server.py` | A Docker test matrix per product (real server builds, backports); fixed-version tables checked against the vendor advisory by a person |
| 4. Approval | PI sign-off, notice and IRB still cover the traffic, plan frozen for the event, Gate A | Gate A, `docs/IRB_DETERMINATION.md`, plan §12 | A short per-event checklist in the catalog entry |
| 5. Scan | One ordinary homepage GET per domain per snapshot | `src/fetch.py`, scheduler (`scripts/live_day.py`) | Nothing new. A new event adds a classifier, never a new kind of request |
| 6. Threshold | Chart marked preliminary until the event reaches **X** days | None | See decision D1 |
| 7. Visualize | Dashboard rebuilt and published | `src/dashboard.py`, `.github/workflows/pages.yml`, live pages | Exposure-window overlay; KEV-deadline marker (done for PHP2Shell) |

**The four-question test** (stage 2): (1) is the product visible in headers or the
homepage? (2) does the fix change the version string? (3) is the product common in the .gov
frame, judged from Common Crawl, HTTP Archive or Censys research data with no requests to
.gov hosts? (4) does a detector pass the test matrix? Failing question 1 or 2 lands an entry
in "Not remotely measurable" with the reason recorded, never dropped.

## 2. Where we stand (checked 2026-10-28)

- **Live pages:** hub https://carrolluniversitycs.github.io/ and dashboard
  https://carrolluniversitycs.github.io/patch-watch/, rebuilt from committed run reports.
- **Collection:** Wisconsin snapshots on days 3.0, 5.3 and 7.0 (Oct 24, 26, 28). Oct 25 and
  Oct 27 have no Wisconsin run. The comparison arm has been held since the Oct 24 halt.
  The scheduler fix (one daily task, plan days in code, calendar-day guard, 19:00 cut-off,
  early-stop rule with EOL counted as exposed) is merged to `main`. **Jack: confirm it is
  installed on the collecting machine** (`scripts\install_schedule.ps1`, then
  `Get-ScheduledTask -TaskName "patch-watch live day" | Get-ScheduledTaskInfo`).
- **Coverage funnel, latest Wisconsin snapshot:** 833 domains → 652 answered → 198 show PHP →
  42 show a version we can rank; 10 domains on end-of-life PHP branches. The early-stop rule
  is not met.
- **KEV:** catalog 2026.10.27, 1,760 entries. PHP2Shell added 2026-10-26, federal due
  2026-10-29 (verified against CISA's catalog). First-pass triage: 6% homepage-visible, 24%
  edge devices, 70% client or local; a version is realistically rankable for roughly one
  KEV event a month.
- **Not built yet:** `src/intake.py`, `src/inventory.py`, the Docker test matrix, any
  pre-registered plan for a second event.

## 3. The pathways as pipelines

Pathways 1-5 are the original list; 6 was added the same day; 7-12 came from the second
sweep. Priority follows `RESEARCH_DIRECTIONS.md`.

| # | Pathway | Pipeline | Inputs | New code | Traffic? | Gate |
|---|---|---|---|---|---|---|
| 1 | **KEV measurability census** | Map every KEV entry to a CPE; run questions 1-3; two independent raters label a stratified sample; report agreement and the share of KEV that leaves a passive fingerprint | KEV, Vulnrichment/NVD CPE, Wappalyzer fingerprints, endoflife.date, Common Crawl | `intake.py` (extends `kev_triage.py`) | None | PI review of tiers |
| 2 | **Federal-deadline comparison** | For each measurable KEV event: endpoint "patched share on the due date and due+7"; schedule a snapshot that day; chart against the federal clock | KEV `dateAdded`/`dueDate`, run reports | Endpoint in a new frozen plan; PHP2Shell stays exploratory | Existing | Plan freeze per event |
| 3 | **Entity panel, all security releases** | Add `PatchEvent`s for PHP, Apache httpd, nginx, SharePoint cumulative updates, WordPress; classify every site running the product; analyse by entity and host cluster | Header inventory, release feeds | `inventory.py`, event tables in `versions.py` | None beyond today's | Notice update; frozen plan |
| 4 | **Coverage as method** | Per-product disclosure rate from the inventory, reported with suppression, next to the PHP figure (42 of 198) | Header inventory | Report section in `analyze.py` | None | Frozen plan |
| 5 | **Government notification experiment** | Fill-rate check on the registry's security-contact column; randomized arm; measure patch lag after notice | `data/frame_meta.json`, frame CSV | Design doc, then arm assignment | Emails, not scans | IRB, frozen plan, notice text, possible CISA/MS-ISAC coordination |
| 6 | **Unsupported-software share** | Branch from stored headers; support dates from a pinned endoflife.date snapshot; daily dashboard number; compare with CISA's 51% | Header inventory, endoflife.date | `inventory.py`, dashboard panel | None | Notice update |
| 7 | **HTTP Archive / Common Crawl retrospective** | Step 0: count frame domains present in HTTP Archive's monthly crawl. If coverage is real, rebuild .gov patch curves for past events | HTTP Archive BigQuery, Common Crawl | `scripts/ha_coverage.py` | None | A billing project (D4) |
| 8 | **Policy evaluation** (grant program, state directives) | Outside outcome measures by state and subrecipient | National frame, program lists | Joins | None | National frame (D2) |
| 9 | **Vendor monoculture** | Platform from headers and host clusters; patch speed by platform | Inventory, hosting tables | Platform classifier | None | PI decision on naming vendors (D5) |
| 10 | **Exposure → incidents** | Link measures to public ransomware trackers | Comparitech, Ransomnews | Linkage with suppression | None | National frame |
| 11 | **Exposure window** | Days from first exploitation to each patch milestone, per event | KEV, GreyNoise/Shadowserver onset | Dashboard overlay | None | Source per event stated |
| 12 | **Election offices** | Existing stratum around the Nov 3 midterm | Run reports | Stratum view | None | Small cells suppressed |

## 4. Phases

### Phase 0: before the 09:00 Central run on 2026-10-29
- **Jack:** pull `main` on the collecting machine and install the scheduled task; check the
  clock is Central and wake timers are allowed; keep local `LIVE_REQUESTS_ENABLED = True`.
- **Hermes:** read `docs/HERMES_UPDATE_2026-10-28.md`; run the 08:30, 09:45 and 18:00 checks.
- **Done when:** `logs\cron.out` shows `RUNNING` then `exit=0` for 10-29, and the report is
  committed. That snapshot is the first on the federal due date.

### Phase 1: 2026-10-29 to 11-04 (daily snapshots to day 14)
- **Jack:** add the two plan §12 entries for the off-schedule Oct 26 run; fix the repo
  description (it still says "tribal"); add a dashboard line to the public notice.
- **Claude:** run the KEV census at first-pass quality for a methods note (no traffic);
  write `src/inventory.py` against the mock rig and a copy of the header columns.
- **Hermes:** daily checks; no code changes.
- **Done when:** nine consecutive snapshots with no missed day, and the day-14 primary
  endpoint A(14) is computed by `analyze.py` (descriptive: the Wisconsin cohort is under 30).

### Phase 2: 2026-11-05 to 11-20 (tapering snapshots on 11-11 and 11-18)
- **Claude:** `src/intake.py` (KEV + cvelistV5 + Vulnrichment) writing proposed tiers; a CPE
  pass for pathway 1; header inventory run on `data/study.db` once Jack runs it locally;
  unsupported-software panel (pathway 6).
- **Jack:** update the public notice for other products' headers and send the IRB a
  courtesy note **before** the inventory is used for anything beyond PHP; check the
  security-contact fill rate (`data/frame_meta.json`).
- **Claude, with Jack's go-ahead on billing:** `scripts/ha_coverage.py`, the pathway 7
  coverage count.
- **Done when:** the census table exists with two-rater agreement; the dashboard shows the
  unsupported share; the HTTP Archive coverage number is known.

### Phase 3: 2026-11-21 to the day-90 snapshot (2027-01-19)
- **Claude/Jack:** write and freeze a second plan for the next events (pathway 3), choosing
  PHP, httpd and nginx releases plus SharePoint updates first; Docker test matrix for each.
- **Jack:** decide the national frame (D2); start the IRB conversation for pathway 5.
- **Hermes:** a weekly intake job that runs `intake.py` and reports proposals; it never
  changes the catalog or enables a scan.
- **Done when:** a second event is measured under a plan frozen before its first snapshot,
  and the dashboard shows both.

## 5. Decisions for Jack

| # | Decision | My recommendation |
|---|---|---|
| D1 | X-day threshold before a chart is published | X = 14, matching the plan's primary endpoint; show earlier points as "preliminary" and keep the federal-deadline marker |
| D2 | Revive the national frame (15,614 domains) | Yes for pathways 3, 8 and 10; Wisconsin alone supports description only |
| D3 | Notice and IRB update for headers beyond PHP | Before any non-PHP use of stored headers |
| D4 | A Google Cloud project to bill for HTTP Archive queries | Approve a small cap; the coverage count first |
| D5 | Name vendors in vendor-concentration results | Aggregate by default; name only with PI sign-off |
| D6 | Run intake automatically through Hermes | Proposals only, weekly, never enabling traffic |

## 6. Risks and stop conditions

- **A missed snapshot day cannot be recovered.** Treat Phase 0 as the project's critical
  path; the 09:45 and 18:00 checks exist for this.
- **Tiny cohorts.** The Wisconsin PHP2Shell cohort is under 30. Do not promise timing
  results from it; lead with measurability and hosting, as plan §7.0 says.
- **Header disclosure for other products is unknown** until the inventory runs. If
  disclosure is as low as PHP's 21%, pathway 3 shrinks and pathways 1, 4 and 6 carry the
  paper.
- **Per-town results are a target list.** Keep aggregate-only reporting and small-cell
  suppression everywhere, including any new panel.
- **Novelty claim.** The Unpatchables (USENIX Security 2024) is the closest prior work; run
  the dblp / Google Scholar check before claiming novelty.
- **Stop an event** if the detector fails the test matrix, a notice or IRB item is open, or
  the kill switch trips; a halt is cleared only by Jack.

## 7. What done looks like

- A census of KEV measurability, with agreement between raters.
- At least two events measured under plans frozen before their data.
- A dashboard that shows measurable events, the unsupported share, and the federal-deadline
  comparison, with unmeasurable events listed and explained.
- No missed snapshot day after 2026-10-29.
