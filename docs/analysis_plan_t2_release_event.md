# Amendment T2 to the analysis plan: the T2 release event (DRAFT, NOT FROZEN)

**Status: DRAFT written 2026-11-06, revised the same day after review. Not frozen, not a pre-registration until the freeze record
below is completed.** The freeze must be recorded (commit and time written into this file) before the release that carries T2 and
before anyone reads any reading taken for it. `docs/analysis_plan.md` (v1.0, frozen 2026-10-23), Amendment 1 and Amendment 2 are
unchanged. Where this file and Amendment 2 section B3 disagree about when a burst starts, this file governs. This file is not the
unadopted coverage-endpoints draft (`docs/proposed/amendment_3_coverage_endpoints_draft.md`); it carries its own name, not a number.

No T2 data exist today. The facts below were read from php.net on 2026-11-06; the only reading used to write this draft is the T1
(PHP2Shell) series, which is not T2.

## 0. What is known about T2 and why the trigger is the vendor release

* **T2 is real and is a low-urgency fix.** php.net's news item of 2026-10-23 ("Informational advisory: Session upload progress")
  says CVE-2026-115560 needs an unusual combination of configuration and application code, that PHP is "handling it in the regular
  release cycle", and that a full advisory will be published "with the next release". It does not name the branches or the version.
  T2 is therefore expected to behave like a routine release, which is the contrast RQ5 of v1.0 asks for.
* **T1 patching ended before the KEV listing.** The T1 fix was announced on php.net at 00:05 to 00:35 UTC on 2026-10-21 (an off-cycle
  security release; v1.0 used 14:00 UTC as t0). The first snapshot was 2026-10-24 (day 3). CISA listed the flaws on 2026-10-26 with a
  federal due date of 2026-10-29. At day 3, 28 of the 30 rankable Wisconsin sites on supported branches already ran the fixed builds.
  A burst starting after a KEV listing would have missed that, so T2 is measured from the release.
* **Regular releases are on Thursdays.** From 2025-11-20 to 2026-10-22 there are twelve 28-day gaps; the 2026-10-21 release came a day
  early. Regular release announcements appear in the php.net news feed between about 10:00 and 23:59 UTC (13 releases checked). The next
  regular release is therefore expected on Thursday 2026-11-19, announced after the scheduled snapshot of 2026-11-18 (14:00 UTC).
  The date is not confirmed.

## 1. The event rule (frozen as a rule; the version table is not frozen)

* **T2 occurs** when php.net publishes a release on a supported branch whose ChangeLog entry lists `CVE-2026-115560`. A release that
  does not list it is recorded as "no T2" and is not an event.
* **Fixed versions.** Per branch, the first release that lists the CVE. A person reads the advisory and the ChangeLog and records the
  versions in a dated section 12 row of `docs/analysis_plan.md` (setting `published` and `fixed_releases` for `CVE_2026_115560` in
  `src/versions.py`). Nothing is classified against T2 before that row exists. v1.0 section 5.2 requires this, and T1 results are never
  restated as T2.
* **t0 is fixed by rule, not chosen later:** the `published` timestamp of the first "PHP x.y.z Released!" item for a fixed-branch
  release in the php.net Atom news feed (`/feed.atom`), copied into the section 12 row with the feed's own text. If no such timestamp
  exists, t0 is 00:00 UTC of the release-list date. No one may change t0 after any T2 reading exists.
* **Branches.** Only branches that receive a fix are analysed. A branch with no fix is reported separately as end of life. If
  branches are fixed on different days, each branch uses its own t0 and the headline uses the earliest.
* **If the next release does not list T2:** nothing is measured and the burst is not started. If two consecutive monthly releases pass
  without T2, T2 is declared not observable in the study window and this amendment lapses (anything further is a new dated amendment).
* **Other CVEs in the same release** are exploratory and labelled so.

## 2. Questions

* **RQ-T2a (primary).** Among at-risk hosts (section 3), what share ran a fixed release by day 7?
* **RQ-T2b (descriptive, Wisconsin only).** How does the share of supported-branch rankable hosts that are patched at days 3, 5, 7 and
  10 compare with the same share recomputed for T1 at the same calendar days? The national arm cannot be compared (its first T1 reading
  was day 10, wave 1 only). T1 days are counted from the release-list date. Days 1 and 2 have no T1 counterpart. The comparison is
  between a security-emergency release and a routine release, two events, and says nothing about cause.
* **RQ-T2c (descriptive).** Which hosts are still unpatched at day 10, and how many hide the version instead of patching?

## 3. Population, unit and cohort

* **Primary population:** the national arm, counting only domains observed at least once before the release (the baseline). Wave 3
  domains count only if observed before the release.
* **Wisconsin** is descriptive, and pooled with the national arm as a sensitivity analysis.
* **Unit: the host, frozen at the baseline.** Each site's host is the resolved address in its baseline reading and is never re-derived
  on later days (addresses change between consecutive days for about 31 percent of domain pairs because of CDN and DNS rotation).
  A site whose baseline headers identify an edge network (the edge tokens and headers in `src/platforms.py`) is its own unit; it is
  not merged with other sites on a shared edge address. Entity, domain and ASN are sensitivity analyses.
* **Cohort ("at risk"):** hosts with at least one rankable site on a fixed branch whose baseline version is below that branch's T2
  fixed version. Hidden versions, ambiguous builds (distribution packages), sites on unfixed branches and unreached domains are not in
  the cohort and are counted in every table.
* **Host state on day d:** patched when every at-risk site on the host that was read on day d is PATCHED; exposed when any is EXPOSED;
  "hid" when a site moved to OPAQUE and none is PATCHED; not estimable that day when no at-risk site on the host was read (the host is
  excluded from that day's denominator and counted).

## 4. Schedule, days and traffic

* **Baseline:** the last snapshot that started before t0. For a Thursday release this is the scheduled snapshot of 2026-11-18.
  If an off-cycle release is announced first, the baseline is the last snapshot before its t0 (2026-11-11 at the earliest), and the
  baseline is then older; this is reported, not repaired.
* **Day convention:** day d is the UTC calendar date of the snapshot minus the UTC date of t0. Hours since t0 are reported beside it.
* **Burst:** daily snapshots of the same frame on days 1, 2, 3, 5, 7 and 10, plus the scheduled run of 2026-12-05 as the late point.
  A release found after the 08:00 live run cannot get a same-day snapshot, so day 1 is the first burst day. Burst dates are entered by
  Jack in the approved-days file, each citing the section 12 row that adopts this amendment (so on release day the entry is the only
  step needed before the 08:00 run). Days with a snapshot stay at or below the plan's 22: 10 run, 5 planned and at most 7 burst; the
  seventh is a reserve for a halted day.
* **Traffic:** the same single homepage request per domain at the same cadence already published; no new kind of request. Wisconsin
  runs first each burst day, as on every snapshot day. Kill switch, limits and blocklist are unchanged.
* **Missed or halted days** are recorded in section 12. Endpoints use the last reading whose day offset is at most d; a day with no
  reading within one day of its target is reported as not estimable, never filled in.
* **Burst readings and v1.0:** readings taken on burst days are excluded from every v1.0 and T1 computation (the adoption curve, the
  Turnbull estimate, test-retest, the early-stop rule), so the pre-registered T1 series is unchanged; they are used only by this
  amendment. The exclusion is by date from the approved-days file and is tested before the freeze.

## 5. Classification

As v1.0 section 5, against the T2 table once recorded: PATCHED, EXPOSED, EOL, AMBIGUOUS (a distribution build is never PATCHED or
EXPOSED), OPAQUE, NO_PHP, UNREACHED. OPAQUE is never counted as patched.

## 6. Endpoints and contingency

* **Primary:** A_host(7) = patched hosts / (patched + exposed hosts) in the cohort at the last reading whose day offset is at most 7,
  with an exact (Clopper-Pearson) interval over hosts, together with the number of cohort hosts never observed patched.
* **Secondary:** A_host(3), A_host(5), A_host(10); the interval-censored time-to-patch curve over hosts (Turnbull, as v1.0 section 7.4)
  with right-censored hosts counted; the Wisconsin comparison of RQ-T2b.
* **Contingency, fixed now:** fewer than `analyze.MIN_COHORT` (30) cohort hosts means descriptive results only, with no median and no
  interval claim; the pooled national and Wisconsin cohort is shown alongside; counts under 10 are hidden as in v1.0 section 8, with
  Amendment 2 pooling of small jurisdictions.

## 7. Sensitivity analyses

Entity, domain and ASN as the unit; edge-fronted sites as one site per unit versus merged; the "any site" rule instead of "every
site" for host state; backports counted as patched and as exposed (bounds); sites with certificate errors excluded; off-domain
redirects excluded; Wisconsin pooled with the national arm; hosts with a refusal (401, 403, 429) on any burst day excluded (the
2026-11-03 change showed refusals can ease between days); the 2026-12-05 reading excluded. A headline is called robust only if its
direction holds across all of them.

## 8. Data handling and disclosure

As v1.0 section 8: per-domain data never leaves the machine; counts under 10 hidden with complementary suppression; no vendor or
hosting provider named; no host-level cell under 10 is published.

## 9. Threats to validity

* Selection: only 4 to 6 percent of responding sites show a rankable version, and they are not a random subset.
* Few independent hosts: effective n is the number of hosts, and the cohort may be near the 30-host floor.
* Fast patching may reflect a few managed hosts' update cadence, not many independent decisions.
* Refusals by bot rules change between days and move the measured and OPAQUE counts.
* CDN fronting hides the origin's headers; distribution builds backport fixes without changing the upstream number.
* Two events, one emergency and one routine: release type cannot be separated from every other difference between them.
* A low-urgency fix may be taken up on the ordinary monthly cadence, so the curve may be flat inside the 10-day burst.

## 10. Checklist (docs/proposed/per_event_checklist.md, split)

**Before the release (all done and written down before the freeze time):**
1. This amendment reviewed and frozen: commit and time recorded below. A hash-pin test is added in the same commit.
2. Public notice text checked against what T2 requests and stores (no new request type).
3. Burst mechanism landed and tested; the approved-days file empty. Burst-day exclusion from v1.0 computations tested.
4. Release watcher installed with the chained check; kill-switch limits unchanged.
5. The endpoint code (national, baseline-fixed host cohort, A_host at days 3, 5, 7, 10, edge rule, host-state rule) is built and its
   tests pass on synthetic data and on stored T1 data labelled REHEARSAL. No T2 reading exists to test it on.
6. The section 12 row adopting this amendment and authorising the burst dates is written.

**On release day, before the next 08:00 live run (only these):**
7. Jack confirms from the php.net news item or ChangeLog that the release lists `CVE-2026-115560` (yes or no).
8. Jack enters the burst dates in the approved-days file, citing the adopting section 12 row.

**After the day-1 snapshot (classification reads stored headers later):**
9. A person reads the advisory and ChangeLog and records the fixed versions and the t0 timestamp in a dated section 12 row; sets
   `published` and `fixed_releases` in `src/versions.py`; the detector matrix passes for the new branches.

## 11. Freeze record (to be completed by Jack)

Frozen at (UTC): ____________  Commit: ____________  Before any T2 release or reading: yes / no

## 12. Deviation log (this amendment)

| Date | Change | Data seen at the time? | Reason |
|---|---|---|---|
