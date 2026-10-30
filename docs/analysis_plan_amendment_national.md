# Amendment 1 to the analysis plan: national extension

**Dated 2026-10-30. Pre-registered before any request goes to a site outside the Wisconsin and comparison frames.**
`docs/analysis_plan.md` (v1.0, frozen 2026-10-23) is unchanged and still governs Wisconsin and the four comparison
states. This amendment adds an extension and records changes to the instrument made after the freeze. Where the two
disagree for the extension, this file governs; for Wisconsin and the comparison states the plan governs.

Governance: Carroll University's IRB replied on 2026-10-23 and again on 2026-10-30 that this work does not involve
human subjects and needs no review. The extension contacts no person, uses no contact data, and sends the same single
ordinary homepage request as the approved arms.

## A1. Population and frame

* **Extension frame.** Every nonfederal, non-tribal .gov domain in the other states and DC in the pinned registry
  (CISA `dotgov-data`, commit `718c7ac8deb13ee4917d45101ee6a0dd08fb94f2`, raw sha256
  `f1bf731322871787f742508a2d7c026c7dfae268092b9dad86e23199c8cddd62`), whose name exists in the public Domain Name System. 15,292 candidate names across
  50 states and DC; 13,203 pass the name check, including Wisconsin's 833 and the comparison states' names. **10,682
  names are new** (the region "expansion"); the comparison arm's own names stay with that arm.
* Territories, registry rows with no state, federal domains and tribal nations are excluded, as in the plan.
* **Estimand.** The master list is "registered names that resolve to a public address through two resolvers", not
  "websites". Names that do not resolve, are sinkholed, or are not confirmed by the second resolver are non-response and
  are reported as such, never silently dropped.

## A2. Name check and resolver rule

* Validity is a DNS lookup and nothing else. No request of any kind goes to a site to decide whether to include it.
* **Two resolvers must agree.** A name is requested only if the campus resolver resolves it to a public address and
  Google (8.8.8.8) returns an address for it. A name on which they disagree, or on which Google never answered, is
  recorded "not measured" and not requested (`src/national.py`, `write_sample`; the excluded names are written to
  `data/national_excluded.csv`). Five of the 10,682 names are excluded on 2026-10-30.
* **The resolver is part of the instrument (threat to validity, for plan §10).** Every request resolves names through the
  collecting machine's network resolver. On 2026-10-29 that resolver returned a loopback address for two of the 833
  Wisconsin domains (0.24%) that two public resolvers resolve normally; the study records those two as no response. The
  count is small and was found by a one-off check, not by the pipeline.

## A3. Rollout in waves, and entry dates

The extension is started in cumulative waves so a problem appears on hundreds of sites before thousands:

| Wave | Names | What |
|---|---|---|
| 1 | 392 | Pilot: up to 170 random names from one state in each size band (30 to 99, 100 to 299, 300 or more). Drawn with seed 20261030: CT, SD and UT |
| 2 | 3,000 | Seeded random draw of the remaining names |
| 3 | 7,290 | Everything else |

(Wave 2 and 3 lose 2 and 3 names to the resolver rule: 3,000 and 7,290 before, 2,998 and 7,287 requested.) A wave is
released by the PI after the previous one met these criteria: no kill-switch trip, no audit problem, rate-limit plus
server-error share under 4%, refusal (401/403) share under 15%, no complaint within 24 hours, and under 1.2 requests
per domain. A later wave starts only on the PI's word. Wave assignment is a function of the master list and the seed
(`national.verify` re-derives it before every run).

**Entry date and the schedule.** The snapshot calendar is anchored to days after the fix (day 0 = 2026-10-21): daily
through 2026-11-04, then 2026-11-11, 11-18, 12-05, 12-20 and 2027-01-19. Extension units enter on the first scheduled day
after their wave is released, so they are first observed about day 10 or later, not at day 3 as Wisconsin was. For these
units "first observed" is the date of their first successful reading, and timing results for late entrants are reported
separately from Wisconsin's and never pooled with them for time to patch. Wisconsin always runs first each day; the
national task refuses if Wisconsin has not completed.

## A4. Strata for the extension

The Wisconsin name rules (Town, Village, City, Municipal other) do not transfer. For the extension the primary stratum
is the registry's `domain_type` with elections offices merged (`primary_stratum()` in the private builder), and Borough
outside Wisconsin. Wisconsin's own strata are unchanged.

## A5. Reporting rule for small groups

A state is reported alone only if its frame has at least 30 domains. Smaller states are pooled into their U.S. Census
region ("Northeast (states under 30)", and so on), and a pool still under 30 falls into one final pool
(`analyze.report_groups`; the region map is fixed in the code and does not depend on any result). The existing rule still
applies to every cell: counts of 1 to 9 print "<10" with complementary suppression, shares are hidden when the numerator,
its remainder or the base is under 10. No site, organization, hosting provider or vendor is named.

## A6. Power

Only 7 states reach 30 rankable sites on their own. Sites on a shared address are not independent: in Wisconsin the 42
rankable sites sit on 29 addresses, a design effect of about 1.45, so national power figures are divided by about 1.5. The
extension's results are descriptive; no hypothesis test is pre-registered for a single small state.

## A7. DNS-hygiene data

For every candidate the DNS settings (name servers, signing, answer codes) were collected from two public resolvers.
This is a separate descriptive data set. It is not an input to any patch-state result and is analyzed, if at all, in its
own note.

## A8. Instrument changes after the freeze (for plan §12)

| Date | Change | Outcomes seen? | Effect |
|---|---|---|---|
| 2026-10-30 | `src/fetch.py`: an overall deadline per request (`TOTAL_TIMEOUT_S`) now bounds a slowly dripped body; before, only each read was bounded | Yes (Wisconsin to 2026-10-28) | None for any response that completed in time. A site that held a worker past the timeout is now recorded `timeout`. |
| 2026-10-30 | `src/fetch.py`: a redirect whose `Location` has no host (`javascript:`, `data:`) is recorded as an off-domain redirect with the response's headers, as `file:` and `ftp:` already were; before it was `crawler_error` and the headers were lost | Yes | None known for Wisconsin |
| 2026-10-30 | `src/fetch.py`: gzip and deflate bodies are inflated with the 64 KB limit applied to decoded bytes | Yes | Same bytes read for any ordinary page; bounds memory for a compression bomb |
| 2026-10-30 | New `src/national.py`, `scripts/national_day.py`, `--region national` | Not applicable | Adds a region; Wisconsin and comparison code paths unchanged |
| 2026-10-29 | The resolver sinkhole of 2 Wisconsin domains: disclosed in A2 | Yes | No class, cohort or table changes |

Checked 2026-10-30: the classifier is unchanged and still reproduces all 833 stored Wisconsin classes from the stored headers; a loopback replay of Wisconsin's 833 names through the changed crawler gives Wisconsin's class mix, no audit problem and at most one request in flight per address; a rehearsal of all 13,203 names (no kill-switch trip, 1.03 requests per name) found nothing further.

## A9. What this amendment does not do

It does not contact any person, load the registry's contact column, name any site or vendor, or change a class,
threshold or endpoint. Any later notification of site contacts or survey of staff is a human-subjects activity and
needs its own application first.
