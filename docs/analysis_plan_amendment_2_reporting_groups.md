# Amendment 2 to the analysis plan: final reporting pool and event bursts

**Dated 2026-10-31. Adopted by the PI before any wave 2 or wave 3 data exist.** `docs/analysis_plan.md` (v1.0, frozen
2026-10-23) and Amendment 1 (`docs/analysis_plan_amendment_national.md`, hash-pinned) are unchanged. Where this file and
Amendment 1 disagree on the points below, this file governs.

## B1. The final reporting pool must reach the minimum (changes A5 of Amendment 1)

Amendment 1 pools states under 30 frame domains into a U.S. Census region and sends a pool still under 30 to one final
pool, without requiring the final pool to reach 30. On the released wave files the final pool would hold 22 domains through
wave 2 and 12 through wave 3, too few to carry any result. The rule gains one step, still a function of frame sizes only and
never of outcomes:

* After the existing pooling, if the final pool ("Other small jurisdictions (pooled)") holds fewer than 30 domains and at
  least one regional pool of 30 or more exists, the final pool is merged into the largest regional pool (ties broken by name).
* If no regional pool of 30 or more exists, the final pool stays and is reported as not estimable.
* A state that is reported alone under Amendment 1 stays alone. Wave 1 (CT 169, SD 53, UT 170) is unchanged.

Implemented in `analyze.report_groups`. Properties checked by tests for every frame tried: the grouping is a partition that
depends on frame sizes only, loses no domain, and leaves no pooled group under the minimum unless it is the only pooled group.

## B2. Complementary suppression (implementation note, no change of rule)

The plan's rule is counts of 1 to 9 hidden with complementary suppression. The implementation now continues withholding the
smallest visible count in a row until the printed row total cannot be used to solve for a hidden count, and withholds the
total itself in the rare row where the hidden cells alone make up the whole total (`analyze.Suppressor.row` and
`Suppressor.total`). It only withholds more than before and changes no analysis, class, threshold or endpoint.

## B3. Event bursts (design decision, not yet scheduled)

For a newly listed exploited flaw that the study has judged measurable, the PI approves in principle a burst of daily
snapshots for 7 days starting the day after listing, because the schedule after 2026-11-04 (gaps of 7 to 30 days) cannot
observe the deadline window of any later flaw. A burst is not automatic. Each event needs its own frozen plan written before
its data are read, a person-verified fixed-version table, a check against the public notice, and the PI's approval to start
it, as in the per-event checklist. The request is the same single homepage request at the same daily cadence already
published, so no new kind of traffic is added.

## B4. What this amendment does not do

It does not contact any person, load the registry's contact column, name any site or vendor, change a class, threshold or
endpoint, or release a wave. Waves 2 and 3 stay released only by the PI.
