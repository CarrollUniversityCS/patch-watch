# Research directions beyond the PHP2Shell pilot

Written 2026-10-28 from a literature and web search on how novel a multi-CVE version
of this study would be. **This is not part of the pre-registration.** `analysis_plan.md`
v1.0 stays frozen; anything below that is run on PHP2Shell data is reported as
exploratory (plan, preamble), and a direction becomes confirmatory only when a new plan
is written and frozen before that CVE's data is collected.

The search was web search, not a systematic literature review. Before claiming novelty,
check dblp / Google Scholar for IMC, USENIX Security, PAM and NDSS 2023–2026 on "patch",
"government", "KEV" and "time to remediate", and read the Kotzias and Nappa
patch-deployment papers directly (neither surfaced).

## Short version

A live per-CVE patch dashboard is **not** new: Censys publishes a public PHP2Shell tracker
(by country, network and PHP version) and Shadowserver publishes CVE trackers and country
totals. What did not turn up anywhere is a fixed population of U.S. nonfederal government
sites, followed across many exploited CVEs, measured against the federal KEV deadline,
with "cannot tell" reported as its own outcome. The pathways below are ordered by how
strong the novelty claim looks.

## Pathways

### 1. How much of KEV is measurable from outside at all

- **Question.** For every CISA KEV entry, does the vulnerable product leave a passive
  fingerprint in one ordinary web response, and does the fix change it?
- **Method.** The four-question candidate test, applied to the whole catalog:
  (1) product visible in headers or the homepage (Wappalyzer fingerprints matched to the
  entry's CPE); (2) the fix changes the version string (OSV/NVD ranges, endoflife.date);
  (3) the product is common in the .gov frame (Common Crawl, Censys research access, Shodan
  academic tier, no requests to .gov hosts); (4) a detector passes the Docker test matrix.
- **Why it looks open.** No measurability census of KEV turned up. It does not depend on
  the PHP2Shell results, and it bounds what every outside dashboard, Censys's included,
  can see.
- **Needs.** KEV, cvelistV5 and CISA Vulnrichment (CPE, SSVC) as inputs; Wappalyzer
  fingerprint data; a triage step that writes proposed tiers into
  `dashboard/catalog.json` for PI review. No live traffic.

### 2. Nonfederal patch speed against the federal deadline

- **Question.** Federal civilian agencies must patch KEV entries by a due date (BOD 26-04
  sets risk-based deadlines; one secondary source describes 3 days for critical exploited
  flaws). State and local governments are not bound by it. What share of the nonfederal
  population has reached a fixed release by that date, and does the federal clock appear
  to pull them along?
- **PHP2Shell.** KEV listing 2026-10-26, federal due 2026-10-29 (verified 2026-10-28 against KEV
  catalog version 2026.10.27). Wisconsin snapshots seen so far:
  days 3.0, 5.3 and 7.0. This question is written down on 2026-10-28, **before** any
  snapshot on or after the due date exists. It is still exploratory for PHP2Shell, since
  it is not in plan v1.0.
- **Action.** Make sure a Wisconsin snapshot runs on or just after 2026-10-29. The
  dashboard flags snapshots taken on or after `kev.federal_due`.
- **For later CVEs.** Pre-register "patched share at the federal due date" as an endpoint
  before collection begins.

### 3. The same entities across many CVEs

- **Question.** Following one fixed set of local governments across successive KEVs: does
  an entity that patches quickly once tend to do so again, and how much of that is the
  hosting provider rather than the entity?
- **Builds on.** The entity frame (`src/wi_frame.py`) and the host-cluster analysis
  (`src/hosting.py`, plan §7.5).
- **Prior work.** The closest panel studies found were on client software (Nappa et al.:
  10 applications, 1,593 vulnerabilities, 8.4M hosts), not government servers.
- **Risk.** Small numbers. Wisconsin has 833 domains but only about 42 show a rankable
  version. Multi-CVE claims probably need the national frame (15,614 domains,
  `src/frame.py`, pilot paused under D2).

### 4. Honest coverage as a methods contribution

- **Claim.** A pinned census frame, pre-registration, explicit indeterminate classes
  (`PHP_VERSION_HIDDEN`, `POSSIBLY_BACKPORTED`, `UNPARSEABLE`, `NOT_MEASURED`) and
  small-cell suppression, set against vendor dashboards that report version counts as
  patch status. Censys itself warns that distro backports make version strings
  unreliable.
- **Reviewer question to answer.** "Why not filter Censys by .gov?" The answer has to be
  the population definition (government entity type, which Censys does not label), method
  transparency and the indeterminate class. It cannot be speed.

### 5. A notification experiment in a government population

- **Question.** Does notifying government operators (directly, or through CISA or
  MS-ISAC) speed patching?
- **Prior work.** Durumeric et al. (Heartbleed, IMC 2014): +47% patching; Stock et al.
  (USENIX Security 2016): 5.8% of emailed reports received, marginal effect; Li et al.
  (WEIS 2019, HTTPS); "Snail Mail Beats Email" (2021). None targeted governments.
- **Constraint.** Per `docs/IRB_DETERMINATION.md`, the passive design is not human-subjects
  research; a notification arm probably would be. It needs its own IRB review and a
  randomized design written before any notice is sent.

## Related findings worth citing

- Bitsight: median 174 days to fix a KEV-listed flaw vs. 621 days otherwise; the sample
  includes local governments but they cannot be separated out.
- CISA Cyber Hygiene: SLTT and critical infrastructure combined showed a 31% drop in KEVs
  exposed 45+ days; the CPG adoption report says SLTT exploitable services rose 95%.
  Results are private to each enrollee.
- University of Maryland: attack surface of 3,095 county-government networks via Shodan
  and Censys, matched to CVEs. One snapshot, not patching over time.
- Basisbeveiliging.nl: public map of Dutch government web security, official policy since
  2022. Configuration, not patching.
- ProjectDiscovery `nuclei-templates-ai`: AI-generated detection templates for new CVEs
  already exist. They send active probes; a passive-only, validated, human-gated pipeline
  is the difference here. Fast detector building is a means, not the contribution.

## Partners to approach

- CISA Cyber Hygiene team: compare passive outside numbers with their authenticated scans.
- Shadowserver: check Wisconsin numbers against their U.S. totals.

## Sources

- Censys PHP2Shell tracker: https://censys.com/php2shell/
- Censys PHP2Shell advisory: https://censys.com/advisory/cve-2026-109618-cve-2026-109619/
- Cybernews on Censys counts: https://cybernews.com/security/php-exploitation-32-million-servers-vulnerable/
- Nextgov/FCW, KEV deadline: https://www.nextgov.com/cybersecurity/2026/10/cisa-gives-federal-agencies-until-thursday-address-exploited-php-flaws/416838/
- CISA BOD 26-04 guidance: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
- CSA note on BOD 26-04: https://labs.cloudsecurityalliance.org/research/csa-research-note-bod-2604-ai-accelerated-patch-mandate-ente/
- Durumeric et al., The Matter of Heartbleed: https://www.icir.org/vern/papers/heartbleed-imc14.pdf
- Stock et al., Hey, You Have a Problem: https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/stock
- Li et al., Fixing HTTPS Misconfigurations at Scale: https://faculty.cc.gatech.edu/~frankli/papers/li-weis2019.pdf
- Snail Mail Beats Email: https://arxiv.org/pdf/2106.08024
- The Secret Life of CVEs (cites Nappa et al.): https://arxiv.org/pdf/2504.03863
- Bitsight KEV remediation (The Record): https://therecord.media/kev-list-vulnerabilities-patched-significantly-faster
- CISA, KEV catalog reaches 1000: https://www.cisa.gov/news-events/news/kev-catalog-reaches-1000-what-does-mean-and-what-have-we-learned
- CISA CPG Adoption Report: https://www.cisa.gov/sites/default/files/2025-01/CPG%20Adoption%20Report.pdf
- County government attack surface: https://academic.oup.com/cybersecurity/article/11/1/tyae032/7959399
- Basisbeveiliging.nl: https://basisbeveiliging.nl/info/
- nuclei-templates-ai: https://github.com/projectdiscovery/nuclei-templates-ai
- Shadowserver dashboard terms: https://www.shadowserver.org/statistics/
- CISA Vulnrichment: https://github.com/cisagov/vulnrichment
