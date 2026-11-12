# Analysis weekly_2026-11-02 - PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

- event t0: `2026-10-21T14:00:00Z`; generated 2026-11-02T18:30:41Z
- frame: 2794 domains, 2599 entities; regions: comparison, wisconsin
- live runs analysed: 12
- archived baseline: {"available": true, "domains_asked": 737, "domains_with_pre_cutoff_capture": 227, "captures_on_or_after_cutoff": 0, "cutoff": "2026-10-17T00:00:00Z"}
- tribal nations' domains are not measured (PI decision D1); excluded: {"MI": 13, "WI": 10, "MN": 10, "IA": 2}
- disclosure: counts 1-9 shown as <10, complementary suppression marked §
- vendors, ASNs and hosting providers are never named
- provenance: code `62f687c` (src/ MODIFIED since commit); frame sha256 `831406213ad8be3b`; ASN table sha256 `not loaded`

## Region: comparison

### RQ0 - measurability (entities)

| point | day | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R20261024T140522Z_CMP_20261024 | 3.0 | 1821 | <10 | <10 | 0 | <10 | 189 | 288 | 1323 | 210 | § | § |

By stratum at the latest live point (`R20261024T140522Z_CMP_20261024`):

| stratum | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|
| City | 576 | <10 | <10 | 0 | <10 | 51 | 106 | 414 | 56 | <10 | § |
| County | 301 | <10 | 0 | 0 | <10 | § | 47 | 210 | 44 | <10 | § |
| Election office | § | <10 | 0 | 0 | 0 | § | § | § | § | <10 | § |
| Interstate | <10 | § | § | § | § | § | § | § | § | § | § |
| Municipal department/other | 44 | 0 | 0 | 0 | 0 | <10 | <10 | § | <10 | 0 | § |
| School district | <10 | § | § | § | § | § | § | § | § | § | § |
| Special district | § | 0 | 0 | 0 | <10 | <10 | § | § | <10 | <10 | § |
| State | 40 | 0 | 0 | 0 | 0 | 0 | <10 | § | 0 | 0 | – |
| Town | 437 | <10 | <10 | 0 | <10 | 65 | 54 | 308 | 75 | <10 | § |
| Village | 169 | 0 | 0 | 0 | 0 | § | § | 121 | § | 0 | § |

Domains at `R20261024T140522Z_CMP_20261024` redirecting off-domain (front door only classified): 49; with certificate errors: 21.

### RQ1 - exposure before disclosure (archived)

No pre-cutoff archived captures in this region.

### RQ2 - adoption among entities exposed when first seen

Cohort: <10 entities. Flapping entities excluded: 0. Became visible only later (reported, not in cohort): 0.

| point | day | cohort | patched | still exposed | went dark | went ambiguous | unreached | A(d) |
|---|---|---|---|---|---|---|---|---|
| R20261024T140522Z_CMP_20261024 | 3.0 | 9 | 0 | <10 | 0 | 0 | 0 | § |

### RQ3 - time to patch (Turnbull NPMLE, interval-censored)

Never observed patched (right-censored; includes cohort entities that later went dark, ambiguous or unreachable): <10. Hid the version instead of patching (exposed -> opaque, never patched): 0.

### RQ4 - shared hosting

PHP-evidence entities at `R20261024T140522Z_CMP_20261024`: 210.

| cluster key | clusters | largest | in clusters >=5 | effective independent servers |
|---|---|---|---|---|
| IP | 164 | <10 | 16% | 97.1 |

### Sensitivity analyses (§7.7) - A(d) at the latest live point

| scenario | cohort | patched | A(latest) | note |
|---|---|---|---|---|
| primary | <10 | 0 | § |  |
| 1a backport counted as patched | <10 | 0 | § |  |
| 1b backport counted as exposed | <10 | 0 | § |  |
| 2 domain is the unit | <10 | 0 | § |  |
| 3 cert-error domains excluded | <10 | 0 | § |  |
| 4 off-domain redirects excluded | <10 | 0 | § |  |
| 5 server-comment deviation off | <10 | 0 | § |  |
| 6a host cluster (IP) is the unit | <10 | 0 | § |  |
| 6b host cluster (ASN) is the unit | – | – | – | ASN table not loaded |

## Region: wisconsin

### RQ0 - measurability (entities)

| point | day | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| baseline | -69.1 | 221 | 10 | <10 | 0 | 0 | 39 | 167 | <10 | 52 | 10 | 19% |
| R20261024T140014Z_WI_20261024 | 3.0 | 778 | <10 | § | 0 | 27 | 153 | 433 | 151 | 194 | 29 | 15% |
| R20261026T215239Z_WI_20261026 | 5.3 | 778 | 0 | 10 | 0 | 30 | 149 | 434 | 155 | 189 | 30 | 16% |
| R20261028T140016Z_WI_20261028 | 7.0 | 778 | 0 | 10 | 0 | 31 | 154 | 431 | 152 | 195 | 31 | 16% |
| R20261029T140019Z_WI_20261029 | 8.0 | 778 | 0 | 11 | 0 | 30 | 149 | 434 | 154 | 190 | 30 | 16% |
| R20261030T140008Z_WI_20261030 | 9.0 | 778 | 0 | 11 | 0 | 31 | 149 | 431 | 156 | 191 | 31 | 16% |
| R20261031T140027Z_WI_20261031 | 10.0 | 778 | 0 | 11 | 0 | 31 | 146 | 435 | 155 | 188 | 31 | 16% |
| R20261101T140002Z_WI_20261101 | 11.0 | 778 | 0 | 10 | 0 | 31 | 146 | 436 | 155 | 187 | 31 | 17% |
| R20261102T164251Z_WI_20261102 | 12.1 | 778 | 0 | § | 0 | 31 | 146 | 433 | 157 | 188 | 31 | 16% |

By stratum at the latest live point (`R20261102T164251Z_WI_20261102`):

| stratum | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|
| City | 116 | 0 | 0 | 0 | <10 | § | 56 | 35 | 25 | <10 | § |
| County | 56 | 0 | 0 | 0 | <10 | § | 29 | § | § | <10 | § |
| Election office | 50 | 0 | 0 | 0 | <10 | § | 23 | § | § | <10 | § |
| Municipal department/other | § | 0 | 0 | 0 | <10 | 0 | <10 | <10 | <10 | <10 | § |
| Special district | 20 | 0 | 0 | 0 | 0 | <10 | <10 | <10 | <10 | 0 | § |
| State | § | 0 | 0 | 0 | 0 | <10 | <10 | <10 | <10 | 0 | § |
| Town | 330 | 0 | <10 | 0 | § | 70 | 189 | 44 | 97 | § | § |
| Village | 181 | 0 | <10 | 0 | <10 | 29 | 111 | 35 | 35 | <10 | § |

Domains at `R20261102T164251Z_WI_20261102` redirecting off-domain (front door only classified): 58; with certificate errors: 32.

### RQ1 - exposure before disclosure (archived)

Capture age before t0 (days): median 69, oldest 75.

Entities with a pre-cutoff capture: 221 of 778 (coverage 28%; NOT a random subset - CC favours larger, linked sites).

|  | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | EXPOSED among V |
|---|---|---|---|---|---|---|---|---|---|---|
| baseline | 10 | <10 | 0 | 0 | 39 | 167 | <10 | 52 | 10 | 100% |

### Primary endpoint (pre-registered, plan §7.0)

A(14) = 100% (10 of 10 still-visible cohort entities patched at `R20261102T164251Z_WI_20261102`, day 12.1); cohort 11; never observed patched by the last observation: <10.

**Contingency rule applies** (Wisconsin cohort < 30): Wisconsin results are descriptive only and no median is reported. Pooled cohort across all regions: 20, A(14) = 100%.

### RQ2 - adoption among entities exposed when first seen

Cohort: 11 entities. Flapping entities excluded: 0. Became visible only later (reported, not in cohort): <10.

| point | day | cohort | patched | still exposed | went dark | went ambiguous | unreached | A(d) |
|---|---|---|---|---|---|---|---|---|
| R20261024T140014Z_WI_20261024 | 3.0 | 11 | <10 | <10 | <10 | 0 | 0 | § |
| R20261026T215239Z_WI_20261026 | 5.3 | 11 | § | 0 | <10 | 0 | 0 | 100% |
| R20261028T140016Z_WI_20261028 | 7.0 | 11 | § | 0 | <10 | 0 | 0 | 100% |
| R20261029T140019Z_WI_20261029 | 8.0 | 11 | § | 0 | <10 | 0 | 0 | 100% |
| R20261030T140008Z_WI_20261030 | 9.0 | 11 | § | 0 | <10 | 0 | 0 | 100% |
| R20261031T140027Z_WI_20261031 | 10.0 | 11 | § | 0 | <10 | 0 | 0 | 100% |
| R20261101T140002Z_WI_20261101 | 11.0 | 11 | § | 0 | <10 | 0 | 0 | 100% |
| R20261102T164251Z_WI_20261102 | 12.1 | 11 | § | 0 | <10 | 0 | 0 | 100% |

### RQ3 - time to patch (Turnbull NPMLE, interval-censored)

| day <= | F(t) |
|---|---|
| 3.0 | 0.80 |
| 5.3 | 1.00 |

Median not reported: cohort below 30 (plan §7.0 contingency).
Never observed patched (right-censored; includes cohort entities that later went dark, ambiguous or unreachable): <10. Hid the version instead of patching (exposed -> opaque, never patched): <10.

### RQ4 - shared hosting

PHP-evidence entities at `R20261024T140014Z_WI_20261024`: 194.

| cluster key | clusters | largest | in clusters >=5 | effective independent servers |
|---|---|---|---|---|
| IP | 153 | <10 | 8% | 110.0 |

### Sensitivity analyses (§7.7) - A(d) at the latest live point

| scenario | cohort | patched | A(latest) | note |
|---|---|---|---|---|
| primary | 11 | 10 | 100% |  |
| 1a backport counted as patched | 11 | 10 | 100% |  |
| 1b backport counted as exposed | 11 | 10 | 100% |  |
| 2 domain is the unit | 11 | 10 | 100% |  |
| 3 cert-error domains excluded | 11 | 10 | 100% |  |
| 4 off-domain redirects excluded | 11 | 10 | 100% |  |
| 5 server-comment deviation off | 11 | 10 | 100% |  |
| 6a host cluster (IP) is the unit | 11 | 10 | 100% |  |
| 6b host cluster (ASN) is the unit | – | – | – | ASN table not loaded |

## RQ6 - Wisconsin vs. comparison states (descriptive, matched day)

A(d) = patched / (patched + still exposed) in each region's cohort. The difference is in percentage points. Entity rows are the primary analysis; host-cluster rows guard against one provider's upgrade standing in for many entities. No test of significance is reported here (plan §7.9).

**Unit: entity**; cohorts: Wisconsin <10, comparison <10.

| day | WI denominator | WI A(d) | comparison denominator | comparison A(d) | WI - comparison (pp) |
|---|---|---|---|---|---|
| 3 | <10 | § | <10 | § | § |
| 5 | <10 | § | – | – | – |
| 7 | <10 | § | – | – | – |
| 8 | <10 | § | – | – | – |
| 9 | <10 | § | – | – | – |
| 10 | <10 | § | – | – | – |
| 11 | <10 | § | – | – | – |
| 12 | <10 | § | – | – | – |

**Unit: host cluster (IP)**; cohorts: Wisconsin <10, comparison <10.

| day | WI denominator | WI A(d) | comparison denominator | comparison A(d) | WI - comparison (pp) |
|---|---|---|---|---|---|
| 3 | <10 | § | <10 | § | § |
| 5 | <10 | § | – | – | – |
| 7 | <10 | § | – | – | – |
| 8 | <10 | § | – | – | – |
| 9 | <10 | § | – | – | – |
| 10 | <10 | § | – | – | – |
| 11 | <10 | § | – | – | – |
| 12 | <10 | § | – | – | – |

## Exploratory: unsupported software among version-showing sites - comparison

NOT pre-registered. `placed` = sites whose headers give a version we can place on a branch, with no package-suffix ambiguity; `unsupported` = of those, on a branch past its maker's end of life on the snapshot date. Support dates: endoflife.date, pinned 2026-10-29. IIS is not tracked. Sites that show no version are outside this table; see the coverage figure before reading a share.

| snapshot (UTC date) | product | version shown | placed | unsupported | share | distro-labelled on EOL branch |
|---|---|---|---|---|---|---|
| 2026-10-24 | php | 21 | 21 | <10 | § | 0 |
| 2026-10-24 | apache | 11 | <10 | 0 | § | <10 |
| 2026-10-24 | nginx | <10 | <10 | <10 | § | <10 |

Latest snapshot (2026-10-24) by entity type:

| entity type | product | placed | unsupported | share |
|---|---|---|---|---|
| City | php | <10 | <10 | § |
| County | php | <10 | 0 | § |
| County | nginx | <10 | <10 | § |
| Election office | php | <10 | 0 | § |
| Other | apache | <10 | 0 | § |
| Special district | php | <10 | 0 | § |
| Town | php | 10 | <10 | § |
| Town | nginx | <10 | <10 | § |

## Exploratory: unsupported software among version-showing sites - wisconsin

NOT pre-registered. `placed` = sites whose headers give a version we can place on a branch, with no package-suffix ambiguity; `unsupported` = of those, on a branch past its maker's end of life on the snapshot date. Support dates: endoflife.date, pinned 2026-10-29. IIS is not tracked. Sites that show no version are outside this table; see the coverage figure before reading a share.

| snapshot (UTC date) | product | version shown | placed | unsupported | share | distro-labelled on EOL branch |
|---|---|---|---|---|---|---|
| 2026-10-24 | php | 42 | 42 | 12 | 29% | 0 |
| 2026-10-24 | apache | <10 | <10 | 0 | § | 0 |
| 2026-10-24 | nginx | 10 | <10 | <10 | § | <10 |
| 2026-10-26 | php | 41 | 41 | 10 | 24% | 0 |
| 2026-10-26 | apache | <10 | <10 | 0 | § | 0 |
| 2026-10-26 | nginx | <10 | <10 | <10 | § | <10 |
| 2026-10-28 | php | 42 | 42 | 10 | 24% | 0 |
| 2026-10-28 | apache | <10 | <10 | 0 | § | 0 |
| 2026-10-28 | nginx | <10 | <10 | <10 | § | <10 |
| 2026-10-29 | php | 42 | 42 | 11 | 26% | 0 |
| 2026-10-29 | apache | <10 | <10 | 0 | § | 0 |
| 2026-10-29 | nginx | <10 | <10 | <10 | § | <10 |
| 2026-10-30 | php | 43 | 43 | 11 | 26% | 0 |
| 2026-10-30 | apache | <10 | <10 | 0 | § | 0 |
| 2026-10-30 | nginx | <10 | <10 | <10 | § | <10 |
| 2026-10-31 | php | 43 | 43 | 11 | 26% | 0 |
| 2026-10-31 | apache | <10 | <10 | 0 | § | 0 |
| 2026-10-31 | nginx | <10 | <10 | <10 | § | <10 |
| 2026-11-01 | php | 42 | 42 | 10 | 24% | 0 |
| 2026-11-01 | apache | <10 | <10 | 0 | § | 0 |
| 2026-11-01 | nginx | <10 | <10 | <10 | § | <10 |
| 2026-11-02 | php | 43 | 43 | 11 | 26% | 0 |
| 2026-11-02 | apache | <10 | <10 | 0 | § | 0 |
| 2026-11-02 | nginx | <10 | <10 | <10 | § | <10 |

Latest snapshot (2026-11-02) by entity type:

| entity type | product | placed | unsupported | share |
|---|---|---|---|---|
| City | php | <10 | 0 | § |
| County | php | <10 | 0 | § |
| Election office | php | <10 | 0 | § |
| Other | php | <10 | 0 | § |
| State | nginx | <10 | <10 | § |
| Town | php | 28 | <10 | § |
| Town | apache | <10 | 0 | § |
| Town | nginx | <10 | 0 | § |
| Village | php | <10 | <10 | § |
| Village | apache | <10 | 0 | § |

## Exploratory: platform and hosting concentration - comparison

NOT pre-registered. Snapshot 2026-10-24; 513 answering domains. Vendors are never named: platforms are ranked by size. Hosting figures group sites by the address they resolved to and keep only group sizes.

| web server or edge, by class | domains | share |
|---|---|---|
| self-run web server | 137 | 27% |
| Microsoft web stack | § | § |
| edge network in front | 182 | 35% |
| hosted site builder | 12 | 2% |
| other or unidentified | <10 | § |
| no identifying server header | 167 | 33% |

| server platform (largest first) | domains | share |
|---|---|---|
| platform 1 | 144 | 28% |
| platform 2 | 76 | 15% |
| platform 3 | 49 | 10% |
| platform 4 | 30 | 6% |
| platform 5 | 13 | 3% |
| platform 6 | 11 | 2% |
| platform 7 | 10 | 2% |
| other platforms | 13 | 3% |

- platform concentration (Herfindahl, 0 to 1): 0.252
- domains sharing a resolved address with another domain: 192 (37%); largest single address: 2%; address-level Herfindahl: 0.005

PHP sites with a placeable version, by class (unsupported = branch PHP no longer fixes):

| class | placed | unsupported | share |
|---|---|---|---|
| self-run web server | 17 | <10 | § |
| edge network in front | <10 | <10 | § |
| other or unidentified | <10 | 0 | § |

## Exploratory: platform and hosting concentration - wisconsin

NOT pre-registered. Snapshot 2026-11-02; 648 answering domains. Vendors are never named: platforms are ranked by size. Hosting figures group sites by the address they resolved to and keep only group sizes.

| web server or edge, by class | domains | share |
|---|---|---|
| self-run web server | 172 | 27% |
| Microsoft web stack | 15 | 2% |
| edge network in front | 294 | 45% |
| hosted site builder | 11 | 2% |
| other or unidentified | 17 | 3% |
| no identifying server header | 139 | 21% |

| server platform (largest first) | domains | share |
|---|---|---|
| platform 1 | 256 | 40% |
| platform 2 | 85 | 13% |
| platform 3 | 61 | 9% |
| platform 4 | 28 | 4% |
| platform 5 | 18 | 3% |
| platform 6 | 14 | 2% |
| other platforms | 47 | 7% |

- platform concentration (Herfindahl, 0 to 1): 0.301
- domains sharing a resolved address with another domain: 251 (39%); largest single address: 4%; address-level Herfindahl: 0.005

PHP sites with a placeable version, by class (unsupported = branch PHP no longer fixes):

| class | placed | unsupported | share |
|---|---|---|---|
| self-run web server | 38 | 10 | 26% |
| Microsoft web stack | <10 | 0 | § |
| edge network in front | <10 | <10 | § |
| other or unidentified | <10 | 0 | § |

## Exploratory: election-office domains around 2026-11-03 - comparison

NOT pre-registered. The stratum is small, so the table is shown only when every count in it can be shown; otherwise it is withheld whole.

Too few election-office domains with a placeable PHP version to report in this region; nothing is shown.

## Exploratory: election-office domains around 2026-11-03 - wisconsin

NOT pre-registered. The stratum is small, so the table is shown only when every count in it can be shown; otherwise it is withheld whole.

Too few election-office domains with a placeable PHP version to report in this region; nothing is shown.

