# Analysis weekly_2026-10-26 - PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

- event t0: `2026-10-21T14:00:00Z`; generated 2026-10-26T23:01:49Z
- frame: 2794 domains, 2599 entities; regions: comparison, wisconsin
- live runs analysed: 3
- archived baseline: {"available": true, "domains_asked": 3, "domains_with_pre_cutoff_capture": 0, "captures_on_or_after_cutoff": 0, "cutoff": "2026-10-17T00:00:00Z"}
- tribal nations' domains are not measured (PI decision D1); excluded: {"MI": 13, "WI": 10, "MN": 10, "IA": 2}
- disclosure: counts 1-9 shown as <10, complementary suppression marked §
- vendors, ASNs and hosting providers are never named
- provenance: code `2873751` (src/ MODIFIED since commit); frame sha256 `831406213ad8be3b`; ASN table sha256 `not loaded`

## Region: comparison

### RQ0 - measurability (entities)

| point | day | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R20261024T140522Z_CMP_20261024 | 3.0 | 1821 | <10 | <10 | 0 | <10 | 189 | 288 | 1323 | 210 | 16 | 8% |

By stratum at the latest live point (`R20261024T140522Z_CMP_20261024`):

| stratum | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|
| City | 576 | <10 | <10 | 0 | <10 | 51 | 106 | 414 | 56 | <10 | § |
| County | 301 | <10 | 0 | 0 | <10 | 40 | 47 | 210 | 44 | <10 | § |
| Election office | 171 | <10 | 0 | 0 | 0 | § | 19 | 137 | 15 | <10 | § |
| Interstate | <10 | § | § | § | § | § | § | § | § | § | § |
| Municipal department/other | 44 | 0 | 0 | 0 | 0 | <10 | <10 | 37 | <10 | 0 | § |
| School district | <10 | § | § | § | § | § | § | § | § | § | § |
| Special district | 77 | 0 | 0 | 0 | <10 | <10 | 13 | 58 | <10 | <10 | § |
| State | 40 | 0 | 0 | 0 | 0 | 0 | <10 | § | 0 | 0 | – |
| Town | 437 | <10 | <10 | 0 | <10 | 65 | 54 | 308 | 75 | <10 | § |
| Village | 169 | 0 | 0 | 0 | 0 | 13 | 35 | 121 | 13 | 0 | 0% |

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
| R20261024T140014Z_WI_20261024 | 3.0 | 778 | <10 | § | 0 | 27 | 153 | 433 | 151 | 194 | 29 | 15% |
| R20261026T215239Z_WI_20261026 | 5.3 | 778 | 0 | 10 | 0 | 30 | 149 | 434 | 155 | 189 | 30 | 16% |

By stratum at the latest live point (`R20261026T215239Z_WI_20261026`):

| stratum | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|
| City | 116 | 0 | 0 | 0 | <10 | § | 56 | 35 | 25 | <10 | § |
| County | 56 | 0 | 0 | 0 | <10 | § | 29 | 16 | 11 | <10 | § |
| Election office | 50 | 0 | 0 | 0 | <10 | 13 | 23 | § | 16 | <10 | § |
| Municipal department/other | 15 | 0 | 0 | 0 | <10 | 0 | <10 | <10 | <10 | <10 | § |
| Special district | 20 | 0 | 0 | 0 | 0 | <10 | <10 | <10 | <10 | 0 | § |
| State | 10 | 0 | 0 | 0 | 0 | <10 | <10 | <10 | <10 | 0 | § |
| Town | 330 | 0 | <10 | 0 | § | 70 | 191 | 44 | 95 | 17 | 18% |
| Village | 181 | 0 | <10 | 0 | <10 | 32 | 110 | 33 | 38 | <10 | § |

Domains at `R20261026T215239Z_WI_20261026` redirecting off-domain (front door only classified): 59; with certificate errors: 33.

### RQ1 - exposure before disclosure (archived)

No pre-cutoff archived captures in this region.

### Primary endpoint (pre-registered, plan §7.0)

A(14) = § (<10 of <10 still-visible cohort entities patched at `R20261026T215239Z_WI_20261026`, day 5.3); cohort <10; never observed patched by the last observation: 0.

**Contingency rule applies** (Wisconsin cohort < 30): Wisconsin results are descriptive only and no median is reported. Pooled cohort across all regions: 11, A(14) = §.

### RQ2 - adoption among entities exposed when first seen

Cohort: <10 entities. Flapping entities excluded: 0. Became visible only later (reported, not in cohort): <10.

| point | day | cohort | patched | still exposed | went dark | went ambiguous | unreached | A(d) |
|---|---|---|---|---|---|---|---|---|
| R20261024T140014Z_WI_20261024 | 3.0 | 2 | 0 | <10 | 0 | 0 | 0 | § |
| R20261026T215239Z_WI_20261026 | 5.3 | 2 | <10 | 0 | 0 | 0 | 0 | § |

### RQ3 - time to patch (Turnbull NPMLE, interval-censored)

| day <= | F(t) |
|---|---|
| 5.3 | 1.00 |

Median not reported: cohort below 30 (plan §7.0 contingency).
Never observed patched (right-censored; includes cohort entities that later went dark, ambiguous or unreachable): 0. Hid the version instead of patching (exposed -> opaque, never patched): 0.

### RQ4 - shared hosting

PHP-evidence entities at `R20261024T140014Z_WI_20261024`: 194.

| cluster key | clusters | largest | in clusters >=5 | effective independent servers |
|---|---|---|---|---|
| IP | 153 | <10 | 8% | 110.0 |

### Sensitivity analyses (§7.7) - A(d) at the latest live point

| scenario | cohort | patched | A(latest) | note |
|---|---|---|---|---|
| primary | <10 | <10 | § |  |
| 1a backport counted as patched | <10 | <10 | § |  |
| 1b backport counted as exposed | <10 | <10 | § |  |
| 2 domain is the unit | <10 | <10 | § |  |
| 3 cert-error domains excluded | <10 | <10 | § |  |
| 4 off-domain redirects excluded | <10 | <10 | § |  |
| 5 server-comment deviation off | <10 | <10 | § |  |
| 6a host cluster (IP) is the unit | <10 | <10 | § |  |
| 6b host cluster (ASN) is the unit | – | – | – | ASN table not loaded |

## RQ6 - Wisconsin vs. comparison states (descriptive, matched day)

A(d) = patched / (patched + still exposed) in each region's cohort. The difference is in percentage points. Entity rows are the primary analysis; host-cluster rows guard against one provider's upgrade standing in for many entities. No test of significance is reported here (plan §7.9).

**Unit: entity**; cohorts: Wisconsin <10, comparison <10.

| day | WI denominator | WI A(d) | comparison denominator | comparison A(d) | WI - comparison (pp) |
|---|---|---|---|---|---|
| 3 | <10 | § | <10 | § | § |
| 5 | <10 | § | – | – | – |

**Unit: host cluster (IP)**; cohorts: Wisconsin <10, comparison <10.

| day | WI denominator | WI A(d) | comparison denominator | comparison A(d) | WI - comparison (pp) |
|---|---|---|---|---|---|
| 3 | <10 | § | <10 | § | § |
| 5 | <10 | § | – | – | – |

