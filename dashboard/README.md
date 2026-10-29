# Dashboard inputs

`src/dashboard.py` builds `dashboard/index.html` from three committed inputs. It reads no
database and makes no network call, so it shows only what is already in the repository.

| Input | What it is |
|---|---|
| `dashboard/catalog.json` | Every vulnerability triaged so far, with its tier. Edited by a person. |
| `reports/run_*.md` | The per-run class counts the pipeline already writes (suppressed totals only). |
| `dashboard/measurability.json` | Optional aggregate summary of the KEV census, written by `scripts/kev_census.py --summary-out`. Public KEV data, no domains. |

## `catalog.json` entries

`{"entries": [ ... ]}`. A malformed entry stops the build (`dashboard.validate_entry`, tested).

| Field | Type | Required | Meaning |
|---|---|---|---|
| `key` | string | yes | Lower-case letters, digits, underscores. Unique. Used as the page anchor. |
| `title` | string | yes | Card title. |
| `cve_ids` | list of strings | yes | `CVE-YYYY-NNNN` ids. May be empty when none is recorded yet. |
| `component` | string | yes | The affected product, in words. |
| `disclosed` | string | yes | `YYYY-MM-DD`, `YYYY-MM`, or empty when unknown. |
| `tier` | string | yes | One of `live`, `validating`, `awaiting_fix`, `archive_only`, `not_measurable`, `untriaged` (`dashboard.TIERS`). A human reviews every tier change. |
| `signal` | string | yes | What a homepage observer would see. |
| `why` | string | yes | Why it has this tier. |
| `sources` | list of strings | yes | URLs or citations. |
| `event` | string or null | for `live` and `archive_only` | Names a published `PatchEvent` in `src/versions.py`. |
| `kev` | object | no | `{added, federal_due, verified, note}`. Dates `YYYY-MM-DD`; `verified` is true only once checked against CISA's catalog. |
| `exploitation` | object | no | `{first_seen, kind, source}`: when exploitation was first seen. `first_seen` is `YYYY-MM-DD`; `kind` is `vendor_reported` or `kev_listing`; `source` says where the date comes from and must not be empty. Without it the exposure window uses the KEV listing date and labels it a floor. |

The proposer in `src/intake.py` writes proposals elsewhere and never edits this file.

## Presentation rules (code, not data)

- **Preliminary points.** `PRELIMINARY_BEFORE_DAYS = 14` in `src/dashboard.py` (decision D1,
  matching the pre-registered primary endpoint). A snapshot fewer days after the fix than this
  is drawn dashed and labelled "preliminary". Nothing about collection changes.
- **Exposure window.** Built from the catalog: fix date, exploitation onset (with its source),
  federal due date, then each snapshot. Every chart has its dated list or table under a
  `<details>` for readers who cannot see the graphic.
- **Suppression.** Counts 1 to 9 print as "<10", with complementary suppression, the same as
  `analyze.Suppressor`. A withheld share is drawn hatched, never as a value.
