"""KEV measurability census. Writes PROPOSALS only.

    python -X utf8 scripts/kev_census.py --cache <dir> [--db <copy of study.db>] [--offline]

Reads CISA's KEV catalog (cisagov/kev-data), then for the rater sample and every
homepage-stack entry also the CVE record (cvelistV5) and CISA Vulnrichment record for CPEs
and SSVC, and EPSS scores to rank. Q3 (is the product common in the frame?) uses aggregate
header-inventory counts from a COPY of the study database, opened read-only; without --db
Q3 is 'unknown'.

Outputs, all public KEV data and aggregates, no domains:
  kev_tiers_proposed.json   proposed tier and reason per entry (homepage-stack,
                                          edge/server and last-12-month entries)
  kev_rater_sample.csv      120 entries for two independent raters (blank columns)
  kev_census_numbers.json   the counts

It never edits dashboard/catalog.json. Network goes through intake.fetch_text only.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import intake  # noqa: E402

RECENT_FROM = "2025-10-28"


def _records(cve: str, cache: Path) -> tuple[dict | None, dict | None]:
    urls = intake.record_urls(cve)
    if not urls:
        return None, None
    out = []
    for u in urls:
        t = intake.fetch_text(u, cache)
        try:
            out.append(json.loads(t) if t else None)
        except ValueError:
            out.append(None)
    return out[0], out[1]


def measurability_summary(rows: list[dict], version: str) -> dict:
    """What the dashboard's 'not remotely measurable' list shows: public KEV data and counts, never a
    domain. Only entries that fail Q1 (no passive fingerprint) are listed as not measurable; edge
    products and homepage-stack entries are counted separately because they are still open."""
    from collections import Counter
    c = [r for r in rows if r["q1_visible"] == "no"]
    top = Counter(f"{r['vendor']} {r['product']}".strip() for r in c).most_common(10)
    return {
        "catalog_version": version,
        "total": len(rows),
        "groups": [{"reason": "Client or local software: leaves no passive fingerprint in an ordinary web response",
                    "count": len(c), "examples": [name for name, _ in top]}],
        "still_open": {"edge_or_server_product": sum(r["q1_visible"] == "maybe" for r in rows),
                       "homepage_stack": sum(r["q1_visible"] == "yes" for r in rows)},
        "caveat": "A first-pass keyword sort over vendor and product names. It over- and under-counts, and no "
                  "second rater has checked it. Entries stay in the catalog with their reason; none are dropped.",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--summary-out", help="also write the dashboard's aggregate summary here "
                                          "(for example dashboard/measurability.json)")
    ap.add_argument("--cache", required=True, help="directory for cached feed downloads")
    ap.add_argument("--kev", help="a downloaded KEV JSON file (default: fetch the mirror)")
    ap.add_argument("--db", help="a COPY of the study database, for Q3 (opened read-only)")
    ap.add_argument("--out-dir", default=str(ROOT / "docs" / "proposed"))
    ap.add_argument("--offline", action="store_true", help="no network: KEV file only, no CPE or EPSS")
    ap.add_argument("--sample-size", type=int, default=120)
    args = ap.parse_args(argv)
    cache, out = Path(args.cache), Path(args.out_dir)

    text = Path(args.kev).read_text(encoding="utf-8") if args.kev else intake.fetch_text(intake.KEV_URL, cache)
    if not text:
        print("error: could not read the KEV catalog", file=sys.stderr)
        return 2
    kev = intake.load_kev(text)

    frame_named = None
    if args.db:
        import inventory
        inv = inventory.aggregate(args.db)
        frame_named = {p: c.named for p, c in inv.by_product.items()}

    first = intake.build_rows(kev, None, None, frame_named)          # keyword pass over everything
    sample = intake.stratified_sample(first, args.sample_size)
    want = {r["cve"] for r in sample} | {r["cve"] for r in first if r["tier"] == intake.TIER_A}

    cpe_by_cve: dict[str, list] = {}
    ssvc_by_cve: dict[str, dict] = {}
    epss: dict[str, float] = {}
    if not args.offline:
        def work(cve: str):
            rec, rich = _records(cve, cache)
            return cve, intake.extract_cpes(rec, rich), intake.extract_ssvc(rich)
        with ThreadPoolExecutor(max_workers=8) as ex:
            for cve, cpes, ssvc in ex.map(work, sorted(want)):
                if cpes:
                    cpe_by_cve[cve] = cpes
                if ssvc:
                    ssvc_by_cve[cve] = ssvc
        cves = [e["cve"] for e in kev["entries"]]
        for i in range(0, len(cves), 100):
            batch = ",".join(cves[i:i + 100])
            epss.update(intake.parse_epss(intake.fetch_text(intake.EPSS_URL.format(cves=batch), cache)))

    rows = intake.build_rows(kev, cpe_by_cve, epss, frame_named)
    for r in rows:
        r["ssvc"] = ssvc_by_cve.get(r["cve"], {})
    counts = intake.census_counts(rows)
    counts.update(catalog_version=kev["version"], released=kev["released"],
                  epss_scored=len(epss), ssvc_present=len(ssvc_by_cve),
                  q3_available=frame_named is not None,
                  sample_size=len(sample))
    out.mkdir(parents=True, exist_ok=True)

    keep = [r for r in rows if r["tier"] == intake.TIER_A or r["added"] >= RECENT_FROM]
    keep.sort(key=lambda r: (-(r["epss"] or 0), r["cve"]))
    head = {"status": "PROPOSAL, not applied. A person approves every tier change.",
            "catalog_version": kev["version"],
            "scope": f"homepage-stack entries and entries added since {RECENT_FROM}; one entry per line"}
    (out / "kev_tiers_proposed.json").write_text(
        json.dumps(head)[:-1] + ',\n"entries": [\n' + ",\n".join(json.dumps(r) for r in keep) + "\n]}\n",
        encoding="utf-8")

    by_cve = {r["cve"]: r for r in rows}
    with open(out / "kev_rater_sample.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["cve", "vendor", "product", "added", "keyword_tier", "rater_a", "rater_b", "notes"])
        for s in sample:
            r = by_cve[s["cve"]]
            w.writerow([r["cve"], r["vendor"], r["product"], r["added"], r["tier"], "", "", ""])
    (out / "kev_census_numbers.json").write_text(json.dumps(counts, indent=1), encoding="utf-8")
    if args.summary_out:
        summary = measurability_summary(rows, kev["version"])
        Path(args.summary_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary_out).write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(counts, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
