"""Aggregate region summary for the dashboard tile map. Writes dashboard/region_map.json (bands only, no per-state or per-site data).

    python -X utf8 scripts/region_map.py --db <study.db> --labels WI_20261118 NAT_20261118 [--out dashboard/region_map.json]

Reads the database read-only. Regions are the four U.S. Census regions already used for pooling in Amendment 1
(`analyze.CENSUS_REGION`); divisions are the nine Census divisions inside them. Each cell is published as a band:
issues are "under 10" (0 to 9, so a zero is never shown beside a hidden count), "10 to 24" or "25 or more"; sites
observed are rounded to the nearest hundred. A region's bands are never finer than a division's. Not a national estimate.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import analyze  # noqa: E402

DIVISIONS = {
    "Northeast": {"New England": "CT ME MA NH RI VT", "Middle Atlantic": "NJ NY PA"},
    "Midwest": {"East North Central": "IL IN MI OH WI", "West North Central": "IA KS MN MO NE ND SD"},
    "South": {"South Atlantic": "DE DC FL GA MD NC SC VA WV", "East South Central": "AL KY MS TN",
              "West South Central": "AR LA OK TX"},
    "West": {"Mountain": "AZ CO ID MT NV NM UT WY", "Pacific": "AK CA HI OR WA"},
}
ISSUE_CLASSES = ("EOL_UNFIXED", "VULNERABLE_BY_VERSION")
BANDS = ("under 10", "10 to 24", "25 or more")
CAVEAT = ("Observed version evidence, not a national estimate and not a ranking. Only a small share of sites show a readable "
          "PHP version, and they are not a random subset, so a region with fewer issues is not a safer region.")


def issue_band(n: int) -> str:
    return BANDS[0] if n < 10 else BANDS[1] if n < 25 else BANDS[2]


def round_sites(n: int) -> int:
    return int(round(n / 100.0)) * 100


def check_division_map() -> None:
    """Every state in analyze.CENSUS_REGION lies in exactly one division of its own region."""
    seen = {}
    for region, divs in DIVISIONS.items():
        for div, states in divs.items():
            for s in states.split():
                assert s not in seen, f"{s} in two divisions"
                assert analyze.CENSUS_REGION.get(s) == region, f"{s}: region mismatch"
                seen[s] = div
    assert set(seen) == set(analyze.CENSUS_REGION), "division map and CENSUS_REGION differ"


def summarise(rows: list[tuple[str, str, int]], snapshot_date: str) -> dict:
    """rows = (state, class, count) for the chosen snapshots. Returns the publishable model (bands only)."""
    check_division_map()
    obs: dict[str, int] = {}
    iss: dict[str, int] = {}
    s2d = {s: d for divs in DIVISIONS.values() for d, st in divs.items() for s in st.split()}
    for state, cls, n in rows:
        d = s2d.get(state)
        if d is None:
            continue
        obs[d] = obs.get(d, 0) + n
        iss[d] = iss.get(d, 0) + (n if cls in ISSUE_CLASSES else 0)
    regions = []
    for region, divs in DIVISIONS.items():
        r_obs = sum(obs.get(d, 0) for d in divs)
        r_iss = sum(iss.get(d, 0) for d in divs)
        regions.append({
            "region": region, "sites_observed": round_sites(r_obs), "issues": issue_band(r_iss),
            "divisions": [{"division": d, "sites_observed": round_sites(obs.get(d, 0)),
                           "issues": issue_band(iss.get(d, 0))} for d in divs],
        })
    return {"snapshot_date": snapshot_date, "bands": list(BANDS), "issue_definition":
            "Sites whose PHP version is below the fixed release or on an end-of-life branch with no fix.",
            "caveat": CAVEAT, "regions": regions}


def validate(m: dict) -> None:
    """Used by the dashboard build: a malformed or too-precise file stops the build."""
    for f in ("snapshot_date", "bands", "caveat", "regions"):
        if f not in m:
            raise ValueError(f"region_map: lacks {f!r}")
    for r in m["regions"]:
        for cell in [r, *r["divisions"]]:
            if cell["issues"] not in BANDS:
                raise ValueError(f"region_map: issue cell {cell['issues']!r} is not a band")
            if cell["sites_observed"] % 100:
                raise ValueError("region_map: sites observed must be rounded to the nearest hundred")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", type=Path, required=True)
    ap.add_argument("--labels", nargs="+", required=True)
    ap.add_argument("--date", required=True, help="snapshot date shown on the page, YYYY-MM-DD")
    ap.add_argument("--out", type=Path, default=ROOT / "dashboard" / "region_map.json")
    a = ap.parse_args(argv)
    conn = sqlite3.connect(f"file:{a.db.as_posix()}?mode=ro", uri=True)
    q = ",".join("?" * len(a.labels))
    rows = conn.execute(f"SELECT d.state, o.class, COUNT(*) FROM observations o JOIN domains d USING(domain) "
                        f"WHERE o.snapshot_label IN ({q}) GROUP BY 1, 2", a.labels).fetchall()
    model = summarise(rows, a.date)
    validate(model)
    a.out.write_text(json.dumps(model, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
