"""Build dashboard/region_geo.json: the Census divisions as map shapes, from state boundary data.

    python -X utf8 scripts/build_region_geo.py <states-albers-10m.json> [--out dashboard/region_geo.json]

Input: the us-atlas 3.0.1 TopoJSON `states-albers-10m.json` (Census cartographic boundaries, already projected to Albers USA
with Alaska and Hawaii inset; public-domain data, package licence ISC). It is NOT committed. This script merges the states
into the nine Census divisions using the shared arcs of the topology, and writes only: one path per division (no state names or
codes), the division borders, the region borders, and the source hash. The page build then needs no download.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import region_map  # noqa: E402

NAME_TO_ABBR = {
    "Alabama": "AL", "Alaska": "AK", "Arizona": "AZ", "Arkansas": "AR", "California": "CA", "Colorado": "CO",
    "Connecticut": "CT", "Delaware": "DE", "District of Columbia": "DC", "Florida": "FL", "Georgia": "GA", "Hawaii": "HI",
    "Idaho": "ID", "Illinois": "IL", "Indiana": "IN", "Iowa": "IA", "Kansas": "KS", "Kentucky": "KY", "Louisiana": "LA",
    "Maine": "ME", "Maryland": "MD", "Massachusetts": "MA", "Michigan": "MI", "Minnesota": "MN", "Mississippi": "MS",
    "Missouri": "MO", "Montana": "MT", "Nebraska": "NE", "Nevada": "NV", "New Hampshire": "NH", "New Jersey": "NJ",
    "New Mexico": "NM", "New York": "NY", "North Carolina": "NC", "North Dakota": "ND", "Ohio": "OH", "Oklahoma": "OK",
    "Oregon": "OR", "Pennsylvania": "PA", "Rhode Island": "RI", "South Carolina": "SC", "South Dakota": "SD",
    "Tennessee": "TN", "Texas": "TX", "Utah": "UT", "Vermont": "VT", "Virginia": "VA", "Washington": "WA",
    "West Virginia": "WV", "Wisconsin": "WI", "Wyoming": "WY",
}
DIV_OF = {s: d for divs in region_map.DIVISIONS.values() for d, st in divs.items() for s in st.split()}
REGION_OF = {d: r for r, divs in region_map.DIVISIONS.items() for d in divs}


def decode_arcs(topo: dict) -> list[list[tuple[float, float]]]:
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]
    out = []
    for arc in topo["arcs"]:
        x = y = 0
        pts = []
        for dx, dy in arc:
            x += dx
            y += dy
            pts.append((x * sx + tx, y * sy + ty))
        out.append(pts)
    return out


def rings_of(geom: dict) -> list[list[int]]:
    if geom["type"] == "Polygon":
        return geom["arcs"]
    if geom["type"] == "MultiPolygon":
        return [r for poly in geom["arcs"] for r in poly]
    raise ValueError(geom["type"])


def _pts(pts, scale) -> list[str]:
    """Whole-pixel coordinates (the map is shown at most about 700 px wide), with repeated points dropped."""
    out, last = [], None
    for x, y in pts:
        c = (round(x * scale), round(y * scale))
        if c != last:
            out.append(f"{c[0]},{c[1]}")
            last = c
    return out


def path_for(arcs: list[list[tuple[float, float]]], ring: list[int], scale: float) -> str:
    pts: list[tuple[float, float]] = []
    for i in ring:
        seg = arcs[i] if i >= 0 else arcs[~i][::-1]
        pts.extend(seg if not pts else seg[1:])
    return "M" + "L".join(_pts(pts, scale)) + "Z"


def line_for(arcs, i, scale) -> str:
    return "M" + "L".join(_pts(arcs[i], scale))


def build(topo: dict, source_sha256: str) -> dict:
    arcs = decode_arcs(topo)
    # Whole-map scale: us-atlas albers is 975 x 610 already (its bbox is in those units), so scale is 1.
    users: dict[int, set[str]] = {}
    div_paths: dict[str, list[str]] = {d: [] for d in DIV_OF.values()}
    for g in topo["objects"]["states"]["geometries"]:
        abbr = NAME_TO_ABBR[g["properties"]["name"]]
        div = DIV_OF[abbr]
        for ring in rings_of(g):
            div_paths[div].append(path_for(arcs, ring, 1.0))
            for i in ring:
                users.setdefault(i if i >= 0 else ~i, set()).add(div)
    div_border, reg_border = [], []
    for i, divs in users.items():
        if len(divs) < 2:
            continue
        regs = {REGION_OF[d] for d in divs}
        (reg_border if len(regs) > 1 else div_border).append(line_for(arcs, i, 1.0))
    x0, y0, x1, y1 = topo["bbox"] if "bbox" in topo else (0, 0, 975, 610)
    return {
        "source": "us-atlas 3.0.1 states-albers-10m.json (Census cartographic boundaries, public domain data)",
        "source_sha256": source_sha256,
        "viewBox": [0, 0, 975, 610],
        "divisions": {d: "".join(p) for d, p in div_paths.items()},
        "division_borders": "".join(div_border),
        "region_borders": "".join(reg_border),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("topojson", type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "dashboard" / "region_geo.json")
    a = ap.parse_args(argv)
    raw = a.topojson.read_bytes()
    geo = build(json.loads(raw), hashlib.sha256(raw).hexdigest())
    a.out.write_text(json.dumps(geo, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"wrote {a.out} ({a.out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
