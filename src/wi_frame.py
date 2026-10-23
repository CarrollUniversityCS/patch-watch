"""Wisconsin census frame (docs/analysis_plan.md §2), with optional comparison states.

PROVENANCE: one input, CISA's public .gov registry, pinned to a COMMIT of
cisagov/dotgov-data rather than to "main" - the registry changes daily, and a frame
that cannot be re-derived byte for byte cannot be audited. The pinned blob is the
2026-10-22 registry day, the same file the national frame (src/frame.py) asserts
against: 16,935 rows, sha256 below. The download is from raw.githubusercontent.com;
no .gov host is contacted here.

WHAT IT BUILDS
    data/raw/current-full@<commit12>.csv   the registry as downloaded
    data/wi_frame.csv                      every in-scope domain, one row each
    data/wi_frame_meta.json                provenance, counts, exclusions

SCOPE
    * nonfederal only (as the national frame);
    * tribal nations are EXCLUDED (PI decision D1, config.EXCLUDED_DOMAIN_TYPE_PREFIXES):
      they are dropped here and only their COUNT is recorded in the meta file;
    * State = WI is region "wisconsin"; `--comparison MN,IL,MI,IA` adds those states as
      region "comparison" (plan §7.9), under the same strata rules.

UNITS (plan §2): `domain` is the unit of measurement; `entity_id` (state + normalised
Organization name) is the unit of analysis. Contact emails never enter this frame.

Run:
    python src/wi_frame.py build [--comparison MN,IL,MI,IA] [--skip-download]
    python src/wi_frame.py verify
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import httpx
import pandas as pd

import config
from frame import EXPECTED_HEADER, assert_registry_shape, sha256_bytes, sha256_file, utc_now_iso

REGISTRY_COMMIT = "718c7ac8deb13ee4917d45101ee6a0dd08fb94f2"     # 2026-10-22T11:23:57Z
REGISTRY_SHA256 = "f1bf731322871787f742508a2d7c026c7dfae268092b9dad86e23199c8cddd62"
REGISTRY_URL = ("https://raw.githubusercontent.com/cisagov/dotgov-data/"
                f"{REGISTRY_COMMIT}/current-full.csv")
RAW_PATH = config.DATA_DIR / "raw" / f"current-full@{REGISTRY_COMMIT[:12]}.csv"
FRAME_PATH = config.DATA_DIR / "wi_frame.csv"
META_PATH = config.DATA_DIR / "wi_frame_meta.json"

STUDY_STATE = "WI"
DEFAULT_COMPARISON = ("MN", "IL", "MI", "IA")

FRAME_COLUMNS = ["domain", "region", "state", "stratum", "domain_type",
                 "organization", "entity_id", "city"]

ELECTION_STRATUM = "Election office"
MUNICIPAL_OTHER = "Municipal department/other"

# Municipal ("City" domain type) names, matched case-insensitively. In Wisconsin a
# "township" is a town; "TN OF" is a registrant abbreviation seen in the 2026-10-22 file.
_TOWN = re.compile(r"^(the\s+)?town(ship)?\s+of\b|,\s*town(ship)?\s+of$|\btownship\b|\btn\s+of\b|^town\b", re.I)
_VILLAGE = re.compile(r"^(the\s+)?village\s+of\b|,\s*village\s+of$|^village\b", re.I)
_CITY = re.compile(r"^(the\s+)?city\s+of\b|,\s*city\s+of$|^city\b", re.I)
# Hand-classified names the rules cannot reach. Each entry was checked against the
# registry row; both are Wisconsin towns registered as "<town> in <county>".
MUNICIPAL_OVERRIDES = {
    "eau pleine in portage county": "Town",
    "hull in portage county": "Town",
}


def municipal_stratum(org: str) -> str:
    name = " ".join((org or "").split())
    if name.lower() in MUNICIPAL_OVERRIDES:
        return MUNICIPAL_OVERRIDES[name.lower()]
    if _TOWN.search(name):
        return "Town"
    if _VILLAGE.search(name):
        return "Village"
    if _CITY.search(name):
        return "City"
    return MUNICIPAL_OTHER


def assign_stratum(domain_type: str, org: str) -> str | None:
    """Reporting stratum, or None when the row is out of scope."""
    t = (domain_type or "").strip()
    if t == "Federal" or t.startswith("Federal - "):
        return None
    if any(t.startswith(p) for p in config.EXCLUDED_DOMAIN_TYPE_PREFIXES):
        return None
    if t.endswith(" - Election"):
        return ELECTION_STRATUM
    if t == "City":
        return municipal_stratum(org)
    if t == "State or territory":
        return "State"
    return t        # County, Special district, School district, Interstate


def entity_id(state: str, org: str) -> str:
    norm = re.sub(r"[^a-z0-9]+", " ", (org or "").lower()).strip()
    return f"{(state or '').strip().upper()}:{norm}"


def build_frame(df: pd.DataFrame, comparison: tuple[str, ...] = ()) -> tuple[pd.DataFrame, dict]:
    """Registry rows -> in-scope frame, plus counts of what was excluded and why."""
    if list(df.columns) != EXPECTED_HEADER:
        raise SystemExit(f"FRAME ASSERTION FAILED: header drift {list(df.columns)!r}")
    d = df.rename(columns={"Domain name": "domain", "Domain type": "domain_type",
                           "Organization name": "organization", "City": "city",
                           "State": "state"})
    for c in ("domain", "domain_type", "organization", "city", "state"):
        d[c] = d[c].fillna("").astype(str).str.strip()
    d["domain"] = d["domain"].str.lower().str.rstrip(".")
    d["state"] = d["state"].str.upper()
    states = {STUDY_STATE, *comparison}
    d = d[d["state"].isin(states)].copy()

    is_fed = d["domain_type"].eq("Federal") | d["domain_type"].str.startswith("Federal - ")
    is_excl = d["domain_type"].apply(
        lambda t: any(t.startswith(p) for p in config.EXCLUDED_DOMAIN_TYPE_PREFIXES))
    excluded = {
        "federal": {s: int(n) for s, n in d[is_fed]["state"].value_counts().items()},
        "tribal_nations_by_decision_D1": {s: int(n) for s, n in d[is_excl]["state"].value_counts().items()},
    }
    d = d[~is_fed & ~is_excl].copy()
    d["stratum"] = [assign_stratum(t, o) for t, o in zip(d["domain_type"], d["organization"])]
    d["region"] = d["state"].map(lambda s: "wisconsin" if s == STUDY_STATE else "comparison")
    d["entity_id"] = [entity_id(s, o) for s, o in zip(d["state"], d["organization"])]
    if d["domain"].duplicated().any():
        raise SystemExit("FRAME ASSERTION FAILED: duplicate domains in frame")
    d = d.sort_values(["region", "state", "stratum", "domain"], ascending=[False, True, True, True])
    return d[FRAME_COLUMNS].reset_index(drop=True), excluded


def summarise(frame: pd.DataFrame) -> dict:
    out: dict = {}
    for (region, state), g in frame.groupby(["region", "state"]):
        out.setdefault(region, {})[state] = {
            "domains": int(len(g)),
            "entities": int(g["entity_id"].nunique()),
            "multi_domain_entities": int((g["entity_id"].value_counts() > 1).sum()),
            "by_stratum": {k: {"domains": int(len(s)), "entities": int(s["entity_id"].nunique())}
                           for k, s in g.groupby("stratum")},
        }
    return out


def download(dest: Path) -> bytes:
    print(f"downloading {REGISTRY_URL}")
    with httpx.Client(headers={"User-Agent": config.USER_AGENT},
                      timeout=httpx.Timeout(60.0, connect=20.0), follow_redirects=True) as c:
        r = c.get(REGISTRY_URL)
    if r.status_code != 200:
        raise SystemExit(f"registry download returned HTTP {r.status_code}")
    body = r.content
    if sha256_bytes(body) != REGISTRY_SHA256:
        raise SystemExit(f"pinned registry hash mismatch: got {sha256_bytes(body)}, "
                         f"expected {REGISTRY_SHA256}. Do not proceed; record it in the plan §12.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(body)
    return body


def load_raw() -> tuple[pd.DataFrame, bytes]:
    if not RAW_PATH.exists():
        raise SystemExit(f"cached registry missing: {RAW_PATH} (run `build` first)")
    raw = RAW_PATH.read_bytes()
    if sha256_bytes(raw) != REGISTRY_SHA256:
        raise SystemExit(f"{RAW_PATH} does not match the pinned sha256; refusing to build")
    df = pd.read_csv(RAW_PATH, encoding="utf-8-sig", dtype=str, keep_default_na=False)
    assert_registry_shape(df)     # same 2026-10-22 census the national frame checks
    return df, raw


def national_frame_cross_check() -> str:
    """The national frame records the hash of the file IT used. Same day, same file?"""
    nat = config.DATA_DIR / "frame_meta.json"
    if not nat.exists():
        return "national frame_meta.json not present on this machine; not checked"
    got = json.loads(nat.read_text(encoding="utf-8")).get("raw_sha256")
    if got == REGISTRY_SHA256:
        return "matches national frame raw_sha256"
    return f"DIFFERS from national frame raw_sha256 ({got}); record in analysis_plan.md §12"


def cmd_build(args: argparse.Namespace) -> int:
    if not args.skip_download:
        download(RAW_PATH)
    df, raw = load_raw()
    comparison = tuple(s.strip().upper() for s in args.comparison.split(",") if s.strip()) \
        if args.comparison else ()
    frame, excluded = build_frame(df, comparison)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    frame.to_csv(FRAME_PATH, index=False, encoding="utf-8", lineterminator="\n")
    meta = {
        "source_url": REGISTRY_URL,
        "registry_commit": REGISTRY_COMMIT,
        "raw_sha256": sha256_bytes(raw),
        "raw_bytes": len(raw),
        "built_at_utc": utc_now_iso(),
        "study_state": STUDY_STATE,
        "comparison_states": list(comparison),
        "excluded_counts": excluded,
        "exclusion_note": ("Tribal nations' domains are not measured (PI decision D1, "
                           "2026-10-23). Only their count is recorded."),
        "summary": summarise(frame),
        "frame_csv_sha256": sha256_file(FRAME_PATH),
        "national_frame_cross_check": national_frame_cross_check(),
        "municipal_overrides": MUNICIPAL_OVERRIDES,
    }
    META_PATH.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: meta[k] for k in ("registry_commit", "excluded_counts", "summary",
                                           "national_frame_cross_check")}, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    df, _ = load_raw()
    meta = json.loads(META_PATH.read_text(encoding="utf-8"))
    frame, _ = build_frame(df, tuple(meta.get("comparison_states", [])))
    rederived = frame.to_csv(index=False, encoding="utf-8", lineterminator="\n").encode()
    if sha256_bytes(rederived) != meta["frame_csv_sha256"] or \
            FRAME_PATH.read_bytes() != rederived:
        raise SystemExit("wi_frame.csv does not match a fresh re-derivation")
    if "security" in ",".join(pd.read_csv(FRAME_PATH, nrows=0).columns).lower():
        raise SystemExit("wi_frame.csv must not contain contact data")
    print(f"verify: wi_frame.csv re-derives exactly (sha256 {meta['frame_csv_sha256']})")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wi_frame.py", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--skip-download", action="store_true")
    b.add_argument("--comparison", default="",
                   help=f"comma-separated comparison states, e.g. {','.join(DEFAULT_COMPARISON)}")
    b.set_defaults(func=cmd_build)
    sub.add_parser("verify").set_defaults(func=cmd_verify)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
