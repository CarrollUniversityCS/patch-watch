"""Stage 1: build the study frame and the stratified pilot sample.

PROVENANCE: the only input is the CISA .gov total-domain registry,
https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv,
accessed 2026-10-22. That file is the ONLY thing this module ever downloads.
No request is ever sent to any .gov domain: the frame is a list of names,
built offline, and live traffic is gated elsewhere (config.LIVE_REQUESTS_ENABLED).

WHAT IT DOES
    build    download the registry to data/raw/current-full.csv (unless
             --skip-download), assert its shape, write
             data/frame_full.csv, data/pilot_sample.csv, data/frame_meta.json
    verify   re-derive everything from the cached raw copy, no network, and
             byte-compare the re-derived pilot sample against the one on disk

The 16935-row census this code asserts against was verified by hand on
2026-10-22. Every one of those numbers is re-checked at run time; a drift in
the registry is a hard stop, not a warning, because a silently different frame
invalidates every downstream percentage.

Sample privacy: pilot_sample.csv deliberately has NO security-contact column.
Contact addresses exist only in data/frame_full.csv, and data/ is gitignored.
Stage 1 sends mail to nobody; the address column is carried for a future
notification experiment that has not been approved.

Determinism: each stratum is sorted alphabetically by domain before the draw,
so the sample does not depend on registry row order. Each stratum gets its own
random.Random(20261022) so that a change in one stratum can never perturb
another stratum's draw.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pandas as pd

from config import (
    CISA_REGISTRY_URL,
    DATA_DIR,
    RANDOM_SEED,
    STRATUM_FLOOR,
    USER_AGENT,
)

ACCESS_DATE = "2026-10-22"          # date the registry was fetched, for provenance
REGISTRY_PATH = DATA_DIR / "raw" / "current-full.csv"
FRAME_PATH = DATA_DIR / "frame_full.csv"
SAMPLE_PATH = DATA_DIR / "pilot_sample.csv"
META_PATH = DATA_DIR / "frame_meta.json"

# ---------------------------------------------------------------- registry shape
EXPECTED_HEADER = [
    "Domain name",
    "Domain type",
    "Organization name",
    "Suborganization name",
    "City",
    "State",
    "Security contact email",
]
EXPECTED_ROWS = 16935
EXPECTED_TYPE_COUNTS = {
    "City": 9223,
    "County": 2716,
    "State or territory": 1438,
    "Federal - Executive": 1174,
    "Special district": 1113,
    "City - Election": 346,
    "County - Election": 325,
    "Tribal": 289,
    "Federal - Legislative": 121,
    "School district": 75,
    "State or territory - Election": 41,
    "Interstate": 39,
    "Federal - Judicial": 24,
    "Special district - Election": 5,
    "Tribal - Election": 4,
    "Federal": 2,
}
EXPECTED_NONFEDERAL_ROWS = 15614
EXPECTED_FEDERAL_ROWS = 1321

# CISA writes this literal token into the Security contact email column when a
# registrant never supplied an address. It is NOT an email; see the census that
# frame.py records in frame_meta.json.
PLACEHOLDER_CONTACT = "(blank)"

# Federal types are out of scope: the study is about nonfederal government.
FEDERAL_TYPES = frozenset(
    t for t in EXPECTED_TYPE_COUNTS if t == "Federal" or t.startswith("Federal - ")
)

# The five election-office types are one analysis stratum (the PI's design).
ELECTION_STRATUM = "Election office"
ELECTION_TYPES = tuple(t for t in EXPECTED_TYPE_COUNTS if t.endswith(" - Election"))

# Strata that keep their raw type name. Interstate has no floor: take all 39.
PASSTHROUGH_STRATA = (
    "City",
    "County",
    "State or territory",
    "Special district",
    "Tribal",
    "School district",
    "Interstate",
)
NO_FLOOR_STRATA = frozenset({"Interstate"})
EXPECTED_STRATA_COUNT = 8

# Expected per-stratum populations, used as a second gate after collapsing.
EXPECTED_STRATUM_POPULATIONS = {
    "City": 9223,
    "County": 2716,
    "State or territory": 1438,
    "Special district": 1113,
    "Tribal": 289,
    "School district": 75,
    ELECTION_STRATUM: 721,   # 346 + 325 + 41 + 5 + 4
    "Interstate": 39,
}
EXPECTED_TOTAL_SAMPLED = 7 * STRATUM_FLOOR + 39   # 319

# frame_full.csv column order; the contact email stops here (data/ is gitignored).
FRAME_COLUMNS = [
    "domain",
    "domain_type",
    "stratum",
    "organization",
    "suborganization",
    "city",
    "state",
    "security_contact",
]
# pilot_sample.csv column order; deliberately no contact email.
SAMPLE_COLUMNS = ["domain", "stratum", "domain_type", "state", "city", "organization"]

_RENAME = {
    "Domain name": "domain",
    "Domain type": "domain_type",
    "Organization name": "organization",
    "Suborganization name": "suborganization",
    "City": "city",
    "State": "state",
    "Security contact email": "security_contact",
}


# ---------------------------------------------------------------- helpers
def sha256_bytes(data: bytes) -> str:
    """Hex sha256 of a byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Hex sha256 of a file, read whole (the registry is a few MB)."""
    return sha256_bytes(path.read_bytes())


def _fail(message: str) -> None:
    """Stop the run with an actionable message; frame drift must never pass quietly."""
    raise SystemExit(f"FRAME ASSERTION FAILED: {message}")


def utc_now_iso() -> str:
    """Current UTC instant, second resolution, e.g. 2026-10-22T19:05:11Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- download
def download_registry(dest: Path, url: str = CISA_REGISTRY_URL) -> bytes:
    """Fetch the one permitted public file and cache it under data/raw/.

    Returns the raw bytes as downloaded. Refuses to write an empty or
    HTML-looking body, because a captive-portal or error page saved as a .csv
    would later be re-read as if it were the registry.
    """
    print(f"downloading {url}")
    with httpx.Client(
        headers={"User-Agent": USER_AGENT},
        timeout=httpx.Timeout(60.0, connect=20.0),
        follow_redirects=True,
    ) as client:
        response = client.get(url)
    if response.status_code != 200:
        _fail(f"registry download returned HTTP {response.status_code}")
    body = response.content
    if len(body) < 10_000:
        _fail(f"registry download suspiciously small: {len(body)} bytes")
    if body.lstrip()[:1] in (b"<",):
        _fail("registry download looks like HTML, not CSV")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(body)
    print(f"  wrote {dest} ({len(body):,} bytes, sha256 {sha256_bytes(body)[:16]}...)")
    return body


# ---------------------------------------------------------------- load + assert
def load_registry(path: Path) -> pd.DataFrame:
    """Read the cached registry as utf-8-sig text, without touching the network."""
    if not path.exists():
        _fail(f"cached registry missing: {path} (run `build` first)")
    return pd.read_csv(path, encoding="utf-8-sig", dtype=str, keep_default_na=False)


def assert_registry_shape(df: pd.DataFrame) -> dict[str, int]:
    """Check header, row count and per-type counts against the 2026-10-22 census.

    Returns the observed type counts so the caller can reuse them.
    """
    header = list(df.columns)
    if header != EXPECTED_HEADER:
        _fail(f"header drift. expected {EXPECTED_HEADER!r}, got {header!r}")
    if len(df) != EXPECTED_ROWS:
        _fail(f"row count drift. expected {EXPECTED_ROWS}, got {len(df)}")
    if df["Domain name"].duplicated().any():
        dupes = df.loc[df["Domain name"].duplicated(), "Domain name"].head(10).tolist()
        _fail(f"duplicate Domain name values, e.g. {dupes}")

    counts = df["Domain type"].value_counts().to_dict()
    counts = {str(k): int(v) for k, v in counts.items()}
    if set(counts) != set(EXPECTED_TYPE_COUNTS):
        extra = sorted(set(counts) - set(EXPECTED_TYPE_COUNTS))
        missing = sorted(set(EXPECTED_TYPE_COUNTS) - set(counts))
        _fail(f"Domain type value drift. unexpected {extra}, missing {missing}")
    for name, expected in EXPECTED_TYPE_COUNTS.items():
        if counts.get(name) != expected:
            _fail(f"type count drift for {name!r}: expected {expected}, got {counts.get(name)}")
    if sum(counts.values()) != EXPECTED_ROWS:
        _fail("type counts do not sum to the row count")

    federal = sum(counts[t] for t in FEDERAL_TYPES)
    nonfederal = EXPECTED_ROWS - federal
    if federal != EXPECTED_FEDERAL_ROWS:
        _fail(f"federal row count drift. expected {EXPECTED_FEDERAL_ROWS}, got {federal}")
    if nonfederal != EXPECTED_NONFEDERAL_ROWS:
        _fail(f"nonfederal row count drift. expected {EXPECTED_NONFEDERAL_ROWS}, got {nonfederal}")
    return counts


# ---------------------------------------------------------------- strata
def assign_stratum(domain_type: str) -> str | None:
    """Map a raw Domain type onto its study stratum, or None if out of scope."""
    if domain_type in FEDERAL_TYPES:
        return None
    if domain_type in ELECTION_TYPES:
        return ELECTION_STRATUM
    if domain_type in PASSTHROUGH_STRATA:
        return domain_type
    _fail(f"unmapped Domain type: {domain_type!r}")   # unreachable after shape check
    return None


def build_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Return every nonfederal domain as a tidy frame with its stratum assigned."""
    frame = df.rename(columns=_RENAME).copy()
    for col in _RENAME.values():
        if col not in frame.columns:
            _fail(f"renamed column {col!r} missing; header changed shape")
        frame[col] = frame[col].fillna("").astype(str).str.strip()

    frame["stratum"] = frame["domain_type"].map(assign_stratum)
    frame = frame.loc[frame["stratum"].notna(), FRAME_COLUMNS].reset_index(drop=True)
    if frame["domain"].duplicated().any():
        _fail("duplicate domains inside the nonfederal frame")
    return frame


def stratum_types() -> dict[str, list[str]]:
    """Stratum name -> the exact raw Domain type values it is built from."""
    spec = {name: [name] for name in PASSTHROUGH_STRATA}
    spec[ELECTION_STRATUM] = list(ELECTION_TYPES)
    return {name: spec[name] for name in sorted(spec)}


def draw_sample(frame: pd.DataFrame, seed: int = RANDOM_SEED) -> pd.DataFrame:
    """Apply the floor rule per stratum and draw the pilot sample.

    Every stratum takes STRATUM_FLOOR domains when it can, else all of it;
    NO_FLOOR_STRATA (Interstate) always take everything they have. The pool is
    sorted before the draw and each stratum uses a fresh Random(seed).
    """
    draws: list[pd.DataFrame] = []
    for stratum in sorted(frame["stratum"].unique()):
        pool = frame.loc[frame["stratum"] == stratum].sort_values("domain")
        size = len(pool)
        if stratum in NO_FLOOR_STRATA:
            take = size
        else:
            take = min(STRATUM_FLOOR, size)
        picked = random.Random(seed).sample(list(pool["domain"]), take)
        draws.append(pool.loc[pool["domain"].isin(set(picked))])

    if not draws:
        _fail("no strata found in the frame")
    sample = pd.concat(draws, ignore_index=True)
    sample = sample.sort_values(["stratum", "domain"]).reset_index(drop=True)
    if sample["domain"].duplicated().any():
        _fail("a domain was sampled twice")
    return sample[SAMPLE_COLUMNS]


def stratum_summary(frame: pd.DataFrame, sample: pd.DataFrame) -> list[dict]:
    """Per-stratum population / sample sizes, ordered by stratum name."""
    pop = frame["stratum"].value_counts().to_dict()
    taken = sample["stratum"].value_counts().to_dict()
    rows = []
    for name in sorted(stratum_types()):
        rows.append(
            {
                "stratum": name,
                "types_merged": stratum_types()[name],
                "floor_applies": name not in NO_FLOOR_STRATA,
                "population": int(pop.get(name, 0)),
                "sampled": int(taken.get(name, 0)),
            }
        )
    for name, expected in EXPECTED_STRATUM_POPULATIONS.items():
        if int(pop.get(name, 0)) != expected:
            _fail(f"stratum population drift for {name!r}: expected {expected}, got {pop.get(name)}")
    if len(rows) != EXPECTED_STRATA_COUNT:
        _fail(f"expected {EXPECTED_STRATA_COUNT} strata, built {len(rows)}")
    if sum(r["sampled"] for r in rows) != EXPECTED_TOTAL_SAMPLED:
        _fail(
            f"sample size drift. expected {EXPECTED_TOTAL_SAMPLED}, got {sum(r['sampled'] for r in rows)}"
        )
    return rows


def format_table(rows: list[dict]) -> str:
    """Human-readable stratum table for stdout."""
    head = f"{'Stratum':<22}{'Population':>11}{'Sampled':>9}{'Share':>8}  Raw types merged"
    line = "-" * len(head)
    out = [head, line]
    total_pop = sum(r["population"] for r in rows)
    total_samp = sum(r["sampled"] for r in rows)
    for r in rows:
        share = r["sampled"] / r["population"] if r["population"] else 0.0
        out.append(
            f"{r['stratum']:<22}{r['population']:>11,}{r['sampled']:>9,}{share:>7.1%}  "
            + ("; ".join(r["types_merged"]) if len(r["types_merged"]) > 1 else "(same)")
        )
    out.append(line)
    out.append(f"{'TOTAL':<22}{total_pop:>11,}{total_samp:>9,}{total_samp / total_pop:>7.1%}")
    return "\n".join(out)


# ---------------------------------------------------------------- outputs
def write_outputs(
    frame: pd.DataFrame,
    sample: pd.DataFrame,
    rows: list[dict],
    raw_bytes: bytes,
    downloaded_at_utc: str,
) -> dict:
    """Write frame_full.csv, pilot_sample.csv and frame_meta.json; return the meta."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # lineterminator="\n" keeps the digests stable across platforms and runs.
    frame.to_csv(FRAME_PATH, index=False, encoding="utf-8", lineterminator="\n")
    sample.to_csv(SAMPLE_PATH, index=False, encoding="utf-8", lineterminator="\n")

    # Re-read the cached registry only to record the exact per-type census.
    raw_counts = load_registry(REGISTRY_PATH)["Domain type"].value_counts().to_dict()
    counts = {str(k): int(v) for k, v in raw_counts.items()}
    total_rows = sum(counts.values())
    kept_types = {t: counts[t] for t in sorted(counts) if assign_stratum(t) is not None}
    excluded_types = {t: counts[t] for t in sorted(counts) if assign_stratum(t) is None}

    meta = {
        "source_url": CISA_REGISTRY_URL,
        "access_date": ACCESS_DATE,
        "downloaded_at_utc": downloaded_at_utc,
        "raw_sha256": sha256_bytes(raw_bytes),
        "raw_bytes": len(raw_bytes),
        "row_counts": {
            "registry_data_rows": total_rows,
            "federal_excluded": EXPECTED_FEDERAL_ROWS,
            "nonfederal_frame_rows": len(frame),
            "pilot_sample_rows": len(sample),
        },
        "random_seed": RANDOM_SEED,
        "stratum_floor": STRATUM_FLOOR,
        "no_floor_strata": sorted(NO_FLOOR_STRATA),
        "strata_spec": {
            r["stratum"]: {
                "types_merged": r["types_merged"],
                "floor_applies": r["floor_applies"],
                "population": r["population"],
                "sampled": r["sampled"],
            }
            for r in rows
        },
        "types_kept": kept_types,
        "types_excluded": excluded_types,
        "excluded_federal_note": (
            f"{EXPECTED_FEDERAL_ROWS} domains carry a federal Domain type "
            f"({', '.join(sorted(FEDERAL_TYPES))}) and are out of scope: the study "
            "measures patching by nonfederal U.S. government sites, whose operators "
            "are not under the same patch-management regime as federal agencies. "
            "Federal rows are dropped from the frame and never sampled."
        ),
        "outputs": {
            "frame_full_csv": str(FRAME_PATH),
            "frame_full_sha256": sha256_file(FRAME_PATH),
            "pilot_sample_csv": str(SAMPLE_PATH),
            "pilot_sample_sha256": sha256_file(SAMPLE_PATH),
            "frame_meta_json": str(META_PATH),
        },
        "contact_data_note": (
            "security_contact appears only in frame_full.csv under gitignored data/. "
            "It is held for a future, not-yet-approved notification experiment and is "
            "used for nothing in Stage 1."
        ),
        # Recorded because it is a registry quirk, not a bug: a large minority of
        # rows carry the literal placeholder text instead of an address, so any
        # later notification work must check for it before treating the column
        # as mailable. Values are passed through verbatim; nothing is normalised.
        "security_contact_census": {
            "address_shaped": int(frame["security_contact"].str.contains("@").sum()),
            "literal_placeholder": int(
                (frame["security_contact"] == PLACEHOLDER_CONTACT).sum()
            ),
            "distinct_addresses": int(
                frame.loc[frame["security_contact"].str.contains("@"), "security_contact"].nunique()
            ),
            "placeholder_token": PLACEHOLDER_CONTACT,
            "note": (
                "Nonfederal rows only. '(blank)' is CISA's own placeholder, not a "
                "parse error, and the address count is below the address-shaped count "
                "because registrants reuse addresses across domains."
            ),
        },
    }
    META_PATH.write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return meta


def derive_from_cache() -> tuple[pd.DataFrame, pd.DataFrame, list[dict], bytes]:
    """Load the cached registry, gate it, build the frame, redraw the sample."""
    raw_bytes = REGISTRY_PATH.read_bytes()
    df = load_registry(REGISTRY_PATH)
    assert_registry_shape(df)
    frame = build_frame(df)
    sample = draw_sample(frame)
    rows = stratum_summary(frame, sample)
    return frame, sample, rows, raw_bytes


def _existing_downloaded_at() -> str:
    """Reuse the download timestamp recorded at build time, if meta exists."""
    if META_PATH.exists():
        try:
            return json.loads(META_PATH.read_text(encoding="utf-8")).get(
                "downloaded_at_utc", "unknown"
            )
        except json.JSONDecodeError:
            return "unknown"
    return "unknown"


# ---------------------------------------------------------------- commands
def cmd_build(args: argparse.Namespace) -> int:
    """build: download (optionally) then write frame, sample and meta."""
    if args.skip_download:
        if not REGISTRY_PATH.exists():
            _fail(f"--skip-download but no cached registry at {REGISTRY_PATH}")
        print(f"reusing cached registry {REGISTRY_PATH}")
    else:
        download_registry(REGISTRY_PATH)

    frame, sample, rows, raw_bytes = derive_from_cache()
    downloaded_at = _existing_downloaded_at() if args.skip_download else utc_now_iso()
    if downloaded_at == "unknown":
        downloaded_at = utc_now_iso()
    meta = write_outputs(frame, sample, rows, raw_bytes, downloaded_at)

    print()
    print(f"registry rows       : {EXPECTED_ROWS:,}")
    print(f"federal excluded    : {meta['row_counts']['federal_excluded']:,}")
    print(f"nonfederal frame    : {len(frame):,}  -> {FRAME_PATH}")
    print(f"pilot sample        : {len(sample):,}  -> {SAMPLE_PATH}")
    print(f"seed                : {RANDOM_SEED}   floor: {STRATUM_FLOOR}")
    print(f"raw sha256          : {meta['raw_sha256']}")
    print(f"pilot csv sha256    : {meta['outputs']['pilot_sample_sha256']}")
    print()
    print(format_table(rows))
    print()
    print(f"meta -> {META_PATH}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """verify: re-derive from the cached raw copy, no network, compare on disk."""
    frame, sample, rows, raw_bytes = derive_from_cache()

    if not SAMPLE_PATH.exists():
        _fail(f"{SAMPLE_PATH} missing; run `build`")
    on_disk = SAMPLE_PATH.read_bytes()
    rederived = sample.to_csv(index=False, encoding="utf-8", lineterminator="\n").encode("utf-8")
    if on_disk != rederived:
        _fail(
            "re-derived pilot sample does not match pilot_sample.csv on disk "
            f"(disk sha256 {sha256_bytes(on_disk)[:16]}..., "
            f"re-derived {sha256_bytes(rederived)[:16]}...)"
        )
    if not FRAME_PATH.exists():
        _fail(f"{FRAME_PATH} missing; run `build`")
    disk_frame = pd.read_csv(FRAME_PATH, dtype=str, keep_default_na=False)
    if list(disk_frame.columns) != FRAME_COLUMNS:
        _fail(f"frame_full.csv header drift: {list(disk_frame.columns)}")
    if len(disk_frame) != len(frame):
        _fail(f"frame_full.csv row drift: {len(disk_frame)} on disk, {len(frame)} re-derived")
    if SAMPLE_PATH.exists() and "security_contact" in pd.read_csv(
        SAMPLE_PATH, nrows=0
    ).columns:
        _fail("pilot_sample.csv must not contain contact emails")

    print("verify: cached registry shape assertions passed")
    print(f"verify: pilot_sample.csv matches a fresh re-derivation "
          f"(sha256 {sha256_file(SAMPLE_PATH)})")
    print(format_table(rows))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point: `python src/frame.py build|verify`."""
    parser = argparse.ArgumentParser(
        prog="frame.py",
        description="Stage 1: CISA .gov domain frame + stratified pilot sample.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="download the registry and write outputs")
    p_build.add_argument(
        "--skip-download",
        action="store_true",
        help="reuse data/raw/current-full.csv instead of hitting the network",
    )
    p_build.set_defaults(func=cmd_build)

    p_verify = sub.add_parser(
        "verify", help="re-derive the frame/sample from the cached copy (no network)"
    )
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
