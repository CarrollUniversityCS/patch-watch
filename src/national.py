"""National extension: assign the validated expansion names to rollout waves, and hand one wave at a time to the crawler.

The extension (every state and DC outside Wisconsin and the four comparison states) is started in waves so that a
problem shows up on a few hundred sites before it can show up on ten thousand. Everything here is offline: it reads
data/master_frame.csv (built from CISA's public registry, names only, no contact data), writes
data/national_waves.csv plus data/national_waves_meta.json, and writes the one wave file a run is allowed to read.

    python src/national.py build [--seed N]   assign waves (deterministic for a seed) and write the files
    python src/national.py verify             recompute and compare with the written files
    python src/national.py show               sizes per wave and per state

Waves are cumulative: a run on wave-N day requests every name in waves 1..N. The active wave is a file
(data/national_active_wave.txt) that only the PI's go/no-go changes; scripts/national_day.py refuses without it.
The wave-N sample carries region "national" so pipeline.select_region and the ApprovedSet see only those names.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

import config

REGION = "national"
SOURCE_REGION = "expansion"                       # master_frame.csv region of states outside the running arms
MASTER_PATH = config.DATA_DIR / "master_frame.csv"
WAVES_PATH = config.DATA_DIR / "national_waves.csv"
META_PATH = config.DATA_DIR / "national_waves_meta.json"
ACTIVE_PATH = config.DATA_DIR / "national_active_wave.txt"
CROSSCHECK_PATH = config.DATA_DIR / "dns_hygiene.csv"        # the second resolver's answers (Google 8.8.8.8)
EXCLUDED_PATH = config.DATA_DIR / "national_excluded.csv"
DEFAULT_SEED = 20261030
PILOT_PER_STATE = 170                             # wave 1: about 500 names over three states of different size
PILOT_BANDS = ((30, 99), (100, 299), (300, 10**9))   # frame names per state: small, medium, large
WAVE2_SIZE = 3000
FIELDS = ["domain", "region", "state", "stratum", "domain_type", "organization", "entity_id", "city", "wave"]


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_master(path: Path = MASTER_PATH) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if r["region"] == SOURCE_REGION]


def assign_waves(rows: list[dict[str, str]], seed: int = DEFAULT_SEED) -> list[dict[str, str]]:
    """Wave 1: a seeded pilot (up to PILOT_PER_STATE random names from one state per size band).
    Wave 2: WAVE2_SIZE random names of the rest. Wave 3: everything else. Deterministic for a seed."""
    rng = random.Random(seed)
    by_state: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in sorted(rows, key=lambda r: r["domain"]):
        by_state[r["state"]].append(r)
    wave: dict[str, int] = {}
    for lo, hi in PILOT_BANDS:
        band = sorted(s for s, v in by_state.items() if lo <= len(v) <= hi)
        if not band:
            continue
        state = rng.choice(band)
        pool = list(by_state[state])
        rng.shuffle(pool)
        for r in pool[:PILOT_PER_STATE]:
            wave[r["domain"]] = 1
    rest = sorted(r["domain"] for r in rows if r["domain"] not in wave)
    rng.shuffle(rest)
    for d in rest[:WAVE2_SIZE]:
        wave[d] = 2
    out = []
    for r in sorted(rows, key=lambda r: (wave.get(r["domain"], 3), r["domain"])):
        out.append({**{k: r.get(k, "") for k in FIELDS if k not in ("region", "wave")},
                    "region": REGION, "wave": str(wave.get(r["domain"], 3))})
    return out


def write_waves(rows: list[dict[str, str]], seed: int, master: Path = MASTER_PATH,
                waves_path: Path = WAVES_PATH, meta_path: Path = META_PATH) -> dict:
    waves_path.parent.mkdir(parents=True, exist_ok=True)
    with open(waves_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    pilot_states = sorted({r["state"] for r in rows if r["wave"] == "1"})
    meta = {"seed": seed, "master_sha256": sha256(master), "waves_sha256": sha256(waves_path),
            "names": len(rows), "per_wave": dict(sorted(Counter(r["wave"] for r in rows).items())),
            "pilot_states": pilot_states, "pilot_per_state": PILOT_PER_STATE, "wave2_size": WAVE2_SIZE}
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


def verify(master: Path = MASTER_PATH, waves_path: Path = WAVES_PATH, meta_path: Path = META_PATH) -> list[str]:
    """Problems with the written wave files; empty means they re-derive exactly from the master list."""
    problems: list[str] = []
    if not (waves_path.exists() and meta_path.exists() and master.exists()):
        return ["master list, wave file or wave metadata is missing"]
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if sha256(master) != meta["master_sha256"]:
        problems.append("master_frame.csv changed after the waves were assigned")
    if sha256(waves_path) != meta["waves_sha256"]:
        problems.append("national_waves.csv does not match its recorded hash")
    fresh = assign_waves(read_master(master), int(meta["seed"]))
    with open(waves_path, newline="", encoding="utf-8") as fh:
        have = list(csv.DictReader(fh))
    if [(r["domain"], r["wave"]) for r in fresh] != [(r["domain"], r["wave"]) for r in have]:
        problems.append("wave assignment does not re-derive from the master list and seed")
    if any(r["region"] != REGION for r in have):
        problems.append("a wave row is not in region 'national'")
    return problems


def active_wave(path: Path = ACTIVE_PATH) -> int:
    """The highest wave the PI has released; 0 when none (the file is absent, empty or not a number)."""
    try:
        n = int(Path(path).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0
    return n if 0 <= n <= 3 else 0


def rows_through(wave: int, waves_path: Path = WAVES_PATH) -> list[dict[str, str]]:
    """Every name of waves 1..wave (cumulative), as sample rows."""
    with open(waves_path, newline="", encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if int(r["wave"]) <= wave]


def resolver_disagreements(path: Path = CROSSCHECK_PATH, resolver: str = "google") -> set[str]:
    """Names the second resolver does not confirm: no successful answer with an address. The study's name check
    needs the campus resolver AND this one to agree; a name they disagree on is recorded 'not measured' and never
    requested. Raises if the cross-check file is missing, so the rule cannot be skipped by accident."""
    if not Path(path).exists():
        raise FileNotFoundError(f"resolver cross-check file {path} is missing; the two-resolver rule cannot be applied")
    confirmed: dict[str, bool] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["resolver"] == resolver:
                confirmed[r["domain"]] = r["a_rcode"] == "noerror" and int(r["a_answers"] or 0) >= 1
    return {d for d, ok in confirmed.items() if not ok}


def write_sample(wave: int, dest: Path | None = None, waves_path: Path = WAVES_PATH,
                 crosscheck: Path = CROSSCHECK_PATH, excluded_path: Path = EXCLUDED_PATH) -> Path:
    """The one sample file a national run reads: the cumulative names of waves 1..wave, region 'national',
    minus any name the two resolvers disagree about or the second resolver never answered for."""
    if wave not in (1, 2, 3):
        raise ValueError(f"no such wave: {wave}")
    dest = Path(dest or (config.DATA_DIR / f"national_sample_w{wave}.csv"))
    rows = rows_through(wave, waves_path)
    bad = resolver_disagreements(crosscheck)
    answered = set()
    with open(crosscheck, newline="", encoding="utf-8") as fh:
        answered = {r["domain"] for r in csv.DictReader(fh) if r["resolver"] == "google"}
    drop = {r["domain"] for r in rows if r["domain"] in bad or r["domain"] not in answered}
    with open(excluded_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["domain", "reason"])
        w.writerows((d, "second resolver does not confirm" if d in bad else "second resolver has no answer") for d in sorted(drop))
    with open(dest, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(r for r in rows if r["domain"] not in drop)
    return dest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="national.py", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--seed", type=int, default=DEFAULT_SEED)
    sub.add_parser("verify")
    sub.add_parser("show")
    args = ap.parse_args(argv)
    if args.cmd == "build":
        meta = write_waves(assign_waves(read_master(), args.seed), args.seed)
        print(json.dumps(meta, indent=2))
        return 0
    if args.cmd == "verify":
        probs = verify()
        print("verify: OK" if not probs else "verify problems:\n  - " + "\n  - ".join(probs))
        return 0 if not probs else 1
    with open(WAVES_PATH, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    print("per wave:", dict(sorted(Counter(r["wave"] for r in rows).items())))
    print("wave 1 by state:", dict(Counter(r["state"] for r in rows if r["wave"] == "1")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
