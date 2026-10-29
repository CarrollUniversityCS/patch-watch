"""Is a release branch still supported, judged by the dates in force on a given day?

The question here is what share of version-disclosing sites run software its maker no longer
fixes. The answer depends on WHEN: PHP 8.1 was supported in 2025 and is not in
October 2026, so an old snapshot is judged by the calendar at its own date.

Data: `src/eol_snapshot.json`, a pinned copy of endoflife.date (retrieved once, with
the retrieval date and source inside). Nothing here makes a network request, and the
file is never refetched at runtime, so the same input always gives the same answer.

Statuses:
    supported       maintained, security fixes expected
    security_only   past active support, security fixes only (PHP's "support" date)
    end_of_life     no further fixes from the maker
    unknown         product not tracked, branch not in the table, or not yet released
IIS is not tracked: its number is the Windows Server release, which a header cannot date.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

SNAPSHOT_PATH = Path(__file__).resolve().parent / "eol_snapshot.json"

SUPPORTED = "supported"
SECURITY_ONLY = "security_only"
END_OF_LIFE = "end_of_life"
UNKNOWN = "unknown"
STATUSES = (SUPPORTED, SECURITY_ONLY, END_OF_LIFE, UNKNOWN)


@lru_cache(maxsize=4)
def load_snapshot(path: str | None = None) -> dict[str, Any]:
    return json.loads(Path(path or SNAPSHOT_PATH).read_text(encoding="utf-8"))


def _to_date(value: Any) -> date | None:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str) and len(value) >= 10:
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None
    return None


def _cycle_key(c: dict[str, Any]) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in str(c["cycle"]).split("."))
    except (ValueError, KeyError):
        return ()


def _find_cycle(cycles: list[dict[str, Any]], version: tuple[int, ...]) -> dict[str, Any] | None:
    """Longest matching cycle: OpenSSL has both '1.1.1' and '1.1.0'; PHP has '8.2'."""
    by_name = {str(c["cycle"]): c for c in cycles}
    for n in range(min(len(version), 3), 0, -1):
        hit = by_name.get(".".join(str(x) for x in version[:n]))
        if hit:
            return hit
    return None


def status(product: str, version: tuple[int, ...] | None, as_of: date | str,
           snapshot: dict[str, Any] | None = None) -> str:
    """Support status of `version` (a branch like (8, 2) or a release like (8, 2, 35))
    on the day `as_of`. Never guesses: anything it cannot place is 'unknown'."""
    snap = snapshot or load_snapshot()
    prod = snap.get("products", {}).get(product)
    day = _to_date(as_of)
    if not prod or not version or day is None:
        return UNKNOWN
    cycles = prod["cycles"]
    c = _find_cycle(cycles, tuple(version))
    if c is None:
        # Older than everything tracked: end of life if the oldest tracked cycle is.
        known = [(k, x) for x in cycles if (k := _cycle_key(x))]
        if not known:
            return UNKNOWN
        oldest_key, oldest = min(known)
        if tuple(version[:len(oldest_key)]) < oldest_key and _is_eol(oldest, day):
            return END_OF_LIFE
        return UNKNOWN
    released = _to_date(c.get("releaseDate"))
    if released and day < released:
        return UNKNOWN                    # the branch did not exist yet on that day
    if _is_eol(c, day):
        return END_OF_LIFE
    sup = c.get("support")
    if sup is False:
        return SECURITY_ONLY
    sup_day = _to_date(sup)
    if sup_day is not None and day >= sup_day:
        return SECURITY_ONLY
    return SUPPORTED


def _is_eol(cycle: dict[str, Any], day: date) -> bool:
    eol = cycle.get("eol")
    if eol is True:
        return True
    d = _to_date(eol)
    return d is not None and day >= d


def snapshot_info() -> dict[str, str]:
    s = load_snapshot()
    return {"retrieved_on": s.get("retrieved_on", ""), "source": s.get("source", "")}
