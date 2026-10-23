"""Who answers for a domain: host clusters by IP, and by ASN (plan §2, §7.5).

Small governments rarely patch their own servers; a hosting provider upgrades PHP
once and dozens of entities "react" at the same moment. The analysis therefore needs
to know which observations share a server. Two keys:

  * IP   - the resolved address recorded by the crawler (or the WARC-IP-Address of
           an archived capture). Exact, but a provider with many addresses looks like
           many clusters.
  * ASN  - the network the address belongs to, from a LOCAL copy of a public
           IP-to-ASN table (iptoasn.com's `ip2asn-v4.tsv.gz`: range_start, range_end,
           as_number, country, as_description). Coarser; used as a sensitivity check.

Nothing here makes a network request. AS descriptions name companies, so they stay in
the database and are never printed by the analysis (plan §8: no vendor is named).
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
from collections import Counter
from pathlib import Path
from typing import Iterable

import config

ASN_TABLE_PATH = config.DATA_DIR / "ip2asn-v4.tsv.gz"


class AsnTable:
    def __init__(self, ranges: list[tuple[int, int, int, str]]):
        self.ranges = sorted(ranges)
        self.starts = [r[0] for r in self.ranges]

    @classmethod
    def load(cls, path: Path | str = ASN_TABLE_PATH) -> "AsnTable":
        p = Path(path)
        opener = gzip.open if p.suffix == ".gz" else open
        ranges = []
        with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5:
                    continue
                try:
                    lo = int(ipaddress.IPv4Address(parts[0]))
                    hi = int(ipaddress.IPv4Address(parts[1]))
                    asn = int(parts[2])
                except ValueError:
                    continue
                if asn:
                    ranges.append((lo, hi, asn, parts[4]))
        return cls(ranges)

    def lookup(self, ip: str | None) -> int | None:
        if not ip:
            return None
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and self.ranges[i][0] <= n <= self.ranges[i][1]:
            return self.ranges[i][2]
        return None


def concentration(keys: Iterable[str | None]) -> dict[str, float | int]:
    """Cluster structure of one set of entities' hosts.

    `effective_independent` is 1 / sum(share^2): with 100 entities on 100 servers it
    is 100; with 100 entities on one server it is 1. Missing keys are left out.
    """
    counts = Counter(k for k in keys if k)
    total = sum(counts.values())
    if not total:
        return {"entities_with_host": 0, "clusters": 0, "largest_cluster": 0,
                "share_in_clusters_ge5": 0.0, "effective_independent": 0.0}
    hhi = sum((n / total) ** 2 for n in counts.values())
    return {
        "entities_with_host": total,
        "clusters": len(counts),
        "largest_cluster": max(counts.values()),
        "share_in_clusters_ge5": sum(n for n in counts.values() if n >= 5) / total,
        "effective_independent": 1.0 / hhi,
    }
