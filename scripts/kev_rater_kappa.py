"""Agreement between two raters on the KEV sample: Cohen's kappa, a 95% interval, tier shares.

    python -I scripts/kev_rater_kappa.py rater_a.csv rater_b.csv [docs/proposed/kev_rater_sample.csv]

Each rater file has columns cve,label with label in A, B or C. No network, no database.
The interval is the large-sample one for kappa (SE = sqrt(po(1-po) / (n (1-pe)^2))), which is
approximate; the table also prints the raw agreement so a reader can check it by hand.
The pass line in docs/EVALUATION.md (kappa >= 0.6, stable tier shares) is read, not changed, here.
"""
import csv
import math
import sys
from collections import Counter

LABELS = ("A", "B", "C")


def read(path):
    with open(path, newline="", encoding="utf-8") as f:
        out = {}
        for row in csv.DictReader(f):
            lab = (row.get("label") or "").strip().upper()
            if lab:
                if lab not in LABELS:
                    raise SystemExit(f"{path}: {row['cve']} has label {lab!r}; use A, B or C")
                out[row["cve"]] = lab
        return out


def kappa(a, b):
    """(kappa, po, pe, n) over the entries both raters labelled."""
    keys = sorted(set(a) & set(b))
    n = len(keys)
    if n == 0:
        raise SystemExit("no entries labelled by both raters")
    po = sum(a[k] == b[k] for k in keys) / n
    ca, cb = Counter(a[k] for k in keys), Counter(b[k] for k in keys)
    pe = sum(ca[x] * cb[x] for x in LABELS) / (n * n)
    k = 1.0 if pe == 1 else (po - pe) / (1 - pe)
    return k, po, pe, n


def interval(k, po, pe, n):
    if pe == 1:
        return k, k
    se = math.sqrt(po * (1 - po) / (n * (1 - pe) ** 2))
    return k - 1.96 * se, k + 1.96 * se


def main(argv):
    a, b = read(argv[1]), read(argv[2])
    k, po, pe, n = kappa(a, b)
    lo, hi = interval(k, po, pe, n)
    print(f"entries labelled by both: {n}   raw agreement: {po:.3f}   chance: {pe:.3f}")
    print(f"Cohen kappa {k:.3f}   95% interval {lo:.3f} to {hi:.3f}")
    for name, r in (("rater A", a), ("rater B", b)):
        c = Counter(r.values())
        print(f"{name} shares: " + "  ".join(f"{x} {c[x]/len(r):.0%}" for x in LABELS))
    if len(argv) > 3:
        with open(argv[3], newline="", encoding="utf-8") as f:
            kw = {r["cve"]: r["keyword_tier"][0] for r in csv.DictReader(f)}
        for name, r in (("A", a), ("B", b)):
            ks = sorted(set(r) & set(kw))
            print(f"rater {name} vs keyword tier: agreement {sum(r[x]==kw[x] for x in ks)/len(ks):.3f}")
    print("pass line (docs/EVALUATION.md): kappa >= 0.6 ->", "PASS" if k >= 0.6 else "MISS")


if __name__ == "__main__":
    main(sys.argv)
