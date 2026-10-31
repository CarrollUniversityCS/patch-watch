"""Cohen's kappa for the KEV rater sheets: hand-checkable cases."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "kev_rater_kappa", Path(__file__).resolve().parent.parent / "scripts" / "kev_rater_kappa.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_known_value():
    a = {str(i): "A" for i in range(10)}
    b = dict(a)
    for i in range(2):
        b[str(i)] = "B"
    # 8/10 agree; shares A .8/.8? rater A all A: pe = 0 -> kappa 0 (agreement is all by chance)
    k, po, pe, n = m.kappa(a, b)
    assert (po, n) == (0.8, 10) and k == 0.0 and pe == 0.8


def test_perfect_and_opposed():
    a = {str(i): "ABC"[i % 3] for i in range(9)}
    assert m.kappa(a, dict(a))[0] == 1.0
    shifted = {k: "ABC"[("ABC".index(v) + 1) % 3] for k, v in a.items()}
    assert m.kappa(a, shifted)[0] == __import__("pytest").approx(-0.5)


def test_interval_contains_estimate():
    a = {str(i): "AB"[i % 2] for i in range(40)}
    b = {k: (v if int(k) % 5 else "C") for k, v in a.items()}
    k, po, pe, n = m.kappa(a, b)
    lo, hi = m.interval(k, po, pe, n)
    assert lo < k < hi
