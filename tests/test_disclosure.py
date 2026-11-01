"""Joint audit of the RQ0 tables: the solver is exact, the 2026-10-26 report as first printed leaked, the generator no longer does."""
import random
import sys
from itertools import product
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import analyze  # noqa: E402
import disclosure  # noqa: E402

# RQ0 blocks of reports/analysis_weekly_2026-10-26_php2shell.md as first committed (commit 57f7aa7). Public numbers.
LEAKED_COMPARISON = """### RQ0 - measurability (entities)

| point | day | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R20261024T140522Z_CMP_20261024 | 3.0 | 1821 | <10 | <10 | 0 | <10 | 189 | 288 | 1323 | 210 | 16 | 8% |

By stratum at the latest live point (`R20261024T140522Z_CMP_20261024`):

| stratum | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|
| City | 576 | <10 | <10 | 0 | <10 | 51 | 106 | 414 | 56 | <10 | § |
| County | 301 | <10 | 0 | 0 | <10 | 40 | 47 | 210 | 44 | <10 | § |
| Election office | 171 | <10 | 0 | 0 | 0 | § | 19 | 137 | 15 | <10 | § |
| Interstate | <10 | § | § | § | § | § | § | § | § | § | § |
| Municipal department/other | 44 | 0 | 0 | 0 | 0 | <10 | <10 | 37 | <10 | 0 | § |
| School district | <10 | § | § | § | § | § | § | § | § | § | § |
| Special district | 77 | 0 | 0 | 0 | <10 | <10 | 13 | 58 | <10 | <10 | § |
| State | 40 | 0 | 0 | 0 | 0 | 0 | <10 | § | 0 | 0 | – |
| Town | 437 | <10 | <10 | 0 | <10 | 65 | 54 | 308 | 75 | <10 | § |
| Village | 169 | 0 | 0 | 0 | 0 | 13 | 35 | 121 | 13 | 0 | 0% |
"""
LEAKED_WISCONSIN = """### RQ0 - measurability (entities)

| point | day | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R20261024T140014Z_WI_20261024 | 3.0 | 778 | <10 | § | 0 | 27 | 153 | 433 | 151 | 194 | 29 | 15% |
| R20261026T215239Z_WI_20261026 | 5.3 | 778 | 0 | 10 | 0 | 30 | 149 | 434 | 155 | 189 | 30 | 16% |

By stratum at the latest live point (`R20261026T215239Z_WI_20261026`):

| stratum | units | EXPOSED | EOL | AMBIGUOUS | PATCHED | OPAQUE | NO_PHP | UNREACHED | P | V | V/P |
|---|---|---|---|---|---|---|---|---|---|---|---|
| City | 116 | 0 | 0 | 0 | <10 | § | 56 | 35 | 25 | <10 | § |
| County | 56 | 0 | 0 | 0 | <10 | § | 29 | 16 | 11 | <10 | § |
| Election office | 50 | 0 | 0 | 0 | <10 | 13 | 23 | § | 16 | <10 | § |
| Municipal department/other | 15 | 0 | 0 | 0 | <10 | 0 | <10 | <10 | <10 | <10 | § |
| Special district | 20 | 0 | 0 | 0 | 0 | <10 | <10 | <10 | <10 | 0 | § |
| State | 10 | 0 | 0 | 0 | 0 | <10 | <10 | <10 | <10 | 0 | § |
| Town | 330 | 0 | <10 | 0 | § | 70 | 191 | 44 | 95 | 17 | 18% |
| Village | 181 | 0 | <10 | 0 | <10 | 32 | 110 | 33 | 38 | <10 | § |
"""
ROOT = Path(__file__).resolve().parent.parent


def test_solver_matches_brute_force_on_small_tables():
    rng = random.Random(3)
    for _ in range(60):
        R, C = rng.choice([(2, 2), (2, 3), (3, 2)])
        names = [f"x{i}_{j}" for i in range(R) for j in range(C)]
        dom = {n: [rng.choice([0, 1]), rng.choice([3, 5, 9])] for n in names}
        truth = {n: rng.randint(*dom[n]) for n in names}
        eqs = []
        for i in range(R):
            dom[f"r{i}"] = [sum(truth[f"x{i}_{j}"] for j in range(C))] * 2
            eqs.append({**{f"x{i}_{j}": 1 for j in range(C)}, f"r{i}": -1})
        for j in range(C):
            dom[f"c{j}"] = [sum(truth[f"x{i}_{j}"] for i in range(R))] * 2
            eqs.append({**{f"x{i}_{j}": 1 for i in range(R)}, f"c{j}": -1})
        sols = []
        for v in product(*[range(dom[n][0], dom[n][1] + 1) for n in names]):
            a = dict(zip(names, v))
            if all(sum(a[f"x{i}_{j}"] for j in range(C)) == dom[f"r{i}"][0] for i in range(R)) and                all(sum(a[f"x{i}_{j}"] for i in range(R)) == dom[f"c{j}"][0] for j in range(C)):
                sols.append(a)
        for n in names:
            assert disclosure.possible_values(dom, eqs, n) == sorted({s[n] for s in sols})


def test_the_report_as_first_printed_leaked():
    assert len(analyze.audit_rq0_text(LEAKED_COMPARISON)) >= 11
    assert len(analyze.audit_rq0_text(LEAKED_WISCONSIN)) >= 19


def test_the_committed_report_no_longer_leaks():
    text = (ROOT / "reports" / "analysis_weekly_2026-10-26_php2shell.md").read_text(encoding="utf-8")
    assert "correction 2026-10-31" in text
    assert analyze.audit_rq0_text(text) == []


def _fake_report(point_tokens, strata_tokens):
    head = "| point | day | " + " | ".join(["units", *analyze.STATES, "P", "V", "V/P"]) + " |"
    sep = "|" + "---|" * (len(analyze._RQ_COLS) + 3)
    lines = ["### RQ0 - measurability", "", head, sep, "| p1 | 1.0 | " + " | ".join(point_tokens) + " |", "",
             "| stratum | units | x |", sep]
    lines += ["| " + name + " | " + " | ".join(t) + " |" for name, t in strata_tokens.items()]
    return "\n".join(lines) + "\n\n### RQ1\n"


def test_joint_suppression_leaves_nothing_recoverable_and_never_changes_a_shown_number():
    rng = random.Random(11)
    sup = analyze.Suppressor()
    for _ in range(10):
        strata = {}
        for k in range(rng.randint(2, 5)):
            counts = {s: rng.choice([0, 0, 1, 2, 3, 6, 9, 10, 14, 25, 60]) for s in analyze.STATES}
            v = dict(counts)
            v["units"] = sum(counts.values())
            v["P"] = sum(counts[s] for s in analyze.P_STATES)
            v["V"] = sum(counts[s] for s in analyze.V_STATES)
            if v["units"]:
                strata[f"S{k}"] = v
        if not strata:
            continue
        point = {c: sum(v[c] for v in strata.values()) for c in analyze._RQ_COLS}
        pt, st = analyze._joint_rq0(point, strata, sup)
        assert analyze.audit_rq0_text(_fake_report(pt, st)) == []
        for toks, v in [(pt, point), *[(st[k], strata[k]) for k in strata]]:
            for tok, col in zip(toks, analyze._RQ_COLS):
                if tok.isdigit():
                    assert int(tok) == v[col]
