"""Exact joint audit of published count tables.

A table whose rows are suppressed one at a time can still leak when its rows add up to a printed margin: the hidden cells
are then tied together by equations, and a short chain of subtractions (or an integer solver) recovers some of them
(found 2026-10-31 in the RQ0 stratum table; see docs/hermes/T7b_lean_followups.md). This module is the check and nothing else.

A table is a set of integer variables with bounds, and linear equations in which every coefficient is +1 or -1.
`pinned` returns the variables whose value is the same in EVERY integer solution, which is exactly what an attacker who sees
the printed table can recover. The search is exact (bounds propagation plus depth-first search). If it runs out of its node
budget the answer for that variable is "undecided"; callers that are choosing what to hide treat undecided as pinned, so a
failure to decide can only cause more suppression, never less. A `hint` (the true values, known to whoever prints the table)
only changes the order in which values are tried; it never changes an answer.

Pure standard library, no network, no database.
"""

from __future__ import annotations

BIG = 100_000                      # stands in for "no upper bound" on a withheld count
DEFAULT_NODES = 2_000


class AuditBudgetExceeded(RuntimeError):
    pass


Domain = dict[str, list[int]]
Equation = dict[str, int]          # variable -> +1 or -1, meaning the signed sum is 0


def _propagate(dom: Domain, eqs: list[Equation]) -> bool:
    """Tighten every bound that the equations force. False when some domain becomes empty."""
    changed = True
    while changed:
        changed = False
        for eq in eqs:
            tot_lo = tot_hi = 0
            for k, a in eq.items():
                lo, hi = dom[k]
                tot_lo += a * lo if a > 0 else a * hi
                tot_hi += a * hi if a > 0 else a * lo
            if tot_lo > 0 or tot_hi < 0:
                return False
            for k, a in eq.items():
                lo, hi = dom[k]
                own_lo, own_hi = (a * lo, a * hi) if a > 0 else (a * hi, a * lo)
                rest_lo, rest_hi = tot_lo - own_lo, tot_hi - own_hi
                # a * x = -(rest), so a * x lies in [-rest_hi, -rest_lo]
                nlo, nhi = (-rest_hi, -rest_lo) if a > 0 else (rest_lo, rest_hi)
                nlo, nhi = max(lo, nlo), min(hi, nhi)
                if nlo > nhi:
                    return False
                if (nlo, nhi) != (lo, hi):
                    dom[k] = [nlo, nhi]
                    changed = True
                    own_lo, own_hi = (a * nlo, a * nhi) if a > 0 else (a * nhi, a * nlo)
                    old_lo, old_hi = (a * lo, a * hi) if a > 0 else (a * hi, a * lo)
                    tot_lo += own_lo - old_lo
                    tot_hi += own_hi - old_hi
    return True


def _order(lo: int, hi: int, prefer: int | None):
    if prefer is None or not lo <= prefer <= hi:
        return range(lo, hi + 1)
    return sorted(range(lo, hi + 1), key=lambda v: abs(v - prefer))


def _feasible(dom: Domain, eqs: list[Equation], budget: list[int], hint: dict[str, int] | None) -> bool:
    if not _propagate(dom, eqs):
        return False
    free = [(hi - lo, k) for k, (lo, hi) in dom.items() if hi > lo]
    if not free:
        return True
    budget[0] -= 1
    if budget[0] < 0:
        raise AuditBudgetExceeded("integer audit exceeded its node budget")
    _, k = min(free)
    lo, hi = dom[k]
    for v in _order(lo, hi, hint.get(k) if hint else None):
        nxt = {n: list(b) for n, b in dom.items()}
        nxt[k] = [v, v]
        if _feasible(nxt, eqs, budget, hint):
            return True
    return False


def possible_values(dom: Domain, eqs: list[Equation], name: str, nodes: int = DEFAULT_NODES,
                    hint: dict[str, int] | None = None) -> list[int]:
    """Every value `name` takes in some integer solution (the domain of `name` must be small)."""
    start = {n: list(b) for n, b in dom.items()}
    if not _propagate(start, eqs):
        raise ValueError("the printed table is inconsistent")
    lo, hi = start[name]
    budget = [nodes]
    out = []
    for v in range(lo, hi + 1):
        trial = {n: list(b) for n, b in start.items()}
        trial[name] = [v, v]
        if _feasible(trial, eqs, budget, hint):
            out.append(v)
    return out


def classify(dom: Domain, eqs: list[Equation], names: list[str], nodes: int = DEFAULT_NODES,
             hint: dict[str, int] | None = None) -> tuple[list[str], list[str]]:
    """(forced, undecided) among `names`.

    forced: every integer solution gives the variable the same value. undecided: the node budget ran out before a second
    value was found or ruled out. With a `hint` (the true values) only the two neighbours of the true value are tried,
    which can call a variable forced when it is not (more suppression, never less) but is fast; without a hint every
    value in the propagated domain is tried, which is exact."""
    forced: list[str] = []
    undecided: list[str] = []
    start = {n: list(b) for n, b in dom.items()}
    if not _propagate(start, eqs):
        raise ValueError("the printed table is inconsistent")
    for n in names:
        lo, hi = start[n]
        if lo == hi:
            forced.append(n)
            continue
        if hint is not None and n in hint:
            truth = hint[n]
            cands = [v for v in (truth + 1, truth - 1) if lo <= v <= hi]
        else:
            cands = list(range(lo, hi + 1))
        budget = [nodes]
        found, open_ = 0, False
        for v in cands:
            trial = {m: list(b) for m, b in start.items()}
            trial[n] = [v, v]
            try:
                ok = _feasible(trial, eqs, budget, hint)
            except AuditBudgetExceeded:
                open_ = True
                break
            if ok:
                found += 1
                if hint is not None:
                    break
                if found >= 2:
                    break
        if hint is not None:
            if found == 0:
                (undecided if open_ else forced).append(n)
        else:
            if found + (1 if open_ else 0) <= 1 and not open_:
                forced.append(n)
            elif open_ and found < 2:
                undecided.append(n)
    return forced, undecided


def pinned(dom: Domain, eqs: list[Equation], names: list[str], nodes: int = DEFAULT_NODES,
           hint: dict[str, int] | None = None) -> list[str]:
    """Names to treat as recoverable: forced, plus any the audit could not decide (fail closed)."""
    forced, undecided = classify(dom, eqs, names, nodes, hint)
    return forced + undecided
