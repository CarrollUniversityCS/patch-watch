"""Cell-wise suppression is not enough for a nested funnel: two printed stages whose difference is 1 to 9 reveal a small count
(attempted 392 and reached 386 would show that 6 sites did not answer). The published funnel of every committed run must not
contain such a pair, and the checker must catch one."""

from __future__ import annotations

import sys
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import analyze  # noqa: E402
import dashboard  # noqa: E402
import versions  # noqa: E402


def small_differences(funnel: dict[str, str], below: int = analyze.SUPPRESS_BELOW) -> list[tuple[str, str, int]]:
    """Pairs of printed (digit) funnel stages whose difference is a small positive count."""
    shown = {k: int(v) for k, v in funnel.items() if str(v).isdigit()}
    return [(a, b, shown[a] - shown[b]) for a, b in combinations(shown, 2) if 0 < abs(shown[a] - shown[b]) < below
            for a, b in [(a, b) if shown[a] >= shown[b] else (b, a)]]


def test_the_checker_catches_a_small_difference_and_ignores_big_ones_and_hidden_cells():
    assert small_differences({"domains": "392", "reached": "386", "php": "97"}) == [("domains", "reached", 6)]
    assert small_differences({"domains": "833", "reached": "649", "php": "191", "visible": "43"}) == []
    assert small_differences({"domains": "392", "reached": "<10", "php": "§"}) == []


def test_no_committed_run_publishes_a_funnel_with_a_small_difference():
    runs = dashboard.load_runs()
    assert runs
    for run in runs:
        pt = dashboard.point(run, versions.PHP2SHELL, analyze.Suppressor())
        assert small_differences(pt["funnel"]) == [], (run["label"], pt["funnel"])
