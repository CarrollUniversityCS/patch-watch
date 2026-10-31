"""Public wording never makes the claims docs/EVALUATION.md rules out: a first study, a national prevalence or estimate, or a
causal effect of the federal deadline or of a notification. A negated mention ("not a national estimate") is allowed."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ["README.md", "docs/project_page.md", "dashboard/template.html", "dashboard/index.html"]
BANNED = [r"\bfirst (ever )?(study|measurement|to measure)\b",
          r"\bnationally representative\b",
          r"(?<!not a )\bnational (prevalence|estimate)s?\b",
          r"\bdeadline (caused|effect)\b",
          r"\bbecause of the (federal )?deadline\b",
          r"\b(notification|notifying) (caused|improved|sped up)\b"]


def hits(text: str) -> list[str]:
    return [m.group(0) for pat in BANNED for m in re.finditer(pat, text, re.I)]


def test_public_text_makes_no_ruled_out_claim():
    for rel in PUBLIC:
        p = ROOT / rel
        if p.exists():
            assert not hits(p.read_text(encoding="utf-8")), (rel, hits(p.read_text(encoding="utf-8")))


def test_the_linter_catches_what_it_should_and_allows_negation():
    assert hits("This is the first study of government patching.")
    assert hits("A national estimate of patching.") and hits("the deadline caused faster patching")
    assert not hits("Other states (released in waves; not a national estimate)")
    assert not hits("The federal deadline falls inside the series; we do not claim an effect.")
