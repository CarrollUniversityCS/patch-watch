from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import kevwatch  # noqa: E402

raise SystemExit(kevwatch.run(sys.argv[1:]))
