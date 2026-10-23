#!/usr/bin/env python
"""The daily job, as a name you can put in a cron line.

All the logic is in src/pipeline.py; this wrapper exists so the scheduled command is
short, so that `run_snapshot.py --help` is discoverable, and so the cron entry does not
have to reach into src/. It adds one thing the library does not: a non-zero exit if the
run reports a safety problem, because cron notices exit codes and nobody reads the log
at 07:00.

Usage:
    python scripts/run_snapshot.py --label SNAP_A            # live (needs Gate A)
    python scripts/run_snapshot.py --mock --limit 20         # loopback rehearsal
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pipeline import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
