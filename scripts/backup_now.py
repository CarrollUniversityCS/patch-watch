"""Backup step from docs/HERMES_RUNBOOK.md section 5.4, Windows form.

The runbook writes this step with the `sqlite3` CLI, which is not installed on this host,
so the same three operations are done with the standard-library sqlite3 module:

  1. a consistent snapshot copy of data/study.db into backups/study_<stamp>.db
     (the online-backup API, the programmatic equivalent of `.backup`),
  2. PRAGMA integrity_check on the copy, which must print ok,
  3. copies of data/ledger_*.csv, data/wi_frame.csv, data/wi_frame_meta.json,
     blocklist.local.txt and logs/optouts.md into backups/.

Section 2.7 forbids deleting, moving or overwriting anything under data/ or backups/, so
this script only ever creates files that are not already there, never prunes, and never
opens the source database for writing.

The second copy goes to the runbook's [BACKUP_DIR]. That placeholder is still unfilled in
docs/HERMES_RUNBOOK.md, so this script will NOT invent a destination: it reads the
environment variable PATCHWATCH_BACKUP_DIR and, if it is unset, reports the second copy as
skipped and exits 3 so the caller's status message says so out loud.

Run:  .venv\\Scripts\\python.exe -X utf8 scripts\\backup_now.py
"""
from __future__ import annotations

import datetime as dt
import os
import shutil
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "data"
BACKUPS = REPO / "backups"
SRC_DB = DATA / "study.db"
EXTRA = [
    DATA / "wi_frame.csv",
    DATA / "wi_frame_meta.json",
    REPO / "blocklist.local.txt",
    REPO / "logs" / "optouts.md",
]


def copy_new(src: Path, dest: Path, done: list[str], skipped: list[str]) -> None:
    """Copy src -> dest only if dest does not already exist (section 2.7: never overwrite)."""
    if dest.exists():
        skipped.append(f"{dest.name} (already in backups/, left untouched)")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    done.append(f"{dest.name} ({dest.stat().st_size:,} bytes)")


def main() -> int:
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M")
    BACKUPS.mkdir(parents=True, exist_ok=True)
    print(f"backup {stamp}: target {BACKUPS}")

    # 1 + 2: consistent database snapshot and integrity check.
    integrity = "no database yet"
    if SRC_DB.exists():
        snap = BACKUPS / f"study_{stamp}.db"
        if snap.exists():
            print(f"  study_{stamp}.db already exists, not overwritten (2.7)")
        else:
            src = sqlite3.connect(f"file:{SRC_DB.as_posix()}?mode=ro", uri=True)
            try:
                dst = sqlite3.connect(snap)
                try:
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
            print(f"  snapshot: {snap.name} ({snap.stat().st_size:,} bytes)")
        check = sqlite3.connect(f"file:{snap.as_posix()}?mode=ro", uri=True)
        try:
            integrity = "\n".join(
                str(r[0]) for r in check.execute("PRAGMA integrity_check")
            ) or "(no output)"
        finally:
            check.close()
        print(f"  integrity_check: {integrity}")
        if integrity != "ok":
            print("  INTEGRITY FAILURE - message Jack before doing anything else (5.4).")
            return 2
    else:
        print(f"  {SRC_DB.name} does not exist yet: no live run has happened, "
              "so there is no database to snapshot. Files below are still backed up.")

    # 3: ledgers and frame, exactly the runbook's list.
    done: list[str] = []
    skipped: list[str] = []
    for src in sorted(DATA.glob("ledger_*.csv")) + EXTRA:
        if src.is_file():
            copy_new(src, BACKUPS / src.name, done, skipped)
    for name in done:
        print(f"  copied  {name}")
    for name in skipped:
        print(f"  kept    {name}")

    # second copy off this disk, only if Jack has named the destination
    dest = os.environ.get("PATCHWATCH_BACKUP_DIR", "").strip()
    if not dest:
        print("  SECOND COPY SKIPPED: [BACKUP_DIR] is still a placeholder in the runbook "
              "and PATCHWATCH_BACKUP_DIR is unset. Jack must choose the off-disk location.")
        rc = 3
    else:
        dest_dir = Path(dest) / "backups"
        dest_dir.mkdir(parents=True, exist_ok=True)
        off_done: list[str] = []
        off_skip: list[str] = []
        for src in sorted(BACKUPS.iterdir()):
            if src.is_file():
                copy_new(src, dest_dir / src.name, off_done, off_skip)
        print(f"  second copy -> {dest_dir}: {len(off_done)} new, {len(off_skip)} already there")
        rc = 0

    print(f"backup done: integrity={integrity!r} new={len(done)} kept={len(skipped)} rc={rc}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
