"""Live progress for whoever is looking at a run's console window.

The scheduled task redirects all output to logs/cron.out, so its window used to stay blank for minutes (on 2026-11-02 a
blank window was taken for a stale one and closed with Ctrl+C). This writes a short status line straight to the console
device instead, so cron.out still gets the full log.

Counts only: never a domain name, address or URL. Every write is best-effort: a missing console, a closed window or any
error makes this a no-op, and nothing here can raise into the crawler.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from typing import Any, Callable, TextIO


def open_console() -> TextIO | None:
    """The Windows console device, or None (no console, not Windows, under tests, or switched off)."""
    if os.environ.get("PATCHWATCH_NO_CONSOLE") or "pytest" in sys.modules or sys.platform != "win32":
        return None
    try:
        return open("CONOUT$", "w", encoding="utf-8", errors="replace")
    except OSError:
        return None


def _span(seconds: float) -> str:
    seconds = max(0, int(seconds))
    return f"{seconds // 60}m{seconds % 60:02d}s"


class ConsoleStatus:
    """One line every `every` seconds: sites done of the total, answered, errors, time, kill-switch state."""

    def __init__(self, name: str, total: int, stream: TextIO | None, *,
                 clock: Callable[[], float] = time.monotonic, every: float = 5.0):
        self.name, self.total, self.stream = name, max(0, int(total)), stream
        self.clock, self.every = clock, every
        self.started = clock()
        self.last_print: float | None = None
        self.done = self.answered = self.errors = self.skipped = 0
        self.kill: Any = None                      # the run's KillSwitch, set by the pipeline when known

    def _write(self, text: str) -> None:
        if self.stream is None:
            return
        try:
            self.stream.write(text + "\n")
            self.stream.flush()
        except Exception:                          # a closed window must never stop a run
            self.stream = None

    def kill_state(self) -> str:
        tripped = getattr(self.kill, "tripped", None)
        return "TRIPPED - the run is stopping" if tripped else "ok"

    def line(self) -> str:
        elapsed = self.clock() - self.started
        left = ""
        if 0 < self.done < self.total:
            left = f" | about {_span(elapsed / self.done * (self.total - self.done))} left"
        return (f"[{datetime.now():%H:%M:%S}] {self.name}: {self.done} of {self.total} sites done"
                f" | {self.answered} answered | {self.errors} errors | {_span(elapsed)} elapsed{left}"
                f" | kill switch {self.kill_state()}")

    def start(self) -> None:
        self._write(f"[{datetime.now():%H:%M:%S}] {self.name}: starting {self.total} sites. "
                    "Progress appears here every few seconds.")
        self.last_print = self.clock()

    def observation_done(self, obs: Any) -> None:
        """Called once per site when its fetch ends (obs is None when the fetch raised)."""
        try:
            self.done += 1
            if obs is None:
                self.errors += 1
            elif getattr(obs, "skipped_reason", None):
                self.skipped += 1
            elif getattr(obs, "status_code", None) is not None:
                self.answered += 1
            else:
                self.errors += 1
            now = self.clock()
            if self.done >= self.total or self.last_print is None or now - self.last_print >= self.every:
                self.last_print = now
                self._write(self.line())
        except Exception:
            pass

    def finish(self, note: str) -> None:
        self._write(f"[{datetime.now():%H:%M:%S}] {self.name}: {note} "
                    f"({self.done} of {self.total} sites, {self.answered} answered, {self.errors} errors, "
                    f"{_span(self.clock() - self.started)}).")
