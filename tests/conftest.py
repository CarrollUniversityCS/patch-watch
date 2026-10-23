"""pytest bootstrap: make `src/` importable as top-level modules.

The project deliberately uses flat imports (`from versions import ...`) so the
code can be run as `python src/run_snapshot.py` without packaging. This file is
the only glue tests need.
"""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# --------------------------------------------------------------------- mock rig
# tests/ itself must be importable so tests can `from mock_server import CASES`.
TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pytest  # noqa: E402

from mock_server import MockStack  # noqa: E402


@pytest.fixture(scope="session")
def mock_stack():
    """Session-wide MockStack: starts 8451/8452/8455, tears them down after."""
    stack = MockStack()
    stack.start()
    try:
        yield stack
    finally:
        stack.stop()

