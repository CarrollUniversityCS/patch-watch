"""The two scheduled .cmd files: Gate A, regions and the runner line stay as they are; the banner is there; CRLF on Windows.

Nothing guarded live_day.cmd before 2026-11-02 (its own comment said so). A .cmd with LF endings is misparsed by cmd.exe,
which once ran fragments of comment lines as commands (2026-10-30).
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = {
    "live_day.cmd": b'".venv\\Scripts\\python.exe" -X utf8 "scripts\\live_day.py" %1 >> "logs\\cron.out" 2>&1',
    "national_day.cmd": b'".venv\\Scripts\\python.exe" -X utf8 "scripts\\national_day.py" >> "logs\\cron.out" 2>&1',
}


def text(name: str) -> bytes:
    return (ROOT / "scripts" / name).read_bytes().replace(b"\r\n", b"\n")


@pytest.mark.parametrize("name", sorted(FILES))
def test_gate_a_line_is_present_exactly_once(name):
    assert text(name).count(b'\nset "PATCHWATCH_GATE_A=APPROVED"\n') == 1


def test_wisconsin_only_region_line_is_kept():
    assert text("live_day.cmd").count(b'\nset "PATCHWATCH_REGIONS=wisconsin"\n') == 1


@pytest.mark.parametrize("name", sorted(FILES))
def test_runner_line_and_exit_code_pass_through(name):
    t = text(name)
    assert t.count(b"\n" + FILES[name] + b'\nset "PW_RC=%errorlevel%"\n') == 1
    assert t.rstrip().endswith(b"exit /b %PW_RC%")
    assert b'cd /d "%~dp0.." || exit /b 9\n' in t


@pytest.mark.parametrize("name", sorted(FILES))
def test_banner_tells_the_person_at_the_window_what_is_running(name):
    t = text(name)
    assert b"\ntitle patch-watch LIVE snapshot" in t
    assert b"Do NOT close it or press Ctrl+C" in t
    assert b"logs\\cron.out" in t
    # the banner comes before the runner line, so it shows before the run starts
    assert t.index(b"Do NOT close it") < t.index(FILES[name])


@pytest.mark.skipif(sys.platform != "win32", reason="the working-tree line endings are CRLF only on Windows checkouts")
@pytest.mark.parametrize("name", sorted(FILES))
def test_crlf_on_windows(name):
    raw = (ROOT / "scripts" / name).read_bytes()
    assert raw.count(b"\r\n") == raw.count(b"\n") > 0
