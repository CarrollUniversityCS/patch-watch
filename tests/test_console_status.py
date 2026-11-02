"""Console progress for the live task window: counts only, rate-limited, and never able to affect a run."""

import asyncio
import csv
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import config  # noqa: E402
import console_status as cs  # noqa: E402
import fetch  # noqa: E402
import pipeline  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class Obs:
    def __init__(self, status_code=None, error_type=None, skipped_reason=None):
        self.status_code, self.error_type, self.skipped_reason = status_code, error_type, skipped_reason


def test_first_update_then_rate_limited_then_last_site_always_printed():
    out, clock = io.StringIO(), Clock()
    s = cs.ConsoleStatus("wisconsin WI_TEST", 4, out, clock=clock, every=5.0)
    s.start()
    clock.t = 1
    s.observation_done(Obs(200))                    # within 5 s of start: no line
    clock.t = 6
    s.observation_done(Obs(None, "timeout"))        # 5 s later: a line
    clock.t = 7
    s.observation_done(Obs(skipped_reason="blocklisted"))   # too soon: no line
    clock.t = 8
    s.observation_done(None)                        # the last site: always a line
    lines = out.getvalue().splitlines()
    assert lines[0].endswith("wisconsin WI_TEST: starting 4 sites. Progress appears here every few seconds.")
    assert "2 of 4 sites done | 1 answered | 1 errors" in lines[1] and "left" in lines[1]
    assert "4 of 4 sites done | 1 answered | 2 errors" in lines[2]
    assert len(lines) == 3
    assert s.skipped == 1


def test_finish_line_and_kill_switch_state():
    out, clock = io.StringIO(), Clock()
    s = cs.ConsoleStatus("national NAT_TEST", 2, out, clock=clock)

    class Kill:
        tripped = "overload"

    s.kill = Kill()
    s.observation_done(Obs(200))
    assert "kill switch TRIPPED" in out.getvalue()
    clock.t = 125
    s.finish("Finished")
    assert out.getvalue().splitlines()[-1].endswith("Finished (1 of 2 sites, 1 answered, 0 errors, 2m05s).")


def test_a_broken_stream_never_raises_and_goes_quiet():
    class Broken:
        def write(self, _):
            raise OSError("window closed")

        def flush(self):
            pass

    s = cs.ConsoleStatus("x", 3, Broken())
    s.start()
    s.observation_done(Obs(200))
    s.finish("Finished")
    assert s.stream is None and s.done == 1


def test_no_stream_is_a_no_op():
    s = cs.ConsoleStatus("x", 1, None)
    s.start()
    s.observation_done(Obs(200))
    s.finish("Finished")
    assert s.done == 1


def test_console_is_never_opened_under_tests():
    assert cs.open_console() is None


def test_fetch_many_reports_every_domain_once_even_when_a_fetch_raises():
    crawler = fetch.Crawler(["a.example", "b.example", "c.example"], run_id="r", snapshot_label="s")
    seen = []

    async def fake_fetch(domain):
        if domain == "b.example":
            raise RuntimeError("boom")
        return fetch.Observation(domain=domain, run_id="r", snapshot_label="s", started_at_utc="t", status_code=200)

    crawler.fetch = fake_fetch
    crawler.on_domain_done = seen.append
    out = asyncio.run(crawler.fetch_many(["a.example", "b.example", "c.example"]))
    assert len(seen) == 3 and seen.count(None) == 1
    assert [o.domain for o in out] == ["a.example", "b.example", "c.example"]
    assert out[1].error_type == "crawler_error: RuntimeError"


def test_a_failing_progress_callback_does_not_change_the_results():
    crawler = fetch.Crawler(["a.example"], run_id="r", snapshot_label="s")

    async def fake_fetch(domain):
        return fetch.Observation(domain=domain, run_id="r", snapshot_label="s", started_at_utc="t", status_code=200)

    def bad(_):
        raise ValueError("display broke")

    crawler.fetch = fake_fetch
    crawler.on_domain_done = bad
    out = asyncio.run(crawler.fetch_many(["a.example"]))
    assert out[0].status_code == 200 and out[0].error_type is None


def _frame(path, n):
    cols = ["domain", "region", "state", "stratum", "domain_type", "organization", "entity_id", "city"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for i in range(n):
            w.writerow({"domain": f"wi{i}.example", "region": "wisconsin", "state": "WI", "stratum": "City",
                        "domain_type": "City", "organization": f"Org {i}", "entity_id": f"WI:org {i}", "city": "X"})


def test_mock_run_end_to_end_prints_counts_and_no_domain(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ABUSE_FLAG_PATH", tmp_path / "abuse.flag")
    for name in ("REPORTS_DIR", "DATA_DIR", "LOGS_DIR"):     # a mock run writes a report, a ledger CSV and a log
        monkeypatch.setattr(config, name, tmp_path / name.lower())
    frame = tmp_path / "f.csv"
    _frame(frame, 6)
    out = io.StringIO()
    s = pipeline.run_snapshot(sample_path=frame, db_path=tmp_path / "s.db", mock=True, region="wisconsin",
                              snapshot_label="WI_MOCK", quiet=True, progress=True, progress_stream=out)
    text = out.getvalue()
    lines = text.splitlines()
    assert "wisconsin WI_MOCK: starting 6 sites" in lines[0]
    assert "6 of 6 sites done" in text
    assert lines[-1].split("] ", 1)[1].startswith("wisconsin WI_MOCK: Finished (6 of 6 sites")
    assert "example" not in text and "127.0.0.1" not in text
    assert s["domains"] == 6


def test_progress_off_by_default_for_library_callers(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ABUSE_FLAG_PATH", tmp_path / "abuse.flag")
    for name in ("REPORTS_DIR", "DATA_DIR", "LOGS_DIR"):     # a mock run writes a report, a ledger CSV and a log
        monkeypatch.setattr(config, name, tmp_path / name.lower())
    frame = tmp_path / "f.csv"
    _frame(frame, 2)
    opened = []
    monkeypatch.setattr(cs, "open_console", lambda: opened.append(1))
    pipeline.run_snapshot(sample_path=frame, db_path=tmp_path / "s.db", mock=True, region="wisconsin", quiet=True)
    assert opened == []
