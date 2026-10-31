"""Wave assignment and the national day wrapper's refusals. Synthetic names only; nothing touches a network."""

import csv
import datetime as dt
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import national_day

import national


def master_rows():
    rows = []
    for state, n in {"AA": 40, "BB": 150, "CC": 600, "DD": 12, "EE": 3500}.items():
        for i in range(n):
            rows.append({"domain": f"d{i}-{state.lower()}.gov", "region": "expansion", "state": state, "stratum": "City",
                         "domain_type": "City", "organization": f"Org {i}", "entity_id": f"{state}:{i}", "city": ""})
    return rows


def test_waves_partition_every_name_once_and_are_deterministic():
    rows = master_rows()
    a, b = national.assign_waves(rows, 7), national.assign_waves(rows, 7)
    assert a == b
    assert sorted(r["domain"] for r in a) == sorted(r["domain"] for r in rows)
    counts = Counter(r["wave"] for r in a)
    assert counts["2"] == national.WAVE2_SIZE and counts["1"] <= 3 * national.PILOT_PER_STATE
    assert counts["1"] + counts["2"] + counts["3"] == len(rows)
    assert {r["region"] for r in a} == {"national"}
    assert national.assign_waves(rows, 8) != a                      # the seed matters


def test_the_pilot_draws_from_one_state_per_size_band_only():
    states = {r["state"] for r in national.assign_waves(master_rows(), 3) if r["wave"] == "1"}
    assert len(states) == 3 and states <= {"AA", "BB", "CC", "EE"} and "DD" not in states   # DD is under 30 names


def test_written_files_verify_and_any_edit_is_caught(tmp_path):
    master = tmp_path / "master.csv"
    rows = master_rows()
    with open(master, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    waves, meta = tmp_path / "w.csv", tmp_path / "m.json"
    national.write_waves(national.assign_waves(national.read_master(master), 5), 5, master, waves, meta)
    assert national.verify(master, waves, meta) == []
    waves.write_text(waves.read_text(encoding="utf-8").replace("wave", "wave", 1) + "extra.gov,national,ZZ,,,,,,1\n", encoding="utf-8")
    assert national.verify(master, waves, meta)
    master.write_text(master.read_text(encoding="utf-8") + "x.gov,expansion,ZZ,,,,,\n", encoding="utf-8")
    assert any("changed" in p for p in national.verify(master, waves, meta))


def test_the_sample_is_cumulative_and_only_released_waves_are_readable(tmp_path):
    waves = tmp_path / "w.csv"
    rows = national.assign_waves(master_rows(), 5)
    with open(waves, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=national.FIELDS)
        w.writeheader()
        w.writerows(rows)
    one = {r["domain"] for r in national.rows_through(1, waves)}
    two = {r["domain"] for r in national.rows_through(2, waves)}
    assert one < two and len(national.rows_through(3, waves)) == len(rows)
    with pytest.raises(ValueError):
        national.write_sample(4, tmp_path / "s.csv", waves)
    for text, expect in (("", 0), ("0", 0), ("2\n", 2), ("9", 0), ("x", 0)):
        f = tmp_path / "a.txt"
        f.write_text(text, encoding="utf-8")
        assert national.active_wave(f) == expect
    assert national.active_wave(tmp_path / "missing.txt") == 0


# ------------------------------------------------------------------ the day wrapper only ever refuses
class Day:
    """A snapshot day at 09:30 Chicago with every precondition met; each test breaks one."""

    def __init__(self, monkeypatch, tmp_path):
        self.mp, self.tmp = monkeypatch, tmp_path
        day = sorted(national_day.ld.SNAPSHOT_DAYS)[3]
        monkeypatch.setattr(national_day.ld, "now_local", lambda: dt.datetime.combine(day, dt.time(9, 30), national_day.ld.LOCAL_TZ))
        monkeypatch.setattr(national_day.ld, "ABUSE_FLAG", tmp_path / "abuse.flag")
        monkeypatch.setattr(national_day.ld, "stop_rule_met", lambda: "")
        monkeypatch.setattr(national_day.ld, "prior_run_for", lambda region, now: "")
        monkeypatch.setattr(national_day, "wisconsin_done_today", lambda now: True)
        monkeypatch.setattr(national_day, "national_halt_since_release", lambda: "")
        monkeypatch.setattr(national.__dict__["config"], "DATA_DIR", tmp_path)
        notice = tmp_path / "notice.txt"
        notice.write_text("2026-10-30 confirmed\n", encoding="utf-8")
        monkeypatch.setattr(national_day, "NOTICE_FLAG", notice)
        monkeypatch.setattr(national, "active_wave", lambda: 1)
        monkeypatch.setattr(national, "verify", list)
        self.calls = []
        monkeypatch.setattr(national_day.subprocess, "call", lambda cmd, cwd=None: self.calls.append(cmd) or 0)
        monkeypatch.setattr(national, "write_sample", lambda wave: tmp_path / f"s{wave}.csv")

    def run(self):
        try:
            return national_day.main(["national_day.py"])
        except SystemExit as exc:
            return exc.code


def test_with_everything_met_the_wrapper_runs_the_national_region_on_the_released_wave(monkeypatch, tmp_path):
    d = Day(monkeypatch, tmp_path)
    assert d.run() == 0 and len(d.calls) == 1
    assert "--region" in d.calls[0] and d.calls[0][d.calls[0].index("--region") + 1] == "national"
    assert d.calls[0][d.calls[0].index("--label") + 1].startswith("NAT_")


@pytest.mark.parametrize("breaker,code", [
    ("no_wave", national_day.EXIT_NOT_RELEASED), ("no_notice", national_day.EXIT_NO_NOTICE),
    ("bad_waves", national_day.EXIT_BAD_WAVES), ("wi_not_done", national_day.EXIT_WI_NOT_DONE),
    ("abuse", national_day.ld.EXIT_HALTED), ("already", national_day.ld.EXIT_ALREADY_RAN),
    ("stopped", national_day.ld.EXIT_STOP_RULE), ("late", national_day.ld.EXIT_TOO_LATE),
    ("halted", national_day.EXIT_NATIONAL_HALTED)])
def test_each_missing_precondition_refuses_and_sends_nothing(monkeypatch, tmp_path, breaker, code):
    d = Day(monkeypatch, tmp_path)
    if breaker == "no_wave":
        monkeypatch.setattr(national, "active_wave", lambda: 0)
    elif breaker == "no_notice":
        monkeypatch.setattr(national_day, "NOTICE_FLAG", tmp_path / "absent.txt")
    elif breaker == "bad_waves":
        monkeypatch.setattr(national, "verify", lambda: ["drift"])
    elif breaker == "wi_not_done":
        monkeypatch.setattr(national_day, "wisconsin_done_today", lambda now: False)
    elif breaker == "abuse":
        (tmp_path / "abuse.flag").write_text("x", encoding="utf-8")
    elif breaker == "already":
        monkeypatch.setattr(national_day.ld, "prior_run_for", lambda region, now: "run_id=x")
    elif breaker == "halted":
        monkeypatch.setattr(national_day, "national_halt_since_release", lambda: "R1 halted: overload")
    elif breaker == "stopped":
        monkeypatch.setattr(national_day.ld, "stop_rule_met", lambda: "nothing exposed")
    elif breaker == "late":
        day = sorted(national_day.ld.SNAPSHOT_DAYS)[3]
        monkeypatch.setattr(national_day.ld, "now_local",
                            lambda: dt.datetime.combine(day, dt.time(19, 30), national_day.ld.LOCAL_TZ))
    assert d.run() == code and d.calls == []


def test_a_day_that_is_not_a_snapshot_day_sends_nothing(monkeypatch, tmp_path):
    d = Day(monkeypatch, tmp_path)
    monkeypatch.setattr(national_day.ld, "now_local",
                        lambda: dt.datetime(2026, 11, 20, 9, 30, tzinfo=national_day.ld.LOCAL_TZ))
    assert d.run() == 0 and d.calls == []


# ------------------------------------------------------------------ the two-resolver rule
def test_names_the_second_resolver_does_not_confirm_are_left_out_of_the_sample(tmp_path):
    cross = tmp_path / "h.csv"
    cross.write_text("domain,resolver,ns_rcode,ns_count,ns_operators,a_rcode,a_answers,ad,servfail_cd,dnskey,checked_at_utc\n"
                     "ok.gov,google,noerror,2,x,noerror,1,0,,0,t\n"
                     "ok.gov,cloudflare,noerror,2,x,noerror,1,0,,0,t\n"
                     "bad.gov,google,noerror,2,x,servfail,0,0,,0,t\n"
                     "empty.gov,google,noerror,2,x,noerror,0,0,,0,t\n", encoding="utf-8")
    waves = tmp_path / "w.csv"
    rows = [{"domain": d, "region": "national", "state": "ZZ", "stratum": "City", "domain_type": "City", "organization": "",
             "entity_id": "", "city": "", "wave": "1"} for d in ("ok.gov", "bad.gov", "empty.gov", "silent.gov")]
    with open(waves, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=national.FIELDS)
        w.writeheader()
        w.writerows(rows)
    out = national.write_sample(1, tmp_path / "s.csv", waves, cross, tmp_path / "x.csv")
    kept = [r["domain"] for r in csv.DictReader(open(out, encoding="utf-8"))]
    assert kept == ["ok.gov"]
    assert {r["domain"] for r in csv.DictReader(open(tmp_path / "x.csv", encoding="utf-8"))} == {"bad.gov", "empty.gov", "silent.gov"}
    with pytest.raises(FileNotFoundError):
        national.write_sample(1, tmp_path / "s2.csv", waves, tmp_path / "missing.csv", tmp_path / "x2.csv")


# ------------------------------------------------------------------ the amendment is pinned like the plan
AMENDMENT_SHA256 = "12bc98293a0042e4ed2fd18288cbee4173ac83037d4af290fa709693616079e6"


def test_the_national_amendment_is_unchanged():
    """Amendment 1 is pre-registered. Changing it is a new dated amendment, not an edit; update this hash only then."""
    import hashlib
    path = Path(__file__).resolve().parent.parent / "docs" / "analysis_plan_amendment_national.md"
    text = path.read_bytes().decode("utf-8").replace(chr(13) + chr(10), chr(10))
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == AMENDMENT_SHA256


# ------------------------------------------------------------------ the dashboard and the schedule know the national arm
def test_the_dashboard_names_the_national_series_and_does_not_present_it_as_an_estimate():
    root = Path(__file__).resolve().parent.parent / "dashboard"
    for name in ("template.html", "index.html"):
        text = (root / name).read_text(encoding="utf-8")
        assert 'national: "Other states (released in waves; not a national estimate)"' in text, name


def test_the_national_task_repeats_until_the_cutoff_so_a_late_wisconsin_run_is_followed():
    script = (Path(__file__).resolve().parent.parent / "scripts" / "install_national_schedule.ps1").read_text(encoding="utf-8")
    assert "RepetitionInterval (New-TimeSpan -Minutes 30)" in script and "RepetitionDuration (New-TimeSpan -Hours 9)" in script
    assert national_day.ld.LATEST_START == dt.time(19, 0)           # 10:00 + 9 h; the wrapper refuses after this
