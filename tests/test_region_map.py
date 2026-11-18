import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import region_map as rm  # noqa: E402


def test_division_map_covers_every_state_once():
    rm.check_division_map()


def test_bands_and_rounding():
    assert [rm.issue_band(n) for n in (0, 9, 10, 24, 25, 99)] == ["under 10", "under 10", "10 to 24", "10 to 24", "25 or more", "25 or more"]
    assert rm.round_sites(2976) == 3000 and rm.round_sites(49) == 0


def test_summary_publishes_bands_only_and_zero_reads_as_under_10():
    rows = [("WI", "VULNERABLE_BY_VERSION", 19), ("WI", "NO_PHP_EVIDENCE", 1502), ("CA", "NO_PHP_EVIDENCE", 1162),
            ("NY", "EOL_UNFIXED", 32), ("TX", "VULNERABLE_BY_VERSION", 6)]
    m = rm.summarise(rows, "2026-11-18")
    text = json.dumps(m)
    rm.validate(m)
    by = {r["region"]: r for r in m["regions"]}
    assert by["Midwest"]["issues"] == "10 to 24" and by["Northeast"]["issues"] == "25 or more"
    pac = [d for d in by["West"]["divisions"] if d["division"] == "Pacific"][0]
    assert pac["issues"] == "under 10"                      # a true zero is shown as under 10
    assert '"19"' not in text and ": 19" not in text and ": 32" not in text   # no exact issue counts
    assert not any(k in text for k in ("WI", "CA", "NY", "TX"))   # no state codes


def test_validate_refuses_exact_counts():
    m = rm.summarise([("WI", "VULNERABLE_BY_VERSION", 19)], "2026-11-18")
    m["regions"][0]["issues"] = "13"
    with pytest.raises(ValueError):
        rm.validate(m)
    m = rm.summarise([("WI", "VULNERABLE_BY_VERSION", 19)], "2026-11-18")
    m["regions"][0]["sites_observed"] = 2976
    with pytest.raises(ValueError):
        rm.validate(m)
