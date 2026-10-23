"""Wisconsin frame rules (src/wi_frame.py), on a synthetic registry. No network."""

from __future__ import annotations

import pandas as pd
import pytest

import wi_frame
from frame import EXPECTED_HEADER


def registry(rows):
    return pd.DataFrame([dict(zip(EXPECTED_HEADER, r)) for r in rows], columns=EXPECTED_HEADER)


ROWS = [
    # domain, type, org, suborg, city, state, contact
    ("TownOfA.gov", "City", "Town of A", "", "A", "WI", "it@a.gov"),
    ("b.gov", "City", "WALWORTH, TOWN OF", "", "B", "WI", "(blank)"),
    ("c.gov", "City", "Township of Mecan", "", "C", "WI", ""),
    ("d.gov", "City", "DEWHURST TN OF WBS", "", "D", "WI", ""),
    ("e.gov", "City", "The Village of Sussex", "", "E", "WI", ""),
    ("f.gov", "City", "Potosi, Village of", "", "F", "WI", ""),
    ("g.gov", "City", "EAGLE RIVER, CITY OF", "", "G", "WI", ""),
    ("h.gov", "City", "Kenosha Police Department", "", "H", "WI", ""),
    ("i.gov", "City", "Hull in Portage County", "", "I", "WI", ""),
    ("j.gov", "County", "Dane County", "", "J", "WI", ""),
    ("j2.gov", "County", "Dane  County", "", "J", "WI", ""),          # same entity, odd spacing
    ("vote-j.gov", "County - Election", "Dane County", "", "J", "WI", ""),
    ("nation.gov", "Tribal", "A Nation", "", "K", "WI", ""),
    ("vote-nation.gov", "Tribal - Election", "A Nation", "", "K", "WI", ""),
    ("agency.gov", "Federal - Executive", "Agency", "", "L", "WI", ""),
    ("mn-city.gov", "City", "City of M", "", "M", "MN", ""),
    ("ca-city.gov", "City", "City of N", "", "N", "CA", ""),
]


def test_strata_follow_the_naming_rules():
    frame, _ = wi_frame.build_frame(registry(ROWS))
    got = dict(zip(frame["domain"], frame["stratum"]))
    assert got["townofa.gov"] == "Town"
    assert got["b.gov"] == "Town" and got["c.gov"] == "Town" and got["d.gov"] == "Town"
    assert got["e.gov"] == "Village" and got["f.gov"] == "Village"
    assert got["g.gov"] == "City"
    assert got["h.gov"] == wi_frame.MUNICIPAL_OTHER
    assert got["i.gov"] == "Town", "hand override"
    assert got["vote-j.gov"] == "Election office"


def test_tribal_and_federal_rows_are_excluded_and_only_counted():
    frame, excluded = wi_frame.build_frame(registry(ROWS))
    assert not frame["domain"].isin(["nation.gov", "vote-nation.gov", "agency.gov"]).any()
    assert excluded["tribal_nations_by_decision_D1"] == {"WI": 2}
    assert excluded["federal"] == {"WI": 1}


def test_only_wisconsin_without_comparison_flag():
    frame, _ = wi_frame.build_frame(registry(ROWS))
    assert set(frame["state"]) == {"WI"} and set(frame["region"]) == {"wisconsin"}


def test_comparison_states_are_tagged():
    frame, _ = wi_frame.build_frame(registry(ROWS), comparison=("MN",))
    assert frame.loc[frame["domain"] == "mn-city.gov", "region"].item() == "comparison"
    assert "ca-city.gov" not in set(frame["domain"])


def test_entity_id_merges_spacing_and_case_and_spans_domains():
    frame, _ = wi_frame.build_frame(registry(ROWS))
    ids = frame.set_index("domain")["entity_id"]
    assert ids["j.gov"] == ids["j2.gov"] == ids["vote-j.gov"] == "WI:dane county"


def test_no_contact_column_ever():
    frame, _ = wi_frame.build_frame(registry(ROWS))
    assert not any("contact" in c or "security" in c for c in frame.columns)


def test_header_drift_is_fatal():
    bad = registry(ROWS).rename(columns={"State": "St"})
    with pytest.raises(SystemExit):
        wi_frame.build_frame(bad)
