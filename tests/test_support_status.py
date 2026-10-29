"""src/support_status.py: support is judged by the dates in force on the day asked about."""

from __future__ import annotations

from datetime import date

import pytest

import support_status as ss


def test_snapshot_records_where_it_came_from():
    info = ss.snapshot_info()
    assert info["retrieved_on"] == "2026-10-29" and "endoflife.date" in info["source"]


def test_php_81_is_security_only_before_its_eol_and_end_of_life_after():
    assert ss.status("php", (8, 1), "2025-06-01") == ss.SECURITY_ONLY
    assert ss.status("php", (8, 1), "2025-12-30") == ss.SECURITY_ONLY
    assert ss.status("php", (8, 1), "2025-12-31") == ss.END_OF_LIFE
    assert ss.status("php", (8, 1), "2026-10-28") == ss.END_OF_LIFE


def test_old_snapshot_judged_by_its_own_date():
    # The same version string, two different answers: the point of an as-of date.
    assert ss.status("php", (8, 0, 30), "2023-06-01") != ss.END_OF_LIFE
    assert ss.status("php", (8, 0, 30), "2026-10-24") == ss.END_OF_LIFE


def test_php_82_changes_status_on_the_posted_dates():
    assert ss.status("php", (8, 2, 35), "2026-10-28") == ss.SECURITY_ONLY
    assert ss.status("php", (8, 2, 35), "2026-12-31") == ss.END_OF_LIFE


def test_current_php_is_supported():
    assert ss.status("php", (8, 5, 12), "2026-10-28") == ss.SUPPORTED


def test_branch_not_yet_released_is_unknown():
    assert ss.status("php", (8, 5), "2025-01-01") == ss.UNKNOWN


def test_branch_older_than_anything_tracked_is_end_of_life():
    assert ss.status("php", (4, 4, 9), "2026-10-28") == ss.END_OF_LIFE
    assert ss.status("apache", (1, 2, 0), "2026-10-28") == ss.END_OF_LIFE


def test_apache_24_supported_and_22_end_of_life():
    assert ss.status("apache", (2, 4, 58), "2026-10-28") == ss.SUPPORTED
    assert ss.status("apache", (2, 2, 34), "2026-10-28") == ss.END_OF_LIFE


def test_openssl_matches_the_three_part_cycle():
    assert ss.status("openssl", (1, 1, 1), "2026-10-28") == ss.END_OF_LIFE
    assert ss.status("openssl", (3, 0, 13), "2024-01-01") == ss.SUPPORTED


def test_nginx_branches():
    assert ss.status("nginx", (1, 31, 8), "2026-10-28") == ss.SUPPORTED
    assert ss.status("nginx", (1, 18, 0), "2026-10-28") == ss.END_OF_LIFE


def test_untracked_product_is_unknown():
    assert ss.status("iis", (10, 0), "2026-10-28") == ss.UNKNOWN
    assert ss.status("litespeed", (6, 0), "2026-10-28") == ss.UNKNOWN


@pytest.mark.parametrize("version,day", [(None, "2026-10-28"), ((), "2026-10-28"),
                                         ((8, 2), "not a date"), ((8, 2), None), ((8, 2), "")])
def test_missing_inputs_are_unknown_not_guessed(version, day):
    assert ss.status("php", version, day) == ss.UNKNOWN


def test_date_objects_are_accepted():
    assert ss.status("php", (8, 1), date(2026, 10, 28)) == ss.END_OF_LIFE


def test_eol_true_means_end_of_life():
    snap = {"products": {"x": {"cycles": [{"cycle": "1.0", "releaseDate": "2000-01-01", "eol": True}]}}}
    assert ss.status("x", (1, 0), "2026-01-01", snapshot=snap) == ss.END_OF_LIFE


def test_support_false_means_security_only():
    snap = {"products": {"x": {"cycles": [{"cycle": "1.0", "releaseDate": "2000-01-01",
                                           "eol": False, "support": False}]}}}
    assert ss.status("x", (1, 0), "2026-01-01", snapshot=snap) == ss.SECURITY_ONLY


def test_every_status_is_one_of_the_documented_values():
    for prod in ("php", "apache", "nginx", "openssl", "wordpress"):
        for v in ((1, 0), (2, 4), (8, 1), (9, 9), (3, 0, 1)):
            assert ss.status(prod, v, "2026-10-28") in ss.STATUSES
