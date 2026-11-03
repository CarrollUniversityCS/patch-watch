import datetime as dt
import json
import socket
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import kevwatch as kw  # noqa: E402


@pytest.fixture(autouse=True)
def forbid_socket_connect(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("CLI tests must not use a real network")

    monkeypatch.setattr(socket.socket, "connect", blocked)


def kev_entry(cve, vendor="Acme", product="Widget", added="2025-01-01", due="2025-01-22"):
    return {
        "cveID": cve,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": f"Test issue {cve}",
        "dateAdded": added,
        "dueDate": due,
        "knownRansomwareCampaignUse": "Unknown",
    }


def catalog(extra=(), count=500, version="fixture"):
    rows = [kev_entry(f"CVE-2025-{1000 + i}") for i in range(count)]
    rows.extend(extra)
    return json.dumps({
        "catalogVersion": version,
        "dateReleased": "2026-11-01T00:00:00Z",
        "vulnerabilities": rows,
    })


def invoke(tmp_path, text, *extra, fetch=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(text, encoding="utf-8")
    args = [
        "--kev", str(catalog_path),
        "--state", str(tmp_path / "state.json"),
        "--out-root", str(tmp_path),
        "--now", "2026-11-02T12:00:00Z",
        *extra,
    ]
    return kw.run(args, fetch=fetch)


def bootstrap(tmp_path, text=None):
    return invoke(tmp_path, text or catalog(), "--bootstrap")


def read_run(tmp_path):
    return json.loads((tmp_path / "last_run.json").read_text(encoding="utf-8"))


def test_no_state_without_bootstrap_is_refused(tmp_path):
    assert invoke(tmp_path, catalog()) == 5
    assert not (tmp_path / "state.json").exists()
    assert read_run(tmp_path)["exit_code"] == 5


def test_bootstrap_initializes_all_entries_once_without_packets(tmp_path):
    text = catalog()
    assert bootstrap(tmp_path, text) == 0
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert len(state["seen"]) == 500
    assert state["candidates"] == {}
    assert not (tmp_path / "docs" / "proposed" / "events").exists()
    assert read_run(tmp_path)["network_requests"] == 0
    assert invoke(tmp_path, text, "--bootstrap") == 5


def test_new_candidate_writes_one_packet_and_counts_enrichment_request(tmp_path):
    assert bootstrap(tmp_path) == 0
    new = kev_entry(
        "CVE-2026-109619",
        vendor="PHP Group",
        product="PHP",
        added="2026-10-26",
        due="2026-10-29",
    )
    text = catalog([new], version="next")

    def fetch(url, cache):
        assert url == kw.intake.record_urls("CVE-2026-109619")[0]
        return json.dumps({
            "containers": {
                "cna": {
                    "affected": [{"versions": [
                        {"status": "affected", "version": "8.2.*", "lessThan": "8.2.35"},
                    ]}]
                }
            }
        })

    assert invoke(tmp_path, text, fetch=fetch) == 0
    folders = list((tmp_path / "docs" / "proposed" / "events").iterdir())
    assert [folder.name for folder in folders] == ["2026-10-26_CVE-2026-109619"]
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert state["candidates"]["CVE-2026-109619"]["product_key"] == "php"
    assert read_run(tmp_path)["network_requests"] == 1
    assert len(read_run(tmp_path)["packets_written"]) == 2


def test_repeated_candidate_run_writes_no_duplicate_or_stamped_packet(tmp_path):
    assert bootstrap(tmp_path) == 0
    candidate = kev_entry(
        "CVE-2026-109619", "PHP Group", "PHP", "2026-10-26", "2026-10-29"
    )
    text = catalog([candidate], version="next")
    fetch = lambda *args: None
    assert invoke(tmp_path, text, "--no-enrich", fetch=fetch) == 0
    assert invoke(tmp_path, text, "--no-enrich", fetch=fetch) == 0
    folder = tmp_path / "docs" / "proposed" / "events" / "2026-10-26_CVE-2026-109619"
    assert sorted(path.name for path in folder.iterdir()) == ["packet.json", "packet.md"]


def test_phPMailer_is_only_a_near_miss(tmp_path):
    assert bootstrap(tmp_path) == 0
    text = catalog([kev_entry("CVE-2026-109620", "PHP", "PHPMailer")], version="next")
    assert invoke(tmp_path, text, "--no-enrich") == 0
    assert not (tmp_path / "docs" / "proposed" / "events").exists()
    record = read_run(tmp_path)
    assert record["near_misses"] == ["CVE-2026-109620"]
    assert record["near_miss_names"] == ["PHP / PHPMailer"]


def test_corrupt_state_is_refused_without_changing_state_bytes(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_bytes(b'{"schema": 2')
    before = state_path.read_bytes()
    assert invoke(tmp_path, catalog()) == 4
    assert state_path.read_bytes() == before


def test_feed_failures_increment_counter_without_changing_seen(tmp_path):
    assert bootstrap(tmp_path) == 0
    state_path = tmp_path / "state.json"
    original_seen = json.loads(state_path.read_text(encoding="utf-8"))["seen"]
    invalid = catalog(count=200)
    for attempt in range(1, 4):
        assert invoke(tmp_path, invalid) == 3
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert state["consecutive_failures"] == attempt
        assert state["seen"] == original_seen


def test_short_file_catalog_is_rejected_by_updated_b6_rule(tmp_path):
    text = catalog(count=200)
    assert invoke(tmp_path, text, "--bootstrap") == 3
    assert not (tmp_path / "state.json").exists()
    assert read_run(tmp_path)["errors"] == ["too few entries"]


def test_dry_run_does_not_change_state_or_write_packet(tmp_path):
    assert bootstrap(tmp_path) == 0
    state_path = tmp_path / "state.json"
    before = state_path.read_bytes()
    candidate = kev_entry(
        "CVE-2026-109619", "PHP Group", "PHP", "2026-10-26", "2026-10-29"
    )
    assert invoke(tmp_path, catalog([candidate]), "--dry", "--no-enrich") == 0
    assert state_path.read_bytes() == before
    assert not (tmp_path / "docs" / "proposed" / "events").exists()
    assert read_run(tmp_path)["mode"] == "dry"


def test_gate_a_environment_refuses_run(tmp_path, monkeypatch):
    assert bootstrap(tmp_path) == 0
    state_path = tmp_path / "state.json"
    before = state_path.read_bytes()
    monkeypatch.setenv("PATCHWATCH_GATE_A", "APPROVED")
    candidate = kev_entry(
        "CVE-2026-109619", "PHP Group", "PHP", "2026-10-26", "2026-10-29"
    )
    assert invoke(tmp_path, catalog([candidate]), "--no-enrich") == 5
    assert state_path.read_bytes() == before
    assert not (tmp_path / "docs" / "proposed" / "events").exists()
    assert read_run(tmp_path)["network_requests"] == 0


def test_crash_after_packet_does_not_create_duplicate_on_retry(tmp_path, monkeypatch):
    assert bootstrap(tmp_path) == 0
    candidate = kev_entry(
        "CVE-2026-109619", "PHP Group", "PHP", "2026-10-26", "2026-10-29"
    )
    text = catalog([candidate])
    real_save_state = kw.save_state

    def fail_save(*args, **kwargs):
        raise OSError("injected state failure")

    monkeypatch.setattr(kw, "save_state", fail_save)
    assert invoke(tmp_path, text, "--no-enrich") == 6
    folder = tmp_path / "docs" / "proposed" / "events" / "2026-10-26_CVE-2026-109619"
    assert (folder / "packet.md").exists()
    monkeypatch.setattr(kw, "save_state", real_save_state)
    assert invoke(tmp_path, text, "--no-enrich") == 0
    assert sorted(path.name for path in folder.iterdir()) == ["packet.json", "packet.md"]


def test_run_writes_only_packet_state_and_last_run_paths(tmp_path):
    assert bootstrap(tmp_path) == 0
    before = {path.resolve() for path in tmp_path.rglob("*") if path.is_file()}
    candidate = kev_entry(
        "CVE-2026-109619", "PHP Group", "PHP", "2026-10-26", "2026-10-29"
    )
    assert invoke(tmp_path, catalog([candidate]), "--no-enrich") == 0
    after = {path.resolve() for path in tmp_path.rglob("*") if path.is_file()}
    new_files = after - before
    events = (tmp_path / "docs" / "proposed" / "events").resolve()
    state_path = (tmp_path / "state.json").resolve()
    allowed = {
        state_path,
        state_path.with_suffix(".json.prev"),
        (tmp_path / "last_run.json").resolve(),
    }
    assert all(path in allowed or events in path.parents for path in new_files)


def test_db_is_read_only_and_no_row_domain_enters_packet(tmp_path):
    assert bootstrap(tmp_path) == 0
    db_path = tmp_path / "study.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE observations (snapshot_label TEXT, domain TEXT, started_at_utc TEXT, "
        "status_code INTEGER, headers_json TEXT)"
    )
    conn.executemany(
        "INSERT INTO observations VALUES (?, ?, ?, ?, ?)",
        [
            ("WI_20261031", f"private-domain-{i}", f"2026-10-31T14:0{i}:00Z", 200,
             json.dumps({"server": ["nginx/1.30.5"]}))
            for i in range(1, 4)
        ],
    )
    conn.commit()
    conn.close()
    before = db_path.read_bytes()
    candidate = kev_entry(
        "CVE-2026-109619", "F5", "NGINX", "2026-10-26", "2026-10-29"
    )
    assert invoke(tmp_path, catalog([candidate]), "--no-enrich", "--db", str(db_path)) == 0
    assert db_path.read_bytes() == before
    folder = tmp_path / "docs" / "proposed" / "events" / "2026-10-26_CVE-2026-109619"
    packet_text = (folder / "packet.md").read_text(encoding="utf-8")
    packet_text += (folder / "packet.json").read_text(encoding="utf-8")
    assert all(f"private-domain-{i}" not in packet_text for i in range(1, 4))


@pytest.mark.parametrize("headers_json", ["not json", "[]"])
def test_unreadable_headers_are_counted_and_do_not_block_packet(tmp_path, headers_json):
    assert bootstrap(tmp_path) == 0
    db_path = tmp_path / "study.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE observations (snapshot_label TEXT, domain TEXT, started_at_utc TEXT, "
        "status_code INTEGER, headers_json TEXT)"
    )
    conn.execute(
        "INSERT INTO observations VALUES (?, ?, ?, ?, ?)",
        ("WI_20261031", "must-not-appear.example", "2026-10-31T14:00:00Z", 200, headers_json),
    )
    conn.commit()
    conn.close()
    candidate = kev_entry("CVE-2026-109619", "F5", "NGINX", "2026-10-26", "2026-10-29")

    assert invoke(tmp_path, catalog([candidate]), "--no-enrich", "--db", str(db_path)) == 0
    folder = tmp_path / "docs" / "proposed" / "events" / "2026-10-26_CVE-2026-109619"
    packet_text = (folder / "packet.md").read_text(encoding="utf-8")
    assert '"unreadable": "<10"' in packet_text
    assert "must-not-appear.example" not in packet_text


def test_changed_candidate_due_date_writes_stamped_packet_and_updates_state(tmp_path):
    assert bootstrap(tmp_path) == 0
    first = kev_entry("CVE-2026-109619", "PHP Group", "PHP", "2026-10-26", "2026-10-29")
    assert invoke(tmp_path, catalog([first]), "--no-enrich") == 0
    updated = kev_entry("CVE-2026-109619", "PHP Group", "PHP", "2026-10-26", "2026-10-30")

    assert invoke(tmp_path, catalog([updated], version="due-updated"), "--no-enrich") == 0
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert state["candidates"]["CVE-2026-109619"]["due"] == "2026-10-30"
    folder = tmp_path / "docs" / "proposed" / "events" / "2026-10-26_CVE-2026-109619"
    stamped = list(folder.glob("packet.*.md"))
    assert len(stamped) == 1
    assert "Window: 4 days" in stamped[0].read_text(encoding="utf-8")


def test_clock_rollback_is_refused_without_changing_state(tmp_path):
    baseline = catalog()
    assert invoke(tmp_path, baseline, "--bootstrap", "--now", "2026-11-02T15:00:00Z") == 0
    assert invoke(tmp_path, baseline, "--now", "2026-11-02T15:00:00Z") == 0
    state_path = tmp_path / "state.json"
    before = state_path.read_bytes()
    assert invoke(tmp_path, baseline, "--now", "2026-10-31T15:00:00Z") == 5
    assert state_path.read_bytes() == before
    assert "refusing clock rollback" in read_run(tmp_path)["errors"][0]


def test_read_only_storage_failure_returns_six_without_state_mutation(tmp_path, monkeypatch, capsys):
    assert bootstrap(tmp_path) == 0
    state_path = tmp_path / "state.json"
    before = state_path.read_bytes()

    def deny_write(*args, **kwargs):
        raise PermissionError("read-only storage")

    monkeypatch.setattr(kw, "save_state", deny_write)
    monkeypatch.setattr(kw, "_write_json", deny_write)
    assert invoke(tmp_path, catalog()) == 6
    assert state_path.read_bytes() == before
    assert "read-only storage" in capsys.readouterr().err


def test_packet_bytes_are_deterministic_when_catalog_order_is_shuffled(tmp_path):
    candidate = kev_entry(
        "CVE-2026-109619", "PHP Group", "PHP", "2026-10-26", "2026-10-29"
    )
    updated_rows = json.loads(catalog([candidate], version="next"))["vulnerabilities"]
    shuffled = list(reversed(updated_rows))
    texts = [
        json.dumps({"catalogVersion": "next", "dateReleased": "2026-11-01T00:00:00Z",
                    "vulnerabilities": rows})
        for rows in (updated_rows, shuffled)
    ]
    roots = [tmp_path / "first", tmp_path / "second"]
    for root, text in zip(roots, texts):
        assert bootstrap(root) == 0
        assert invoke(root, text, "--no-enrich") == 0
    packet_dirs = [
        root / "docs" / "proposed" / "events" / "2026-10-26_CVE-2026-109619"
        for root in roots
    ]
    for filename in ("packet.md", "packet.json"):
        assert (packet_dirs[0] / filename).read_bytes() == (packet_dirs[1] / filename).read_bytes()


def test_live_collector_files_do_not_reference_watcher():
    for relative in (
        "src/config.py", "src/fetch.py", "src/pipeline.py", "src/classify.py", "src/versions.py",
        "scripts/live_day.py", "scripts/national_day.py", "scripts/run_snapshot.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "kevwatch" not in text and "kev_watch" not in text, relative


def test_intake_still_refuses_gov_hosts():
    assert kw.intake._host_ok("https://example.gov/a") is False


def test_bootstrap_records_a_success_time(tmp_path):
    assert bootstrap(tmp_path) == 0
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert state["last_attempt_utc"] == "2026-11-02T12:00:00Z"
    assert state["last_success_utc"] == "2026-11-02T12:00:00Z"
    assert state["consecutive_failures"] == 0
    assert state["last_error"] == ""


def test_status_check_accepts_a_fresh_bootstrap(tmp_path):
    assert bootstrap(tmp_path) == 0
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert state["last_success_utc"], "a bootstrap must leave a valid success time for the 06:45 check"
    assert dt.datetime.fromisoformat(state["last_success_utc"].replace("Z", "+00:00"))
