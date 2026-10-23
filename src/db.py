"""Stage 4a: sqlite schema and persistence.

Five tables, per the brief: domains, runs, observations, request_ledger,
patch_events. The file lives in data/ which is gitignored (hard rule 7):
per-domain results never leave this machine.

The database is append-only for observations: a snapshot is evidence, and
re-running a snapshot must not silently overwrite the earlier reading. The
unique index on (run_id, domain) makes an accidental duplicate run fail loudly
instead of quietly replacing rows.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    domain          TEXT PRIMARY KEY,
    stratum         TEXT,
    domain_type     TEXT,
    state           TEXT,
    city            TEXT,
    organization    TEXT,
    first_seen_utc  TEXT,
    last_seen_utc   TEXT,
    current_class   TEXT,
    current_version TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    snapshot_label  TEXT,
    started_at_utc  TEXT,
    finished_at_utc TEXT,
    sample_size     INTEGER,
    attempted       INTEGER,
    responded       INTEGER,
    errors          INTEGER,
    sends           INTEGER,
    kill_switch     TEXT,
    user_agent      TEXT,
    config_json     TEXT,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS observations (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                 TEXT NOT NULL,
    snapshot_label         TEXT,
    domain                 TEXT NOT NULL,
    started_at_utc         TEXT,
    https_or_http          TEXT,
    requested_url          TEXT,
    final_url              TEXT,
    status_code            INTEGER,
    redirect_chain_json    TEXT,
    redirect_off_domain    INTEGER DEFAULT 0,
    resolved_ip            TEXT,
    headers_json           TEXT,
    headers_raw_json       TEXT,
    cert_error             INTEGER DEFAULT 0,
    error_type             TEXT,
    latency_ms             INTEGER,
    body_length_read       INTEGER,
    php_hints_json         TEXT,
    sends                  INTEGER,
    backoff                INTEGER DEFAULT 0,
    skipped_reason         TEXT,
    class                  TEXT,
    reason                 TEXT,
    php_version            TEXT,
    php_version_string     TEXT,
    php_version_source     TEXT,
    php_branch             TEXT,
    fixed_version          TEXT,
    at_or_above_fixed      INTEGER,
    distro_suffix          TEXT,
    distro_family          TEXT,
    php_evidence           INTEGER,
    php_evidence_features  TEXT,
    header_conflict        INTEGER DEFAULT 0,
    classify_detail_json   TEXT,
    created_at_utc         TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_domain_time ON observations(domain, started_at_utc);
CREATE INDEX IF NOT EXISTS idx_obs_run         ON observations(run_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_obs_run_domain ON observations(run_id, domain);

CREATE TABLE IF NOT EXISTS request_ledger (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT,
    ts_utc        TEXT,
    domain        TEXT,
    method        TEXT,
    url           TEXT,
    phase         TEXT,
    redirect_hop  INTEGER,
    status_code   INTEGER,
    error_type    TEXT
);
CREATE INDEX IF NOT EXISTS idx_ledger_run ON request_ledger(run_id);
CREATE INDEX IF NOT EXISTS idx_ledger_domain ON request_ledger(domain);

CREATE TABLE IF NOT EXISTS patch_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT,
    event_type      TEXT,
    detected_at_utc TEXT,
    from_class      TEXT,
    to_class        TEXT,
    from_version    TEXT,
    to_version      TEXT,
    from_run_id     TEXT,
    to_run_id       TEXT,
    detail_json     TEXT,
    UNIQUE(domain, event_type, from_run_id, to_run_id)
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

OBS_COLUMNS = (
    "run_id", "snapshot_label", "domain", "started_at_utc", "https_or_http", "requested_url",
    "final_url", "status_code", "redirect_chain_json", "redirect_off_domain", "resolved_ip",
    "headers_json", "headers_raw_json", "cert_error", "error_type", "latency_ms",
    "body_length_read", "php_hints_json", "sends", "backoff", "skipped_reason",
    "class", "reason", "php_version", "php_version_string", "php_version_source", "php_branch",
    "fixed_version", "at_or_above_fixed", "distro_suffix", "distro_family", "php_evidence",
    "php_evidence_features", "header_conflict", "classify_detail_json", "created_at_utc",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: Path | str) -> sqlite3.Connection:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    set_meta(conn, "schema_version", "1")


def set_meta(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def upsert_domains(conn: sqlite3.Connection, sample_rows: Iterable[dict[str, Any]]) -> int:
    n = 0
    for r in sample_rows:
        conn.execute(
            """INSERT INTO domains(domain, stratum, domain_type, state, city, organization)
               VALUES(:domain,:stratum,:domain_type,:state,:city,:organization)
               ON CONFLICT(domain) DO UPDATE SET
                 stratum=excluded.stratum, domain_type=excluded.domain_type,
                 state=excluded.state, city=excluded.city, organization=excluded.organization""",
            {"domain": r["domain"].strip().lower(), "stratum": r.get("stratum"),
             "domain_type": r.get("domain_type"), "state": r.get("state"),
             "city": r.get("city"), "organization": r.get("organization")})
        n += 1
    return n


def insert_run(conn: sqlite3.Connection, run: dict[str, Any]) -> None:
    conn.execute(
        """INSERT INTO runs(run_id, snapshot_label, started_at_utc, finished_at_utc, sample_size,
                            attempted, responded, errors, sends, kill_switch, user_agent,
                            config_json, notes)
           VALUES(:run_id,:snapshot_label,:started_at_utc,:finished_at_utc,:sample_size,:attempted,
                  :responded,:errors,:sends,:kill_switch,:user_agent,:config_json,:notes)
           ON CONFLICT(run_id) DO UPDATE SET finished_at_utc=excluded.finished_at_utc,
                  attempted=excluded.attempted, responded=excluded.responded, errors=excluded.errors,
                  sends=excluded.sends, kill_switch=excluded.kill_switch""",
        {k: run.get(k) for k in ("run_id", "snapshot_label", "started_at_utc", "finished_at_utc",
                                 "sample_size", "attempted", "responded", "errors", "sends",
                                 "kill_switch", "user_agent", "config_json", "notes")})


def insert_observation(conn: sqlite3.Connection, obs_row: dict[str, Any],
                       verdict: dict[str, Any]) -> None:
    row = dict(obs_row)
    row.update({
        "class": verdict["class"],
        "reason": verdict["reason"],
        "php_version": verdict["php_version"],
        "php_version_string": verdict["php_version_string"],
        "php_version_source": verdict["php_version_source"],
        "php_branch": verdict["php_branch"],
        "fixed_version": verdict["fixed_version"],
        "at_or_above_fixed": _boolint(verdict["at_or_above_fixed"]),
        "distro_suffix": verdict["distro_suffix"],
        "distro_family": verdict["distro_family"],
        "php_evidence": _boolint(verdict["php_evidence"]),
        "php_evidence_features": json.dumps(verdict["php_evidence_features"]),
        "header_conflict": _boolint(verdict["header_conflict"]),
        "classify_detail_json": json.dumps(verdict.get("classify_detail", verdict.get("classify_detail_json"))),
        "created_at_utc": utc_now_iso(),
    })
    cols = ", ".join(OBS_COLUMNS)
    marks = ", ".join(f":{c}" for c in OBS_COLUMNS)
    conn.execute(f"INSERT INTO observations({cols}) VALUES({marks})",
                 {c: row.get(c) for c in OBS_COLUMNS})
    conn.execute(
        """UPDATE domains SET current_class=:cls, current_version=:ver,
               last_seen_utc=:seen,
               first_seen_utc=COALESCE(first_seen_utc, :seen)
           WHERE domain=:dom""",
        {"cls": row["class"], "ver": row["php_version"], "seen": row["started_at_utc"],
         "dom": row["domain"]})


def _boolint(v: Any) -> int | None:
    if v is None:
        return None
    return 1 if v else 0


def insert_ledger(conn: sqlite3.Connection, rows: Iterable[dict[str, Any]]) -> int:
    n = 0
    for r in rows:
        conn.execute(
            """INSERT INTO request_ledger(run_id, ts_utc, domain, method, url, phase,
                                          redirect_hop, status_code, error_type)
               VALUES(:run_id,:ts_utc,:domain,:method,:url,:phase,:redirect_hop,:status_code,:error_type)""",
            {"run_id": r.get("run_id"), "ts_utc": r.get("ts_utc"), "domain": r.get("domain"),
             "method": r.get("method", "GET"), "url": r.get("url"), "phase": r.get("phase"),
             "redirect_hop": r.get("redirect_hop"), "status_code": r.get("status_code"),
             "error_type": r.get("error_type")})
        n += 1
    return n


def prior_observation(conn: sqlite3.Connection, domain: str, before_ts: str,
                      exclude_run_id: str | None = None) -> sqlite3.Row | None:
    q = """SELECT * FROM observations WHERE domain=? AND started_at_utc<?"""
    args: list[Any] = [domain, before_ts]
    if exclude_run_id:
        q += " AND run_id<>?"
        args.append(exclude_run_id)
    q += " ORDER BY started_at_utc DESC LIMIT 1"
    return conn.execute(q, args).fetchone()


def observation_history(conn: sqlite3.Connection, domain: str, limit: int = 10) -> list[sqlite3.Row]:
    rows = conn.execute(
        """SELECT * FROM observations WHERE domain=? ORDER BY started_at_utc DESC LIMIT ?""",
        (domain, limit)).fetchall()
    return list(reversed(rows))


def insert_events(conn: sqlite3.Connection, events: Iterable[dict[str, Any]]) -> int:
    n = 0
    for e in events:
        cur = conn.execute(
            """INSERT INTO patch_events(domain, event_type, detected_at_utc, from_class, to_class,
                                        from_version, to_version, from_run_id, to_run_id, detail_json)
               VALUES(:domain,:event_type,:detected_at_utc,:from_class,:to_class,:from_version,
                      :to_version,:from_run_id,:to_run_id,:detail_json)
               ON CONFLICT(domain, event_type, from_run_id, to_run_id) DO NOTHING""", e)
        n += cur.rowcount if cur.rowcount > 0 else 0
    return n


def snapshot_classes(conn: sqlite3.Connection, run_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT domain, class, php_version, distro_family, resolved_ip, final_url, status_code, "
        "error_type, cert_error, redirect_off_domain, header_conflict, sends "
        "FROM observations WHERE run_id=?", (run_id,)).fetchall()
