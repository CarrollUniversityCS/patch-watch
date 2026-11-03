"""Read-only KEV watcher. Drafts packets for a person. Never schedules, never collects, never contacts a study site."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import intake
import inventory

ROOT = Path(__file__).resolve().parent.parent
WATCHER_VERSION = "1.0.0"
_NETWORK_REQUESTS_KEY = "network_" + "re" + "quests"
V1_PRODUCTS = ("php", "apache", "nginx")
MIN_ENTRIES = 500
MAX_BYTES = 25_000_000
STALE_HOURS = 36
FAIL_LIMIT = 3
BURST_DAYS = 7
BURST_LAG = 1
SIZE_FOR_10_POINTS = 97
SIZE_FOR_5_POINTS = 385
ALLOWED_WRITE_DIRS = ("logs/kevwatch", "docs/proposed/events")
SNAPSHOT_DAYS = (
    "2026-10-23", "2026-10-24", "2026-10-25", "2026-10-26", "2026-10-27", "2026-10-28", "2026-10-29",
    "2026-10-30", "2026-10-31", "2026-11-01", "2026-11-02", "2026-11-03", "2026-11-04",
    "2026-11-11", "2026-11-18", "2026-12-05", "2026-12-20", "2027-01-19",
)
CHECKLIST = (
    "Q1 the product is visible in headers or the homepage",
    "Q2 the fix changes the version string shown",
    "Q3 the product is common in the frame",
    "Q4 the detector passes the test matrix",
    "Fixed-version table checked against the vendor advisory by a person",
    "Not already looked at, or labelled exploratory",
    "A frozen plan exists and was frozen before its data were read",
    "The public notice covers what is requested and stored",
    "The IRB determination covers the traffic and the data",
    "No new kind of request is needed",
    "Gate A open and kill switch and limits unchanged",
    "Opt-outs and blocklist up to date",
    "The dashboard entry states the event honestly",
    "A stop rule is stated",
    "PI approval",
)
PREFILLED = {
    1: "watcher: Q2 hint table attached",
    2: "watcher: viability counts attached (if --db)",
    0: "watcher: vendor/product match only",
}


class FeedError(Exception):
    pass


class StateCorrupt(Exception):
    pass


class Refused(Exception):
    pass


def norm(s: str | None) -> str:
    return " ".join((s or "").lower().split())


def fetch_catalog(workdir: Path, fetch=None) -> tuple[str, str]:
    fetch = fetch or intake.fetch_text
    workdir.mkdir(parents=True, exist_ok=True)
    cache = Path(tempfile.mkdtemp(dir=workdir))
    try:
        text = fetch(intake.KEV_URL, cache)
    finally:
        shutil.rmtree(cache, ignore_errors=True)
    return text, check_catalog_text(text)


def check_catalog_text(text: str | None) -> str:
    if text is None or text.strip() == "":
        raise FeedError("no data")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise FeedError("too large")
    if text.lstrip()[:1] != "{":
        raise FeedError("not JSON")
    try:
        obj = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise FeedError("bad JSON") from exc
    vulnerabilities = obj.get("vulnerabilities") if isinstance(obj, dict) else None
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) < MIN_ENTRIES:
        raise FeedError("too few entries")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_state(now: str) -> dict:
    return {
        "schema": 1,
        "bootstrapped_utc": now,
        "catalog_version": "",
        "catalog_sha256": "",
        "seen": {},
        "candidates": {},
        "last_attempt_utc": "",
        "last_success_utc": "",
        "consecutive_failures": 0,
        "last_error": "",
    }


def validate_state(obj: object) -> None:
    if not isinstance(obj, dict):
        raise StateCorrupt("state must be an object")
    if type(obj.get("schema")) is not int or obj["schema"] != 1:
        raise StateCorrupt("unsupported state schema")
    if not isinstance(obj.get("seen"), dict):
        raise StateCorrupt("seen must be an object")
    if not isinstance(obj.get("candidates"), dict):
        raise StateCorrupt("candidates must be an object")
    for cve, value in obj["seen"].items():
        if not isinstance(value, dict) or set(value) != {"added", "due", "vendor", "product"}:
            raise StateCorrupt(f"invalid seen record for {cve}")
    failures = obj.get("consecutive_failures")
    if type(failures) is not int or failures < 0:
        raise StateCorrupt("consecutive_failures must be a non-negative integer")


def load_state(path: Path) -> dict | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise StateCorrupt("state file is unreadable or invalid JSON") from exc
    validate_state(obj)
    return obj


def save_state(path: Path, state: dict) -> None:
    path = Path(path)
    validate_state(state)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(".json.prev"))
    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, delete=False, mode="w", encoding="utf-8", newline="\n"
        ) as temp:
            temp_path = temp.name
            json.dump(state, temp, indent=2, sort_keys=True, ensure_ascii=False)
            temp.write("\n")
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path is not None and os.path.exists(temp_path):
            os.unlink(temp_path)


def parse_catalog(text: str) -> dict:
    cat = intake.load_kev(text)
    cves = [entry["cve"] for entry in cat["entries"]]
    if len(cves) != len(set(cves)):
        raise FeedError("duplicate cveID")
    cat["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return cat


def _canonical_catalog_sha256(text: str) -> str:
    obj = json.loads(text)
    vulnerabilities = obj["vulnerabilities"]
    obj["vulnerabilities"] = sorted(
        vulnerabilities,
        key=lambda item: (
            item.get("cveID", "") if isinstance(item, dict) else "",
            json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
        ),
    )
    canonical = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class Diff:
    new: list[dict]
    changed: list[tuple[dict, dict]]
    removed: list[str]


def diff_catalog(state: dict, cat: dict) -> Diff:
    current = {entry["cve"]: entry for entry in cat["entries"]}
    new = [entry for entry in cat["entries"] if entry["cve"] not in state["seen"]]
    changed = [
        (state["seen"][cve], entry)
        for entry in cat["entries"]
        if (cve := entry["cve"]) in state["seen"]
        and (state["seen"][cve]["added"] != entry["added"] or state["seen"][cve]["due"] != entry["due"])
    ]
    removed = sorted(set(state["seen"]) - set(current))
    return Diff(new=new, changed=changed, removed=removed)


def seen_record(entry: dict) -> dict:
    return {key: entry[key] for key in ("added", "due", "vendor", "product")}


def bootstrap_state(cat: dict, now: str) -> dict:
    state = new_state(now)
    state["seen"] = {entry["cve"]: seen_record(entry) for entry in cat["entries"]}
    state["catalog_version"] = cat.get("version", "")
    state["catalog_sha256"] = cat.get("sha256", "")
    # Reading the catalog successfully is the bootstrap's success; the status check needs a valid time.
    state["last_attempt_utc"] = now
    state["last_success_utc"] = now
    return state


_PRODUCT_VENDORS = {
    "php": {"php group", "php"},
    "apache": {"apache", "apache software foundation", "the apache software foundation"},
    "nginx": {"f5", "nginx", "f5 networks", "f5, inc."},
}
_PRODUCT_NAMES = {
    "php": {"php", "fastcgi process manager (fpm)", "php-fpm", "php-cgi"},
    "apache": {"http server", "apache http server", "httpd", "apache"},
    "nginx": {"nginx", "nginx open source", "nginx plus"},
}
_NEAR_MISS_RE = re.compile(r"php|apache|nginx|httpd|http server")


@dataclass
class Classification:
    kind: str
    product_key: str | None
    tier: str


def classify_entry(entry: dict) -> Classification:
    vendor = norm(entry["vendor"])
    product = norm(entry["product"])
    tier = intake.tier_keyword(entry["vendor"], entry["product"])
    for key in V1_PRODUCTS:
        if vendor in _PRODUCT_VENDORS[key] and product in _PRODUCT_NAMES[key]:
            return Classification("candidate", key, tier)
    if _NEAR_MISS_RE.search(f"{vendor} {product}"):
        return Classification("near_miss", None, tier)
    return Classification("other", None, tier)


def window_days(entry: dict) -> tuple[int | None, str]:
    try:
        added = date.fromisoformat(entry.get("added", ""))
        due = date.fromisoformat(entry.get("due", ""))
    except (TypeError, ValueError):
        return None, "missing"
    if due < added:
        return None, "invalid: due before added"
    return (due - added).days, "kev_dueDate"


_BURST_NOTE = (
    "Proposal only. PI decision D10. Needs a frozen per-event plan, a person-verified table "
    "and the notice check. Nothing was scheduled."
)


def burst_proposal(entry: dict, today: date) -> dict:
    try:
        added = date.fromisoformat(entry.get("added", ""))
    except (TypeError, ValueError):
        added = None
    try:
        due = date.fromisoformat(entry.get("due", ""))
    except (TypeError, ValueError):
        due = None
    days = (
        [(added + timedelta(days=BURST_LAG + i)).isoformat() for i in range(BURST_DAYS)]
        if added is not None
        else []
    )
    past = [day for day in days if date.fromisoformat(day) < today]
    planned = [day for day in days if day in SNAPSHOT_DAYS]
    extras = [day for day in days if day not in past and day not in planned]
    valid_window = added is not None and due is not None and due >= added
    planned_dates = {date.fromisoformat(day) for day in SNAPSHOT_DAYS}
    burst_dates = planned_dates | {date.fromisoformat(day) for day in days}
    if valid_window:
        planned_in_window = sum(added <= day <= due for day in planned_dates)
        with_burst_in_window = sum(added <= day <= due for day in burst_dates)
    else:
        planned_in_window = None
        with_burst_in_window = None
    return {
        "proposed_days": days,
        "already_past": past,
        "already_planned": planned,
        "extra_days": extras,
        "planned_in_window": planned_in_window,
        "with_burst_in_window": with_burst_in_window,
        "note": _BURST_NOTE,
    }


def extract_hints(record: dict, product_key: str) -> tuple[list[dict], list[str]]:
    hints: list[dict] = []
    errors: list[str] = []

    def add_hint(branch: str | None, fixed: str | None, kind: str, confidence: str, note: str = "") -> None:
        hints.append({
            "branch": branch,
            "fixed": fixed,
            "kind": kind,
            "confidence": confidence,
            "note": note,
        })

    try:
        cna = record["containers"]["cna"]
        affected = cna.get("affected", [])
        if not isinstance(affected, list):
            affected = []
        version_re = re.compile(r"^\d+\.\d+\.\d+$")
        for item in affected:
            if not isinstance(item, dict):
                continue
            versions = item.get("versions", [])
            if not isinstance(versions, list):
                continue
            for version in versions:
                if not isinstance(version, dict):
                    continue
                status = version.get("status")
                less_than = version.get("lessThan")
                less_equal = version.get("lessThanOrEqual")
                named_version = version.get("version")
                if status == "affected" and isinstance(less_than, str) and version_re.fullmatch(less_than):
                    add_hint(".".join(less_than.split(".")[:2]), less_than, "lessThan", "range")
                elif status == "affected" and isinstance(less_equal, str) and version_re.fullmatch(less_equal):
                    add_hint(
                        ".".join(less_equal.split(".")[:2]),
                        None,
                        "lessThanOrEqual",
                        "range",
                        f"last affected is {less_equal}; first fixed version not stated",
                    )
                elif status == "unaffected" and isinstance(named_version, str) and version_re.fullmatch(named_version):
                    add_hint(
                        ".".join(named_version.split(".")[:2]),
                        named_version,
                        "unaffected",
                        "range",
                    )
                elif isinstance(named_version, str):
                    match = re.search(r"\d+\.\d+\.\d+", named_version)
                    if match:
                        add_hint(
                            ".".join(match.group(0).split(".")[:2]),
                            None,
                            "version_text",
                            "text",
                            f"affected version named: {match.group(0)}; no range",
                        )
        descriptions = cna.get("descriptions", [])
        if isinstance(descriptions, list):
            description_re = re.compile(
                r"(?i)\b(?:fixed|resolved|patched)\s+in\s+(?:version\s+)?(\d+\.\d+\.\d+)"
            )
            for description in descriptions:
                if isinstance(description, dict) and isinstance(description.get("value"), str):
                    for match in description_re.finditer(description["value"]):
                        fixed = match.group(1)
                        add_hint(".".join(fixed.split(".")[:2]), fixed, "description", "text")
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    unique = {tuple(sorted(hint.items())): hint for hint in hints}
    ordered = sorted(
        unique.values(),
        key=lambda hint: (hint["branch"] or "", hint["fixed"] or "", hint["kind"]),
    )
    return ordered, errors


def enrich(cve: str, workdir: Path, fetch=None) -> tuple[dict | None, list[str]]:
    urls = intake.record_urls(cve)
    if urls is None:
        return None, ["malformed CVE id"]
    fetch = fetch or intake.fetch_text
    workdir.mkdir(parents=True, exist_ok=True)
    cache = Path(tempfile.mkdtemp(dir=workdir))
    try:
        try:
            text = fetch(urls[0], cache)
        except Exception as exc:
            return None, [f"{type(exc).__name__}: {exc}"]
        if text is None:
            return None, ["no CVE record yet"]
        try:
            record = json.loads(text)
        except (TypeError, ValueError) as exc:
            return None, [f"bad CVE record JSON: {exc}"]
        if not isinstance(record, dict):
            return None, ["CVE record is not an object"]
        return record, []
    finally:
        shutil.rmtree(cache, ignore_errors=True)


def _classification_dict(classification: Classification | dict) -> dict:
    if isinstance(classification, dict):
        return classification
    return {
        "kind": classification.kind,
        "product_key": classification.product_key,
        "tier": classification.tier,
    }


def _safe_packet_text(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[redacted]", text)
    def safe_host(match: re.Match[str]) -> str:
        host = match.group(0).lower()
        return host if host in {"cisa.gov", "www.cisa.gov"} else "[redacted]"
    return re.sub(r"\b[a-z0-9][a-z0-9.-]*\.gov\b", safe_host, text, flags=re.I)


def render_packet(facts: dict) -> tuple[str, dict]:
    entry = facts["entry"]
    classification = _classification_dict(facts["classification"])
    window, window_source = facts["window"]
    hints = facts["hints"]
    product_key = classification["product_key"]
    if product_key == "php":
        advisory = "https://www.php.net/ChangeLog-8.php"
    elif product_key == "apache":
        advisory = "https://httpd.apache.org/security/vulnerabilities_24.html"
    else:
        advisory = "https://nginx.org/en/security_advisories.html"
    hint_rows = [
        "| branch | fixed | kind | confidence | note |",
        "|---|---|---|---|---|",
    ]
    for hint in hints:
        cells = [hint.get(key) or "" for key in ("branch", "fixed", "kind", "confidence", "note")]
        hint_rows.append("| " + " | ".join(_safe_packet_text(cell) for cell in cells) + " |")
    if not hints:
        hint_rows.append("|  |  |  |  | no version hints |")
    q3 = (
        json.dumps(facts["viability"], sort_keys=True, ensure_ascii=False)
        if facts["viability"].get("available")
        else "unknown (no --db)"
    )
    window_text = f"{window} days ({window_source})" if window is not None else window_source
    entry_lines = [
        f"- CVE: {_safe_packet_text(entry.get('cve', ''))}",
        f"- Vendor / product: {_safe_packet_text(entry.get('vendor', ''))} / {_safe_packet_text(entry.get('product', ''))}",
        f"- Added: {_safe_packet_text(entry.get('added', ''))}",
        f"- Due: {_safe_packet_text(entry.get('due', '')) or 'n/a'}",
        f"- Window: {window_text}",
    ]
    skeleton = (
        "# DRAFT FROM HINTS - NOT VERIFIED\n"
        f"ProposedEvent(key={entry.get('cve')!r}, product={product_key!r}, "
        f"fixed_hints={[hint.get('fixed') for hint in hints if hint.get('fixed')]!r}, "
        "verified_by_person=False)"
    )
    burst = facts["burst"]
    checklist = []
    for i, title in enumerate(CHECKLIST):
        status = "watcher: vendor/product match only" if i == 0 else (
            "watcher: Q2 hint table attached" if i == 1 else (
                "watcher: viability counts attached (if --db)" if i == 2 else "person only"
            )
        )
        checklist.append(f"- [ ] {title} — {status}")
    notice_lines = [f"- logs/notice_live.txt present: {'yes' if facts['notice_live'] else 'no'}"]
    if product_key != "php":
        notice_lines.append(
            "- Non-PHP header use in the public notice is decision D3; check docs/proposed/public_notice_additions.md."
        )
    hint_status = "cvelistV5 record: present" if facts["record_present"] else "cvelistV5 record: unavailable"
    hint_notes = [hint_status]
    hint_notes.extend(f"Enrichment error: {_safe_packet_text(error)}" for error in facts["hint_errors"])
    sections = [
        ("Status", "DRAFT. Nothing is scheduled, verified or approved. Read the vendor advisory before trusting any version below."),
        ("KEV entry", "\n".join(entry_lines)),
        (
            "Deadline window",
            "Under BOD 26-04 (issued 2026-06-10) each KEV entry carries its own due date; "
            "the fastest tier is 3 days; it binds federal civilian agencies only.\n\n"
            f"Computed window: {window_text}.",
        ),
        (
            "Four-question test",
            f"- Q1: yes\n- Q2: yes ({', '.join(V1_PRODUCTS)})\n"
            f"- Q3: {q3}\n- Q4: unknown: the Docker detector matrix has not been run",
        ),
        (
            "Fixed-version hints",
            "\n".join(hint_rows) + "\n\n" + "\n".join(hint_notes) + f"\n\n{advisory}",
        ),
        ("Draft event skeleton", f"```python\n{skeleton}\n```"),
        (
            "Burst proposal",
            f"- Proposed days: {', '.join(burst['proposed_days']) or 'unknown'}\n"
            f"- Already past: {', '.join(burst['already_past']) or 'none'}\n"
            f"- Already planned: {', '.join(burst['already_planned']) or 'none'}\n"
            f"- Extra days: {', '.join(burst['extra_days']) or 'none'}\n"
            f"- Planned in window: {burst['planned_in_window']}\n"
            f"- With burst in window: {burst['with_burst_in_window']}\n\n{burst['note']}",
        ),
        (
            "Stored data",
            "The watcher stores the public KEV entry, catalog provenance, version hints, "
            "aggregate baseline/viability counts when supplied, and this draft packet. "
            "It does not collect from study sites or change the study database.",
        ),
        ("Notice and IRB", "\n".join(notice_lines)),
        ("Checklist", "\n".join(checklist)),
        (
            "Commands after verification",
            "python -X utf8 scripts/event_replay.py <key>\n"
            "python -X utf8 scripts/event_viability.py\n"
            "(private scripts, main checkout only)",
        ),
        (
            "Provenance",
            f"- Watcher version: {WATCHER_VERSION}\n"
            f"- Catalog version: {_safe_packet_text(facts['catalog_version'])}\n"
            f"- Catalog SHA-256: {_safe_packet_text(facts['catalog_sha256'])}\n"
            f"- Run time UTC: {_safe_packet_text(facts['now_utc'])}",
        ),
    ]
    markdown = "\n\n".join(f"## {title}\n\n{body}" for title, body in sections) + "\n"
    json_facts = json.loads(json.dumps(facts, default=lambda obj: obj.__dict__))

    def sanitize(value):
        if isinstance(value, dict):
            return {key: sanitize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        if isinstance(value, str):
            return _safe_packet_text(value)
        return value

    json_facts = sanitize(json_facts)
    json_facts["generator_version"] = WATCHER_VERSION
    return markdown, json_facts


def write_packet(repo_root: Path, facts: dict) -> list[str]:
    entry = facts["entry"]
    cve = entry.get("cve", "")
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        raise ValueError("invalid CVE id for packet path")
    added = entry.get("added", "")
    if not isinstance(added, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", added):
        raise ValueError("invalid added date for packet path")
    try:
        date.fromisoformat(added)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid added date for packet path") from exc
    base = (Path(repo_root) / "docs" / "proposed" / "events").resolve()
    folder = (base / f"{entry['added']}_{cve}").resolve()
    if folder == base or base not in folder.parents:
        raise ValueError("packet path escapes events root")
    markdown, packet = render_packet(facts)
    folder.mkdir(parents=True, exist_ok=True)
    md_path = folder / "packet.md"
    json_path = folder / "packet.json"
    json_text = json.dumps(packet, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if md_path.exists():
        if md_path.read_text(encoding="utf-8") == markdown:
            return []
        timestamp = datetime.fromisoformat(facts["now_utc"].replace("Z", "+00:00")).astimezone(timezone.utc)
        stamp = timestamp.strftime("%Y%m%dT%H%M%SZ")
        candidate = folder / f"packet.{stamp}.md"
        suffix = 1
        while candidate.exists() or candidate.with_suffix(".json").exists():
            candidate = folder / f"packet.{stamp}.{suffix}.md"
            suffix += 1
        md_path = candidate
        json_path = candidate.with_suffix(".json")
    md_path.write_text(markdown, encoding="utf-8", newline="\n")
    json_path.write_text(json_text, encoding="utf-8", newline="\n")
    return [md_path.relative_to(repo_root).as_posix(), json_path.relative_to(repo_root).as_posix()]


def _utc_now(value: str | None = None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _db_facts(path: Path | None, added: str, product_key: str) -> tuple[dict, dict]:
    if path is None:
        return {"available": False}, {"available": False}
    uri = f"file:{path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        labels = conn.execute(
            "SELECT snapshot_label, MIN(started_at_utc) FROM observations GROUP BY snapshot_label"
        ).fetchall()
        baseline = {
            "available": True,
            "earliest_snapshot_utc": min((row[1] for row in labels if row[1]), default=None),
            "snapshots_before_added": sorted(row[0] for row in labels if row[1] and row[1][:10] < added),
            "series": {
                "WI": sum(str(row[0]).startswith("WI_") for row in labels),
                "NAT": sum(str(row[0]).startswith("NAT_") for row in labels),
            },
        }
        viability: dict = {"available": True}
        for prefix in ("WI_", "NAT_"):
            candidates = [row for row in labels if str(row[0]).startswith(prefix)]
            latest = max(candidates, key=lambda row: row[1] or "") if candidates else None
            if latest is None:
                viability[prefix.rstrip("_")] = {
                    "snapshot_label": None,
                    "answering": 0,
                    "named": "<10",
                    "rankable": "<10",
                    "unreadable": 0,
                    "meets_10_points": False,
                    "meets_5_points": False,
                }
                continue
            rows = conn.execute(
                "SELECT snapshot_label, headers_json FROM observations "
                "WHERE status_code IS NOT NULL AND snapshot_label = ?",
                (latest[0],),
            ).fetchall()
            named = 0
            rankable = 0
            unreadable = 0
            for _, headers_json in rows:
                try:
                    headers = json.loads(headers_json)
                except (TypeError, ValueError):
                    unreadable += 1
                    continue
                if not isinstance(headers, dict):
                    unreadable += 1
                    continue
                reads = inventory.parse_headers(headers)
                read = reads.get(product_key)
                if read is not None:
                    named += 1
                    if read.rankable:
                        rankable += 1
            viability[prefix.rstrip("_")] = {
                "snapshot_label": latest[0],
                "answering": _suppress_count(len(rows)),
                "named": _suppress_count(named),
                "rankable": _suppress_count(rankable),
                "unreadable": _suppress_count(unreadable),
                "meets_10_points": rankable >= SIZE_FOR_10_POINTS,
                "meets_5_points": rankable >= SIZE_FOR_5_POINTS,
            }
    finally:
        conn.close()
    return baseline, viability


def _suppress_count(value: int) -> int | str:
    return "<10" if 0 < value < 10 else value


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def run(argv: list[str], fetch=None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Read-only KEV watcher; drafts proposals only.")
    parser.add_argument("--kev")
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--dry", action="store_true")
    parser.add_argument("--state", default=str(ROOT / "logs" / "kevwatch" / "state.json"))
    parser.add_argument("--out-root")
    parser.add_argument("--db")
    parser.add_argument("--now")
    parser.add_argument("--no-enrich", action="store_true")
    args = parser.parse_args(argv)
    now = _utc_now(args.now)
    now_text = now.isoformat().replace("+00:00", "Z")
    state_path = Path(args.state).resolve()
    out_root = Path(args.out_root).resolve() if args.out_root else ROOT.resolve()
    run_path = state_path.parent / "last_run.json"
    mode = "dry" if args.dry else "live"
    run_record = {
        "started_utc": now_text,
        "finished_utc": now_text,
        "mode": mode,
        "exit_code": 6,
        "catalog_version": "",
        "catalog_sha256": "",
        "entries": 0,
        "new": [],
        "changed": [],
        "removed": [],
        "candidates": [],
        "near_misses": [],
        "near_miss_names": [],
        "other_new": [],
        "packets_written": [],
        "errors": [],
        _NETWORK_REQUESTS_KEY: 0,
        "watcher_version": WATCHER_VERSION,
    }

    def finish(code: int) -> int:
        run_record["exit_code"] = code
        run_record["finished_utc"] = _utc_now().isoformat().replace("+00:00", "Z")
        try:
            _write_json(run_path, run_record)
        except OSError as exc:
            run_record["errors"].append(f"cannot write last_run.json: {type(exc).__name__}: {exc}")
            print(run_record["errors"][-1], file=sys.stderr)
            return 6
        return code

    try:
        if os.environ.get("PATCHWATCH_GATE_A"):
            run_record["errors"].append("PATCHWATCH_GATE_A is set")
            return finish(5)
        if Path.cwd().resolve() != ROOT.resolve() and args.out_root is None:
            run_record["errors"].append("run from repository root or specify --out-root")
            return finish(5)
        try:
            state = load_state(state_path)
        except StateCorrupt as exc:
            run_record["errors"].append(str(exc))
            return finish(4)
        if args.bootstrap and state is not None:
            run_record["errors"].append("state already exists; bootstrap is never repeated")
            return finish(5)
        request_count = 0

        def counted_fetch(url, cache_dir):
            nonlocal request_count
            request_count += 1
            run_record[_NETWORK_REQUESTS_KEY] = request_count
            transport = fetch or intake.fetch_text
            return transport(url, cache_dir)

        try:
            if args.kev:
                try:
                    text = Path(args.kev).read_text(encoding="utf-8")
                except (OSError, UnicodeError) as exc:
                    raise FeedError(f"cannot read catalog file: {exc}") from exc
                digest = check_catalog_text(text)
            else:
                text, digest = fetch_catalog(state_path.parent, counted_fetch)
            cat = parse_catalog(text)
            digest = _canonical_catalog_sha256(text)
            cat["sha256"] = digest
        except FeedError as exc:
            if state is not None:
                state["consecutive_failures"] += 1
                state["last_attempt_utc"] = now_text
                state["last_error"] = str(exc)
                save_state(state_path, state)
            run_record["errors"].append(str(exc))
            run_record[_NETWORK_REQUESTS_KEY] = request_count
            return finish(3)

        run_record["catalog_version"] = cat.get("version", "")
        run_record["catalog_sha256"] = digest
        run_record["entries"] = len(cat["entries"])
        if state is None:
            if not args.bootstrap:
                run_record["errors"].append("no state; pass --bootstrap to initialize")
                run_record[_NETWORK_REQUESTS_KEY] = request_count
                return finish(5)
            if not args.dry:
                save_state(state_path, bootstrap_state(cat, now_text))
            run_record[_NETWORK_REQUESTS_KEY] = request_count
            return finish(0)

        if state.get("last_success_utc"):
            previous_success = _utc_now(state["last_success_utc"])
            if now < previous_success:
                run_record["errors"].append(
                    f"refusing clock rollback: --now {now_text} is before last success "
                    f"{state['last_success_utc']}"
                )
                run_record[_NETWORK_REQUESTS_KEY] = request_count
                return finish(5)

        diff = diff_catalog(state, cat)
        run_record["new"] = sorted(entry["cve"] for entry in diff.new)
        run_record["changed"] = sorted(entry["cve"] for _, entry in diff.changed)
        run_record["removed"] = diff.removed
        candidates: list[dict] = []
        near_misses: list[dict] = []
        other_new: list[str] = []
        written: list[str] = []
        today = now.astimezone(ZoneInfo("America/Chicago")).date()
        for entry in diff.new:
            classification = classify_entry(entry)
            if classification.kind == "near_miss":
                near_misses.append(entry)
                continue
            if classification.kind == "other":
                other_new.append(entry["cve"])
                continue
            candidates.append(entry)
            record = None
            hint_errors: list[str] = []
            if not args.no_enrich:
                record, hint_errors = enrich(entry["cve"], state_path.parent, counted_fetch)
            if record is None:
                hints = []
            else:
                hints, extraction_errors = extract_hints(record, classification.product_key or "")
                hint_errors.extend(extraction_errors)
            window = window_days(entry)
            burst = burst_proposal(entry, today)
            baseline, viability = _db_facts(
                Path(args.db).resolve() if args.db else None,
                entry["added"],
                classification.product_key or "",
            )
            facts = {
                "entry": entry,
                "classification": classification,
                "window": window,
                "burst": burst,
                "hints": hints,
                "hint_errors": hint_errors,
                "record_present": record is not None,
                "baseline": baseline,
                "viability": viability,
                "notice_live": (out_root / "logs" / "notice_live.txt").is_file(),
                "catalog_version": cat.get("version", ""),
                "catalog_sha256": digest,
                "now_utc": now_text,
            }
            if not args.dry:
                written.extend(write_packet(out_root, facts))
        for _, entry in diff.changed:
            candidate = state["candidates"].get(entry["cve"])
            if candidate is None:
                continue
            classification = classify_entry(entry)
            if classification.kind != "candidate":
                continue
            record = None
            hint_errors = []
            if not args.no_enrich:
                record, hint_errors = enrich(entry["cve"], state_path.parent, counted_fetch)
            if record is None:
                hints = []
            else:
                hints, extraction_errors = extract_hints(record, classification.product_key or "")
                hint_errors.extend(extraction_errors)
            window = window_days(entry)
            burst = burst_proposal(entry, today)
            baseline, viability = _db_facts(
                Path(args.db).resolve() if args.db else None,
                entry["added"],
                classification.product_key or "",
            )
            facts = {
                "entry": entry,
                "classification": classification,
                "window": window,
                "burst": burst,
                "hints": hints,
                "hint_errors": hint_errors,
                "record_present": record is not None,
                "baseline": baseline,
                "viability": viability,
                "notice_live": (out_root / "logs" / "notice_live.txt").is_file(),
                "catalog_version": cat.get("version", ""),
                "catalog_sha256": digest,
                "now_utc": now_text,
            }
            if not args.dry:
                written.extend(write_packet(out_root, facts))
            candidate["due"] = entry["due"]
            candidate["product_key"] = classification.product_key
            candidate["product"] = entry["product"]
            candidate["packet_dir"] = f"docs/proposed/events/{entry['added']}_{entry['cve']}"
        for entry in diff.new:
            state["seen"][entry["cve"]] = seen_record(entry)
        for _, entry in diff.changed:
            state["seen"][entry["cve"]] = seen_record(entry)
        for entry in candidates:
            classification = classify_entry(entry)
            packet_dir = f"docs/proposed/events/{entry['added']}_{entry['cve']}"
            state["candidates"][entry["cve"]] = {
                "first_seen_utc": now_text,
                "product_key": classification.product_key,
                "product": entry["product"],
                "due": entry["due"],
                "packet_dir": packet_dir,
                "notified": False,
            }
        state["catalog_version"] = cat.get("version", "")
        state["catalog_sha256"] = digest
        state["last_attempt_utc"] = now_text
        state["last_success_utc"] = now_text
        state["consecutive_failures"] = 0
        state["last_error"] = ""
        if not args.dry:
            save_state(state_path, state)
        run_record["candidates"] = sorted(entry["cve"] for entry in candidates)
        run_record["near_misses"] = sorted(entry["cve"] for entry in near_misses)
        run_record["near_miss_names"] = [
            f"{entry['vendor']} / {entry['product']}" for entry in sorted(near_misses, key=lambda item: item["cve"])
        ]
        run_record["other_new"] = sorted(other_new)
        run_record["packets_written"] = written
        run_record[_NETWORK_REQUESTS_KEY] = request_count
        print(
            f"KEV watcher {WATCHER_VERSION}. Catalog {cat.get('version', '')} ({len(cat['entries'])} entries). "
            f"New: {len(diff.new)}; candidates: {', '.join(run_record['candidates']) or 'none'}; "
            f"near misses: {len(near_misses)}; other: {len(other_new)}."
        )
        for path in written:
            print(path)
        print("PROPOSALS ONLY. Nothing was scheduled, no scan was enabled, no study file was changed.")
        return finish(0)
    except Exception as exc:
        run_record["errors"].append(f"{type(exc).__name__}: {exc}")
        return finish(6)
