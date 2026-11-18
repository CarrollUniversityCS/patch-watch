"""Amendment T2 (PHP release event) is pre-registered and frozen. Changing it is a new dated amendment, not an edit."""
import hashlib
from pathlib import Path

T2_SHA256 = "c7c76fcd5b5b95701876c74ddbfea83f6a8242b26bdda424e35859e1053b2053"


def test_the_t2_amendment_is_unchanged():
    """Pinned at the freeze (2026-11-17T17:32:00Z, plan text of cd35e4b, plus status/title/section 11). Update this hash only
    for a dated section 12 row of the amendment itself, in the same commit. Row 2026-11-18 added the adoption."""
    path = Path(__file__).resolve().parent.parent / "docs" / "analysis_plan_t2_release_event.md"
    text = path.read_bytes().decode("utf-8").replace(chr(13) + chr(10), chr(10))
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == T2_SHA256
