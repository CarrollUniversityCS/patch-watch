"""Project configuration. Every hard rule from the mission brief that is a
number lives here so it can be audited in one place.

GATE A: nothing in this file authorises live traffic. `LIVE_REQUESTS_ENABLED`
stays False until the operator (Jack Forden) replies "GATE A APPROVED", and the
fetcher refuses to run when it is False.

Gate A is a human decision, not a check the code can make: the one condition the
fetcher can verify is a filled-in User-Agent. Its other precondition — that the
notice at PROJECT_URL, Jack Forden's GitHub profile README, is actually published
and reads as an opt-out page — has to be confirmed by the operator. There is no
separate hosted project page; PROJECT_URL is the address our own traffic carries,
so an operator who looks us up from a log lands on the notice. See
docs/OPERATIONS.md, "Identity URL".
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------- identity (rules 3, 10)
PROJECT_URL = "https://github.com/JForden/JForden"        # profile README = human-readable notice page
CONTACT_EMAIL = "jforden@carrollu.edu"
USER_AGENT = f"CarrollPHPStudy/1.0 (+{PROJECT_URL}; {CONTACT_EMAIL})"
RESEARCHER = "Jack Forden, Carroll University (Waukesha, WI)"

# ---------------------------------------------------------------- gates
# Hard rule 8 (human gate). The fetcher raises unless this is True AND the
# marker file exists AND the UA placeholders are filled in.
LIVE_REQUESTS_ENABLED = False
GATE_MARKER_ENV = "PATCHWATCH_GATE_A"   # must contain exactly "APPROVED" at run time

# ---------------------------------------------------------------- frame (Stage 1)
CISA_REGISTRY_URL = "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv"
RANDOM_SEED = 20261022                  # recorded in README, used for the pilot draw
STRATUM_FLOOR = 40                      # min per stratum where the stratum can supply it
TARGET_SAMPLE = 300                     # soft target; the floor wins (see analysis plan)

# ---------------------------------------------------------------- transport (rules 1, 2, 4)
MAX_CONCURRENCY = 20                    # workers overall
MAX_PER_IP = 1                          # concurrent requests per resolved IP
JITTER_MIN_S = 0.100
JITTER_MAX_S = 0.500
CONNECT_TIMEOUT_S = 10.0
TOTAL_TIMEOUT_S = 20.0
MAX_REDIRECTS = 3                       # same registrable domain only
MAX_BODY_BYTES = 64 * 1024              # read, derive php_hints, discard
COOKIE_JAR = False                      # never send cookies
MAX_SENDS_PER_DOMAIN = 3                # rule 2: 3 budget-charged PHASES, not raw requests:
                                        # https | +https_unverified | +http_fallback (see
                                        # docs/OPERATIONS.md "Request-count promise"). Redirect
                                        # hops are charged to the phase, not to this cap.

# ---------------------------------------------------------------- kill switch (rule 6)
KILL_ROLLING_WINDOW = 50
KILL_TRIP_RATIO = 0.10                  # >10% of requests in the window are 403/429/5xx
KILL_STATUS_CODES = frozenset({403, 429})
KILL_ABUSE_MARKER = "ABUSE_COMPLAINT"   # presence of this string in logs/abuse.flag halts runs

# ---------------------------------------------------------------- storage paths
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
LOGS_DIR = ROOT / "logs"
REPORTS_DIR = ROOT / "reports"
DOCS_DIR = ROOT / "docs"
DB_PATH = Path(os.environ.get("PATCHWATCH_DB", DATA_DIR / "study.db"))
BLOCKLIST_PATH = Path(os.environ.get("PATCHWATCH_BLOCKLIST", ROOT / "blocklist.txt"))
# Rule 6, second trigger. Written by the operator only; the code reads it, never creates it.
ABUSE_FLAG_PATH = Path(os.environ.get("PATCHWATCH_ABUSE_FLAG", LOGS_DIR / "abuse.flag"))
GATE_ABUSE_FLAG_PATH = ABUSE_FLAG_PATH
LEDGER_EXPORT_PATH = DATA_DIR / "request_ledger.csv"

# ---------------------------------------------------------------- snapshots (Stage 6)
SNAPSHOT_A_LABEL = "A_day1"
SNAPSHOT_B_LABEL = "B_day1p8h"
MIN_SNAPSHOT_GAP_H = 6.0

__all__ = [n for n in dir() if n.isupper()]
