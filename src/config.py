"""Project configuration. Every hard rule from the mission brief that is a
number lives here so it can be audited in one place.

GATE A: nothing in this file alone authorises live traffic. Live requests require
both `LIVE_REQUESTS_ENABLED=True` and the `PATCHWATCH_GATE_A=APPROVED` environment
marker. Keep the flag False until the operator (Jack Forden) replies "GATE A APPROVED".

Gate A is a human decision, not a check the code can make: alongside the two-key
check, the fetcher verifies a filled-in User-Agent. The notice at PROJECT_URL,
Jack Forden's GitHub profile README, must actually be published and read as an
opt-out page; the operator has to confirm that. There is no separate hosted
project page; PROJECT_URL is the address our own traffic carries, so an operator
who looks us up from a log lands on the notice. See docs/OPERATIONS.md, "Identity URL".
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
# PATCHWATCH_GATE_A environment variable is APPROVED AND the UA placeholders are
# filled in.
LIVE_REQUESTS_ENABLED = False
GATE_MARKER_ENV = "PATCHWATCH_GATE_A"   # must contain exactly "APPROVED" at run time

# ---------------------------------------------------------------- scope
# PI decision 2026-10-23 (docs/analysis_plan.md §11, D1): tribal nations' domains are
# not measured, in any frame or sample. Sovereign governments warrant consultation,
# not just cell suppression, and with nine Wisconsin nations any tribal cell would
# identify one. pipeline.load_sample() drops these rows before anything else runs,
# so no sample file, old or new, can put a tribal domain on the wire.
EXCLUDED_DOMAIN_TYPE_PREFIXES = ("Tribal",)

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
# Two trips over the same rolling window (plan §12, 2026-10-23):
#  * OVERLOAD: >10% of outcomes are 429 or 5xx - signs we may be causing load.
#  * BLOCK:    >30% of outcomes are 401/403 - our crawler is being refused broadly,
#              so stop and find out why. A single CDN firewall 403 on first contact is
#              a site saying no (recorded NOT_MEASURED, never retried that day); on
#              2026-10-23 such 403s alone (Cloudflare/Akamai) tripped the old combined
#              10% rule a quarter of the way through Wisconsin with no load signal at all.
KILL_TRIP_RATIO = 0.10                  # overload trip: >10% of the window are 429/5xx
KILL_STATUS_CODES = frozenset({429})    # plus every status >= 500 (KillSwitch.bad)
KILL_BLOCK_RATIO = 0.30                 # block trip: >30% of the window are 401/403
KILL_BLOCK_STATUS_CODES = frozenset({401, 403})
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
# Fetch order is shuffled per run (plan §12, 2026-10-23) so that firewalled or
# shared-host sites, which cluster in the frame's sorted order, do not bunch into one
# kill-switch window. The seed is drawn per run unless given, and is recorded in the
# run's config_json and report, so the order is reproducible.

__all__ = [n for n in dir() if n.isupper()]
