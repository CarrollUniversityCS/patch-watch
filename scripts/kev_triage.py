"""Rough keyword triage of the CISA KEV catalog by how a product could be observed.

Keyword first-pass triage of the KEV catalog. It is a
first pass, not the four-question candidate test: it reads only the
vendorProject and product names, so it under-counts edge products (several land in C).
No network; give it a downloaded catalog:

    curl -L -o kev.json https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json
    python -I scripts/kev_triage.py kev.json

Tiers: A = product that can show a version on a public homepage (web server, PHP, CMS,
SharePoint); B = edge device or server product on its own host or path (VPN, firewall,
mail, file transfer); C = client or local software, plus anything not matched.
"""
import json, collections, sys
d = json.load(open(sys.argv[1]))
v = d['vulnerabilities']
# The keyword lists now live in src/intake.py so the census and this first pass cannot drift.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent / "src"))
from intake import tier_keyword  # noqa: E402
def tier(x):
    return tier_keyword(x['vendorProject'], x['product'])
rows = [(x, tier(x)) for x in v]
def summarize(rs, label):
    c = collections.Counter(t for _, t in rs)
    n = len(rs)
    print(f"{label}: n={n}", {k: f"{c[k]} ({100*c[k]/n:.0f}%)" for k in sorted(c)})
summarize(rows, 'all KEV')
summarize([r for r in rows if r[0]['dateAdded'] >= '2025-10-28'], 'added last 12 months')
for k in ('A_homepage_stack',):
    c = collections.Counter(f"{x['vendorProject']} | {x['product']}" for x, t in rows if t == k)
    print(k, c.most_common(40))
    print('A last 12 months:', [(x['cveID'], x['vendorProject'], x['product'], x['dateAdded']) for x, t in rows if t == k and x['dateAdded'] >= '2025-10-28'])
c = collections.Counter(x['vendorProject'] for x, t in rows if t == 'C_client_or_local')
print('C top vendors', c.most_common(15))
c = collections.Counter(f"{x['vendorProject']} | {x['product']}" for x, t in rows if t == 'C_client_or_local' and x['dateAdded'] >= '2025-10-28')
print('C last12 sample', c.most_common(40))
