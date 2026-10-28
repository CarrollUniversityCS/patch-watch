"""Rough keyword triage of the CISA KEV catalog by how a product could be observed.

Reproduces the counts in docs/RESEARCH_DIRECTIONS.md ("KEV triage, first pass"). It is a
first pass for pathway 1, not the four-question candidate test: it reads only the
vendorProject and product names, so it under-counts edge products (several land in C).
No network; give it a downloaded catalog:

    curl -L -o kev.json https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json
    python -I scripts/kev_triage.py kev.json

Tiers: A = product that can show a version on a public homepage (web server, PHP, CMS,
SharePoint); B = edge device or server product on its own host or path (VPN, firewall,
mail, file transfer); C = client or local software, plus anything not matched.
"""
import json, collections, re, sys
d = json.load(open(sys.argv[1]))
v = d['vulnerabilities']
# A: product whose version can show up on a public homepage (headers or page markup)
A = [r'\bphp\b', r'apache.*http', r'http server', r'\bnginx', r'\biis\b', r'internet information services',
     r'tomcat', r'drupal', r'wordpress', r'joomla', r'magento', r'adobe commerce', r'liferay', r'sitecore',
     r'telerik', r'sharepoint', r'craft cms', r'\bstruts', r'coldfusion', r'\.net framework', r'asp\.net',
     r'jquery', r'kentico', r'umbraco', r'progress sitefinity', r'cpanel', r'plesk', r'webmin', r'openssl']
# B: internet-facing appliance or server product, usually on its own host or path (VPN, mail, file transfer...)
B = [r'fortios', r'fortigate', r'fortiweb', r'fortimanager', r'fortiproxy', r'fortisiem', r'forticlient ems', r'fortivoice',
     r'connect secure', r'policy secure', r'pulse', r'ivanti', r'epmm', r'mobileiron', r'netscaler', r'citrix adc', r'citrix gateway',
     r'pan-os', r'globalprotect', r'sonicwall', r'\bsma\b', r'\basa\b', r'firepower', r'ios xe', r'adaptive security', r'big-ip', r'f5',
     r'exchange', r'zimbra', r'roundcube', r'moveit', r'goanywhere', r'confluence', r'jira', r'bitbucket', r'gitlab', r'jenkins',
     r'vcenter', r'esxi', r'horizon', r'workspace one', r'connectwise', r'screenconnect', r'solarwinds', r'n-able', r'kaseya',
     r'check point', r'quantum security', r'zyxel', r'draytek', r'mikrotik', r'qnap', r'synology', r'd-link', r'netgear', r'tp-link',
     r'weblogic', r'e-business suite', r'peoplesoft', r'sap netweaver', r'jfrog', r'langflow', r'crushftp', r'wing ftp', r'arista', r'velocloud',
     r'veeam', r'commvault', r'cyberark', r'beyondtrust', r'array networks', r'sophos', r'barracuda', r'owa', r'outlook web', r'plex']
def tier(x):
    t = f"{x['vendorProject']} {x['product']}".lower()
    if any(re.search(p, t) for p in A): return 'A_homepage_stack'
    if any(re.search(p, t) for p in B): return 'B_edge_or_server_product'
    return 'C_client_or_local'
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
