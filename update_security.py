import requests
import re
from datetime import datetime

def get_latest_cve():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&startIndex=0"
    r = requests.get(url, headers={"User-Agent": "GitHubProfileBot/1.0"}, timeout=10)
    r.raise_for_status()
    data = r.json()
    cve = data['vulnerabilities'][0]['cve']

    cve_id = cve['id']

    desc = next(
        (d['value'] for d in cve['descriptions'] if d['lang'] == 'en'),
        'No description available.'
    )
    if len(desc) > 160:
        desc = desc[:157] + "..."

    score = None
    severity = None
    metrics = cve.get('metrics', {})
    for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if key in metrics:
            score = metrics[key][0]['cvssData']['baseScore']
            severity = metrics[key][0]['cvssData']['baseSeverity']
            break

    published = cve.get('published', '')[:10]
    return cve_id, desc, score, severity, published


def get_latest_breach():
    url = "https://haveibeenpwned.com/api/v3/breaches"
    r = requests.get(url, headers={"User-Agent": "GitHubProfileBot/1.0"}, timeout=10)
    r.raise_for_status()
    breaches = r.json()

    breaches.sort(key=lambda x: x['AddedDate'], reverse=True)
    b = breaches[0]

    name = b['Name']
    domain = b.get('Domain', 'N/A')
    pwn_count = b['PwnCount']
    added_date = b['AddedDate'][:10]

    # Strip HTML tags from description
    raw_desc = re.sub(r'<[^>]+>', '', b.get('Description', ''))
    if len(raw_desc) > 160:
        raw_desc = raw_desc[:157] + "..."

    data_classes = b.get('DataClasses', [])[:4]
    return name, domain, pwn_count, added_date, raw_desc, data_classes


def severity_emoji(severity):
    mapping = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢',
    }
    return mapping.get(str(severity).upper(), '⚪')


def update_readme():
    print("Fetching latest CVE...")
    cve_id, cve_desc, score, severity, published = get_latest_cve()

    print("Fetching latest breach...")
    b_name, b_domain, b_count, b_date, b_desc, b_classes = get_latest_breach()

    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    sev_icon = severity_emoji(severity)
    score_str = f"CVSS {score} {sev_icon} {severity}" if score else "Score N/A"
    classes_str = " · ".join(f"`{c}`" for c in b_classes) if b_classes else "N/A"

    section = f"""<!-- SECURITY-START -->
## 🔐 Live Threat Pulse
*Auto-updated daily · {now}*

**⚠️ Latest CVE**
[`{cve_id}`](https://nvd.nist.gov/vuln/detail/{cve_id}) — {score_str} · Published {published}
{cve_desc}

---

**💥 Latest Breach Added to HIBP**
**{b_name}** `{b_domain}` · {int(b_count):,} accounts exposed · Added {b_date}
{b_desc}
Exposed data: {classes_str}
<!-- SECURITY-END -->"""

    with open('README.md', 'r') as f:
        content = f.read()

    new_content = re.sub(
        r'<!-- SECURITY-START -->.*?<!-- SECURITY-END -->',
        section,
        content,
        flags=re.DOTALL
    )

    with open('README.md', 'w') as f:
        f.write(new_content)

    print(f"README updated successfully at {now}")


if __name__ == '__main__':
    update_readme()
