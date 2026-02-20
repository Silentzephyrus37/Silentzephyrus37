import requests
import re
import sys
from datetime import datetime

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; GitHubProfileBot/1.0)"
}

def get_latest_cve():
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5&startIndex=0"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        data = r.json()

        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            cve_id = cve['id']

            desc = next(
                (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'),
                'No description available.'
            )
            if len(desc) > 200:
                desc = desc[:197] + "..."

            score = None
            severity = None
            metrics = cve.get('metrics', {})
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if key in metrics and metrics[key]:
                    try:
                        score = metrics[key][0]['cvssData']['baseScore']
                        severity = metrics[key][0]['cvssData']['baseSeverity']
                        break
                    except (KeyError, IndexError):
                        continue

            published = cve.get('published', '')[:10]
            print(f"Got CVE: {cve_id}")
            return cve_id, desc, score, severity, published

    except Exception as e:
        print(f"CVE fetch error: {e}")
        return "N/A", "Could not fetch CVE data at this time.", None, None, "N/A"


def get_latest_breach():
    try:
        url = "https://haveibeenpwned.com/api/v3/breaches"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        breaches = r.json()

        breaches.sort(key=lambda x: x.get('AddedDate', ''), reverse=True)
        b = breaches[0]

        name = b.get('Name', 'Unknown')
        domain = b.get('Domain', 'N/A')
        pwn_count = b.get('PwnCount', 0)
        added_date = b.get('AddedDate', '')[:10]

        raw_desc = re.sub(r'<[^>]+>', '', b.get('Description', ''))
        raw_desc = re.sub(r'\s+', ' ', raw_desc).strip()
        if len(raw_desc) > 200:
            raw_desc = raw_desc[:197] + "..."

        data_classes = b.get('DataClasses', [])[:4]
        print(f"Got breach: {name}")
        return name, domain, pwn_count, added_date, raw_desc, data_classes

    except Exception as e:
        print(f"Breach fetch error: {e}")
        return "N/A", "N/A", 0, "N/A", "Could not fetch breach data at this time.", []


def severity_emoji(severity):
    mapping = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢',
    }
    return mapping.get(str(severity).upper(), '⚪') if severity else '⚪'


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

    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print("ERROR: README.md not found in current directory")
        sys.exit(1)

    if '<!-- SECURITY-START -->' not in content:
        print("ERROR: Could not find <!-- SECURITY-START --> markers in README.md")
        sys.exit(1)

    new_content = re.sub(
        r'<!-- SECURITY-START -->.*?<!-- SECURITY-END -->',
        section,
        content,
        flags=re.DOTALL
    )

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"README updated successfully at {now}")


if __name__ == '__main__':
    update_readme()
