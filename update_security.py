import requests
import re
import sys
from datetime import datetime

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; GitHubProfileBot/1.0)"
}

def get_latest_cves(count=5):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={count}&startIndex=0"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        data = r.json()

        results = []
        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            cve_id = cve['id']

            desc = next(
                (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'),
                'No description available.'
            )
            if len(desc) > 150:
                desc = desc[:147] + "..."

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
            results.append((cve_id, desc, score, severity, published))
            if len(results) == count:
                break

        print(f"Got {len(results)} CVEs")
        return results

    except Exception as e:
        print(f"CVE fetch error: {e}")
        return [("N/A", "Could not fetch CVE data at this time.", None, None, "N/A")]


def get_latest_breaches(count=5):
    try:
        url = "https://haveibeenpwned.com/api/v3/breaches"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        breaches = r.json()

        breaches.sort(key=lambda x: x.get('AddedDate', ''), reverse=True)

        results = []
        for b in breaches[:count]:
            name = b.get('Name', 'Unknown')
            domain = b.get('Domain', 'N/A')
            pwn_count = b.get('PwnCount', 0)
            added_date = b.get('AddedDate', '')[:10]
            data_classes = b.get('DataClasses', [])[:3]
            results.append((name, domain, pwn_count, added_date, data_classes))

        print(f"Got {len(results)} breaches")
        return results

    except Exception as e:
        print(f"Breach fetch error: {e}")
        return [("N/A", "N/A", 0, "N/A", [])]


def severity_emoji(severity):
    mapping = {
        'CRITICAL': '🔴',
        'HIGH':     '🟠',
        'MEDIUM':   '🟡',
        'LOW':      '🟢',
    }
    return mapping.get(str(severity).upper(), '⚪') if severity else '⚪'


def update_readme():
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    print("Fetching top 5 CVEs...")
    cves = get_latest_cves(5)

    print("Fetching top 5 breaches...")
    breaches = get_latest_breaches(5)

    # Build CVE lines
    cve_lines = []
    for i, (cve_id, desc, score, severity, published) in enumerate(cves, 1):
        icon = severity_emoji(severity)
        score_str = f"CVSS {score} {icon} {severity}" if score else "Score N/A"
        cve_lines.append(
            f"**{i}. [`{cve_id}`](https://nvd.nist.gov/vuln/detail/{cve_id})** — {score_str} · {published}\n{desc}"
        )
    cve_block = "\n\n".join(cve_lines)

    # Build breach lines
    breach_lines = []
    for i, (name, domain, count, added_date, data_classes) in enumerate(breaches, 1):
        classes_str = " · ".join(f"`{c}`" for c in data_classes) if data_classes else "N/A"
        breach_lines.append(
            f"**{i}. {name}** `{domain}` · {int(count):,} accounts · Added {added_date}\nExposed: {classes_str}"
        )
    breach_block = "\n\n".join(breach_lines)

    section = f"""<!-- SECURITY-START -->
## 🛰 Threat Intelligence Feed
*Auto-updated daily · {now}*

### ⚠️ Latest CVEs

{cve_block}

---

### 💥 Recent Breaches · HaveIBeenPwned

{breach_block}
<!-- SECURITY-END -->"""

    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print("ERROR: README.md not found")
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
