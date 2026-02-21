import requests
import re
import sys
import urllib.parse
from datetime import datetime

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; GitHubProfileBot/1.0)"}

def severity_label(severity):
    mapping = {
        'CRITICAL': '🔴 `CRIT`',
        'HIGH':     '🟠 `HIGH`',
        'MEDIUM':   '🟡 `MED`',
        'LOW':      '🟢 `LOW`',
    }
    return mapping.get(str(severity).upper(), '⚪ `N/A`')

def get_latest_cves(count=5):
    try:
        # Fetch more than needed so we can sort properly
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50&startIndex=0"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        data = r.json()
        vulns = data.get('vulnerabilities', [])

        # Sort by published date descending — fixes the 1999 CVE problem
        vulns.sort(key=lambda x: x['cve'].get('published', ''), reverse=True)

        results = []
        for item in vulns[:count]:
            cve = item['cve']
            cve_id = cve['id']

            desc = next(
                (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'),
                'No description available.'
            )

            score, severity, product = "N/A", "N/A", "N/A"

            metrics = cve.get('metrics', {})
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if key in metrics and metrics[key]:
                    try:
                        score    = metrics[key][0]['cvssData']['baseScore']
                        severity = metrics[key][0]['cvssData']['baseSeverity']
                        break
                    except (KeyError, IndexError):
                        continue

            # Extract affected product from CPE
            try:
                configs = cve.get('configurations', [])
                if configs:
                    nodes = configs[0].get('nodes', [])
                    if nodes:
                        cpe = nodes[0].get('cpeMatch', [{}])[0].get('criteria', '')
                        parts = cpe.split(':')
                        if len(parts) > 4:
                            vendor  = parts[3].replace('_', ' ').title()
                            product_name = parts[4].replace('_', ' ').title()
                            product = f"{vendor} {product_name}".strip()
            except (IndexError, KeyError):
                product = "N/A"

            published = cve.get('published', '')[:10]
            results.append((cve_id, desc, score, severity, published, product))

        print(f"Got {len(results)} CVEs — latest: {results[0][4] if results else 'none'}")
        return results

    except Exception as e:
        print(f"CVE fetch error: {e}")
        return [("N/A", "Could not fetch CVE data.", "N/A", "N/A", "N/A", "N/A")] * count

def get_latest_breaches(count=5):
    try:
        url = "https://haveibeenpwned.com/api/v3/breaches"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        breaches = r.json()
        breaches.sort(key=lambda x: x.get('AddedDate', ''), reverse=True)

        results = []
        for b in breaches[:count]:
            results.append((
                b.get('Name', 'Unknown'),
                b.get('Domain', 'N/A'),
                b.get('PwnCount', 0),
                b.get('AddedDate', '')[:10],
                b.get('DataClasses', [])[:4]
            ))
        print(f"Got {len(results)} breaches")
        return results

    except Exception as e:
        print(f"Breach fetch error: {e}")
        return [("N/A", "N/A", 0, "N/A", [])] * count

def update_readme():
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    print("Fetching CVEs...")
    cves = get_latest_cves(5)
    print("Fetching breaches...")
    breaches = get_latest_breaches(5)

    # ── CVE TABLE ─────────────────────────────────────────────────────────
    cve_rows = []
    for cve_id, desc, score, sev, published, product in cves:
        sev_str  = severity_label(sev)
        short_desc = desc[:100] + "..." if len(desc) > 100 else desc
        col1 = f"[`{cve_id}`](https://nvd.nist.gov/vuln/detail/{cve_id})<br>**{score}** {sev_str}"
        col2 = f"`{product}`<br><sub>{published}</sub>"
        col3 = f"<sub>{short_desc}</sub>"
        cve_rows.append(f"| {col1} | {col2} | {col3} |")

    cve_table = (
        "| CVE ID | Affected Product | Description |\n"
        "| :--- | :---: | :--- |\n"
        + "\n".join(cve_rows)
    )

    # ── BREACH TABLE ──────────────────────────────────────────────────────
    breach_rows = []
    for name, domain, count, added, classes in breaches:
        query   = urllib.parse.quote(f"{name} data breach")
        news_url = f"https://www.google.com/search?q={query}&tbm=nws"
        tags    = " ".join(f"`{d.lower()}`" for d in classes) if classes else "`N/A`"
        col1    = f"[**{name}**]({news_url}) ↗<br><sub>`{domain}`</sub>"
        col2    = f"**{int(count):,}**<br><sub>accounts</sub>"
        col3    = f"<sub>{added}</sub>"
        col4    = f"<sub>{tags}</sub>"
        breach_rows.append(f"| {col1} | {col2} | {col3} | {col4} |")

    breach_table = (
        "| Company | Exposed | Date Added | Data Types |\n"
        "| :--- | :---: | :---: | :--- |\n"
        + "\n".join(breach_rows)
    )

    section = (
        f"<!-- SECURITY-START -->\n"
        f"## 🛰 Threat Intelligence Feed\n"
        f"<p align='center'><sub>Active Monitoring · {now}</sub></p>\n\n"
        f"### ⚠️ Latest CVEs\n\n"
        f"{cve_table}\n\n"
        f"### 💥 Recent Breaches\n\n"
        f"{breach_table}\n"
        f"<!-- SECURITY-END -->"
    )

    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print("ERROR: README.md not found")
        sys.exit(1)

    if '<!-- SECURITY-START -->' not in content:
        print("ERROR: Security markers not found in README.md")
        sys.exit(1)

    # Fixed regex — properly targets only the security section
    new_content = re.sub(
        r'<!-- SECURITY-START -->.*?<!-- SECURITY-END -->',
        section,
        content,
        flags=re.DOTALL
    )

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"README updated at {now}")

if __name__ == '__main__':
    update_readme()
