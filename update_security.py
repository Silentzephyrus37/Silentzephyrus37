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
            desc = next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), 'No description available.')
            
            # Truncate description for table fit
            desc = (desc[:75] + '..') if len(desc) > 75 else desc

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

            results.append((cve_id, desc, score, severity))
            if len(results) == count:
                break
        return results
    except Exception as e:
        print(f"CVE fetch error: {e}")
        return [("N/A", "Fetch Error", None, None)] * count

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
            count_val = b.get('PwnCount', 0)
            data_classes = b.get('DataClasses', [])[:2] # Top 2 for space
            results.append((name, count_val, data_classes))
        return results
    except Exception as e:
        print(f"Breach fetch error: {e}")
        return [("N/A", 0, [])] * count

def severity_emoji(severity):
    mapping = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
    return mapping.get(str(severity).upper(), '⚪')

def update_readme():
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    cves = get_latest_cves(5)
    breaches = get_latest_breaches(5)

    # Building the Table Rows
    table_rows = []
    for (cve_id, desc, score, sev), (b_name, b_count, b_data) in zip(cves, breaches):
        # CVE Column
        icon = severity_emoji(sev)
        cve_col = f"[**{cve_id}**](https://nvd.nist.gov/vuln/detail/{cve_id}) <br> {icon} **{score if score else 'N/A'}** · {desc}"
        
        # Breach Column
        data_str = " · ".join(f"`{d}`" for d in b_data)
        breach_col = f"**{b_name}** • {int(b_count):,} <br> {data_str}"
        
        table_rows.append(f"| {cve_col} | {breach_col} |")

    table_header = "| ⚠️ Latest CVEs (NIST) | 💥 Recent Breaches (HIBP) |\n| :--- | :--- |"
    table_body = "\n".join(table_rows)

    section = f"""## 🛰️ Threat Intelligence Feed
*Auto-updated daily · {now}*

{table_header}
{table_body}
"""

    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            content = f.read()
        
        if '' not in content:
            print("Error: Markers missing")
            return

        new_content = re.sub(r'.*?', section, content, flags=re.DOTALL)
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Success: Updated at {now}")
    except Exception as e:
        print(f"File error: {e}")

if __name__ == '__main__':
    update_readme()
