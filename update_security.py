import requests
import re
import sys
from datetime import datetime
import urllib.parse

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; GitHubProfileBot/1.0)"}

def severity_label(severity):
    # Native GitHub-friendly emojis
    mapping = {
        'CRITICAL': '🔴 `CRIT` ',
        'HIGH':     '🟠 `HIGH` ',
        'MEDIUM':   '🟡 `MED` ',
        'LOW':      '🟢 `LOW` ',
    }
    return mapping.get(str(severity).upper(), '⚪ `N/A`')

def get_latest_cves(count=3):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={count}&startIndex=0"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        data = r.json()
        results = []
        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            cve_id = cve['id']
            desc = next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), 'No description.')
            score = "N/A"
            severity = "N/A"
            metrics = cve.get('metrics', {})
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if key in metrics and metrics[key]:
                    try:
                        score = metrics[key][0]['cvssData']['baseScore']
                        severity = metrics[key][0]['cvssData']['baseSeverity']
                        break
                    except: continue
            results.append((cve_id, desc, score, severity))
        return results
    except: return [("N/A", "N/A", "0.0", "N/A")] * count

def get_latest_breaches(count=3):
    try:
        url = "https://haveibeenpwned.com/api/v3/breaches"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        breaches = r.json()
        breaches.sort(key=lambda x: x.get('AddedDate', ''), reverse=True)
        results = []
        for b in breaches[:count]:
            results.append((b.get('Name', 'Unknown'), b.get('Domain', 'N/A'), b.get('PwnCount', 0), b.get('DataClasses', [])[:2]))
        return results
    except: return [("N/A", "N/A", 0, [])] * count

def update_readme():
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    cves, breaches = get_latest_cves(3), get_latest_breaches(3)
    table_rows = []
    
    for (cve_id, desc, score, sev), (b_name, b_domain, b_count, b_data) in zip(cves, breaches):
        # Column 1: Vulnerability (Clickable ID + Status)
        status = severity_label(sev)
        col1 = f"[`{cve_id}`](https://nvd.nist.gov/vuln/detail/{cve_id}) <br> **{score}** &nbsp; {status}"
        
        # Column 2: Analysis (Small font for 'Slim' look)
        col2 = f"<sub>{desc[:80]}...</sub>"
        
        # Column 3: Breach News (Google News Link)
        query = urllib.parse.quote(f"{b_name} data breach news 2026")
        news_url = f"https://www.google.com/search?q={query}&tbm=nws"
        tags = " ".join(f"`{d.lower()}`" for d in b_data)
        col3 = f"[**{b_name}**]({news_url}) ↗️ <br> {int(b_count):,} accounts <br> {tags}"
        
        table_rows.append(f"| {col1} | {col2} | {col3} |")

    # Header Stretching Trick
    h1 = "&nbsp;" * 15 + "Vulnerability" + "&nbsp;" * 15
    h2 = "Analysis"
    h3 = "&nbsp;" * 15 + "Breach News" + "&nbsp;" * 15
    
    table_header = f"| {h1} | {h2} | {h3} |\n| :---: | :---: | :---: |"
    section = f"\n## 🛰️ Threat Intelligence Pulse\n<p align='center'><i>Active Monitoring • {now}</i></p>\n\n{table_header}\n" + "\n".join(table_rows) + "\n"

    with open('README.md', 'r', encoding='utf-8') as f:
        content = f.read()
    new_content = re.sub(r'.*?', section, content, flags=re.DOTALL)
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)

if __name__ == '__main__':
    update_readme()
