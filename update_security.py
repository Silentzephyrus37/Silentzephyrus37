import requests
import re
import sys
from datetime import datetime
import urllib.parse

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; GitHubProfileBot/1.0)"
}

def get_latest_cves(count=6):
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
            
            # Slim description for dashboard feel
            desc = (desc[:100] + '...') if len(desc) > 100 else desc

            score = "N/A"
            severity = "N/A"
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
        return [("N/A", "Data unavailable", "0.0", "N/A")] * count

def get_latest_breaches(count=6):
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
            count_val = b.get('PwnCount', 0)
            data_classes = b.get('DataClasses', [])[:3] 
            results.append((name, domain, count_val, data_classes))
        return results
    except Exception as e:
        print(f"Breach fetch error: {e}")
        return [("N/A", "N/A", 0, [])] * count

def severity_style(severity):
    mapping = {
        'CRITICAL': '🔴 `CRIT` ',
        'HIGH':     '🟠 `HIGH` ',
        'MEDIUM':   '🟡 `MED` ',
        'LOW':      '🟢 `LOW` ',
    }
    return mapping.get(str(severity).upper(), '⚪ `N/A`')

def update_readme():
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    cves = get_latest_cves(6)
    breaches = get_latest_breaches(6)

    table_rows = []
    # Spacer trick to force horizontal stretch
    spacer = "&nbsp;" * 30
    
    for (cve_id, desc, score, sev), (b_name, b_domain, b_count, b_data) in zip(cves, breaches):
        # Column 1: Analysis
        status = severity_style(sev)
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        cve_col = f"[`{cve_id}`]({cve_url}) &nbsp; **{score}** &nbsp; {status} <br> {desc}"
        
        # Column 2: Breach News Navigation
        query = urllib.parse.quote(f"{b_name} {b_domain} breach news 2026")
        news_url = f"https://www.google.com/search?q={query}&tbm=nws"
        data_str = " ".join(f"`{d.lower()}`" for d in b_data)
        breach_col = f"[**{b_name}**]({news_url}) • {int(b_count):,} <br> {data_str}"
        
        table_rows.append(f"| {cve_col} | {breach_col} |")

    # Stretch the headers
    h_left = f"Threat Analysis &nbsp; {spacer}"
    h_right = f"Recent Breach News &nbsp; {spacer}"
    table_header = f"| {h_left} | {h_right} |\n| :---: | :---: |"
    table_body = "\n".join(table_rows)

    section = f"""## 🛰️ Threat Intelligence Pulse
<p align="center"><i>Refresh Frequency: Daily • {now}</i></p>

{table_header}
{table_body}
"""

    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            content = f.read()
        
        if '' not in content:
            print("Error: marker not found")
            return

        new_content = re.sub(r'.*?', section, content, flags=re.DOTALL)
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Success: README updated at {now}")
    except Exception as e:
        print(f"File writing error: {e}")

if __name__ == '__main__':
    update_readme()
