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
            
            # Gentle truncation for readability
            desc = (desc[:160] + '...') if len(desc) > 160 else desc

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
        return [("N/A", "Data unavailable", 0, "N/A")] * count

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
            data_classes = b.get('DataClasses', [])[:3] 
            results.append((name, count_val, data_classes))
        return results
    except Exception as e:
        print(f"Breach fetch error: {e}")
        return [("N/A", 0, [])] * count

def severity_style(severity):
    # Using standard Unicode circles - GitHub renders these natively with no external loading issues.
    mapping = {
        'CRITICAL': '🔴 `CRIT` ',
        'HIGH':     '🟠 `HIGH` ',
        'MEDIUM':   '🟡 `MED` ',
        'LOW':      '🟢 `LOW` ',
    }
    return mapping.get(str(severity).upper(), '⚪ `N/A`')

def update_readme():
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    
    # Increased count to 6 as requested
    cves = get_latest_cves(6)
    breaches = get_latest_breaches(6)

    table_rows = []
    for (cve_id, desc, score, sev), (b_name, b_domain, b_count, b_date, b_data) in zip(cves, breaches):
        
        # COLUMN 1: Optimized Threat Analysis
        status = severity_style(sev)
        # Compact header: ID | SCORE | STATUS
        cve_header = f"[`{cve_id}`](https://nvd.nist.gov/vuln/detail/{cve_id}) &nbsp; **{score}** &nbsp; {status}"
        short_desc = (desc[:90] + '...') if len(desc) > 90 else desc
        cve_col = f"{cve_header} <br> {short_desc}"
        
        # COLUMN 2: Optimized & Clickable Recent Breaches
        # Navigates to the domain when clicked
        breach_link = f"[**{b_name}**](https://{b_domain})" if b_domain != 'N/A' else f"**{b_name}**"
        data_str = " ".join(f"`{d.lower()}`" for d in b_data)
        breach_col = f"{breach_link} • {int(b_count):,} <br> {data_str}"
        
        table_rows.append(f"| {cve_col} | {breach_col} |")

    # Double-centered alignment
    table_header = "| Threat Analysis | Recent Breaches |\n| :---: | :---: |"
    table_body = "\n".join(table_rows)

    section = f"""## 🛰️ Threat Intelligence
<p align="center"><i>Refresh: Daily • {now}</i></p>

{table_header}
{table_body}

"""
    
    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            content = f.read()
        
        if '' not in content:
            print("Error: marker not found in README.md")
            return

        new_content = re.sub(r'.*?', section, content, flags=re.DOTALL)
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Successfully updated README at {now}")
    except Exception as e:
        print(f"File writing error: {e}")

if __name__ == '__main__':
    update_readme()
