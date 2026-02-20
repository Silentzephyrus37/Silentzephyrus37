import requests
import re
import sys
from datetime import datetime
import urllib.parse

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; GitHubProfileBot/1.0)"}

def severity_label(severity):
    # Native GitHub emojis for maximum compatibility across all themes
    mapping = {
        'CRITICAL': '🔴 `CRIT` ',
        'HIGH':     '🟠 `HIGH` ',
        'MEDIUM':   '🟡 `MED` ',
        'LOW':      '🟢 `LOW` ',
    }
    return mapping.get(str(severity).upper(), '⚪ `N/A`')

def update_readme():
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    cves = get_latest_cves(3)
    breaches = get_latest_breaches(3)

    table_rows = []
    for (cve_id, desc, score, sev), (b_name, b_domain, b_count, b_date, b_data) in zip(cves, breaches):
        
        # COLUMN 1: Vulnerability (High Weight)
        status = severity_label(sev)
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        col1 = f"[`{cve_id}`]({cve_url}) <br> **{score}** &nbsp; {status}"
        
        # COLUMN 2: Analysis (Slim Weight)
        # We wrap this in a smaller font size or keep it very concise
        col2 = f"{desc[:85]}..."
        
        # COLUMN 3: Breach Impact (High Weight)
        query = urllib.parse.quote(f"{b_name} data breach news")
        news_url = f"https://www.google.com/search?q={query}&tbm=nws"
        data_tags = " ".join(f"`{d.lower()}`" for d in b_data[:2])
        col3 = f"[**{b_name}**]({news_url}) <br> {int(b_count):,} accounts <br> {data_tags}"
        
        table_rows.append(f"| {col1} | {col2} | {col3} |")

    # The &nbsp; strings force the outer columns to be wider than the center one.
    h1 = f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Vulnerability &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
    h2 = f"Analysis" # No padding here to keep it slim
    h3 = f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Breach Impact &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
    
    table_header = f"| {h1} | {h2} | {h3} |\n| :---: | :---: | :---: |"
    table_body = "\n".join(table_rows)

    section = f"""## 🛰️ Threat Intelligence Pulse
<p align="center"><i>Active Monitoring • {now}</i></p>

{table_header}
{table_body}
"""

    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            content = f.read()
        if '' not in content: return
        new_content = re.sub(r'.*?', section, content, flags=re.DOTALL)
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Update Success: {now}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    update_readme()
