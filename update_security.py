import requests
import re
import sys
import urllib.parse
from datetime import datetime, timedelta

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; GitHubProfileBot/1.0)"}

def severity_label(severity):
    return {
        'CRITICAL': '🔴 CRIT',
        'HIGH':     '🟠 HIGH',
        'MEDIUM':   '🟡 MED',
        'LOW':      '🟢 LOW',
    }.get(str(severity).upper(), '⚪ N/A') if severity else '⚪ N/A'

def get_latest_cves(count=3):
    try:
        end   = datetime.utcnow()
        start = end - timedelta(days=60)
        fmt   = "%Y-%m-%dT%H:%M:%S.000"
        url   = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={start.strftime(fmt)}"
            f"&pubEndDate={end.strftime(fmt)}"
            f"&resultsPerPage=100"
        )
        r = requests.get(url, headers=HEADERS, timeout=25)
        r.raise_for_status()
        vulns = r.json().get('vulnerabilities', [])
        vulns.sort(key=lambda x: x['cve'].get('published', ''), reverse=True)

        results = []
        for item in vulns:
            if len(results) == count:
                break
            cve    = item['cve']
            cve_id = cve['id']
            desc   = next(
                (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), ''
            )
            reject_kw = ['** REJECT', '** DISPUTED', 'DO NOT USE', '** RESERVED', 'not yet assigned']
            if any(kw in desc for kw in reject_kw) or len(desc) < 30:
                continue
            score, severity = None, None
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                m = cve.get('metrics', {}).get(key)
                if m:
                    try:
                        score    = m[0]['cvssData']['baseScore']
                        severity = m[0]['cvssData']['baseSeverity']
                        break
                    except (KeyError, IndexError):
                        continue
            if not score:
                continue
            if len(desc) > 100: desc = desc[:97] + "..."
            published = cve.get('published', '')[:10]
            results.append((cve_id, desc, score, severity, published))

        print(f"Got {len(results)} CVEs")
        return results
    except Exception as e:
        print(f"CVE error: {e}")
        return [("N/A", "Could not fetch.", "N/A", "N/A", "N/A")] * count


def get_latest_breaches(count=3):
    try:
        r = requests.get("https://haveibeenpwned.com/api/v3/breaches", headers=HEADERS, timeout=20)
        r.raise_for_status()
        breaches = sorted(r.json(), key=lambda x: x.get('AddedDate',''), reverse=True)
        results  = []
        for b in breaches[:count]:
            results.append((
                b.get('Name','Unknown'),
                b.get('Domain','N/A'),
                b.get('PwnCount', 0),
                b.get('AddedDate','')[:10],
                b.get('DataClasses',[])[:3]
            ))
        print(f"Got {len(results)} breaches")
        return results
    except Exception as e:
        print(f"Breach error: {e}")
        return [("N/A","N/A",0,"N/A",[])] * count


def update_readme():
    now      = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    cves     = get_latest_cves(3)
    breaches = get_latest_breaches(3)

    rows = []
    for (cve_id, desc, score, sev, published), (name, domain, count, added, classes) in zip(cves, breaches):
        sev_str  = severity_label(sev)
        tags     = " &nbsp; ".join(f"`{d.lower()}`" for d in classes) if classes else "`N/A`"
        query    = urllib.parse.quote(f"{name} data breach")
        news_url = f"https://www.google.com/search?q={query}&tbm=nws"

        col_cve = (
            f"**[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})**"
            f"&nbsp;&nbsp;`{score}` {sev_str}&nbsp;&nbsp;📅 `{published}`"
            f"<br><sub>{desc}</sub>"
        )
        col_breach = (
            f"**[{name}]({news_url})**&nbsp;&nbsp;`{domain}`"
            f"<br>💥 `{int(count):,}` accounts&nbsp;&nbsp;📅 `{added}`"
            f"<br><sub>{tags}</sub>"
        )
        rows.append(f"| {col_cve} | {col_breach} |")

    # Use HTML spacers to force equal 50/50 column widths
    spacer = "&nbsp;" * 40
    table = (
        f"| ⚠️ Latest CVE {spacer} | 💥 Latest Breach {spacer} |\n"
        "| :--- | :--- |\n"
        + "\n".join(rows)
    )

    section = (
        f"<!-- SECURITY-START -->\n"
        f"## 🛰 Threat Intelligence Feed\n"
        f"<sub>Auto-updated daily · {now}</sub>\n\n"
        f"{table}\n"
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
