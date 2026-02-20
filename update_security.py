def update_readme():
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    print("Fetching top 5 CVEs...")
    cves = get_latest_cves(5)

    print("Fetching top 5 breaches...")
    breaches = get_latest_breaches(5)

    # 1. Build Table Rows using zip to align columns
    table_rows = []
    # zip pairs the lists; if one is shorter, it stops at the end of the shorter list
    for (cve_id, desc, score, severity, published), (name, domain, count, added_date, data_classes) in zip(cves, breaches):
        
        # Format Column 1: CVEs
        icon = severity_emoji(severity)
        cve_link = f"[**{cve_id}**](https://nvd.nist.gov/vuln/detail/{cve_id})"
        cve_info = f"**CVSS {score}** {icon} <br> {desc[:80]}..." # Truncated for table fit
        
        # Format Column 2: Breaches
        classes_str = " · ".join(f"`{c}`" for c in data_classes[:2]) # Keep it to top 2 for space
        breach_info = f"**{name}** • {int(count):,} accts <br> {classes_str}"
        
        # Create the row string
        table_rows.append(f"| {cve_link} <br> {cve_info} | {breach_info} |")

    # 2. Construct the final Markdown Table
    table_header = "| ⚠️ Latest CVEs (NIST) | 💥 Recent Breaches (HIBP) |\n| :--- | :--- |"
    table_body = "\n".join(table_rows)

    section = f"""## 🛰️ Threat Intelligence Feed
*Auto-updated daily · {now}*

{table_header}
{table_body}

"""

    # 3. File injection logic
    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print("ERROR: README.md not found")
        sys.exit(1)

    if '' not in content:
        print("ERROR: Could not find markers in README.md")
        sys.exit(1)

    new_content = re.sub(
        r'.*?',
        section,
        content,
        flags=re.DOTALL
    )

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"README updated successfully at {now}")
