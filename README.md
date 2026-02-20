Hi, I’m Samuel. I’m a Security Researcher driven by a simple question: Why does security so often feel like it’s fighting the user? I believe that the strongest defenses are those that protect people without getting in their way, turning security into a seamless asset rather than a technical hurdle.I am currently focused on the intersection of AI and LLM security, specifically identifying vulnerabilities in agentic workflows and adversarial prompt engineering. My goal is to engineer robust, invisible guardrails that secure autonomous systems while preserving the intuitive experience that users expect.

## 📰 Reading List

Things I've read and kept thinking about. Updated when something actually sticks.

**01 · [Indirect Prompt Injection Attacks Against LLM-Integrated Applications](https://arxiv.org/abs/2302.12173)**
`Greshake et al. · 2023` &nbsp; `Prompt Injection` &nbsp; `Agentic Security`
The paper that made me realize how wide the attack surface actually is once you start chaining LLM calls. Required reading before building anything agentic.

**02 · [MITRE ATLAS: Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)**
`MITRE · Ongoing` &nbsp; `AI Red Teaming` &nbsp; `Threat Modeling`
ATT&CK for ML systems. I go back to this constantly when thinking through what a detection pipeline should actually be watching for.

**03 · [Zero Trust Architecture — NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final)**
`NIST · 2020` &nbsp; `Zero Trust` &nbsp; `Architecture`
Takes some effort to get through but worth it. A lot of how I think about authentication and trust scoring traces back to the principles in here.

**04 · [SoK: Attacks on Large Language Models](https://arxiv.org/abs/2402.06674)**
`Yao et al. · 2024` &nbsp; `LLM Security` &nbsp; `Survey`
The most complete map of the LLM attack landscape I've come across. Good place to start if you're trying to understand the threat surface before jumping into red teaming.

---

![GitHub Space Shooter](game.gif)


---

<!-- SECURITY-START -->
## 🛰 Threat Intelligence Feed


### ⚠️ Latest CVEs

**1. [`CVE-1999-0095`](https://nvd.nist.gov/vuln/detail/CVE-1999-0095)** — CVSS 10.0 ⚪ None · 1988-10-01
The debug command in Sendmail is enabled, allowing attackers to execute commands as root.

**2. [`CVE-1999-0082`](https://nvd.nist.gov/vuln/detail/CVE-1999-0082)** — CVSS 10.0 ⚪ None · 1988-11-11
CWD ~root command in ftpd allows root access.

**3. [`CVE-1999-1471`](https://nvd.nist.gov/vuln/detail/CVE-1999-1471)** — CVSS 7.2 ⚪ None · 1989-01-01
Buffer overflow in passwd in BSD based operating systems 4.3 and earlier allows local users to gain root privileges by specifying a long shell or G...

**4. [`CVE-1999-1122`](https://nvd.nist.gov/vuln/detail/CVE-1999-1122)** — CVSS 4.6 ⚪ None · 1989-07-26
Vulnerability in restore in SunOS 4.0.3 and earlier allows local users to gain privileges.

**5. [`CVE-1999-1467`](https://nvd.nist.gov/vuln/detail/CVE-1999-1467)** — CVSS 10.0 ⚪ None · 1989-10-26
Vulnerability in rcp on SunOS 4.0.x allows remote attackers from trusted hosts to execute arbitrary commands as root, possibly related to the confi...

---

### 💥 Recent Breaches 

**1. CarMax** `carmax.com` · 431,371 accounts · Added 2026-02-20
Exposed: `Email addresses` · `Names` · `Phone numbers`

**2. Figure** `figure.com` · 967,178 accounts · Added 2026-02-18
Exposed: `Dates of birth` · `Email addresses` · `Names`

**3. CanadaGoose** `canadagoose.com` · 581,877 accounts · Added 2026-02-17
Exposed: `Device information` · `Email addresses` · `IP addresses`

**4. UniversityOfPennsylvania** `upenn.edu` · 623,750 accounts · Added 2026-02-16
Exposed: `Charitable donations` · `Dates of birth` · `Email addresses`

**5. APOIAse** `apoia.se` · 450,764 accounts · Added 2026-02-16
Exposed: `Email addresses` · `Names` · `Physical addresses`
<!-- SECURITY-END -->
---


