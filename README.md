<img align="right" width="200" src="octocat.gif" alt="Octocat detective" />

Hi, I’m Samuel. I’m a Security Researcher driven by a simple question: Why does security so often feel like it’s fighting the user? I believe that the strongest defenses are those that protect people without getting in their way, turning security into a seamless asset rather than a technical hurdle.I am currently focused on the intersection of AI and LLM security, specifically identifying vulnerabilities in agentic workflows and adversarial prompt engineering. My goal is to engineer robust, invisible guardrails that secure autonomous systems while preserving the intuitive experience that users expect.

<br clear="right"/>

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
## Threat Intelligence Feed
<sub>Automated · NVD + HaveIBeenPwned · Last updated: 2026-04-07 09:11 UTC</sub>

| VULNERABILITY &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | BREACH DISCLOSURE &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; |
| :--- | :--- |
| [**`CVE-2026-25641`**](https://nvd.nist.gov/vuln/detail/CVE-2026-25641) ![CRITICAL](https://img.shields.io/badge/CRITICAL-FF0000?style=flat-square) **10.0**<br><sub>SandboxJS is a JavaScript sandboxing library. Prior to 0.8.29, there is a sandbox escape vuln...</sub><br><sub>Published: `2026-02-06`</sub> | [**Crunchyroll**](https://www.google.com/search?q=Crunchyroll%20data%20breach&tbm=nws) &nbsp; <sub>`https://www.crunchyroll.com/`</sub><br><sub>**1,195,684** accounts compromised</sub><br><sub>Data: `email addresses` &nbsp;·&nbsp; Added: `2026-04-04`</sub> |
| [**`CVE-2026-25640`**](https://nvd.nist.gov/vuln/detail/CVE-2026-25640) ![HIGH](https://img.shields.io/badge/HIGH-FF6600?style=flat-square) **7.1**<br><sub>Pydantic AI is a Python agent framework for building applications and workflows with Generati...</sub><br><sub>Published: `2026-02-06`</sub> | [**SongTrivia2**](https://www.google.com/search?q=SongTrivia2%20data%20breach&tbm=nws) &nbsp; <sub>`songtrivia2.io`</sub><br><sub>**291,739** accounts compromised</sub><br><sub>Data: `auth tokens` `avatars` `email addresses` &nbsp;·&nbsp; Added: `2026-04-04`</sub> |
| [**`CVE-2026-25587`**](https://nvd.nist.gov/vuln/detail/CVE-2026-25587) ![CRITICAL](https://img.shields.io/badge/CRITICAL-FF0000?style=flat-square) **10.0**<br><sub>SandboxJS is a JavaScript sandboxing library. Prior to 0.8.29, as Map is in SAFE_PROTOYPES, i...</sub><br><sub>Published: `2026-02-06`</sub> | [**SUCCESS**](https://www.google.com/search?q=SUCCESS%20data%20breach&tbm=nws) &nbsp; <sub>`success.com`</sub><br><sub>**253,510** accounts compromised</sub><br><sub>Data: `device information` `email addresses` `ip addresses` &nbsp;·&nbsp; Added: `2026-04-01`</sub> |
<!-- SECURITY-END -->
---
