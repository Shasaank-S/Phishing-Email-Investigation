# 🛡️ Phishing Email Investigation Lab

[![Cases](https://img.shields.io/badge/Cases_Analyzed-3-green.svg)](#case-studies)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red.svg)](#mitre-attck-coverage)

> A hands-on cybersecurity project demonstrating real-world phishing email investigation methodology. Each case study walks through the complete analyst workflow — from evidence preservation through IOC extraction, threat-intelligence enrichment, and incident documentation.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Case Studies](#case-studies)
- [Skills Demonstrated](#skills-demonstrated)
- [Tools Used](#tools-used)
- [MITRE ATT\&CK Coverage](#mitre-attck-coverage)
- [Investigation Methodology](#investigation-methodology)
- [IOC Report](#ioc-report)
- [Blog Post](#blog-post)
- [Disclaimer](#disclaimer)

---

## Overview

Phishing remains the most prevalent initial access vector in cyberattacks. This repository contains three complete phishing email investigations that I performed as part of my security analyst portfolio. Each case involves a real phishing email sample and follows a structured, repeatable investigation workflow used in Security Operations Centers (SOCs) worldwide.

Every investigation covers:

- **Evidence preservation** — hashing original `.eml` samples
- **Header analysis** — sender verification, Received-header tracing, Message-ID inspection
- **Authentication checks** — SPF, DKIM, and DMARC interpretation
- **Social-engineering analysis** — identifying persuasion techniques and attacker objectives
- **Attachment / URL analysis** — static reputation, sandbox execution, safe link decoding
- **IOC extraction** — defanged indicators with confidence ratings
- **MITRE ATT&CK mapping** — only techniques supported by evidence
- **Incident response recommendations** — containment, remediation, and long-term controls

---

## Case Studies

| # | Case | Attack Type | Verdict | Severity | Write-Up |
|---|------|------------|---------|----------|----------|
| 001 | [Malicious ISO Attachment Phishing](case-001-malicious-iso-phishing/) | Malware delivery via ISO disk image | 🔴 Malicious | High | [Read →](case-001-malicious-iso-phishing/README.md) |
| 002 | [Amazon Account-Lock Phishing](case-002-amazon-account-lock-phishing/) | Credential harvesting via phishing link | 🔴 Phishing | High | [Read →](case-002-amazon-account-lock-phishing/README.md) |
| 003 | [Bradesco Livelo Points Phishing](case-003-bradesco-livelo-phishing/) | Brand impersonation via phishing link | 🔴 Phishing | High | [Read →](case-003-bradesco-livelo-phishing/README.md) |

### Quick Comparison

| Feature | Case 001 | Case 002 | Case 003 |
|---------|----------|----------|----------|
| Attack vector | ISO attachment | Embedded link | Embedded link |
| Brand impersonated | Business/Invoice | Amazon | Bradesco/Livelo |
| Authentication | SPF fail, no DKIM, DMARC fail | No SPF record, DKIM neutral | SPF temperror, no DKIM, DMARC temperror |
| Attachment | `quotation.iso` (20/41 VT detections) | None | None |
| Sandbox used | ANY.RUN | N/A | N/A |
| Key technique | ISO disk-image malware delivery | Typosquatted domain + Safe Links wrapping | VPS-generated email + Base64-encoded body |

---

## Skills Demonstrated

- 📧 Email header analysis and sender verification
- 🔐 SPF, DKIM, and DMARC interpretation
- 🔍 Received-header tracing and infrastructure mapping
- 🎭 Social-engineering technique identification
- 📎 Static attachment analysis and hash generation
- 🧪 Sandbox result interpretation (ANY.RUN)
- 🌐 URL extraction, Safe Links decoding, and typosquatting detection
- 🔗 Threat-intelligence enrichment (VirusTotal, URLVoid, MXToolbox)
- 🗂️ IOC extraction with confidence classification
- 🗺️ MITRE ATT&CK technique mapping
- 📝 Professional incident documentation
- 🛡️ Safe indicator defanging

---

## Tools Used

<table>
  <tr>
    <td align="center"><strong>Platform</strong></td>
    <td>Kali Linux</td>
  </tr>
  <tr>
    <td align="center"><strong>Email Client</strong></td>
    <td>Mozilla Thunderbird</td>
  </tr>
  <tr>
    <td align="center"><strong>Phishing Analysis</strong></td>
    <td>PhishTool</td>
  </tr>
  <tr>
    <td align="center"><strong>Header Analysis</strong></td>
    <td>MXToolbox · PowerDMARC</td>
  </tr>
  <tr>
    <td align="center"><strong>Threat Intelligence</strong></td>
    <td>VirusTotal · URLVoid · Google Safe Browsing</td>
  </tr>
  <tr>
    <td align="center"><strong>Sandbox</strong></td>
    <td>ANY.RUN</td>
  </tr>
  <tr>
    <td align="center"><strong>Encoding</strong></td>
    <td>Base64 decoding tools</td>
  </tr>
</table>

---

## MITRE ATT&CK Coverage

| Tactic | ID | Technique | Observed In | Evidence & Context |
|---|---|---|---|---|
| **Initial Access** | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment | Case 001 | Inbound email delivering malicious `quotation.iso` attachment |
| **Initial Access** | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | Case 002, Case 003 | Inbound emails delivering typosquatted Amazon & Bradesco credential harvesting links |
| **Execution** | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | User Execution: Malicious Link | Case 002, Case 003 | Coercing victims to click embedded phishing URLs ("Review Account", "Redeem Points") |
| **Execution** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | Case 001 | Mounting `.iso` disk image and executing embedded Windows Trojan executable |
| **Defense Evasion** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Container Files | Case 001 | Wrapping executable payload inside ISO container to bypass email gateway filters |
| **Defense Evasion** | [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Case 001, Case 002, Case 003 | Impersonating trusted brands (Moss.it, Amazon, Banco Bradesco / Livelo) |
| **Resource Development** | [T1584](https://attack.mitre.org/techniques/T1584/) | Compromised Infrastructure | Case 001, Case 003 | Leveraging compromised business mail servers (`moss.it`) & DigitalOcean VPS droplets |

---

## Investigation Methodology

Every case in this repository follows the same structured workflow:

```
┌─────────────────────────────────────┐
│       1. Evidence Preservation      │
│    Hash the original .eml sample    │
├─────────────────────────────────────┤
│         2. Header Analysis          │
│  Sender, Return-Path, Message-ID,   │
│  Received headers, timestamps       │
├─────────────────────────────────────┤
│     3. Authentication Analysis      │
│      SPF / DKIM / DMARC checks      │
├─────────────────────────────────────┤
│    4. Body & Social Engineering     │
│  Theme, persuasion techniques,      │
│  attacker objectives                │
├─────────────────────────────────────┤
│   5. Attachment / URL Analysis      │
│  Hashing, extraction, VirusTotal,   │
│  sandbox, Safe Links decoding       │
├─────────────────────────────────────┤
│      6. IOC Extraction              │
│  Defanged indicators with           │
│  confidence ratings                 │
├─────────────────────────────────────┤
│    7. Threat Intel Enrichment       │
│  VirusTotal, URLVoid, MXToolbox     │
├─────────────────────────────────────┤
│     8. MITRE ATT&CK Mapping         │
│  Only evidence-supported techniques │
├─────────────────────────────────────┤
│  9. Risk Assessment & Verdict       │
├─────────────────────────────────────┤
│   10. Incident Documentation        │
│  Recommendations & lessons learned  │
└─────────────────────────────────────┘
```

---

## IOC Report

📋 A consolidated **[IOC Report](IOC-REPORT.md)** is available with all indicators of compromise organized by type:

- File hashes (SHA-256, SHA-1, MD5)
- Malicious URLs and domains
- Sender email addresses
- Sending infrastructure (IPs, hostnames, mail servers)
- Message-IDs for campaign correlation
- Contextual indicators (legitimate infrastructure to NOT block)
- Infrastructure mapping trees for each case

---

## Blog Post

📝 I wrote a detailed walkthrough of **Case 001 (Malicious ISO Phishing)** on Medium:

<!-- TODO: Replace with your actual Medium URL -->
**[Dissecting a Malicious ISO Phishing Email — A Complete SOC Analyst Investigation](https://medium.com/@YOUR_MEDIUM_USERNAME/dissecting-malicious-iso-phishing-email)**

---

## Disclaimer

> ⚠️ **Educational Purpose Only**
>
> This repository is intended for **educational and research purposes only**. The email samples, indicators of compromise (IOCs), and analysis are provided to demonstrate phishing investigation methodology.
>
> - All malicious indicators have been **defanged** (e.g., `hxxps://`, `[.]`) to prevent accidental access.
> - Do **not** attempt to access, visit, or interact with any domains, URLs, or IP addresses mentioned in these reports.
> - The `.eml` samples are real phishing emails. Handle them in a **sandboxed environment** only.
> - The author is not responsible for any misuse of the information or samples provided.

> ℹ️ **Note on Project Documentation:** The hands-on phishing analysis, header extraction, evidence gathering, and threat investigation were performed manually. The markdown write-ups, formatting, and documentation structure were refined and polished with AI assistance.

---

## Author

**Shasaank Sridhar** — Cybersecurity Analyst & Security Researcher

- 🌐 [shasaanksridhar.me](https://shasaanksridhar.me)
- 💼 [LinkedIn](https://linkedin.com/in/shasaank-sridhar)
- 🐙 [GitHub](https://github.com/Shasaank-S)

---

<p align="center">
  <em>If you found this useful, consider giving it a ⭐</em>
</p>
