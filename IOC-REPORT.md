# 📋 Consolidated IOC Report — Phishing Email Investigations

**Report Date:** July 2025
**Analyst:** Shasaank Sridhar
**Cases Covered:** CASE-001, CASE-002, CASE-003
**Classification:** TLP:CLEAR — For public sharing and educational use

---

## Executive Summary

This report consolidates all Indicators of Compromise (IOCs) extracted from three phishing email investigations. The IOCs are organized by type, tagged with confidence ratings, and include recommended defensive actions.

All indicators have been **defanged** to prevent accidental access (e.g., `[.]` replaces `.` in domains, `hxxps` replaces `https`).

| Case | Attack Type | Primary IOC Category | Verdict |
|---|---|---|---|
| [CASE-001](case-001-malicious-iso-phishing/) | Malicious ISO attachment | File hashes | 🔴 Malicious |
| [CASE-002](case-002-amazon-account-lock-phishing/) | Credential harvesting link | URLs / Domains | 🔴 Phishing |
| [CASE-003](case-003-bradesco-livelo-phishing/) | Brand impersonation link | URLs / Domains | 🔴 Phishing |

---

## IOCs by Type

### 🔐 File Hashes

> From CASE-001 — `quotation.iso` attachment (20/41 VirusTotal detections)

| Algorithm | Hash | Confidence |
|---|---|---|
| **SHA-256** | `75fdb848eac332b4ca7d88f497e7ba7ebbb9a798d825b28cf1f87b9d7149e87f` | 🔴 High |
| **SHA-1** | `3fe45f8cd20cd7c63e55e3918dac1d3a0d7fb05a` | 🔴 High |
| **MD5** | `6aef1d7f88e8aa450a0c604b4caee5ba` | 🔴 High |

**Recommended Actions:**
- Block hashes at email gateway and endpoint protection
- Add to SIEM watchlists
- Hunt across file telemetry

---

### 🌐 Malicious URLs

| URL | Source | Confidence | Case |
|---|---|---|---|
| `hxxps://amaozn[.]zzyuchengzhika[.]cn/?mailtoken=saintington73@outlook[.]com` | Email body | 🔴 High | 002 |
| `hxxps://blog1seguimentmydomaine2bra[.]me/` | Decoded HTML | 🔴 High | 003 |

**Recommended Actions:**
- Block at web proxy / DNS filtering
- Search proxy and browser logs for historical access
- Report to domain registrars

---

### 🏷️ Malicious Domains

| Domain | Role | Confidence | Case |
|---|---|---|---|
| `amaozn[.]zzyuchengzhika[.]cn` | Phishing landing page (typosquatted Amazon) | 🔴 High | 002 |
| `zzyuchengzhika[.]cn` | Parent domain of phishing site | 🟠 Medium-High | 002 |
| `blog1seguimentmydomaine2bra[.]me` | Phishing landing page | 🔴 High | 003 |

**Recommended Actions:**
- Block domains and subdomains at DNS level
- Monitor for domain variations / siblings
- Review DNS query logs

---

### 📧 Malicious / Suspicious Email Addresses

| Email Address | Role | Confidence | Case |
|---|---|---|---|
| `amazon@zyevantoby[.]cn` | Sender (From + Return-Path) | 🔴 High | 002 |
| `Paol.Reggiani@moss[.]it` | Claimed sender (From) | 🟡 Medium | 001 |
| `Paolo.Reggiani@moss[.]it` | Envelope sender (Return-Path) | 🟡 Medium | 001 |
| `banco.bradesco@atendimento[.]com[.]br` | Spoofed sender (From) | 🟠 Medium-High | 003 |
| `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` | Envelope sender (Return-Path) | 🟠 Medium-High | 003 |

**Recommended Actions:**
- Block sender addresses at email gateway
- Search mailboxes for messages from these addresses
- Hunt for related Message-IDs

---

### 🖥️ Sending Infrastructure — IP Addresses

| IP Address | Associated Hostname | Provider | Confidence | Case |
|---|---|---|---|---|
| `213[.]227[.]154[.]65` | Sending server for `moss[.]it` | Unknown | 🟡 Medium | 001 |
| `45[.]156[.]23[.]138` | `mta0[.]zyevantoby[.]cn` | Unknown | 🟠 Medium-High | 002 |
| `137[.]184[.]34[.]4` | `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` | DigitalOcean (AS14061) | 🟠 Medium-High | 003 |

**Recommended Actions:**
- Search mail logs for other messages from these IPs
- Investigate associated hostnames
- Consider blocking after validation (avoid blocking shared hosting ranges without context)

---

### 🖧 Sending Infrastructure — Hostnames

| Hostname | Role | Confidence | Case |
|---|---|---|---|
| `mta0[.]zyevantoby[.]cn` | Mail transfer agent | 🟠 Medium-High | 002 |
| `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` | VPS hostname (Postfix origin) | 🟠 Medium-High | 003 |

---

### 📮 Sender Domains

| Domain | Role | Confidence | Case |
|---|---|---|---|
| `zyevantoby[.]cn` | Sender domain (attacker-controlled) | 🟠 Medium-High | 002 |
| `moss[.]it` | Claimed sender domain (status unclear) | 🟡 Low-Medium | 001 |
| `atendimento[.]com[.]br` | Spoofed sender domain | 🟡 Medium | 003 |

> **Note on `moss[.]it`:** This domain appeared legitimate. It may have been compromised or spoofed. Do not block without further WHOIS/DNS investigation.

> **Note on `atendimento[.]com[.]br`:** Evidence did not confirm the entire domain was malicious. May have been spoofed.

---

### 📑 Message-IDs (Campaign Correlation)

| Message-ID | Case |
|---|---|
| `20200114000605.14E3983143C82AAA@moss[.]it` | 001 |
| `<000756bf516d$9bad2034$6e617fb$@vinuquo>` | 002 |
| `<20230919183549.39DEA3F725@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>` | 003 |

**Recommended Actions:**
- Search all mailboxes for these Message-IDs
- Use for campaign correlation across the environment
- Cross-reference with SIEM data

---

### 📝 Suspicious Filenames

| Filename | Type | Confidence | Case |
|---|---|---|---|
| `quotation.iso` | ISO disk image attachment | 🟡 Medium | 001 |

---

## Contextual Indicators (NOT Malicious)

The following indicators appeared in the investigations but are **legitimate infrastructure** and should **NOT** be blocked:

| Indicator | Reason |
|---|---|
| `emea01[.]safelinks[.]protection[.]outlook[.]com` | Microsoft Safe Links — legitimate URL wrapping service |
| `fonts[.]googleapis[.]com` | Google Fonts CDN |
| `fonts[.]gstatic[.]com` | Google static content CDN |
| Microsoft Office 365 internal mail hosts | Legitimate mail delivery infrastructure |
| `www[.]facebook[.]com/amir[.]boyka[.]7` | Present in Case 002 source — not confirmed malicious |
| Recipient email addresses | Victim identifiers, not attacker IOCs |

---

## Infrastructure Summary

### CASE-001: Malicious ISO Phishing

```
moss[.]it (sender domain)
  └── 213[.]227[.]154[.]65 (sending IP)
       └── quotation.iso (malicious ISO attachment)
            └── Windows executable payload (embedded)
```

### CASE-002: Amazon Credential Harvesting

```
zyevantoby[.]cn (sending domain)
  └── mta0[.]zyevantoby[.]cn (MTA hostname)
       └── 45[.]156[.]23[.]138 (sending IP)

zzyuchengzhika[.]cn (phishing parent domain)
  └── amaozn[.]zzyuchengzhika[.]cn (typosquatted landing page)
       └── ?mailtoken= (per-victim tracking)
```

### CASE-003: Bradesco/Livelo Brand Impersonation

```
DigitalOcean AS14061 (hosting provider)
  └── ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (VPS)
       └── 137[.]184[.]34[.]4 (sending IP)
            └── Postfix as root (userid 0)

blog1seguimentmydomaine2bra[.]me (phishing domain)
  └── Landing page (credential/payment collection)
```

---

## MITRE ATT&CK Techniques Observed

| Technique | Name | Cases |
|---|---|---|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment | 001 |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | 002, 003 |
| [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | User Execution: Malicious Link | 002, 003 |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | 001 |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | 001, 002, 003 |

---

## Usage Notes

- **SHA-256** is the preferred hash for file-based IOCs
- All domains and IPs are **defanged** — restore brackets before using in detection rules
- IOCs should be validated against your environment before broad blocking
- Cloud IPs (e.g., DigitalOcean) may be reassigned — time-scope your blocks
- Message-IDs are most useful for historical mailbox hunting

---

## Disclaimer

> ⚠️ These IOCs are provided for **educational and defensive purposes only**. Do not access, visit, or interact with any of the listed domains, URLs, or IP addresses. All indicators are from real phishing samples analyzed in a sandboxed environment.

---

[← Back to Main Repository](README.md)
