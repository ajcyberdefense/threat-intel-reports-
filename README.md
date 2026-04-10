# threat-intel-reports-
# Threat Investigation Report: Phishing Domain Impersonating Michigan DMV

**Date:** April 9, 2026  
**Analyst:** Anthony Joseph Jr
**Classification:** TLP:WHITE — Unrestricted  
**Threat Type:** Credential Phishing — Government Impersonation  
**Confidence Level:** High  
**Status:** Active / Under Monitoring

---

## 1. Executive Summary

On April 9, 2026, a suspicious URL was identified and flagged for investigation. The URL, `michigan.govqo[.]cyou/dmv`, was designed to impersonate the Michigan Department of Motor Vehicles (DMV) through domain typosquatting.

Through sandbox analysis (ANY.RUN), passive DNS reconnaissance (urlscan.io), and WHOIS investigation, the domain was confirmed with **high confidence** to be phishing infrastructure targeting Michigan residents for credential and personal data theft.

Despite an automated verdict of "No threats detected" from the sandbox environment, manual analysis of domain registration data, hosting infrastructure, TLS certificate age, and naming conventions conclusively identified the site as malicious.

> **Key Takeaway:** Automated sandbox verdicts alone are insufficient for phishing detection. OSINT enrichment and infrastructure analysis are essential for identifying credential-harvesting campaigns that don't rely on malware delivery.

---

## 2. Indicators of Compromise (IOCs)

| Indicator | Value | Context |
|-----------|-------|---------|
| **URL** | `michigan.govqo[.]cyou/dmv` | Primary phishing URL |
| **Domain** | `govqo[.]cyou` | Malicious parent domain |
| **IP Address** | `47.245.176.247` | Alibaba Cloud (CN) |
| **Registrar** | Gname.com Pte. Ltd. | Singapore-based registrar |
| **TLS Issuer** | Let's Encrypt (R13) | 12-hour-old certificate |
| **ASN** | AS45102 — ALIBABA-CN-NET | Frequently abused cloud provider |
| **SHA-256** | `C1F21464E607A37510B224E4144B1CA2B58D799CA0393AD5435AD5AA500F177B` | URL hash (ANY.RUN) |
| **Domain Age** | < 24 hours (registered April 9, 2026) | Disposable infrastructure |

> **Note:** Indicators are defanged using `[.]` notation per standard threat intelligence sharing practices to prevent accidental navigation.

---

## 3. Analysis Methodology

The investigation followed a structured, multi-layered approach using open-source intelligence (OSINT) tools and sandbox detonation:

### 3.1 Sandbox Detonation — ANY.RUN

The suspicious URL was submitted to [ANY.RUN](https://any.run) for dynamic analysis in a Windows 10 sandbox environment using Microsoft Edge. The sandbox monitored:

- Process creation and process tree behavior
- File system activity (drops, modifications)
- Registry modifications
- Network connections and DNS requests
- Suricata IDS signature matching against captured traffic

**ANY.RUN Report:** [Full Analysis](https://app.any.run/tasks/074c68a5-0411-48a0-b6d1-c470ed7c35cf)

#### ANY.RUN Screenshots

> *Insert your ANY.RUN sandbox screenshots here. Recommended captures:*
> - Main verdict/overview page
> - Network activity tab showing the 404 response and IP connections
> - Process tree showing only Edge browser processes
> - HTTP requests tab highlighting the connection to `47.245.176.247`
>
> Save screenshots to the `screenshots/` folder and reference them like:
> ```
> ![ANY.RUN Overview](screenshots/anyrun-overview.png)
> ![ANY.RUN Network Activity](screenshots/anyrun-network.png)
> ```

### 3.2 Passive Reconnaissance — urlscan.io

The URL was submitted to [urlscan.io](https://urlscan.io) to obtain hosting infrastructure details, TLS certificate information, DOM snapshots, and community reputation data. This provided critical context that the sandbox alone could not capture.

#### urlscan.io Screenshots

> *Insert your urlscan.io screenshots here. Recommended captures:*
> - Summary page showing IP, domain, TLS cert age, and geolocation
> - HTTP transactions tab
> - Domain/IP details panel
>
> ```
> ![urlscan.io Summary](screenshots/urlscan-summary.png)
> ![urlscan.io Details](screenshots/urlscan-details.png)
> ```

### 3.3 WHOIS Domain Intelligence

A WHOIS lookup was conducted on the parent domain `govqo[.]cyou` to determine registration date, registrar, registrant information, and name server configuration. Domain age is one of the most reliable indicators for identifying phishing infrastructure.

#### WHOIS Key Data

```
Domain Name: GOVQO.CYOU
Creation Date: 2026-04-09T12:33:30Z
Registrar: Gname.com Pte. Ltd.
Registrant Country: US (redacted behind privacy protection)
Name Servers: A11.SHARE-DNS.COM / B11.SHARE-DNS.NET
DNSSEC: unsigned
```

---

## 4. Key Findings

### 4.1 Domain Typosquatting

The URL `michigan.govqo[.]cyou` is engineered to visually impersonate `michigan.gov` at a glance.

**How the deception works:**

```
michigan.govqo.cyou/dmv
├── michigan.     ← Subdomain (attacker-controlled, creates false trust)
├── govqo.cyou    ← Actual registered domain (malicious)
└── /dmv          ← Path designed to reinforce legitimacy
```

The `.cyou` generic top-level domain is a low-cost TLD with a well-documented history of abuse in phishing campaigns. No legitimate Michigan state service operates on this TLD.

### 4.2 Domain Registered Same Day

WHOIS records confirm `govqo[.]cyou` was registered on **April 9, 2026** — the same day the URL was flagged for investigation.

This is consistent with **"register-phish-burn"** operational patterns:

1. **Register** — Threat actor registers a disposable domain
2. **Phish** — Blast phishing links via email/SMS for hours or days
3. **Burn** — Abandon the domain before blocklists and abuse reports catch up

### 4.3 Suspicious Hosting Infrastructure

The domain resolves to IP address `47.245.176.247`, hosted on **Alibaba Cloud (AS45102)**.

| Attribute | Phishing Domain | Legitimate michigan.gov |
|-----------|----------------|------------------------|
| **Hosting** | Alibaba Cloud (CN) | US government infrastructure |
| **TLD** | .cyou (cheap gTLD) | .gov (verified government) |
| **Domain Age** | < 24 hours | Established for years |
| **TLS Certificate** | Let's Encrypt, 12hrs old | Government-issued or EV cert |
| **WHOIS** | Privacy-redacted | Public government registrant |

### 4.4 TLS Certificate Analysis

urlscan.io revealed the site's TLS certificate was issued by **Let's Encrypt (R13)** just **12 hours** before analysis, with a 3-month validity period.

While Let's Encrypt is a legitimate certificate authority, its free, automated issuance process is routinely exploited by phishing operators to obtain the HTTPS padlock icon, creating a false sense of legitimacy for victims.

### 4.5 Sandbox Results — Why "No Threats Detected" Doesn't Mean Safe

ANY.RUN returned a verdict of **"No threats detected."** This is a critical learning point:

- The HTTP request to the phishing URL returned a **404 (Not Found)** response
- Possible explanations: page was taken down, not yet deployed, or using evasion techniques (geofencing, user-agent filtering, bot detection)
- **No malware was dropped** and no suspicious processes were spawned
- This is **expected behavior** for credential-harvesting phishing sites — they steal data through fake forms, not malware delivery

> **Lesson:** Sandbox verdicts measure behavioral maliciousness (malware drops, exploit execution). For phishing, domain intelligence and infrastructure analysis tell the real story. Always layer your analysis.

---

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|-------------|---------------|-----------|
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | Malicious URL distributed to targets |
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains | Disposable domain registered same day |
| [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Acquire Infrastructure: Web Services | Alibaba Cloud hosting for phishing page |
| [T1608.005](https://attack.mitre.org/techniques/T1608/005/) | Stage Capabilities: Link Target | Phishing page staged at crafted URL |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name | Domain mimics michigan.gov naming |

---

## 6. Recommendations

### 6.1 Immediate Actions

- **Block** the domain `govqo[.]cyou` (all subdomains) and IP `47.245.176.247` at firewall, proxy, and DNS sinkhole layers
- **Hunt** — Search email gateway logs, web proxy logs, and SIEM for any historical access to this domain or IP
- **Remediate** — If user exposure is confirmed, initiate credential reset procedures and monitor affected accounts for unauthorized access

### 6.2 Reporting

- Report the URL to [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/), Microsoft SmartScreen, and [PhishTank](https://phishtank.org/)
- Submit abuse reports to registrar Gname.com and Alibaba Cloud for domain suspension and infrastructure takedown
- Notify the Michigan Attorney General's office and the [Anti-Phishing Working Group (APWG)](mailto:reportphishing@apwg.org)

### 6.3 Ongoing Monitoring

- Monitor VirusTotal, PassiveTotal, and SecurityTrails for additional domains resolving to `47.245.176.247` or registered through Gname.com on the same date
- Create detection rules for similar typosquatting patterns targeting `.gov` domains (e.g., `[state].gov[random].cyou`)
- Consider deploying lookalike domain monitoring services to proactively detect future impersonation attempts

---

## 7. Tools Used

| Tool | Purpose |
|------|---------|
| [ANY.RUN](https://any.run) | Dynamic malware sandbox — behavioral analysis of URL |
| [urlscan.io](https://urlscan.io) | Passive URL scanning — infrastructure, TLS, DOM analysis |
| WHOIS Lookup | Domain registration intelligence — age, registrar, registrant |
| [MITRE ATT&CK](https://attack.mitre.org/) | Threat behavior mapping framework |
| [VirusTotal](https://www.virustotal.com/) | Multi-engine reputation and relationship analysis |
| [PhishTank](https://phishtank.org/) | Community-driven phishing URL database and reporting |

---

## Repository Structure

```
threat-intel-reports/
├── README.md                          ← You are here
├── reports/
│   └── 2026-04-09-michigan-dmv-phishing/
│       ├── report.md                  ← This report
│       └── screenshots/
│           ├── anyrun-overview.png
│           ├── anyrun-network.png
│           ├── anyrun-http-requests.png
│           ├── urlscan-summary.png
│           └── urlscan-details.png
└── iocs/
    └── 2026-04-09-michigan-dmv-phishing.csv
```

---

## IOC Export (CSV Format)

For SIEM ingestion or threat intel platform import:

```csv
indicator_type,indicator_value,context,confidence,date_added
url,michigan.govqo[.]cyou/dmv,Primary phishing URL,high,2026-04-09
domain,govqo[.]cyou,Malicious parent domain,high,2026-04-09
ip,47.245.176.247,Alibaba Cloud hosting,high,2026-04-09
asn,AS45102,ALIBABA-CN-NET,medium,2026-04-09
registrar,Gname.com Pte. Ltd.,Singapore-based registrar,informational,2026-04-09
hash_sha256,C1F21464E607A37510B224E4144B1CA2B58D799CA0393AD5435AD5AA500F177B,URL hash,high,2026-04-09
```

---

## License

This report is shared under [TLP:WHITE](https://www.cisa.gov/tlp) — unrestricted distribution. Information may be shared freely.

