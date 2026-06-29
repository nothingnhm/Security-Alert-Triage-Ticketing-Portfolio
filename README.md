# Security Alert Triage & Ticketing Portfolio

[![Portfolio](https://img.shields.io/badge/Portfolio-SOC%20Alert%20Triage-blue)](#)
[![Role Focus](https://img.shields.io/badge/Role-SOC%20Analyst%20L1-green)](#)
[![Documentation](https://img.shields.io/badge/Documentation-Case%20Studies-orange)](#)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](#)

## Overview

This repository is a professional cybersecurity portfolio project containing **80+ sanitized SOC and IT support ticket case studies**. Each case study demonstrates how alerts and tickets are reviewed, triaged, investigated, documented, resolved, or escalated in a real-world SOC/helpdesk-style workflow.

The goal of this project is to show practical readiness for entry-level security roles by documenting investigation logic, evidence review, impact validation, IOC extraction, MITRE ATT&CK mapping, escalation decisions, and final closure notes.

> **Important:** All tickets are sanitized and written for educational and portfolio purposes. No confidential company information, real client data, internal screenshots, production credentials, or sensitive logs are included.

---

## Role Alignment

This project is designed to demonstrate practical skills for roles such as:

- SOC Analyst L1
- Security Analyst Intern
- Cybersecurity Analyst Trainee
- NOC/SOC Trainee
- IT Support / Helpdesk Analyst
- Junior Security Operations Analyst
- Technical Support Engineer

---

## Key Skills Demonstrated

| Skill Area | What This Repository Demonstrates |
|---|---|
| Alert Triage | Reviewing alert details, severity, affected users/assets, and initial indicators |
| SIEM Log Analysis | Using Splunk-style investigation logic and log correlation |
| IOC Identification | Extracting IPs, domains, URLs, users, hosts, file paths, commands, and suspicious payloads |
| Investigation Workflow | Moving from alert review to validation, correlation, impact assessment, and closure |
| True/False Positive Analysis | Determining whether activity is suspicious, benign, blocked, or requires escalation |
| MITRE ATT&CK Mapping | Mapping relevant security events to attacker techniques where applicable |
| Incident Documentation | Writing structured analyst notes, findings, timelines, recommendations, and closure summaries |
| Escalation Handling | Identifying when L2/L3, network, endpoint, or incident response escalation is required |
| Communication | Explaining technical findings in a clear, professional, recruiter-readable format |

---

## Tools, Logs, and Technologies Covered

The case studies include scenarios involving:

- Splunk SIEM investigation
- Firewall logs
- WAF alerts
- VPN authentication logs
- Email gateway alerts
- Proxy logs
- IPS alerts
- Linux security logs
- Windows/Event-style investigation concepts
- Endpoint/security alert triage
- Ticketing workflows similar to osTicket, Jira, and ServiceNow
- Threat intelligence and IOC validation concepts

---

## Featured Investigations

These are strong examples to review first because they show deeper SOC investigation flow and evidence-based reporting.

| Category | Case Study | Focus Area | Outcome |
|---|---|---|---|
| Linux | [Suspicious Script Execution from Non-standard Path](Linux-Ticket/Linux%3A_Suspicious_Script_Execution_from_Non-standard_Path.md) | Suspicious process execution, Linux log review, MITRE mapping | Investigated and documented with escalation guidance |
| WAF | [SQL Injection](WAF-Ticket/WAF%3A_SQL_Injection.md) | SQLi payload review, WAF evidence, blocked attack validation | Blocked / monitored |
| Email Gateway | [Phishing Email with Credential Harvesting Attempt](Email-Gateway-Ticket/Phishing_Email_with_Credential_Harvesting_Attempt.md) | Phishing analysis, credential harvesting, user impact validation | True positive investigation |
| Firewall | [SMB DDoS Attack](Firewall-Ticket/Firewall_SMB_DDOS_Attack.md) | Firewall log analysis, DDoS validation, mitigation review | Blocked / monitored |
| VPN | [User Login from Geographically Distant Locations](VPN-Ticket/VPN%3A_User_Login_from_Geographically_Distant_Locations_in_Short_Duration.md) | Impossible travel, VPN session review, account risk analysis | Investigated / escalation decision |

---

## Repository Structure

```text
Security-Alert-Triage-Ticketing-Portfolio/
│
├── Email-Gateway-Ticket/     # Phishing, suspicious sender, macro attachment, spam, credential harvesting
├── Firewall-Ticket/          # DDoS, port scanning, brute force, C2, RCE, DNS amplification
├── IPS-Ticket/               # Intrusion prevention and exploit detection alerts
├── Linux-Ticket/             # SSH brute force, suspicious scripts, cron jobs, root access, log tampering
├── Proxy-Ticket/             # Web access, suspicious domains, blocked URLs, user browsing investigation
├── System-Fault/             # IT support and system issue tickets
├── VPN-Ticket/               # Geo-login, TOR exit node, blacklisted country, bad reputation IP, device compliance
├── WAF-Ticket/               # SQLi, XSS, RCE, CSRF, directory traversal, HTTP flood, malicious upload
└── README.md
```

---

## Case Study Categories

| Category | Example Alert Types | Skills Practiced |
|---|---|---|
| Email Gateway | Phishing, spam, malicious attachment, credential harvesting | Header review, sender validation, user impact, IOC extraction |
| Firewall | DDoS, port scanning, brute force, C2 traffic, RCE attempts | Network log review, source/destination analysis, block validation |
| IPS | Exploit attempts, suspicious network signatures | Signature review, threat validation, escalation logic |
| Linux | SSH brute force, cron abuse, suspicious script execution, privilege misuse | Linux log analysis, command review, persistence checks |
| Proxy | Suspicious URL access, blocked domains, policy violations | Web access review, domain reputation, user activity validation |
| System Fault | Disk, service, access, and operational issues | IT troubleshooting and ticket closure documentation |
| VPN | Impossible travel, TOR exit node, bad reputation IP, unusual login | Authentication review, geo-analysis, account risk validation |
| WAF | SQLi, XSS, RCE, CSRF, directory traversal, HTTP flood | Web attack analysis, payload review, WAF decision validation |

---

## Standard Investigation Workflow

```text
Alert / Ticket Received
        ↓
Review Ticket Details
        ↓
Identify Affected User, Host, IP, Application, or Asset
        ↓
Validate Severity and Business Impact
        ↓
Review SIEM / Firewall / WAF / VPN / Endpoint / Email Logs
        ↓
Extract IOCs and Suspicious Indicators
        ↓
Correlate Related Events
        ↓
Determine True Positive, False Positive, Benign, or Blocked Attempt
        ↓
Recommend Containment, Remediation, Monitoring, or Escalation
        ↓
Document Evidence and Final Closure Notes
```

---

## Standard Ticket Report Format

Most security case studies follow a structure similar to:

```text
Ticket ID:
Alert Name:
Category:
Severity / Priority:
Status:
Affected User / Host / Asset:
Source IP / Destination IP:
Alert Summary:
Initial Observation:
IOCs Identified:
SIEM / Splunk Query Used:
Log Evidence:
Timeline of Events:
Investigation Steps:
Correlation and Analysis:
Impact Assessment:
MITRE ATT&CK Mapping:
True Positive / False Positive Decision:
Recommended Actions:
Escalation Decision:
Final Closure Note:
Key Learning:
```

---

## Severity and Priority Guide

| Priority | Meaning | Example |
|---|---|---|
| Low | Minimal impact or informational activity | General request, benign policy event |
| Medium | Limited impact or suspicious activity requiring review | Single-user issue, blocked suspicious traffic |
| High | Security concern with possible business or account impact | Phishing, brute force, suspicious VPN login |
| Critical | Confirmed compromise or major service/security impact | Malware outbreak, confirmed account takeover, privileged compromise |

---

## Investigation Questions Used

During analysis, each ticket is reviewed using questions such as:

- What triggered the alert?
- Which user, host, IP, domain, application, or asset is affected?
- What evidence exists in SIEM, firewall, WAF, VPN, proxy, endpoint, or email logs?
- Is the activity expected, suspicious, blocked, or confirmed malicious?
- Are there related events before or after the alert?
- Was any user interaction, login success, payload execution, or data access observed?
- What IOCs should be documented?
- Does the event map to any MITRE ATT&CK technique?
- Is containment, monitoring, or escalation required?
- What should be written in the final closure note?

---

## MITRE ATT&CK Usage

Where applicable, security tickets include MITRE ATT&CK mapping to connect alert activity with real adversary behavior, such as:

- Initial Access
- Credential Access
- Discovery
- Execution
- Persistence
- Command and Control
- Impact

This helps demonstrate that the investigation is not only based on alert names, but also on attacker tactics, techniques, and possible intent.

---

## What This Project Shows to Recruiters

This repository demonstrates that I can:

- Read and understand security alerts
- Investigate logs using a structured SOC workflow
- Identify key indicators from alerts and logs
- Document evidence professionally
- Separate blocked attempts from confirmed compromise
- Decide when escalation is required
- Write clear closure notes and recommendations
- Understand common SOC L1 alert categories across firewall, VPN, WAF, Linux, email, proxy, and IPS logs

---

## Future Improvements

Planned improvements for this repository:

- Standardize all ticket names using a clean naming convention
- Add a master ticket index with severity, category, outcome, and MITRE technique
- Add MITRE ATT&CK mapping to every security-related ticket
- Add more Splunk SPL examples for investigation and correlation
- Add incident response and escalation checklists
- Add sanitized lab screenshots where safe
- Add detection engineering notes for selected high-value cases

---

## Privacy and Safety Notice

All tickets in this repository are sanitized and created for learning, portfolio building, and career development purposes only.

This repository does **not** contain:

- Real company names
- Real client data
- Real passwords
- Confidential production logs
- Internal screenshots
- Proprietary ticket information
- Sensitive business data

Any resemblance to real environments is purely for educational demonstration.

---

## ⚠️ Disclaimer

This repository is created for educational, portfolio, and career development purposes only.

All scenarios are sanitized and written in a safe format. No confidential company information, client data, or real production logs are included.

---

## 👤 Author

**Ananda Das**

Cybersecurity Student | Cyber Security Trainer |  SOC Analyst L1

GitHub: [@nothingnhm](https://github.com/nothingnhm)

---

## ⭐ Repository Purpose

This project is part of my cybersecurity portfolio to demonstrate hands-on understanding of SOC alert triage, IT support investigation, SIEM log review, incident documentation, and professional ticket closure practices.

