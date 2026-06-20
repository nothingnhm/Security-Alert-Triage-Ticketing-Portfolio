# Triage-Ticketing-Portfolio
A professional internship case-study repository documenting 150 solved IT support and cybersecurity tickets, including issue analysis, troubleshooting steps, root cause identification, resolution notes, escalation handling, and key learning outcomes.


# SOC Ticket Triage Case Studies

## 📌 Project Overview

This repository is a professional portfolio project documenting **150 sanitized IT support and cybersecurity ticket case studies** based on internship-style practical experience.

The main goal of this project is to demonstrate how tickets are analyzed, triaged, investigated, resolved, documented, and escalated in a real-world IT/SOC environment.

Each case study is written in a safe and professional format without exposing any confidential company data, client information, usernames, IP addresses, domains, internal screenshots, or sensitive logs.

---

## 🎯 Project Objective

The objective of this repository is to showcase practical understanding of:

* IT support ticket handling
* SOC alert triage
* Basic incident investigation
* Log analysis
* Root cause identification
* Troubleshooting methodology
* Escalation handling
* Resolution documentation
* Communication and reporting skills

This project is designed to help demonstrate entry-level readiness for roles such as:

* SOC Analyst L1
* Security Analyst Intern
* IT Support Engineer
* Junior Systems Administrator
* Technical Support Engineer
* Helpdesk Analyst
* NOC/SOC Trainee

---

## 🧠 Skills Demonstrated

This repository highlights hands-on knowledge in the following areas:

| Skill Area          | Description                                                         |
| ------------------- | ------------------------------------------------------------------- |
| Ticket Triage       | Categorizing, prioritizing, and analyzing incoming tickets          |
| Incident Analysis   | Understanding symptoms, affected assets, and possible impact        |
| Troubleshooting     | Applying step-by-step investigation methods                         |
| Log Review          | Reviewing Windows, Linux, firewall, proxy, VPN, and SIEM logs       |
| Root Cause Analysis | Identifying why the issue or alert occurred                         |
| Escalation          | Knowing when and how to escalate to L2/L3 teams                     |
| Documentation       | Writing clear ticket notes, resolution steps, and closure summaries |
| Communication       | Explaining technical issues in a simple and professional way        |

---

## 🛠️ Tools and Technologies Covered

The tickets in this repository may include scenarios related to:

* Windows Event Viewer
* Linux system logs
* Active Directory
* Splunk SIEM
* CrowdStrike alerts
* Firewall logs
* VPN logs
* Email security alerts
* Endpoint security alerts
* Basic networking tools
* Ticketing platforms such as osTicket/Jira/ServiceNow-style workflows

---

## 📂 Repository Structure

```text
SOC-Ticket-Triage-Case-Studies/
│
├── README.md
│
├── 01-Authentication-and-Login-Issues/
│   ├── ticket-001-failed-login-attempts.md
│   ├── ticket-002-account-lockout.md
│   └── ticket-003-password-reset-request.md
│
├── 02-Endpoint-Security-Alerts/
│   ├── ticket-021-suspicious-process-detected.md
│   ├── ticket-022-malware-alert-review.md
│   └── ticket-023-usb-device-alert.md
│
├── 03-Network-and-Firewall-Issues/
│   ├── ticket-041-firewall-blocked-connection.md
│   ├── ticket-042-unusual-outbound-traffic.md
│   └── ticket-043-dns-resolution-issue.md
│
├── 04-Email-and-Phishing-Investigation/
│   ├── ticket-061-phishing-email-analysis.md
│   ├── ticket-062-suspicious-attachment-review.md
│   └── ticket-063-malicious-url-analysis.md
│
├── 05-VPN-and-Remote-Access/
│   ├── ticket-081-vpn-login-failure.md
│   ├── ticket-082-multiple-vpn-failed-logins.md
│   └── ticket-083-remote-access-issue.md
│
├── 06-SIEM-and-Log-Analysis/
│   ├── ticket-101-splunk-alert-investigation.md
│   ├── ticket-102-high-failed-login-count.md
│   └── ticket-103-suspicious-user-activity.md
│
├── 07-System-Administration-Issues/
│   ├── ticket-121-service-not-running.md
│   ├── ticket-122-disk-space-alert.md
│   └── ticket-123-patch-status-review.md
│
└── 08-Escalated-and-High-Priority-Cases/
    ├── ticket-141-possible-compromised-account.md
    ├── ticket-142-suspicious-admin-login.md
    └── ticket-150-critical-alert-escalation.md
```

---

## 🧾 Ticket Documentation Format

Each ticket case study follows a standard documentation format:

```text
Ticket ID:
Category:
Priority:
Status:
Reported By:
Affected Asset:
Issue Summary:
Initial Observation:
Investigation Steps:
Logs Reviewed:
Findings:
Root Cause:
Resolution:
Escalation Required:
Closure Notes:
Key Learning:
```

---

## ✅ Sample Ticket Case Study

### Ticket ID: TKT-001

### Category: Authentication / Login Issue

### Priority: Medium

### Status: Resolved

---

### Issue Summary

A user reported that they were unable to log in to their system after multiple attempts. The account was later found to be locked due to repeated failed login attempts.

---

### Initial Observation

The ticket was reviewed to understand the affected user, system name, reported time, and business impact.

Initial checks confirmed:

* User was unable to authenticate
* Account lockout message was displayed
* Multiple failed login attempts were observed
* No confirmed signs of compromise were identified during initial review

---

### Investigation Steps

1. Verified the user account status in Active Directory.
2. Checked whether the account was locked.
3. Reviewed recent failed login events.
4. Validated whether the login attempts came from the user’s assigned workstation.
5. Checked for abnormal login source or suspicious IP address.
6. Confirmed whether the issue was caused by an old saved password, mapped drive, VPN session, or mobile email configuration.
7. Documented all findings in the ticket.

---

### Logs Reviewed

| Log Source            | Purpose                               |
| --------------------- | ------------------------------------- |
| Windows Security Logs | To review failed login events         |
| Active Directory Logs | To confirm account lockout status     |
| VPN Logs              | To check remote login attempts        |
| Endpoint Logs         | To verify source workstation activity |

---

### Findings

Multiple failed login attempts were detected for the user account. The attempts were coming from the user’s own workstation. No suspicious external source was identified.

The most likely cause was an outdated saved password stored on the endpoint.

---

### Root Cause

The account lockout was caused by repeated authentication attempts using an old cached password.

---

### Resolution

* Unlocked the user account.
* Asked the user to update the saved password on the workstation.
* Verified successful login after unlock.
* Monitored for additional failed login attempts.
* Closed the ticket after confirmation from the user.

---

### Escalation Required

No escalation was required because the activity was confirmed as non-malicious and resolved at L1 level.

---

### Closure Notes

The user account was unlocked successfully. The issue was caused by an outdated saved password. User confirmed successful login after updating credentials.

---

### Key Learning

Account lockout tickets should not be closed immediately after unlocking the account. The analyst should identify the source of failed login attempts to confirm whether the issue is user-related or potentially suspicious.

---

## 🔍 Ticket Categories Covered

This repository includes ticket examples from the following categories:

| Category              | Example Scenarios                                     |
| --------------------- | ----------------------------------------------------- |
| Authentication Issues | Failed login, account lockout, password reset         |
| Endpoint Alerts       | Malware alert, suspicious process, USB alert          |
| Network Issues        | Firewall block, DNS issue, connectivity issue         |
| Email Security        | Phishing email, suspicious attachment, malicious link |
| VPN Issues            | VPN login failure, remote access problem              |
| SIEM Alerts           | Brute-force alert, suspicious login, high event count |
| System Administration | Disk space, service failure, patch check              |
| Escalation Cases      | Compromised account, admin login, critical alert      |

---

## 📊 Severity and Priority Understanding

| Priority | Meaning                              | Example                                           |
| -------- | ------------------------------------ | ------------------------------------------------- |
| Low      | Minimal impact, no immediate risk    | General user request                              |
| Medium   | Affects one user or limited system   | Account lockout                                   |
| High     | Security concern or business impact  | Suspicious login activity                         |
| Critical | Confirmed compromise or major outage | Malware outbreak or privileged account compromise |

---

## 🚦 Basic Ticket Triage Workflow

```text
Ticket Received
      ↓
Understand the Issue
      ↓
Check Priority and Impact
      ↓
Collect Required Details
      ↓
Review Logs and Evidence
      ↓
Identify Root Cause
      ↓
Resolve or Escalate
      ↓
Document Findings
      ↓
Close Ticket
```

---

## 🧩 SOC Alert Triage Workflow

```text
Alert Triggered
      ↓
Validate Alert Details
      ↓
Identify User / Host / IP / Time
      ↓
Review Related Logs
      ↓
Check Threat Intelligence
      ↓
Determine True Positive or False Positive
      ↓
Contain / Escalate if Required
      ↓
Document Evidence
      ↓
Close or Escalate Ticket
```

---

## 📌 Example Investigation Questions

During ticket analysis, the following questions are useful:

* What happened?
* When did it happen?
* Which user, host, or IP is affected?
* Is this expected or suspicious activity?
* What logs support the finding?
* Is there any business impact?
* Is escalation required?
* What action was taken?
* What should be monitored after resolution?

---

## 🛡️ Security and Privacy Notice

All tickets in this repository are sanitized and created for educational and portfolio purposes.

This repository does not contain:

* Real company names
* Real client data
* Real usernames
* Real passwords
* Real IP addresses
* Real domains
* Internal screenshots
* Confidential logs
* Proprietary ticket information

Any resemblance to real environments is purely for learning and demonstration purposes.

---

## 📚 Learning Outcomes

After completing this project, the following skills are demonstrated:

* Ability to handle IT and security tickets professionally
* Understanding of L1 SOC and helpdesk workflow
* Ability to investigate common alerts and issues
* Ability to document root cause and resolution clearly
* Understanding of when to resolve and when to escalate
* Awareness of security, privacy, and professional reporting standards

---

## 🚀 Future Improvements

Planned improvements for this repository:

* Add 150 individual ticket case studies
* Add severity-wise ticket classification
* Add sample Splunk SPL queries for investigation
* Add MITRE ATT&CK mapping for security-related tickets
* Add incident response checklist
* Add phishing investigation checklist
* Add escalation templates
* Add dashboard screenshots from a lab environment

---

## ⚠️ Disclaimer

This repository is created for educational, portfolio, and career development purposes only.

All scenarios are sanitized and written in a safe format. No confidential company information, client data, or real production logs are included.

---

## 👤 Author

**Ananda Das**
Cybersecurity Student | SOC Analyst Learner | IT Security Enthusiast

GitHub: [@your-github-username](https://github.com/your-github-username)

---

## ⭐ Repository Purpose

This project is part of my cybersecurity portfolio to demonstrate practical experience in ticket triage, IT troubleshooting, SOC alert analysis, and professional documentation.
