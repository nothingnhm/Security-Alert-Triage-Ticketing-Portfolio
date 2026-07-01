# SOC Analyst Investigation Report

## Ticket Overview

| Field                | Details                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------ |
| Ticket ID            | CS-057                                                                                    |
| Alert Name           | Phishing Email Reporting                                                                   |
| Incident Title       | Suspicious Email — Marketing Communication                                                 |
| Ticket Status        | Closed                                                                                     |
| Priority / SLA       | Normal / Medium                                                                            |
| Created Date         | 3/12/25 9:28 PM                                                                            |
| Reported By          | Meera Sharma                                                                               |
| Reporter Email       | `meera.sharma@abc.com`                                                                     |
| Closed By            | Ananda Das                                                                                 |
| Submitted Attachment | `Still Searching for the Perfect AI-Powered Customer Support Tool_.eml`                    |
| Analyst Decision     | **False Positive — Legitimate Freshworks Marketing Email / No Security Threat Identified** |

## Executive Summary

User **Meera Sharma** reported a suspicious email for analysis. The attached email was reviewed to determine whether it contained phishing indicators, malicious URLs, suspicious attachments, credential harvesting behavior, malware delivery, or signs of user/account compromise.

The email was sent from:

`ashl.hacker@works.com`

The sender domain was:

`freshworks.com`

The email was delivered to two internal recipients:

* `meera.sharma@abc.com`
* `hr@abc.com`

The email content was related to an AI-powered customer support tool and was consistent with Freshworks marketing/promotional communication.

Email authentication checks passed, including **SPF**, **DKIM**, and **DMARC**. No malicious attachments, credential harvesting pages, suspicious redirects, malware links, proxy activity, VPN anomalies, endpoint compromise, or account compromise indicators were identified.

Based on the investigation, this ticket is assessed as a **False Positive — Legitimate Marketing Email**.

## Alert Details

| Field              | Value                                                             |
| ------------------ | ----------------------------------------------------------------- |
| Email Time         | 2025-03-03 23:56:00                                               |
| Sender Name        | Ashlyn Saju                                                       |
| Sender Email       | `ashl.hacker@works.com`                                      |
| Sender Domain      | freshworks.com                                                    |
| Recipients         | `meera.sharma@abc.com`, `hr@abc.com`                              |
| Email Subject      | Still Searching for the Perfect AI-Powered Customer Support Tool? |
| Email Type         | Marketing / Promotional                                           |
| Direction          | Inbound                                                           |
| Status             | Delivered                                                         |
| Action             | Allowed                                                           |
| Attachment Present | No malicious attachment identified                                |
| Final Verdict      | False Positive                                                    |

## Affected Assets

| Asset / Entity  | Details                      |
| --------------- | ---------------------------- |
| Reporting User  | Meera Sharma                 |
| Reporter Email  | `meera.sharma@abc.com`       |
| Recipient 1     | `meera.sharma@abc.com`       |
| Recipient 2     | `hr@abc.com`                 |
| Sender          | `ashl.hacker@works.com` |
| Sender Domain   | freshworks.com               |
| Sender IP       | 148.113.46.138               |
| System          | Email Infrastructure         |
| Endpoint Impact | Not Observed                 |
| Account Impact  | Not Observed                 |
| Security Threat | Not Confirmed                |

## Evidence Reviewed

### IOC / Indicator Summary

| Indicator Type | Indicator                                                         | Classification                  | Status                        |
| -------------- | ----------------------------------------------------------------- | ------------------------------- | ----------------------------- |
| Sender Email   | `ashl.hacker@works.com`                                      | Legitimate Sender               | Benign                        |
| Sender Domain  | freshworks.com                                                    | Trusted SaaS / Marketing Domain | Benign                        |
| Sender IP      | 148.113.46.138                                                    | Email Infrastructure            | Benign from provided evidence |
| Recipient      | `meera.sharma@abc.com`                                            | Internal Recipient              | No impact observed            |
| Recipient      | `hr@abc.com`                                                      | Internal Recipient              | No impact observed            |
| Email Subject  | Still Searching for the Perfect AI-Powered Customer Support Tool? | Marketing Subject               | Benign                        |
| URLs           | No malicious URL identified                                       | Clean                           | No malicious URL              |
| Attachments    | No malicious attachment identified                                | Clean                           | No malicious attachment       |
| Threat Type    | Not Applicable                                                    | False Positive                  | No threat confirmed           |

**IOC Assessment:** No malicious indicators of compromise were identified during the investigation.

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The ticket was reviewed as a user-reported suspicious email. Since the email was submitted as an `.eml` attachment, the investigation focused on sender authenticity, email authentication, delivery scope, URLs, attachments, proxy activity, VPN activity, and potential user impact.

Key review points:

| Check              | Result                             |
| ------------------ | ---------------------------------- |
| Sender identity    | Freshworks sender                  |
| Sender domain      | freshworks.com                     |
| Email content      | Marketing / promotional            |
| Attachment risk    | No malicious attachment identified |
| URL risk           | No malicious URL identified        |
| Proxy activity     | No suspicious activity found       |
| VPN activity       | No suspicious activity detected    |
| Endpoint impact    | Not observed                       |
| Account compromise | Not observed                       |

#### 2. Source and Authentication Review

| Authentication Control | Result | Analyst Interpretation                     |
| ---------------------- | ------ | ------------------------------------------ |
| SPF                    | Pass   | Sender infrastructure was authorized       |
| DKIM                   | Valid  | Message integrity/authentication validated |
| DMARC                  | Valid  | Domain alignment passed                    |

The sender domain `freshworks.com` was consistent with the sender identity. Email authentication checks passed, reducing the likelihood of spoofing or sender impersonation.

#### 3. Delivery Scope Review

The email was delivered to two recipients and matched expected bulk marketing behavior.

| Recipient              | Status    | Action  |
| ---------------------- | --------- | ------- |
| `meera.sharma@abc.com` | Delivered | Allowed |
| `hr@abc.com`           | Delivered | Allowed |

The delivery pattern was consistent with marketing communication and did not show signs of targeted credential phishing.

#### 4. Splunk Email Log Review

```spl id="cs0237_email_query"
index=main sourcetype="email_logs" "ashl.hacker@works.com"
| table _time Sender Recipient Email_Subject MessageID Action
```

```text id="cs0237_email_results"
_time	Sender	Recipient	Email_Subject	Action
2025-03-03 23:56:00	ashl.hacker@works.com	meera.sharma@abc.com	AI Support Tool Marketing	Allowed
2025-03-03 23:56:00	ashl.hacker@works.com	hr@abc.com	AI Support Tool Marketing	Allowed
```

#### 5. Content and Attachment Review

| Check                      | Result                  |
| -------------------------- | ----------------------- |
| Email Content Type         | Marketing / Promotional |
| Phishing Indicators        | Not Observed            |
| Malicious Links            | Not Observed            |
| Malicious Attachments      | Not Observed            |
| Redirection / Obfuscation  | Not Detected            |
| Credential Harvesting Page | Not Observed            |
| Executable Attachment      | Not Observed            |

The email content was consistent with a Freshworks promotional message about AI-powered customer support tools. No credential request, malicious attachment, suspicious link, executable file, or phishing page was identified.

#### 6. Proxy and VPN Review

| Log Source                    | Result                            |
| ----------------------------- | --------------------------------- |
| Proxy Logs                    | No suspicious activity found      |
| VPN Logs                      | No suspicious activity detected   |
| User Interaction              | No malicious interaction observed |
| Malicious Outbound Connection | Not observed                      |
| Suspicious Login Activity     | Not observed                      |

No proxy activity or VPN anomalies were linked to the email. No evidence of malicious outbound communication, credential submission, or suspicious authentication was identified.

#### 7. Timeline Reconstruction

| Time                | Event                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------- |
| 2025-03-03 23:56:00 | Freshworks marketing email delivered to `meera.sharma@abc.com`                        |
| 2025-03-03 23:56:00 | Freshworks marketing email delivered to `hr@abc.com`                                  |
| 2025-03-12 21:28    | Meera Sharma reported the email for analysis                                          |
| Investigation Time  | Sender, authentication, content, attachment, Splunk, proxy, and VPN evidence reviewed |
| Closure Time        | Ticket closed as false positive                                                       |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID  | Reason                                                                                  |
| ------ | --------- | --- | --------------------------------------------------------------------------------------- |
| N/A    | N/A       | N/A | No malicious behavior confirmed                                                         |
| N/A    | N/A       | N/A | No phishing, malware delivery, credential harvesting, or compromise indicators observed |

**MITRE Note:** No MITRE ATT&CK technique is assigned because the investigation did not confirm adversary behavior.

## Analyst Assessment

**Assessment:** **False Positive — Legitimate Freshworks Marketing Communication**

The reported email was confirmed to be a legitimate marketing/promotional email from Freshworks. The sender domain was legitimate, email authentication passed, the message content matched marketing activity, and no malicious URLs or attachments were identified.

No proxy activity, VPN anomaly, credential submission, endpoint compromise, or account compromise was observed.

The alert was likely triggered due to sender IP reputation heuristics or user suspicion, but the investigation did not identify any confirmed security threat.

## Impact Analysis

| Impact Area                             | Status        |
| --------------------------------------- | ------------- |
| Phishing Email                          | Not Confirmed |
| Malware Infection                       | No Evidence   |
| Credential Theft                        | No Evidence   |
| User Interaction with Malicious Content | No Evidence   |
| Data Exposure                           | No Evidence   |
| System Compromise                       | No Evidence   |
| Endpoint Impact                         | No Evidence   |
| Account Compromise                      | No Evidence   |
| VPN Abuse                               | No Evidence   |
| Residual Risk                           | Low           |

Current impact: **No security impact identified.**

## Recommended Actions

1. No sender block is required.
2. No domain block is required for `freshworks.com`.
3. No password reset is required.
4. No endpoint isolation is required.
5. No SOC L2 escalation is required.
6. Inform the reporting user that the email appears to be legitimate marketing communication.
7. Optionally delete or unsubscribe from the email if the recipient considers it unwanted marketing.
8. Continue standard monitoring for future suspicious emails.

## Escalation Decision

**Decision:** **No escalation required.**

**Reason:** The investigation confirmed that the email was a legitimate Freshworks marketing communication. No malicious URL, suspicious attachment, credential harvesting behavior, user interaction with malicious infrastructure, VPN anomaly, endpoint compromise, or account compromise indicator was identified.

## Final Ticket Closure Comment

SOC investigated ticket **CS-057 — Phishing Email Reporting** submitted by **Meera Sharma**. The reported email was sent from `ashl.hacker@works.com` to `meera.sharma@abc.com` and `hr@abc.com` with the subject **Still Searching for the Perfect AI-Powered Customer Support Tool?**. Email authentication checks passed, including SPF, DKIM, and DMARC. Splunk email logs confirmed the messages were delivered and allowed. The email content was reviewed and identified as Freshworks marketing/promotional communication. No malicious URLs, suspicious attachments, credential harvesting behavior, proxy activity, VPN anomaly, malware execution, endpoint compromise, or user/account impact was identified. Ticket closed as **False Positive — Legitimate Marketing Email / No Security Threat Identified**.

## Skills Demonstrated

User-reported phishing triage, email authentication review, sender reputation validation, Splunk email log analysis, marketing email classification, proxy activity validation, VPN anomaly review, IOC assessment, false positive determination, impact validation, escalation decision-making, and SOC ticket documentation.

---

## ⚠️ Disclaimer

This repository is created for educational, portfolio, and career development purposes only.

All scenarios are sanitized and written in a safe format. No confidential company information, client data, or real production logs are included.

---

## 👤 Author

**Ananda Das**
Cybersecurity Student | SOC Analyst Learner | SIEM, Threat Detection & Incident Response Enthusiast

GitHub: [@nothingnhm](https://github.com/nothingnhm)

---

## ⭐ Repository Purpose

This project is part of my cybersecurity portfolio to demonstrate practical experience in ticket triage, IT troubleshooting, SOC alert analysis, and professional documentation.
