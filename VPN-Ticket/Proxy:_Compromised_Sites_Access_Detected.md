# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                       |
| ---------------- | ----------------------------------------------------------------------------- |
| Ticket ID        | CS-037                                                                       |
| Alert Name       | Proxy: Compromised Sites Access Detected                                      |
| Ticket Status    | Closed                                                                        |
| Priority / SLA   | Normal / Default SLA                                                          |
| Created Date     | 3/16/25 7:42 PM                                                               |
| Closed By        | Ananda Das                                                                    |
| Analyst Decision | **True Positive — Compromised Site Access Attempt / No Confirmed Compromise** |

## Executive Summary

A proxy alert was triggered for **Compromised Sites Access Detected** involving user **Alice Gupta** from internal source IP **10.1.2.47** accessing external destination IP **203.0.86.25**.

The accessed domain was **accounts.instagram.com.bb3.in**, categorized by the proxy as **Compromised Sites**. The URL appears suspicious because it uses an Instagram-like subdomain pattern that may be used for phishing or impersonation.

The initial proxy action was **Allowed**, but Splunk evidence showed HTTP response code **403**, indicating the request was denied or blocked at the destination/proxy/application layer. No malware download, credential submission, C2 callback, endpoint compromise, or data exfiltration was confirmed from the provided evidence.

## Alert Details

| Field               | Value                                                                   |
| ------------------- | ----------------------------------------------------------------------- |
| Timestamp           | 3/15/2025 09:49                                                         |
| Username            | Alice Gupta                                                             |
| Source IP           | 10.1.2.47                                                               |
| Destination IP      | 203.0.86.25                                                             |
| URL Domain          | accounts.instagram.com.bb3.in                                           |
| URL                 | http://accounts.instagram.com.bb3.in                                    |
| Web Category        | Compromised Sites                                                       |
| Proxy Action        | Allowed                                                                 |
| HTTP Method         | GET                                                                     |
| Response Code       | 403                                                                     |
| Bytes Sent          | 2966                                                                    |
| Bytes Received      | 15816                                                                   |
| User-Agent          | Chrome on Windows                                                       |
| Destination Details | Chevron Corporation; Data Center/Web Hosting/Transit; Sydney, Australia |

## Affected Assets

| Asset Field             | Details                       |
| ----------------------- | ----------------------------- |
| User                    | Alice Gupta                   |
| Role                    | Security Engineer L1          |
| Department              | Cybersecurity                 |
| Source IP               | 10.1.2.47                     |
| Endpoint                | ENDP-590                      |
| Endpoint OS             | Windows 11-64                 |
| External Destination IP | 203.0.86.25                   |
| Suspicious Domain       | accounts.instagram.com.bb3.in |
| Business Criticality    | Not Provided                  |

## Evidence Reviewed

| Evidence Source       | Observation                                                 |
| --------------------- | ----------------------------------------------------------- |
| Proxy Alert           | User accessed a domain categorized as **Compromised Sites** |
| URL Pattern           | Instagram-like domain: `accounts.instagram.com.bb3.in`      |
| HTTP Method           | GET                                                         |
| Proxy Action          | Allowed                                                     |
| Response Code         | 403                                                         |
| Malware Download      | Not Observed                                                |
| Credential Submission | Not Observed                                                |
| C2 Communication      | Not Observed                                                |
| Endpoint Compromise   | Not Observed                                                |
| Data Exfiltration     | Not Observed                                                |

## SIEM / Splunk Analysis

```spl id="t7p4qx"
index=main "10.1.2.47" "203.0.86.25" sourcetype="proxy_logs"
| table _time, "Bytes Sent", "Bytes Received", "HTTP Method", "Response Code", "URL Domain", "User Agent", Username
```

| _time               | Username    | Source IP | Destination IP | URL Domain                    | Method | Response | Bytes Sent | Bytes Received |
| ------------------- | ----------- | --------- | -------------- | ----------------------------- | ------ | -------: | ---------: | -------------: |
| 2025-03-15 09:49:00 | Alice Gupta | 10.1.2.47 | 203.0.86.25    | accounts.instagram.com.bb3.in | GET    |      403 |       2966 |          15816 |

**Analysis Note:** The request reached a suspicious domain categorized as compromised, but HTTP **403** and lack of download/credential/C2 evidence reduce the likelihood of confirmed compromise.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                           |
| ------------------- | ----------------------------------------- | --------- | -------------------------------------------------------------------------------- |
| Initial Access      | Drive-by Compromise                       | T1189     | User accessed a suspicious web domain categorized as compromised                 |
| Initial Access      | Phishing                                  | T1566     | Domain impersonation pattern may indicate phishing; source of link not confirmed |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Web access to suspicious external infrastructure was observed; C2 not confirmed  |

## Analyst Assessment

**Assessment:** **True Positive — Suspicious Compromised Site Access Attempt**

The alert is valid because the user accessed a domain categorized as **Compromised Sites**, and the domain appears to impersonate Instagram using a suspicious lookalike structure.

This is **not confirmed endpoint compromise**. The request returned HTTP **403**, and no malware download, credential submission, C2 callback, endpoint alert, or data exfiltration was confirmed from the reviewed logs.

## Impact Analysis

| Area            | Assessment                                                                |
| --------------- | ------------------------------------------------------------------------- |
| Confidentiality | No credential submission or data exposure confirmed                       |
| Integrity       | No endpoint or application change confirmed                               |
| Availability    | No service impact reported                                                |
| Business Impact | No confirmed impact                                                       |
| Current Risk    | Medium until user validation confirms no interaction or download occurred |

## Recommended Actions

1. Contact **Alice Gupta** to confirm whether she intentionally visited the URL.
2. Ask whether the link came from email, chat, social media, redirect, or browser pop-up.
3. Confirm whether any credentials, OTP, or corporate login details were entered.
4. Confirm whether any file was downloaded or opened.
5. Block domain **accounts.instagram.com.bb3.in** in proxy/DNS security controls.
6. Block destination IP **203.0.86.25** if no business requirement exists.
7. Review endpoint **ENDP-590** for browser downloads, suspicious processes, or EDR alerts.
8. Escalate to SOC L2 only if credential entry, file download, endpoint alert, C2 callback, or suspicious follow-up traffic is confirmed.

## Escalation Decision

**Decision:** **User validation required; conditional SOC L2 escalation.**

**Reason:** The proxy alert indicates access to a compromised/suspicious domain, but the request returned HTTP **403** and no compromise indicators were confirmed. SOC L2 escalation is required only if user interaction, credential submission, file download, endpoint compromise, or suspicious outbound activity is identified.

## Final Ticket Closure Comment

SOC investigated ticket **CS-037 — Proxy: Compromised Sites Access Detected**. User **Alice Gupta** from **10.1.2.47 / ENDP-590** accessed **http://accounts.instagram.com.bb3.in**, categorized as **Compromised Sites**, with destination IP **203.0.86.25**. The proxy action was initially Allowed, but Splunk evidence showed HTTP **403**. No malware download, credential submission, C2 callback, endpoint compromise, or data exfiltration was observed from the provided logs. Ticket closed as **True Positive — Compromised Site Access Attempt / No Confirmed Compromise**, with user validation, domain/IP blocking, and endpoint review recommended.

## Skills Demonstrated

Proxy alert triage, compromised-site investigation, URL/domain analysis, user and endpoint correlation, Splunk proxy log review, IOC handling, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
