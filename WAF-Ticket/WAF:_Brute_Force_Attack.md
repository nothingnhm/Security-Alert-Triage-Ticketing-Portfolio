# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                   |
| ---------------- | --------------------------------------------------------- |
| Ticket ID        | CS-029                                                    |
| Alert Name       | WAF: Brute Force Attack                                   |
| Ticket Status    | In Progress                                               |
| Priority / SLA   | Low / Default SLA                                         |
| Created Date     | 3/2/25 7:45 PM                                            |
| Assigned To      | Ananda Das / SOC Team                                     |
| Analyst Decision | **False Positive — Authorized Internal Scanner Activity** |

## Executive Summary

A WAF alert was triggered for **Brute Force Attack** involving internal source IP **10.0.2.53 / LinITQualys01** targeting internal destination **10.0.16.24 / LinOPWebServer05** over **443/TCP**.

The request targeted **marketing.abc.com/admin** using HTTP method **PUT** with the matched string `username=admin&password=admin123`. The WAF action was **Allowed**, and the alert severity was **Medium**.

The source asset is identified as an internal **Qualys Scanner**, making the activity consistent with authorized vulnerability scanning or web application security testing. No successful unauthorized login, account compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field            | Value                              |
| ---------------- | ---------------------------------- |
| Receive Time     | 2/9/2025 11:15                     |
| Source IP        | 10.0.2.53                          |
| Source Port      | 29389                              |
| Destination IP   | 10.0.16.24                         |
| Destination Port | 443                                |
| Site Name        | marketing.abc.com                  |
| URL              | /admin                             |
| HTTP Method      | PUT                                |
| Threat Name      | Brute Force Attack                 |
| Severity         | Medium                             |
| Matched String   | `username=admin&password=admin123` |
| WAF Action       | Allowed                            |
| Log Source       | WAF Alert                          |

## Affected Assets

| Asset Field          | Source Asset           | Destination Asset |
| -------------------- | ---------------------- | ----------------- |
| IP Address           | 10.0.2.53              | 10.0.16.24        |
| Hostname             | LinITQualys01          | LinOPWebServer05  |
| OS                   | Linux - RHEL 8         | Linux - RHEL 8    |
| Role                 | Qualys Scanner         | Web Server        |
| Hosting              | Internal Security Tool | AWS Cloud         |
| Business Criticality | Not Provided           | Not Provided      |

## Evidence Reviewed

| Evidence Source    | Observation                                         |
| ------------------ | --------------------------------------------------- |
| WAF Alert          | Brute-force-style request detected against `/admin` |
| Credential Pattern | `username=admin&password=admin123`                  |
| Source Asset       | Internal Qualys Scanner                             |
| Destination Site   | `marketing.abc.com`                                 |
| WAF Action         | Allowed                                             |
| Successful Login   | Not Observed                                        |
| Account Compromise | Not Observed                                        |
| Service Impact     | Not Provided                                        |
| Splunk Query       | Not Provided                                        |

## SIEM / Splunk Analysis

No Splunk query results were provided for this ticket. Based on the available WAF event, the alert was reviewed using the source asset context and destination asset mapping.

Suggested validation query for portfolio/lab use:

```spl
index=main sourcetype="waf_logs" srcIP="10.0.2.53" dstIP="10.0.16.24" Threat_Name="Brute Force Attack"
| table _time, srcIP, srcPort, dstIP, dstPort, site_name, URL, matched_string, http_method, Threat_Name, Severity, Action
```

## MITRE ATT&CK Mapping

| Tactic            | Technique                         | ID        | Reason                                           |
| ----------------- | --------------------------------- | --------- | ------------------------------------------------ |
| Credential Access | Brute Force                       | T1110     | WAF detected a brute-force-style login attempt   |
| Credential Access | Password Guessing                 | T1110.001 | Request used `admin/admin123` credential pattern |
| Initial Access    | Exploit Public-Facing Application | T1190     | Administrative web path `/admin` was tested      |

**Mapping Note:** MITRE mapping reflects the observed detection behavior only. The activity is attributed to an approved internal scanner, so it is not assessed as hostile attacker activity.

## Analyst Assessment

**Assessment:** **False Positive — Authorized Qualys Scanner Activity**

The alert was triggered because the request matched a brute-force login pattern against an administrative path. However, the source IP **10.0.2.53** belongs to **LinITQualys01**, an internal Qualys scanner.

The activity is consistent with authorized vulnerability scanning or web application testing. No evidence indicates malicious external activity, successful unauthorized login, account compromise, or application impact.

## Impact Analysis

| Area            | Assessment                         |
| --------------- | ---------------------------------- |
| Confidentiality | No unauthorized access observed    |
| Integrity       | No application change confirmed    |
| Availability    | No service disruption reported     |
| Business Impact | No confirmed impact                |
| Current Risk    | Low due to approved scanner source |

## Recommended Actions

1. Close the ticket as **False Positive / Authorized Internal Scanner Activity**.
2. Tag **10.0.2.53 / LinITQualys01** as `Approved_Qualys_Scanner` in SIEM.
3. Confirm the scan was within the approved scan scope and scan window.
4. Apply scoped alert tuning only for the approved scanner IP and approved destination scope.
5. Keep WAF brute-force detection enabled for all external and non-approved sources.
6. Investigate normally if similar activity appears from unknown IPs, user workstations, or non-approved internal sources.

## Escalation Decision

**Decision:** **No SOC L2 escalation required.**

**Reason:** The source is an internal Qualys scanner, and the observed request is consistent with authorized security testing. No successful unauthorized login, account compromise, service impact, or malicious external activity was confirmed.

## Final Ticket Closure Comment

SOC investigated ticket **CS-029 — WAF: Brute Force Attack**. The alert involved internal source **10.0.2.53 / LinITQualys01** targeting **10.0.16.24 / LinOPWebServer05** over HTTPS. The WAF detected a brute-force-style request to **marketing.abc.com/admin** with matched string `username=admin&password=admin123`. Source asset validation confirmed the traffic originated from an internal Qualys scanner. No unauthorized login, account compromise, application compromise, or service impact was observed. Ticket can be closed as **False Positive — Authorized Internal Scanner Activity**, with scoped SIEM/WAF tuning recommended.

## Skills Demonstrated

WAF alert triage, scanner validation, false-positive handling, web brute-force detection review, asset context correlation, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
