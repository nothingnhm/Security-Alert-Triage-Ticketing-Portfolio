# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                               |
| ---------------- | ----------------------------------------------------- |
| Ticket ID        | CS-031                                                |
| Alert Name       | WAF: Credential Stuffing                              |
| Ticket Status    | Closed                                                |
| Priority / SLA   | Normal / Default SLA                                  |
| Created Date     | 3/2/25 7:45 PM                                        |
| Closed By        | Ananda Das                                            |
| Analyst Decision | **True Positive — Failed Login / No Impact Observed** |

## Executive Summary

A WAF alert was triggered for **Credential Stuffing** involving inbound HTTPS traffic from external source IP **20.246.68.215** to internal web server **10.0.14.12 / LinHRWebServer03** on **443/TCP**.

The request targeted **hr.abc.com/login** using HTTP method **POST** with the matched credential pattern `username=admin&password=admin123`. The WAF action was **Allowed** while operating in **Monitoring** mode, but the application returned HTTP **401**, indicating the login attempt was not authorized.

No successful login, session creation, account compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field            | Value                                                                                                           |
| ---------------- | --------------------------------------------------------------------------------------------------------------- |
| Receive Time     | 2/26/2025 00:02                                                                                                 |
| Source IP        | 20.246.68.215                                                                                                   |
| Source Port      | 56689                                                                                                           |
| Destination IP   | 10.0.14.12                                                                                                      |
| Destination Port | 443                                                                                                             |
| Site Name        | hr.abc.com                                                                                                      |
| URL              | /login                                                                                                          |
| HTTP Method      | POST                                                                                                            |
| Threat Name      | Credential Stuffing                                                                                             |
| Severity         | Medium                                                                                                          |
| Matched String   | `username=admin&password=admin123`                                                                              |
| WAF Action       | Allowed                                                                                                         |
| WAF Mode         | Monitoring                                                                                                      |
| Response Code    | 401                                                                                                             |
| Source Details   | Microsoft Corporation; Data Center/Web Hosting/Transit; AS8075; microsoft.com; Boydton, Virginia, United States |
| Abuse Confidence | 100%                                                                                                            |

## Affected Assets

| Asset Field          | Details                                                     |
| -------------------- | ----------------------------------------------------------- |
| Destination IP       | 10.0.14.12                                                  |
| Hostname             | LinHRWebServer03                                            |
| Operating System     | Linux - RHEL 8                                              |
| Platform             | Linux                                                       |
| Asset Role           | Web Server                                                  |
| Hosting              | AWS Cloud                                                   |
| Site                 | hr.abc.com                                                  |
| Business Criticality | Not Provided                                                |
| Exposure Concern     | HR login page targeted with weak/default credential pattern |

## Evidence Reviewed

| Evidence Source    | Observation                                   |
| ------------------ | --------------------------------------------- |
| WAF Alert          | Credential stuffing detected against `/login` |
| Credential Pattern | `username=admin&password=admin123`            |
| HTTP Method        | POST                                          |
| WAF Action         | Allowed                                       |
| WAF Mode           | Monitoring                                    |
| Response Code      | 401                                           |
| Successful Login   | Not Observed                                  |
| Session Creation   | Not Observed                                  |
| Account Compromise | Not Observed                                  |
| Service Impact     | Not Provided                                  |

## SIEM / Splunk Analysis

```spl
index=main "20.246.68.215" "10.0.14.12" sourcetype=waf_logs Threat_Name="Credential Stuffing"
| table _time, srcIP, dstIP, Action, http_method, matched_string, response_code, URL, user_agent, waf_mode
```

| _time               | srcIP         | dstIP      | Action  | Method | URL    | Matched String                     | Response | WAF Mode   |
| ------------------- | ------------- | ---------- | ------- | ------ | ------ | ---------------------------------- | -------: | ---------- |
| 2025-02-26 00:02:00 | 20.246.68.215 | 10.0.14.12 | Allowed | POST   | /login | `username=admin&password=admin123` |      401 | Monitoring |

**Analysis Note:** The request was allowed by WAF monitoring mode, but the application returned HTTP **401**. This supports failed authentication, not confirmed compromise.

## MITRE ATT&CK Mapping

| Tactic            | Technique         | ID        | Reason                                                                              |
| ----------------- | ----------------- | --------- | ----------------------------------------------------------------------------------- |
| Credential Access | Brute Force       | T1110     | WAF detected credential stuffing/login attempt                                      |
| Credential Access | Password Guessing | T1110.001 | Payload used weak/default-looking credentials                                       |
| Initial Access    | Valid Accounts    | T1078     | Credential stuffing could lead to valid account access if successful; not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Failed Credential Stuffing Attempt**

The alert is valid because the request targeted a login page using a common weak credential pair. The source IP has high abuse confidence and belongs to cloud/data center infrastructure.

This is **not confirmed compromise**. The application returned HTTP **401**, and no successful login, session creation, account compromise, or service impact was observed.

## Impact Analysis

| Area            | Assessment                                                   |
| --------------- | ------------------------------------------------------------ |
| Confidentiality | No unauthorized access observed                              |
| Integrity       | No account or application change confirmed                   |
| Availability    | No service disruption reported                               |
| Business Impact | No confirmed impact                                          |
| Current Risk    | Low to Medium; failed login but suspicious source reputation |

## Recommended Actions

1. Block source IP **20.246.68.215** at the firewall/IPS as per policy.
2. Move WAF credential stuffing detection from **Monitoring** to **Blocking** after validation.
3. Review application logs for additional failed login attempts from the same IP.
4. Confirm whether username **admin** is a valid application account.
5. Ensure login rate limiting, account lockout, and MFA are enabled for sensitive accounts.
6. Monitor for repeated credential stuffing attempts from related IPs.
7. Escalate only if successful login, session creation, account lockout, user compromise, or repeated activity after blocking is observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall/IPS block documentation.**

**Reason:** The WAF detected a credential stuffing attempt, but the application returned HTTP **401**. No successful authentication, session creation, account compromise, or service impact was confirmed.

## Final Ticket Closure Comment

SOC investigated ticket **CS-031 — WAF: Credential Stuffing**. Inbound HTTPS traffic from **20.246.68.215** to **10.0.14.12 / LinHRWebServer03** targeted **hr.abc.com/login** using HTTP **POST** with matched string `username=admin&password=admin123`. The WAF was in Monitoring mode and allowed the request, but the application returned HTTP **401**, indicating failed authentication. No successful login, session creation, account compromise, or service impact was observed. Ticket closed as **True Positive — Failed Login / No Impact Observed**, with source IP blocking and WAF credential stuffing enforcement recommended.

## Skills Demonstrated

WAF alert triage, credential stuffing investigation, failed-login validation, Splunk log review, source reputation analysis, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
