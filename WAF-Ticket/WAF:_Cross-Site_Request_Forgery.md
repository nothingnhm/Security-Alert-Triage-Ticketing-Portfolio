# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                 |
| ---------------- | ------------------------------------------------------- |
| Ticket ID        | CS-030                                                  |
| Alert Name       | WAF: Cross-Site Request Forgery                         |
| Ticket Status    | Closed                                                  |
| Priority / SLA   | Normal / High                                           |
| Created Date     | 3/2/25 7:45 PM                                          |
| Closed By        | Ananda Das                                              |
| Analyst Decision | **Needs Escalation — Potential Successful CSRF Action** |

## Executive Summary

A WAF alert was triggered for **Cross-Site Request Forgery** involving inbound HTTPS traffic from external source IP **110.22.190.227** to internal destination **10.0.11.10** on **443/TCP**.

The request targeted **finance.abc.com/accounts** using HTTP method **GET** with the matched string `delete?user=1`. The WAF action was **Allowed**. Additional provided WAF evidence shows the request returned HTTP **200** while the WAF was in **Monitoring** mode.

Because the matched string appears related to account deletion or account-management functionality, successful business impact cannot be ruled out from WAF evidence alone. Developer/application validation is required to confirm whether any user account was deleted or modified.

## Alert Details

| Field             | Value                      |
| ----------------- | -------------------------- |
| Receive Time      | 2/17/2025 10:59            |
| Source IP         | 110.22.190.227             |
| Source Port       | 39621                      |
| Destination IP    | 10.0.11.10                 |
| Destination Port  | 443                        |
| Site Name         | finance.abc.com            |
| URL               | /accounts                  |
| HTTP Method       | GET                        |
| Threat Name       | Cross-Site Request Forgery |
| Severity          | High                       |
| Matched String    | `delete?user=1`            |
| WAF Action        | Allowed                    |
| Response Code     | 200                        |
| WAF Mode          | Monitoring                 |
| Source Reputation | Not Provided               |

## Affected Assets

| Asset Field          | Details                                                                |
| -------------------- | ---------------------------------------------------------------------- |
| Destination IP       | 10.0.11.10                                                             |
| Hostname             | LinFDWebServer06                                                       |
| Operating System     | Linux - RHEL 8                                                         |
| Platform             | Linux                                                                  |
| Asset Role           | Web Server                                                             |
| Hosting              | AWS Cloud                                                              |
| Site                 | finance.abc.com                                                        |
| Business Criticality | Not Provided                                                           |
| Exposure Concern     | Account-management endpoint may have accepted a state-changing request |

## Evidence Reviewed

| Evidence Source            | Observation            |
| -------------------------- | ---------------------- |
| WAF Alert                  | CSRF activity detected |
| Targeted URL               | `/accounts`            |
| Matched String             | `delete?user=1`        |
| HTTP Method                | GET                    |
| WAF Action                 | Allowed                |
| WAF Mode                   | Monitoring             |
| Response Code              | 200                    |
| Account Deletion Confirmed | Not Provided           |
| CSRF Token Validation      | Not Provided           |
| Authorization Validation   | Not Provided           |
| Service Impact             | Not Provided           |

## SIEM / Splunk Analysis

```spl id="m73vcp"
index=main "110.22.190.227" "10.0.11.10" sourcetype=waf_logs Threat_Name="Cross-Site Request Forgery"
| table _time, srcIP, dstIP, Action, http_method, matched_string, response_code, URL, user_agent, waf_mode
```

| _time               | srcIP          | dstIP      | Action  | Method | URL       | Matched String  | Response | WAF Mode   |
| ------------------- | -------------- | ---------- | ------- | ------ | --------- | --------------- | -------: | ---------- |
| 2025-02-17 10:59:00 | 110.22.190.227 | 10.0.11.10 | Allowed | GET    | /accounts | `delete?user=1` |      200 | Monitoring |

**Analysis Note:** This is not a blocked/no-impact event. The request was allowed and returned HTTP **200**, so application-side validation is required before confirming closure.

## MITRE ATT&CK Mapping

| Tactic          | Technique                         | ID    | Reason                                                                            |
| --------------- | --------------------------------- | ----- | --------------------------------------------------------------------------------- |
| Initial Access  | Exploit Public-Facing Application | T1190 | CSRF-style request targeted a public web application endpoint                     |
| Impact          | Account Access Removal            | T1531 | Payload indicates possible user deletion action; actual deletion not confirmed    |
| Defense Evasion | Abuse Elevation Control Mechanism | T1548 | Potential abuse of application workflow if CSRF/authorization checks were missing |

## Analyst Assessment

**Assessment:** **Needs Escalation — Potential CSRF / Broken Access Control Abuse**

The alert is valid because the WAF detected a CSRF-style request against an account-management endpoint. The matched string `delete?user=1` suggests a possible state-changing action.

This is **not confirmed compromise** from WAF logs alone. However, because the request was **Allowed** and returned **200**, SOC should not close it as no impact until the developer/application team confirms whether the action was rejected, authorized, or actually processed.

## Impact Analysis

| Area            | Assessment                                                     |
| --------------- | -------------------------------------------------------------- |
| Confidentiality | No data disclosure observed                                    |
| Integrity       | Potential account modification/deletion risk                   |
| Availability    | No service disruption reported                                 |
| Business Impact | Potential user account deletion or account-management abuse    |
| Current Risk    | High until application logs confirm no account change occurred |

## Recommended Actions

1. Escalate to **SOC L2 / Application Team** for validation.
2. Confirm whether `/accounts?delete?user=1` or similar delete functionality exists.
3. Review application logs around **2025-02-17 10:59** for account deletion or modification.
4. Validate whether user ID **1** was deleted, disabled, modified, or accessed.
5. Confirm whether the action requires authentication and proper authorization.
6. Confirm whether CSRF token validation is enforced for all state-changing actions.
7. Avoid using HTTP **GET** for delete/update actions; use protected POST/DELETE workflows.
8. Move the WAF CSRF rule from **Monitoring** to **Blocking** after testing.
9. Block or monitor source IP **110.22.190.227** if no business requirement exists.
10. Reopen or escalate further if account deletion, unauthorized modification, repeated attempts, or missing CSRF controls are confirmed.

## Escalation Decision

**Decision:** **Escalate to SOC L2 / Developer Team Validation Required.**

**Reason:** The WAF allowed a CSRF-style request with HTTP **200** against `/accounts`, and the matched string indicates possible user deletion. Successful account modification is not confirmed, but cannot be ruled out without application logs and developer validation.

## Final Ticket Closure Comment

SOC investigated ticket **CS-030 — WAF: Cross-Site Request Forgery**. Inbound HTTPS traffic from **110.22.190.227** to **10.0.11.10** targeted **finance.abc.com/accounts** using HTTP **GET** with matched string `delete?user=1`. The WAF action was Allowed, and provided WAF evidence showed HTTP **200** while in Monitoring mode. No confirmed account deletion, authorization bypass, or application compromise was proven from WAF logs alone. Due to the possible state-changing account-management action, SOC L2 and developer validation are required to confirm whether any user account was modified or deleted and to enforce CSRF/authorization controls.

## Skills Demonstrated

WAF alert triage, CSRF investigation, Broken Access Control risk assessment, Splunk log review, web application security validation planning, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
