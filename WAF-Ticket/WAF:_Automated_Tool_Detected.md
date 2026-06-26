# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                           |
| ---------------- | ----------------------------------------------------------------- |
| Ticket ID        | CS-034                                                            |
| Alert Name       | WAF: Automated Tool Detected                                      |
| Ticket Status    | Closed                                                            |
| Priority / SLA   | Normal / Default SLA                                              |
| Created Date     | 3/2/25 7:45 PM                                                    |
| Closed By        | Ananda Das                                                        |
| Analyst Decision | **True Positive — Automated Tool Activity / No Confirmed Impact** |

## Executive Summary

A WAF alert was triggered for **Automated Tool Detected** involving inbound HTTPS traffic from external source IP **13.250.46.201** to internal web server **10.0.11.10 / LinFDWebServer06** on **443/TCP**.

The request targeted **finance.abc.com/admin** using HTTP method **GET**. The WAF detected automated tool indicators in the request, including `curl/7.68.0` and `python-requests/2.24.0`. The WAF action was **Allowed**, the WAF was in **Monitoring** mode, and the application returned HTTP **200**.

Only **1 request** was observed in the provided Splunk result. No successful login, admin session creation, exploitation, data exposure, application compromise, or service impact was confirmed from the evidence.

## Alert Details

| Field            | Value                                                                   |
| ---------------- | ----------------------------------------------------------------------- |
| Receive Time     | 2/26/2025 04:56                                                         |
| Source IP        | 13.250.46.201                                                           |
| Source Port      | 47876                                                                   |
| Destination IP   | 10.0.11.10                                                              |
| Destination Port | 443                                                                     |
| Site Name        | finance.abc.com                                                         |
| URL              | /admin                                                                  |
| HTTP Method      | GET                                                                     |
| Threat Name      | Automated Tool Detected                                                 |
| Severity         | Medium                                                                  |
| Matched String   | `curl/7.68.0 and python-requests/2.24.0`                                |
| WAF Action       | Allowed                                                                 |
| WAF Mode         | Monitoring                                                              |
| Response Code    | 200                                                                     |
| Source Details   | Amazon Data Services Singapore; AWS EC2; AS16509; amazon.com; Singapore |
| Abuse Confidence | 100%                                                                    |

## Affected Assets

| Asset Field          | Details          |
| -------------------- | ---------------- |
| Destination IP       | 10.0.11.10       |
| Hostname             | LinFDWebServer06 |
| Operating System     | Linux - RHEL 8   |
| Platform             | Linux            |
| Asset Role           | Web Server       |
| Hosting              | AWS Cloud        |
| Site                 | finance.abc.com  |
| Targeted Endpoint    | `/admin`         |
| Business Criticality | Not Provided     |

## Evidence Reviewed

| Evidence Source  | Observation                                |
| ---------------- | ------------------------------------------ |
| WAF Alert        | Automated tool activity detected           |
| Tool Indicator   | `curl/7.68.0` and `python-requests/2.24.0` |
| Targeted URL     | `/admin`                                   |
| HTTP Method      | GET                                        |
| WAF Action       | Allowed                                    |
| WAF Mode         | Monitoring                                 |
| Response Code    | 200                                        |
| Observed Count   | 1                                          |
| Successful Login | Not Observed                               |
| Exploitation     | Not Observed                               |
| Service Impact   | Not Provided                               |

## SIEM / Splunk Analysis

```spl id="cj6a82"
index=main "13.250.46.201" "10.0.11.10" sourcetype=waf_logs Threat_Name="Automated Tool Detected"
| stats count by _time, srcIP, dstIP, Action, http_method, matched_string, response_code, URL, user_agent, waf_mode
| sort - count
```

| _time               | srcIP         | dstIP      | Action  | Method | Matched String                           | Response | URL    | User-Agent    | WAF Mode   | Count |
| ------------------- | ------------- | ---------- | ------- | ------ | ---------------------------------------- | -------: | ------ | ------------- | ---------- | ----: |
| 2025-02-26 04:56:00 | 13.250.46.201 | 10.0.11.10 | Allowed | GET    | `curl/7.68.0 and python-requests/2.24.0` |      200 | /admin | `curl/7.68.0` | Monitoring |     1 |

**Analysis Note:** The request was allowed and returned HTTP **200**, but only a single request was observed and no authentication success, exploit payload, or follow-up malicious activity was provided.

## MITRE ATT&CK Mapping

| Tactic         | Technique                         | ID        | Reason                                                         |
| -------------- | --------------------------------- | --------- | -------------------------------------------------------------- |
| Reconnaissance | Active Scanning                   | T1595     | Automated tooling targeted a public web endpoint               |
| Reconnaissance | Vulnerability Scanning            | T1595.002 | `curl` / `python-requests` indicators suggest scripted probing |
| Initial Access | Exploit Public-Facing Application | T1190     | Public `/admin` path was targeted; exploitation not confirmed  |

## Analyst Assessment

**Assessment:** **True Positive — Automated Tool Probing**

The alert is valid because the WAF detected automation-related indicators in traffic targeting a sensitive admin path. The source IP belongs to cloud infrastructure and has high abuse confidence, increasing suspicion.

This is **not confirmed compromise**. The evidence shows only **1 request**, and no successful login, admin session creation, exploitation, file upload, data exposure, or service impact was observed.

## Impact Analysis

| Area            | Assessment                                                       |
| --------------- | ---------------------------------------------------------------- |
| Confidentiality | No data exposure observed                                        |
| Integrity       | No unauthorized change confirmed                                 |
| Availability    | No service disruption reported                                   |
| Business Impact | No confirmed impact                                              |
| Current Risk    | Medium due to automated access to `/admin` and HTTP 200 response |

## Recommended Actions

1. Block source IP **13.250.46.201** at the firewall/IPS as per policy.
2. Add the source IP to WAF denylist or watchlist if supported.
3. Move automated tool detection from **Monitoring** to **Blocking** for sensitive paths after validation.
4. Restrict `/admin` access to trusted IP ranges, VPN, or authenticated users only.
5. Review web server logs for additional requests from the same source IP.
6. Confirm whether HTTP **200** on `/admin` exposes a public page or protected login page.
7. Enable bot protection and rate limiting for `/admin` and `/login`.
8. Escalate only if repeated probing, exploit payloads, successful login, sensitive data access, or application compromise is observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall/IPS block documentation.**

**Reason:** The WAF detected automated tool activity against `/admin`, but only one request was observed and no successful authentication, exploitation, application compromise, or service impact was confirmed from the provided evidence.

## Final Ticket Closure Comment

SOC investigated ticket **CS-034 — WAF: Automated Tool Detected**. Inbound HTTPS traffic from **13.250.46.201** to **10.0.11.10 / LinFDWebServer06** targeted **finance.abc.com/admin** using HTTP **GET**. The WAF detected automated tool indicators including `curl/7.68.0` and `python-requests/2.24.0`. The WAF was in Monitoring mode and allowed the request, with HTTP **200** returned. Only **1 request** was observed, and no successful login, exploitation, data exposure, application compromise, or service impact was confirmed. Ticket closed as **True Positive — Automated Tool Activity / No Confirmed Impact**, with source IP blocking and WAF automation-detection enforcement recommended.

## Skills Demonstrated

WAF alert triage, automated tool detection analysis, user-agent review, Splunk aggregation, source reputation assessment, admin endpoint risk assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
