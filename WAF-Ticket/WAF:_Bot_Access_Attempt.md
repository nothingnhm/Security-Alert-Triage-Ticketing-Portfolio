# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                               |
| ---------------- | ----------------------------------------------------- |
| Ticket ID        | CS-036                                                |
| Alert Name       | WAF: Bot Access Attempt                               |
| Ticket Status    | Closed                                                |
| Priority / SLA   | Normal / Medium                                       |
| Created Date     | 3/2/25 7:45 PM                                        |
| Closed By        | Ananda Das                                            |
| Analyst Decision | **True Positive — Bot Access Attempt Blocked by WAF** |

## Executive Summary

A WAF alert was triggered for **Bot Access Attempt** involving inbound HTTPS traffic from external source IP **13.250.46.201** to internal web server **10.0.11.10 / LinFDWebServer06** on **443/TCP**.

The initial alert targeted **finance.abc.com/login** using HTTP method **GET**. Additional WAF evidence showed bot-like requests from the same source targeting **/admin**, **/search**, and **/login** with a user-agent claiming `YandexBot/3.0`.

All observed requests were **Blocked** by the WAF in **Blocking** mode and returned HTTP **401**. No successful authentication, data exposure, application compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field            | Value                                                                   |
| ---------------- | ----------------------------------------------------------------------- |
| Receive Time     | 1/16/2025 08:55                                                         |
| Source IP        | 13.250.46.201                                                           |
| Source Port      | 35103                                                                   |
| Destination IP   | 10.0.11.10                                                              |
| Destination Port | 443                                                                     |
| Site Name        | finance.abc.com                                                         |
| Initial URL      | /login                                                                  |
| Observed URLs    | /admin, /search, /login                                                 |
| HTTP Method      | GET                                                                     |
| Threat Name      | Bot Access Attempt                                                      |
| Severity         | Medium                                                                  |
| WAF Action       | Blocked                                                                 |
| WAF Mode         | Blocking                                                                |
| Response Code    | 401                                                                     |
| Source Details   | Amazon Data Services Singapore; AWS EC2; AS16509; amazon.com; Singapore |
| Abuse Confidence | 100%                                                                    |

## Affected Assets

| Asset Field          | Details                       |
| -------------------- | ----------------------------- |
| Destination IP       | 10.0.11.10                    |
| Hostname             | LinFDWebServer06              |
| Operating System     | Linux - RHEL 8                |
| Platform             | Linux                         |
| Asset Role           | Web Server                    |
| Hosting              | AWS Cloud                     |
| Site                 | finance.abc.com               |
| Targeted Endpoints   | `/admin`, `/search`, `/login` |
| Business Criticality | Not Provided                  |

## Evidence Reviewed

| Evidence Source           | Observation                                                        |
| ------------------------- | ------------------------------------------------------------------ |
| WAF Alert                 | Bot access attempt detected                                        |
| User-Agent                | `Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)` |
| Targeted Paths            | `/admin`, `/search`, `/login`                                      |
| HTTP Method               | GET                                                                |
| WAF Action                | Blocked                                                            |
| WAF Mode                  | Blocking                                                           |
| Response Code             | 401                                                                |
| Successful Authentication | Not Observed                                                       |
| Data Exposure             | Not Observed                                                       |
| Service Impact            | Not Provided                                                       |

## SIEM / Splunk Analysis

```spl id="u8xb42"
index=main "13.250.46.201" "10.0.11.10" sourcetype=waf_logs Threat_Name="Bot Access Attempt"
| table _time, srcIP, dstIP, Action, http_method, response_code, URL, user_agent, waf_mode
```

| _time               | srcIP         | dstIP      | Action  | Method | Response | URL     | User-Agent                                                         | WAF Mode |
| ------------------- | ------------- | ---------- | ------- | ------ | -------: | ------- | ------------------------------------------------------------------ | -------- |
| 2025-01-16 08:55:00 | 13.250.46.201 | 10.0.11.10 | Blocked | GET    |      401 | /admin  | `Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)` | Blocking |
| 2025-01-16 08:55:00 | 13.250.46.201 | 10.0.11.10 | Blocked | GET    |      401 | /search | `Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)` | Blocking |
| 2025-01-16 08:55:00 | 13.250.46.201 | 10.0.11.10 | Blocked | GET    |      401 | /login  | `Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)` | Blocking |

**Analysis Note:** The WAF blocked all observed bot-like requests and returned HTTP **401**, supporting unauthorized access being denied.

## MITRE ATT&CK Mapping

| Tactic         | Technique                         | ID        | Reason                                                                 |
| -------------- | --------------------------------- | --------- | ---------------------------------------------------------------------- |
| Reconnaissance | Active Scanning                   | T1595     | Bot-like requests targeted multiple web paths                          |
| Reconnaissance | Vulnerability Scanning            | T1595.002 | Requests to `/admin` and `/login` may indicate automated probing       |
| Initial Access | Exploit Public-Facing Application | T1190     | Public web application paths were targeted; exploitation not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Bot Activity Blocked**

The alert is valid because WAF detected bot-like access attempts from a cloud-hosted source IP with high abuse confidence. The requests targeted sensitive paths including `/admin` and `/login`.

This is **not confirmed compromise**. All observed requests were blocked by WAF in Blocking mode and returned HTTP **401**. No successful access, authentication, data exposure, application compromise, or service impact was observed.

## Impact Analysis

| Area            | Assessment                                     |
| --------------- | ---------------------------------------------- |
| Confidentiality | No data exposure observed                      |
| Integrity       | No unauthorized change confirmed               |
| Availability    | No service disruption reported                 |
| Business Impact | No confirmed impact                            |
| Current Risk    | Low to Medium because WAF blocked the activity |

## Recommended Actions

1. Block source IP **13.250.46.201** at the firewall/IPS as per policy.
2. Keep WAF bot protection in **Blocking** mode.
3. Add the source IP to WAF denylist or watchlist if repeated activity continues.
4. Monitor for related activity from the same AWS EC2 source.
5. Confirm no HTTP **200** access from the same source to sensitive paths.
6. Restrict `/admin` and `/login` to authorized users, trusted IP ranges, or VPN where possible.
7. Enable rate limiting and bot protection for sensitive paths.
8. Escalate only if successful access, repeated activity after blocking, credential attacks, exploit payloads, or application compromise is observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall/IPS block documentation.**

**Reason:** The WAF blocked all observed bot access attempts in Blocking mode, and all requests returned HTTP **401**. No successful authentication, data exposure, application compromise, or service impact was confirmed.

## Final Ticket Closure Comment

SOC investigated ticket **CS-036 — WAF: Bot Access Attempt**. Inbound HTTPS traffic from **13.250.46.201** to **10.0.11.10 / LinFDWebServer06** targeted **finance.abc.com** using HTTP **GET**. The WAF detected bot-like activity using a user-agent claiming `YandexBot/3.0`, targeting `/admin`, `/search`, and `/login`. All observed requests were blocked by WAF in Blocking mode and returned HTTP **401**. No successful authentication, data exposure, application compromise, or service impact was observed. Ticket closed as **True Positive — Bot Access Attempt Blocked by WAF**, with source IP blocking and continued bot protection enforcement recommended.

## Skills Demonstrated

WAF alert triage, bot traffic analysis, user-agent review, Splunk log review, source reputation assessment, sensitive endpoint risk assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
