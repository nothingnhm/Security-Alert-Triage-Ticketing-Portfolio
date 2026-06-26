# SOC Analyst Investigation Report

**Ticket ID:** CS-027
**Alert Name:** WAF: SQL Injection

---

## 1. Executive Summary

A WAF alert was triggered for **SQL Injection** involving inbound HTTPS traffic from external source IP **91.194.84.10** to internal destination IP **10.0.2.32 / LinITWebServer01** on destination port **443**.

The destination host **10.0.2.32** is identified as **LinITWebServer01**, running **Linux RHEL 8**, with the role of **Web Server** hosted in **AWS Cloud**. The affected site was **it.abc.com**.

The WAF detected multiple SQL injection payloads, including authentication bypass, UNION-based extraction, and time-based SQL injection patterns:

* `' OR '1'='1'; --`
* `' UNION SELECT username, password FROM users --`
* `' AND SLEEP(5) --`

The initial alert on **12/26/2024 05:06** showed **Action: Allowed** while the WAF was in **Monitoring** mode. However, the response code was **403**, indicating the request was denied. Later events from the same source IP were **Blocked** by WAF in **Blocking** mode with response code **403**.

Based on the reviewed WAF logs, there is **no confirmed successful SQL injection, authentication bypass, database disclosure, credential exposure, web application compromise, or service impact**.

Current status: **SQL Injection attempts denied/blocked by WAF. No confirmed compromise. Block source IP in firewall/IPS and add/enforce SQL injection signatures for future prevention.**

---

## 2. Alert Details

| Field                   | Details               |
| ----------------------- | --------------------- |
| Ticket ID               | CS-027                |
| Alert Name              | WAF: SQL Injection    |
| Severity                | High                  |
| Receive Time            | 12/26/2024 05:06      |
| Source IP               | 91.194.84.10          |
| Source Port             | 43544                 |
| Destination IP          | 10.0.2.32             |
| Destination Port        | 443                   |
| Site Name               | it.abc.com            |
| URL                     | /login                |
| HTTP Method             | GET                   |
| Initial Matched String  | `' OR '1'='1'; --`    |
| Threat Name             | SQL Injection         |
| Initial Action          | Allowed               |
| Initial WAF Mode        | Monitoring            |
| Initial Response Code   | 403                   |
| Later WAF Action        | Blocked               |
| Later WAF Mode          | Blocking              |
| Later WAF Response Code | 403                   |
| Destination Hostname    | LinITWebServer01      |
| Destination OS          | Linux - RHEL 8        |
| Destination Role        | Web Server            |
| Hosting Location        | AWS Cloud             |
| Log Source              | WAF Logs / Splunk     |

---

## 3. Source IP Details

| Field            | Value                              |
| ---------------- | ---------------------------------- |
| Source IP        | 91.194.84.10                       |
| ISP              | WIIT AG                            |
| Usage Type       | Data Center/Web Hosting/Transit    |
| ASN              | AS24961                            |
| Hostname         | mail.legaltricks.com               |
| Domain           | wiit.cloud                         |
| Country          | Germany                            |
| City             | Dusseldorf, North Rhine-Westphalia |
| Abuse Confidence | 26%                                |

---

## 4. Destination Asset Information

| Field            | Value                 |
| ---------------- | --------------------- |
| Destination IP   | 10.0.2.32             |
| Hostname         | LinITWebServer01      |
| Operating System | Linux - RHEL 8        |
| Platform         | Linux                 |
| Role             | Web Server            |
| Hosting          | AWS Cloud             |
| Site Name        | it.abc.com |
| Targeted Service | HTTPS / Port 443      |

---

## 5. Investigation Performed

The following investigation steps were performed:

1. Reviewed the WAF alert details, including source IP, destination IP, destination port, site name, URL, matched string, HTTP method, severity, and action.
2. Confirmed inbound HTTPS traffic from external source IP **91.194.84.10** to internal web server **10.0.2.32**.
3. Confirmed destination host **10.0.2.32** as **LinITWebServer01**, a **Linux RHEL 8 Web Server** hosted in **AWS Cloud**.
4. Reviewed source IP context and identified the source as **WIIT AG / wiit.cloud**, categorized as **Data Center/Web Hosting/Transit**.
5. Reviewed WAF logs for repeated SQL Injection attempts from the same source IP to the same destination host.
6. Identified multiple SQL injection patterns, including authentication bypass, UNION-based extraction, and time-delay testing.
7. Confirmed repeated attempts against multiple application paths, including `/login`, `/admin`, and `/api`.
8. Confirmed later WAF events were **Blocked** with response code **403** in **Blocking** mode.
9. Noted the initial event was logged as **Allowed** while WAF was in **Monitoring** mode, but response code was still **403**.
10. No evidence was identified showing successful SQL injection, authentication bypass, database response, credential disclosure, web application compromise, or service impact.
11. Recommended blocking the source IP in firewall/IPS and adding/enforcing SQL injection signatures in IPS/WAF for future prevention.

---

## 6. Evidence Observed

### Initial WAF Alert Evidence

| Field            | Value                 |
| ---------------- | --------------------- |
| Receive Time     | 12/26/2024 05:06      |
| Source IP        | 91.194.84.10          |
| Source Port      | 43544                 |
| Destination IP   | 10.0.2.32             |
| Destination Port | 443                   |
| Site Name        | it.abc.com            |
| URL              | /login                |
| Matched String   | `' OR '1'='1'; --`    |
| HTTP Method      | GET                   |
| Threat Name      | SQL Injection         |
| Severity         | High                  |
| Action           | Allowed               |

---

### Splunk Query Used

```spl
index=main "91.194.84.10" "10.0.2.32" sourcetype=waf_logs Threat_Name="SQL Injection"
| table _time, srcIP, dstIP,  Action, http_method, matched_string, response_code, URL, user_agent, waf_mode
```

### Full Splunk Log Results

```text
_time	srcIP	dstIP	Action	http_method	matched_string	response_code	URL	user_agent	waf_mode
2025-02-17 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' AND SLEEP(5) --	403	/admin	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.3	Blocking
2025-02-05 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' OR '1'='1'; --	403	/api	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-02-05 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' UNION SELECT username, password FROM users --	403	/login	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-02-05 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' OR '1'='1'; --	403	/api	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-02-04 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' OR '1'='1'; --	403	/admin	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-01-24 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' AND SLEEP(5) --	403	/admin	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-01-24 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' UNION SELECT username, password FROM users --	403	/login	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-01-15 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' OR '1'='1'; --	403	/admin	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-01-15 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' UNION SELECT username, password FROM users --	403	/api	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-01-03 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' OR '1'='1'; --	403	/admin	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-01-01 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' OR '1'='1'; --	403	/api	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2024-12-30 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' AND SLEEP(5) --	403	/admin	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2024-12-30 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	' UNION SELECT username, password FROM users --	403	/admin	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2024-12-26 05:06:00	91.194.84.10	10.0.2.32	Allowed	GET	' OR '1'='1'; --	403	/login	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Monitoring
```

---

## 7. Analysis

The reviewed WAF logs show repeated SQL Injection attempts from source IP **91.194.84.10** to web server **10.0.2.32 / LinITWebServer01**.

The activity is considered suspicious because:

* The WAF detected **SQL Injection** attempts.
* The alert severity was **High**.
* The payloads attempted authentication bypass using `' OR '1'='1'; --`.
* The payloads attempted credential extraction using `UNION SELECT username, password FROM users`.
* The payloads attempted time-based testing using `SLEEP(5)`.
* The requests targeted sensitive application paths including `/login`, `/admin`, and `/api`.
* The source IP belongs to data center/web hosting/transit infrastructure.
* The same source repeatedly attempted SQL injection payloads across multiple dates.

The initial alert showed **Allowed** while WAF mode was **Monitoring**. However, the response code was **403**, indicating the request was denied. Later WAF events show **Blocked** action in **Blocking** mode with HTTP response code **403**.

No evidence was observed showing successful SQL injection, successful authentication bypass, database response, credential disclosure, or web application compromise.

Current assessment: **Suspicious SQL Injection attempts denied/blocked by WAF. No confirmed compromise observed.**

---

## 8. Possible False Positive Reason

This alert may be non-impacting from an incident perspective due to the following reasons:

1. Later WAF events show the requests were blocked in **Blocking** mode.
2. Blocked requests returned HTTP **403**.
3. The initial monitoring-mode event also returned HTTP **403**.
4. No successful SQL injection was confirmed.
5. No database response or credential disclosure was observed.
6. No authentication bypass was confirmed.
7. No web application compromise or service impact was observed.
8. The activity appears consistent with automated web exploitation attempts.

Important note: This should not be documented as “no threat detected.” The correct wording is **SQL Injection attempt detected and denied/blocked by WAF / no impact observed**.

---

## 9. Impact Assessment

Based on the reviewed WAF logs, there is **no confirmed impact** to **10.0.2.32 / LinITWebServer01**.

If the SQL injection attempt had succeeded, possible impact could include:

* Authentication bypass
* Unauthorized admin access
* Database information disclosure
* Username and password extraction
* Sensitive data exposure
* Web application compromise
* Data manipulation
* Further exploitation using stolen credentials
* Compliance and reputational impact

Current confirmed impact: **No confirmed impact observed. Requests were denied/blocked by WAF with HTTP 403.**

---

## 10. Actions Taken

The following actions were completed by SOC L1:

1. Reviewed WAF alert details.
2. Validated source IP, destination IP, destination port, site name, URL, matched string, HTTP method, severity, and action.
3. Confirmed destination host **10.0.2.32** as **LinITWebServer01**, a **Linux RHEL 8 Web Server** hosted in **AWS Cloud**.
4. Reviewed source IP context and identified the source as **WIIT AG / wiit.cloud**.
5. Reviewed WAF logs for repeated SQL Injection attempts from the same source IP.
6. Identified multiple SQL Injection payload patterns.
7. Confirmed later events were **Blocked** with HTTP response code **403** in WAF **Blocking** mode.
8. Noted initial event was **Allowed** while WAF mode was **Monitoring**, but the response code was **403**.
9. Confirmed no successful SQL injection, authentication bypass, credential disclosure, or service impact from the reviewed logs.
10. Recommended firewall/IPS source IP block and IPS/WAF SQL Injection signature enforcement.

---

## 11. Firewall / IPS / WAF Rule Update

### Required Rule Updates

| Control  | Direction / Scope  | Source               | Destination            | Service / Pattern        | Recommended Action             |
| -------- | ------------------ | -------------------- | ---------------------- | ------------------------ | ------------------------------ |
| Firewall | Inbound            | 91.194.84.10         | 10.0.2.32              | HTTPS / 443              | Block                          |
| Firewall | Outbound           | 10.0.2.32            | 91.194.84.10           | Any / Related Session    | Block if not business-required |
| IPS      | Inbound inspection | 91.194.84.10         | 10.0.2.32              | SQL Injection signatures | Add / enforce block            |
| WAF      | Application layer  | Any untrusted source | SQL Injection payloads | Keep Blocking            |                                |
| WAF      | Application layer  | 91.194.84.10         | 10.0.2.32              | All requests             | Block / denylist as per policy |

### Signature / Indicator Update

| Indicator Type     | Value                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------------ |
| Source IP          | 91.194.84.10                                                                               |
| Destination IP     | 10.0.2.32                                                                                  |
| Site               | it.abc.com                                                                      |
| Affected URLs      | /login, /admin, /api                                                                       |
| Attack Category    | SQL Injection                                                                              |
| Matched Strings    | `' OR '1'='1'; --`, `' UNION SELECT username, password FROM users --`, `' AND SLEEP(5) --` |
| WAF Threat Name    | SQL Injection                                                                              |
| WAF Response Code  | 403                                                                                        |
| WAF Modes Observed | Monitoring / Blocking                                                                      |
| Severity           | High                                                                                       |

---

## 12. Severity Update Recommendation

**Recommended Severity: High**

Reason:

The alert was marked **High**, and the payloads were consistent with SQL Injection attempts. The severity should remain **High** because:

* SQL injection can lead to authentication bypass.
* SQL injection can lead to database information disclosure.
* One payload attempted to extract usernames and passwords.
* The target is a public-facing web server.
* The same source repeated attempts across multiple dates.

Severity does not need to be increased to Critical because:

* Requests were denied/blocked with HTTP **403**.
* No successful SQL injection was confirmed.
* No credential disclosure or service impact was observed.

Final disposition: **Denied/Blocked by WAF / No Impact Observed**

---

## 13. Recommendation

Recommended next steps:

1. Block source IP **91.194.84.10** at the firewall as per policy.
2. Add **91.194.84.10** to IPS/WAF denylist or watchlist as per organizational policy.
3. Ensure WAF SQL Injection protection remains in **Blocking** mode.
4. Add or validate IPS/WAF signatures for the observed SQL Injection payload patterns.
5. Review web server access logs for any HTTP **200** responses involving similar SQL Injection payloads.
6. Confirm no successful login, authentication bypass, or database error leakage occurred.
7. Review application logs for SQL errors, unusual database queries, or suspicious admin access.
8. Validate input validation and parameterized query implementation on `/login`, `/admin`, and `/api`.
9. Review whether the affected application exposes unnecessary parameters to unauthenticated users.
10. Close the ticket after firewall/IPS/WAF rule updates and source IP block are documented.
11. Reopen or escalate only if successful SQL injection, HTTP 200 response, database error leakage, credential disclosure, application compromise, or service impact is later observed.

---

## 14. Escalation Decision

**Decision:** No SOC L2 escalation required / Close after rule update

**Reason:**

The WAF detected repeated **SQL Injection** attempts from source IP **91.194.84.10** to **10.0.2.32 / LinITWebServer01**. The initial event was logged as **Allowed** while the WAF was in **Monitoring** mode, but it returned HTTP **403**. Later events were **Blocked** by WAF in **Blocking** mode with HTTP **403**.

No successful SQL injection, authentication bypass, database disclosure, credential exposure, web application compromise, or service impact was confirmed from the provided logs.

SOC L2 escalation is not required at this time because the malicious requests were denied/blocked and no impact was observed.

Escalation should only be considered if:

* Similar SQL Injection payloads receive HTTP **200**
* Database error leakage is observed
* Sensitive data is returned in the response
* Successful login or authentication bypass is confirmed
* Suspicious database activity is observed
* WAF fails to block future attempts
* Application compromise indicators are identified

Current SOC L1 decision: **Close as denied/blocked by WAF / no impact observed after firewall, IPS, and WAF rule updates are documented.**

---

## 15. Final Analyst Note

SOC investigated ticket **CS-027 — WAF: SQL Injection**. Logs show inbound HTTPS traffic from external source IP **91.194.84.10** to internal destination IP **10.0.2.32 / LinITWebServer01**, a **Linux RHEL 8 Web Server** hosted in **AWS Cloud** for site **it.abc.com**.

The source IP is associated with **WIIT AG**, hostname **mail.legaltricks.com**, domain **wiit.cloud**, located in **Dusseldorf, North Rhine-Westphalia, Germany**, with reported **26% abuse confidence**.

The WAF detected repeated SQL Injection payloads attempting authentication bypass, credential extraction, and time-based SQL injection testing. The initial event showed **Allowed** while WAF was in **Monitoring** mode, but the response code was **403**. Later events from the same source IP were **Blocked** by WAF in **Blocking** mode with HTTP **403**.

No successful SQL injection, authentication bypass, database information disclosure, credential exposure, web application compromise, or service impact was identified from the provided logs.

Assessment: **Suspicious SQL Injection attempts were denied/blocked by WAF. No confirmed compromise. No SOC L2 escalation required. Ticket can be closed after blocking source IP 91.194.84.10 in firewall/IPS and confirming SQL Injection signatures are enforced in IPS/WAF.**

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
