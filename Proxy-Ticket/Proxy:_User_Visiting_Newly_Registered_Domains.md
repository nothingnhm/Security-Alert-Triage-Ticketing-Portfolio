# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Ticket ID        | CS-045                                                                                                                   |
| Alert Name       | Proxy: User Visiting Newly Registered Domains                                                                            |
| Ticket Status    | Closed                                                                                                                   |
| Priority / SLA   | High / Default SLA                                                                                                       |
| Created Date     | 3/16/25 5:03 PM                                                                                                          |
| Closed By        | Ananda Das                                                                                                               |
| Analyst Decision | **True Positive — Newly Registered Security-Risk Login Page Access / Possible Credential Submission Pending Validation** |

## Executive Summary

A proxy alert was triggered for **User Visiting Newly Registered Domains** after user **Ajay Malhotra** from internal source IP **10.1.2.118** accessed a suspicious login page hosted at:

`https://rapiddevapi.com/login.php`

The URL was categorized as **Newly Registered Domain** and marked as a **security risk**. The proxy action was **Allowed**, and the response code was **200**, confirming the page was successfully accessed.

Further Splunk review showed two events:

| Time                | Method | URL                                 | Response Code | Key Observation                                 |
| ------------------- | ------ | ----------------------------------- | ------------: | ----------------------------------------------- |
| 2025-03-16 16:10:00 | GET    | `https://rapiddevapi.com/login.php` |           200 | User accessed the login page from Google search |
| 2025-03-16 16:11:00 | POST   | `https://rapiddevapi.com/login.php` |           200 | Possible form submission to the login page      |

The **POST** request is the most important finding because it may indicate that the user submitted information through the login form. Since the user is a **Payroll Manager** in the **Finance Department**, any credential or payroll-related data exposure would be high-risk.

No confirmed credential compromise, malware download, endpoint compromise, C2 callback, or data exfiltration was identified from the provided logs. However, user and endpoint validation are required because the suspicious login page received a successful POST request.

## Alert Details

| Field                      | Value                               |
| -------------------------- | ----------------------------------- |
| Timestamp                  | 3/16/2025 16:10                     |
| Username                   | Ajay Malhotra                       |
| Source IP                  | 10.1.2.118                          |
| Destination IP             | 46.173.214.32                       |
| URL                        | `https://rapiddevapi.com/login.php` |
| Domain                     | rapiddevapi.com                     |
| Web Category               | Newly Registered Domain             |
| Proxy Action               | Allowed                             |
| HTTP Method                | GET                                 |
| Response Code              | 200                                 |
| Additional Method Observed | POST                                |
| URL Risk Note              | Security Risk                       |
| Destination Hosting        | Garant-Park-Internet LLC            |
| Destination Country        | Russian Federation                  |
| Destination City           | Moscow                              |

## Affected Assets

| Asset Field       | Details                                              |
| ----------------- | ---------------------------------------------------- |
| User              | Ajay Malhotra                                        |
| Role              | Payroll Manager                                      |
| Department        | Finance Department                                   |
| Source IP         | 10.1.2.118                                           |
| Endpoint          | ENDP-040                                             |
| Endpoint OS       | Windows 11-64                                        |
| Destination IP    | 46.173.214.32                                        |
| Suspicious Domain | rapiddevapi.com                                      |
| Suspicious URL    | `https://rapiddevapi.com/login.php`                  |
| Business Risk     | Possible credential or finance/payroll data exposure |

## Investigation Flow

### 1. Alert Review

The alert was reviewed as a high-priority proxy event because the user accessed a **newly registered domain**, which is commonly abused for phishing, malware delivery, fake login pages, and temporary attack infrastructure.

The destination URL contained `/login.php`, which increased suspicion because newly registered domains with login pages may be used to collect credentials.

Key alert observations:

| Indicator     | Observation                    |
| ------------- | ------------------------------ |
| Domain Type   | Newly Registered Domain        |
| Page Type     | Login page                     |
| Proxy Action  | Allowed                        |
| Response Code | 200                            |
| User Context  | Finance / Payroll Manager      |
| Primary Risk  | Possible credential submission |

### 2. Entity and Asset Identification

The activity was associated with **Ajay Malhotra**, a **Payroll Manager** in the **Finance Department**, using source IP **10.1.2.118** and endpoint **ENDP-040 / Windows 11-64**.

This user context is important because payroll users may have access to employee salary details, finance systems, payroll portals, tax records, and other sensitive business data.

### 3. Destination Infrastructure Review

The destination IP **46.173.214.32** was associated with **Garant-Park-Internet LLC**, categorized as **Data Center/Web Hosting/Transit**, and geolocated to **Moscow, Russian Federation**.

| Field          | Value                           |
| -------------- | ------------------------------- |
| Destination IP | 46.173.214.32                   |
| ISP            | Garant-Park-Internet LLC        |
| Usage Type     | Data Center/Web Hosting/Transit |
| ASN            | AS47196                         |
| Domain Name    | parking.ru                      |
| Country        | Russian Federation              |
| City           | Moscow                          |

The hosting location alone does not prove malicious activity, but when combined with a newly registered/security-risk login page and POST request, it increases investigation priority.

### 4. Timeline Reconstruction

| Time                | Activity                                                                                        |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| 2025-03-16 16:10:00 | User accessed `https://rapiddevapi.com/login.php` from a Google search referrer using HTTP GET  |
| 2025-03-16 16:11:00 | User sent an HTTP POST request to the same login page                                           |
| 2025-03-16 16:11:00 | POST request returned HTTP 200, indicating the request was accepted/processed by the web server |

### 5. SIEM Evidence Review

The proxy evidence confirms that the user first loaded the login page and then generated a POST request one minute later.

| Evidence Point                 | Result        |
| ------------------------------ | ------------- |
| Newly registered domain access | Confirmed     |
| Login page access              | Confirmed     |
| GET request                    | Confirmed     |
| POST request                   | Confirmed     |
| HTTP 200 response              | Confirmed     |
| Credential submission          | Not confirmed |
| Malware download               | Not observed  |
| Endpoint compromise            | Not observed  |

### 6. Threat and Risk Context

The activity is suspicious because:

| Risk Factor             | Why It Matters                                                                |
| ----------------------- | ----------------------------------------------------------------------------- |
| Newly registered domain | Often used for phishing, malware hosting, and temporary attack infrastructure |
| `/login.php` path       | Indicates a login form or authentication page                                 |
| HTTP POST request       | May indicate form submission                                                  |
| Response code 200       | Server accepted and responded successfully                                    |
| Finance payroll user    | Higher impact if credentials or sensitive information were entered            |
| Data-center hosting     | Common for temporary suspicious infrastructure                                |
| Proxy action allowed    | Security control did not block access                                         |

The POST request does not prove credential compromise by itself, but it creates a strong need for user validation and account review.

### 7. Impact Validation

| Impact Area                     | Validation Result                          |
| ------------------------------- | ------------------------------------------ |
| Successful Page Access          | Confirmed                                  |
| Possible Form Submission        | Confirmed by POST request                  |
| Corporate Credential Entry      | Not Confirmed                              |
| Payroll/Finance Data Submission | Not Confirmed                              |
| Malware Download                | Not Observed                               |
| Endpoint Compromise             | Not Observed                               |
| C2 Callback                     | Not Observed                               |
| Data Exfiltration               | Not Observed                               |
| Confirmed Impact                | No confirmed compromise from provided logs |

The correct SOC conclusion is: **suspicious newly registered login page access with possible form submission; credential compromise is not confirmed but cannot be ruled out without user validation.**

## Evidence Reviewed

### Initial Proxy Alert Evidence

| Timestamp       | Username      | Source IP  | Destination IP | URL                                 | Web Category            | Action  | HTTP Method | Response Code |
| --------------- | ------------- | ---------- | -------------- | ----------------------------------- | ----------------------- | ------- | ----------- | ------------: |
| 3/16/2025 16:10 | Ajay Malhotra | 10.1.2.118 | 46.173.214.32  | `https://rapiddevapi.com/login.php` | Newly Registered Domain | Allowed | GET         |           200 |

## SIEM / Splunk Analysis

### Splunk Query Used

```spl id="cs0250_proxy_query"
index=main "https://rapiddevapi.com/login.php" sourcetype=proxy_logs
| table _time "Destination IP" "HTTP Method" "Referrer" "Response Code" "URL" "User Agent" Username "Web Category"
```

### Full Unique Splunk Log Results

```text id="cs0250_proxy_results"
_time	Destination IP	HTTP Method	Referrer	Response Code	URL	User Agent	Username	Web Category
2025-03-16 16:11:00	46.173.214.32	POST		200	https://rapiddevapi.com/login.php	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Ajay Malhotra	Newly Registered Domain
2025-03-16 16:10:00	46.173.214.32	GET	https://www.google.com/search?q=https://rapiddevapi.com/login.php	200	https://rapiddevapi.com/login.php	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Ajay Malhotra	Newly Registered Domain
```

### Evidence Interpretation

| Observation                        | Analyst Interpretation                                            |
| ---------------------------------- | ----------------------------------------------------------------- |
| GET request to login page          | User accessed the suspicious site                                 |
| Google search referrer             | User may have searched for or clicked the URL from search results |
| POST request one minute later      | Possible form submission to the login page                        |
| Response code 200                  | Server successfully responded to the request                      |
| User-agent shows Chrome on Windows | Browser-based activity from user endpoint                         |
| No file/hash evidence              | No malware download confirmed                                     |
| No EDR/process evidence            | No endpoint compromise confirmed                                  |

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                            |
| ------------------- | ----------------------------------------- | --------- | --------------------------------------------------------------------------------- |
| Initial Access      | Drive-by Compromise                       | T1189     | User accessed a suspicious newly registered web page; compromise not confirmed    |
| Initial Access      | Phishing                                  | T1566     | Possible phishing-style login page; delivery source not confirmed                 |
| Credential Access   | Input Capture                             | T1056     | POST to login page may indicate submitted input; credential capture not confirmed |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP/S web communication to suspicious external infrastructure was observed       |

## Analyst Assessment

**Assessment:** **True Positive — Suspicious Newly Registered Login Page Access**

The alert is valid because the user accessed a newly registered/security-risk domain hosting a login page, and Splunk logs show a follow-up **POST** request with HTTP **200**.

This is **not confirmed credential compromise** based on the available evidence. The proxy logs show that a POST request occurred, but they do not show what data was submitted. No malware download, endpoint compromise, C2 callback, or data exfiltration was observed.

## Impact Analysis

| Area             | Assessment                                                |
| ---------------- | --------------------------------------------------------- |
| Confidentiality  | Possible risk if credentials or payroll data were entered |
| Integrity        | No endpoint modification confirmed                        |
| Availability     | No service impact reported                                |
| Account Risk     | Possible credential exposure pending user validation      |
| Business Impact  | Potentially high due to Finance/Payroll user context      |
| Confirmed Impact | No confirmed compromise from provided logs                |

## User Validation Required

SOC should contact **Ajay Malhotra** and confirm:

1. Why was `https://rapiddevapi.com/login.php` accessed?
2. Did Ajay intentionally search for or open this website?
3. Was the activity business-related?
4. Did the page show a login form?
5. Did Ajay enter a username, password, OTP, MFA code, payroll data, or personal information?
6. Were corporate credentials used on the website?
7. Did the site redirect to another domain after submission?
8. Was any file downloaded or uploaded?
9. Did Ajay receive the link through email, chat, SMS, or another source?
10. Did the browser show warnings, pop-ups, redirects, or suspicious behavior?

## Endpoint / Account Validation Required

SOC or endpoint team should validate **ENDP-040** for:

| Validation Item                    | Purpose                                                          |
| ---------------------------------- | ---------------------------------------------------------------- |
| Browser history around 16:10–16:11 | Confirm exact user navigation                                    |
| Browser downloads                  | Check for file download activity                                 |
| Browser saved credentials/autofill | Determine whether credentials may have been submitted            |
| EDR/AV alerts                      | Identify malicious process or browser exploit activity           |
| Suspicious redirects               | Check if the page redirected after login                         |
| Additional suspicious domains      | Identify broader browsing activity                               |
| Authentication logs                | Check for follow-up suspicious login attempts                    |
| MFA logs                           | Identify MFA prompts or anomalies after event                    |
| Finance/payroll app logs           | Validate potential credential misuse                             |
| Password reset need                | Trigger only if credential submission or compromise is confirmed |

## Recommended Actions

1. Block **rapiddevapi.com** in proxy/SWG controls.
2. Block `https://rapiddevapi.com/login.php` as a specific URL indicator.
3. Sinkhole or block **rapiddevapi.com** through DNS security.
4. Block destination IP **46.173.214.32** if no business requirement exists.
5. Add **rapiddevapi.com**, **46.173.214.32**, and **Ajay Malhotra / 10.1.2.118** to SIEM watchlist.
6. Contact **Ajay Malhotra** to confirm whether credentials or sensitive information were entered.
7. Review endpoint **ENDP-040** browser history, downloads, and EDR telemetry.
8. Review authentication logs for Ajay after **2025-03-16 16:11**.
9. Reset password and revoke sessions only if credential submission or suspicious login activity is confirmed.
10. Escalate to SOC L2 if credential entry, file download, endpoint compromise, or broader campaign activity is identified.

## Containment / Blocking Plan

| Control           | Indicator                             | Recommended Action                                                       |
| ----------------- | ------------------------------------- | ------------------------------------------------------------------------ |
| Proxy / SWG       | rapiddevapi.com                       | Block                                                                    |
| Proxy / SWG       | `https://rapiddevapi.com/login.php`   | Block                                                                    |
| DNS Security      | rapiddevapi.com                       | Sinkhole / block                                                         |
| Firewall          | 46.173.214.32                         | Block outbound if not business-required                                  |
| IPS               | rapiddevapi.com / 46.173.214.32       | Add to watchlist/blocklist                                               |
| SIEM              | Ajay Malhotra / 10.1.2.118 / ENDP-040 | Add monitoring correlation                                               |
| EDR               | ENDP-040                              | Investigate if suspicious behavior or credential submission is confirmed |
| Identity Platform | Ajay Malhotra                         | Review logins and reset password only if needed                          |

## Severity Recommendation

**Recommended Severity:** **Medium to High**

The alert was high priority and should be treated seriously because it involved a newly registered/security-risk login page and a POST request from a Finance/Payroll user.

Severity can remain **Medium** if:

| Condition                             | Reason                           |
| ------------------------------------- | -------------------------------- |
| No credentials were entered           | No confirmed credential exposure |
| No file upload/download occurred      | Lower compromise risk            |
| No EDR alerts were found              | No endpoint impact               |
| No suspicious login activity followed | Account compromise not observed  |

Severity should remain or be raised to **High** if:

| Condition                              | Reason                          |
| -------------------------------------- | ------------------------------- |
| Corporate credentials were entered     | Possible account compromise     |
| OTP/MFA code was entered               | Immediate account takeover risk |
| Payroll/finance data was submitted     | Sensitive data exposure         |
| File download/upload occurred          | Malware or data loss risk       |
| Suspicious logins occurred after event | Credential misuse risk          |
| Similar activity is seen across users  | Possible phishing campaign      |

## Escalation Decision

**Decision:** **User validation required; conditional SOC L2 escalation.**

**Reason:** The proxy evidence confirms access to a suspicious newly registered login page and a POST request, but the logs do not confirm what data was submitted.

SOC L2 escalation is **not required** if:

1. Ajay confirms no credentials or sensitive information were entered.
2. No suspicious authentication activity is found.
3. No file upload/download occurred.
4. No EDR/AV alerts are identified.
5. Domain/IP blocking is completed.

Escalate to **SOC L2 / Incident Response** if:

1. Ajay entered corporate credentials, OTP, MFA code, or payroll data.
2. Suspicious login attempts are observed after the event.
3. File download/upload occurred.
4. Endpoint compromise indicators are found.
5. Multiple users accessed the same domain.
6. The domain is linked to a broader phishing campaign.

## Final Ticket Closure Comment

SOC investigated ticket **CS-045 — Proxy: User Visiting Newly Registered Domains**. Logs show user **Ajay Malhotra** from **10.1.2.118 / ENDP-040** accessed `https://rapiddevapi.com/login.php`, categorized as **Newly Registered Domain** and marked as a security risk. Splunk evidence shows an initial HTTP **GET** request from a Google search referrer at **2025-03-16 16:10:00**, followed by an HTTP **POST** request to the same login page at **2025-03-16 16:11:00**. Both requests returned HTTP **200** and were allowed by proxy policy. No malware download, endpoint compromise, C2 callback, data exfiltration, or confirmed credential compromise was identified from the provided logs. Ticket closed as **True Positive — Suspicious Newly Registered Login Page Access / Possible Credential Submission Pending Validation**, with user validation, endpoint review, authentication log review, domain/IP blocking, and conditional SOC L2 escalation recommended if credential submission or suspicious activity is confirmed.

## Skills Demonstrated

Proxy alert triage, newly registered domain investigation, suspicious login page analysis, timeline reconstruction, user and endpoint correlation, Splunk proxy log review, POST request interpretation, credential exposure risk assessment, MITRE ATT&CK mapping, impact validation, containment planning, escalation decision-making, and SOC ticket documentation.

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
