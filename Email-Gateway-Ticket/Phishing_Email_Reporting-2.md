# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Ticket ID        | CS-047                                                                                                                   |
| Alert Name       | Phishing Email                                                                                                           |
| Category         | Phishing Email Reporting                                                                                                 |
| Status           | Closed                                                                                                                   |
| Priority         | Normal                                                                                                                   |
| Severity         | High                                                                                                                     |
| Logs Received    | 29-JAN-2025                                                                                                              |
| Create Date      | 4/17/25 7:39 PM                                                                                                          |
| Reported By      | Ananda Das — SOC Team                                                                                                    |
| Initial Reporter | Sneha Rathod                                                                                                             |
| Analyst Decision | **True Positive — Phishing Email with Possible Credential Harvesting / Suspicious VPN Authentication Attempts Observed** |

## Executive Summary

A phishing email alert was reported by user **Sneha Rathod**. The email used an urgent account-verification theme and was delivered to multiple recipients.

The suspicious subject was:

`URGENT: confirm account activity`

The email appeared to be sent from:

`abc" <abc@zimbramail.serino.com>`

Email authentication failed for **SPF**, **DKIM**, and **DMARC**, increasing the likelihood of spoofing, unauthorized sending, or malicious email infrastructure. The email contained a redirect-based phishing URL using **secure.adnxs.com**, which redirected to the suspicious final domain:

`maxloglogistica.com`

The final domain was categorized as **Business/Economy** and **Compromised Sites**. Email gateway logs confirmed the message was delivered and allowed to multiple recipients. Proxy logs confirmed user interaction from **Rahul Joshi** and **Rachel Moore**. Rahul Joshi generated both **GET** and **POST** requests, where the POST request may indicate form or credential submission.

VPN logs also showed suspicious authentication attempts for **Rahul Joshi** from source IP **186.23.212.74**, where MFA challenges were initiated and failed due to incorrect OTP entries. No successful VPN session was observed.

A timeline mismatch was identified because the VPN log timestamp is **2025-02-23**, while the phishing email and proxy activity occurred on **2025-02-24**. This should be validated during escalation, but the VPN activity remains relevant for user risk review.

## Alert Details

| Field                   | Value                                  |
| ----------------------- | -------------------------------------- |
| Email Time              | 2025-02-24 10:39:54                    |
| Sender                  | `abc@zimbramail.serino.com` |
| Display Name            | `abc"`                      |
| Receiver                | Multiple Users                         |
| Subject                 | `URGENT: confirm account activity`     |
| Return Path             | `abc@zimbramail.serino.com` |
| Sender IP               | 52.101.10.18                           |
| Email Gateway Sender IP | 18.139.53.140                          |
| SPF                     | Failed                                 |
| DKIM                    | Failed                                 |
| DMARC                   | Failed                                 |
| Email Status            | Delivered                              |
| Email Action            | Allowed                                |
| Redirect Domain         | secure.adnxs.com                       |
| Final Domain            | maxloglogistica.com                    |
| URL Category            | Business/Economy and Compromised Sites |
| Web Server IP           | 5.62.56.113                            |
| Proxy Detected IP       | 68.67.160.76                           |
| Malicious VPN Source IP | 186.23.212.74                          |
| IPS Detected IP         | 65.55.127.63                           |

## Affected Assets

| User / Recipient                    | Evidence Observed                                                              | Risk Level |
| ----------------------------------- | ------------------------------------------------------------------------------ | ---------- |
| Rahul Joshi                         | Email delivered, proxy GET/POST activity, suspicious VPN MFA failures observed | High       |
| Rachel Moore                        | Email delivered, proxy GET activity observed                                   | Medium     |
| [info@abc.com](mailto:info@abc.com) | Email delivered, no proxy or VPN activity provided                             | Medium     |

## Evidence Reviewed

### IOC Summary

| Indicator Type          | Indicator                                                                                                                                                                                           |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Phishing URL            | `https://secure.adnxs.com/clktrb?id=092070&redir=https://secure.adnxs.com/clktrb?id=092070&redir=https://maxloglogistica.com/bWUuY29tL/0RyRWFNa/0cpLrPAW/Ef6vPnXL/aW5mb0BjeWJlcnNlY3hwZXJ0cy5jb20=` |
| Redirect Domain         | secure.adnxs.com                                                                                                                                                                                    |
| Final Domain            | maxloglogistica.com                                                                                                                                                                                 |
| Email Sender            | `abc@zimbramail.serino.com`                                                                                                                                                              |
| Email Domain            | zimbramail.serino.com                                                                                                                                                                               |
| Web Server IP           | 5.62.56.113                                                                                                                                                                                         |
| Email Sender IP         | 18.139.53.140                                                                                                                                                                                       |
| Proxy Detected IP       | 68.67.160.76                                                                                                                                                                                        |
| Malicious VPN Source IP | 186.23.212.74                                                                                                                                                                                       |
| IPS Detected IP         | 65.55.127.63                                                                                                                                                                                        |

### IP Reputation Details

| IP Address    | Purpose         | Reputation / Ownership Details                                                                                                                       |
| ------------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 5.62.56.113   | Web Server IP   | Abuse Confidence: 50%; ISP: AVAST Software s.r.o.; Usage: Data Center/Web Hosting/Transit; Hostname: r-113.56.62.5.ptr.avast.com; Country: Guatemala |
| 18.139.53.140 | Email Sender IP | Abuse Confidence: 32%; ISP: Amazon Data Services Singapore; ASN: AS16509; Hostname: zimbramail.serino.com; Country: Singapore                        |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The alert was reviewed as a phishing incident because the email used urgent account-verification wording and was delivered to multiple recipients. The sender domain and return path were suspicious, and email authentication failed for SPF, DKIM, and DMARC.

Key alert indicators:

| Indicator             | Observation                                      |
| --------------------- | ------------------------------------------------ |
| Subject Theme         | Urgent account verification                      |
| Authentication        | SPF, DKIM, and DMARC failed                      |
| URL Type              | Redirect-based URL                               |
| Final Domain Category | Compromised Sites                                |
| Email Status          | Delivered and Allowed                            |
| User Interaction      | Confirmed through proxy logs                     |
| VPN Activity          | Suspicious MFA failures observed for Rahul Joshi |

#### 2. Email Gateway Log Review

```spl id="cs0278_email_query"
index=main sourcetype="email_logs" "zimbramail.serino.com"
| table _time "Destination IP" Sender SenderIP Recipient Email_Subject URL Status Action
```

```text id="cs0278_email_results"
_time	Destination IP	Sender	SenderIP	Recipient	Email_Subject	URL	Status	Action
2025-02-24 10:39:00		abc" <abc@zimbramail.serino.com>	18.139.53.140	rahul.joshi@abc.com	URGENT: confirm account activity	https://secure.adnxs.com/clktrb?id=092070&redir=https://secure.adnxs.com/clktrb?id=092070&redir=https://maxloglogistica.com/bWUuY29tL/0RyRWFNa/0cpLrPAW/Ef6vPnXL/aW5mb0BjeWJlcnNlY3hwZXJ0cy5jb20=	Delivered	Allowed
2025-02-24 10:39:00		abc" <abc@zimbramail.serino.com>	18.139.53.140	rachel.moore@abc.com	URGENT: confirm account activity	https://secure.adnxs.com/clktrb?id=092070&redir=https://secure.adnxs.com/clktrb?id=092070&redir=https://maxloglogistica.com/bWUuY29tL/0RyRWFNa/0cpLrPAW/Ef6vPnXL/aW5mb0BjeWJlcnNlY3hwZXJ0cy5jb20=	Delivered	Allowed
2025-02-24 10:39:00		abc" <abc@zimbramail.serino.com>	18.139.53.140	info@abc.com	URGENT: confirm account activity	https://secure.adnxs.com/clktrb?id=092070&redir=https://secure.adnxs.com/clktrb?id=092070&redir=https://maxloglogistica.com/bWUuY29tL/0RyRWFNa/0cpLrPAW/Ef6vPnXL/aW5mb0BjeWJlcnNlY3hwZXJ0cy5jb20=	Delivered	Allowed
```

**Email Evidence Interpretation**

| Observation                         | Analyst Interpretation                        |
| ----------------------------------- | --------------------------------------------- |
| Email delivered to three recipients | Confirmed exposure scope                      |
| Action was Allowed                  | Email security control did not block delivery |
| SPF, DKIM, and DMARC failed         | Strong spoofing/phishing indicator            |
| Urgent subject used                 | Social engineering pressure tactic            |
| Redirect URL present                | Common phishing evasion technique             |

#### 3. Proxy Log Review

```spl id="cs0278_proxy_query"
index=main sourcetype="proxy_logs" "https://maxloglogistica.com"
| table _time "Destination IP" "HTTP Method" "Response Code" URL "User Agent" "Username" Username
```

```text id="cs0278_proxy_results"
_time	Destination IP	HTTP Method	Response Code	URL	User Agent	Username
2025-02-24 11:46:00	68.67.160.76	POST	200	https://secure.adnxs.com/clktrb?id=092070&redir=https://secure.adnxs.com/clktrb?id=092070&redir=https://maxloglogistica.com/bWUuY29tL/0RyRWFNa/0cpLrPAW/Ef6vPnXL/aW5mb0BjeWJlcnNlY3hwZXJ0cy5jb20=	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Rahul Joshi
2025-02-24 11:45:00	68.67.160.76	GET	200	https://secure.adnxs.com/clktrb?id=092070&redir=https://secure.adnxs.com/clktrb?id=092070&redir=https://maxloglogistica.com/bWUuY29tL/0RyRWFNa/0cpLrPAW/Ef6vPnXL/aW5mb0BjeWJlcnNlY3hwZXJ0cy5jb20=	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Rahul Joshi
2025-02-24 10:39:00	68.67.160.76	GET	200	https://secure.adnxs.com/clktrb?id=092070&redir=https://secure.adnxs.com/clktrb?id=092070&redir=https://maxloglogistica.com/bWUuY29tL/0RyRWFNa/0cpLrPAW/Ef6vPnXL/aW5mb0BjeWJlcnNlY3hwZXJ0cy5jb20=	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Rachel Moore
```

**Proxy Evidence Interpretation**

| Observation                             | Analyst Interpretation                        |
| --------------------------------------- | --------------------------------------------- |
| Rachel Moore generated GET request      | User accessed or loaded the phishing URL      |
| Rahul Joshi generated GET request       | Rahul opened the phishing URL                 |
| Rahul Joshi generated POST request      | Possible form or credential submission        |
| Response code 200                       | Web server successfully responded             |
| Domain categorized as Compromised Sites | Increases confidence of malicious activity    |
| Browser user-agent observed             | Activity was browser-based from user endpoint |

#### 4. VPN Log Review — Rahul Joshi

```spl id="cs0278_vpn_query"
index=main sourcetype="vpn_logs" "Rahul.Joshi" source_ip="186.23.212.74"
| table _time alert_status authentication_method device_name device_type disconnect_reason Hostname Message mfa_status session_status user
```

```text id="cs0278_vpn_results"
_time	alert_status	authentication_method	device_name	device_type	disconnect_reason	Hostname	Message	mfa_status	session_status	user
2025-02-23 08:29:00	Suspicious	MFA	IvantiVPN01	Windows 11	Failed Authentication	Dstldfnd	User 'rahul.joshi' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	Failed	None	rahul.joshi
2025-02-23 08:29:00	Normal	MFA	IvantiVPN01	Windows 11	None	Dstldfnd	User 'rahul.joshi' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	OTP Sent	Pending Authentication	rahul.joshi
2025-02-23 08:29:00	Suspicious	Password	IvantiVPN01	Windows 11	None	Dstldfnd	User 'rahul.joshi' Realm 'Corporate_VPN' - Authentication initiated	Prompted	Authentication initiated	rahul.joshi
```

**VPN Evidence Interpretation**

| Observation                             | Analyst Interpretation                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------- |
| VPN source IP was 186.23.212.74         | Suspicious external authentication source                                       |
| Password authentication initiated       | Credential use attempt occurred                                                 |
| MFA challenge initiated                 | Authentication reached MFA stage                                                |
| MFA failed due to incorrect OTP         | Full VPN access was blocked                                                     |
| Session status remained None / Pending  | No successful VPN session confirmed                                             |
| VPN log date differs from phishing date | Requires validation for timezone, ingestion delay, or separate related activity |

#### 5. Timeline Reconstruction

| Time             | Event                                                                                                      |
| ---------------- | ---------------------------------------------------------------------------------------------------------- |
| 2025-02-23 08:29 | Suspicious VPN authentication attempts observed for Rahul Joshi from source IP 186.23.212.74; MFA failed   |
| 2025-02-24 10:39 | Phishing email delivered and allowed to Rahul Joshi, Rachel Moore, and [info@abc.com](mailto:info@abc.com) |
| 2025-02-24 10:39 | Rachel Moore generated GET request to phishing URL                                                         |
| 2025-02-24 11:45 | Rahul Joshi generated GET request to phishing URL                                                          |
| 2025-02-24 11:46 | Rahul Joshi generated POST request to phishing URL                                                         |

**Timeline Note:** The VPN event occurred one day before the email/proxy evidence. This may be caused by a timestamp/timezone issue, ingestion delay, unrelated earlier credential attack, or another phishing event not included in the provided evidence. The mismatch should be validated during SOC L2 review.

#### 6. Attack Chain Correlation

The investigation supports the following attack chain:

1. Phishing email was delivered to multiple recipients.
2. Email authentication failed, supporting spoofing or unauthorized email delivery.
3. The email used a redirect URL to hide or route users to the final suspicious domain.
4. The final domain was categorized as **Compromised Sites**.
5. Proxy logs confirmed user interaction with the phishing URL.
6. Rahul Joshi generated a POST request, indicating possible submitted data.
7. VPN logs showed suspicious authentication attempts for Rahul Joshi from external IP **186.23.212.74**.
8. MFA prevented full VPN access.
9. No successful VPN session, malware execution, or data exfiltration was confirmed.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                      | ID        | Reason                                                                     |
| ------------------- | ---------------------------------------------- | --------- | -------------------------------------------------------------------------- |
| Initial Access      | Phishing                                       | T1566     | Phishing email was delivered to multiple users                             |
| Initial Access      | Spearphishing Link                             | T1566.002 | Email contained a malicious/redirect link that users accessed              |
| Credential Access   | Input Capture                                  | T1056     | Rahul Joshi generated a POST request that may indicate submitted form data |
| Credential Access   | Valid Accounts                                 | T1078     | Suspicious VPN login attempt suggests possible credential use              |
| Initial Access      | External Remote Services                       | T1133     | Corporate VPN was targeted                                                 |
| Credential Access   | Multi-Factor Authentication Request Generation | T1621     | MFA challenge was generated during suspicious VPN authentication           |
| Command and Control | Application Layer Protocol: Web Protocols      | T1071.001 | Web traffic to phishing-related infrastructure was observed                |

## Analyst Assessment

**Assessment:** **True Positive — Phishing Email with Possible Credential Harvesting**

The alert is valid because the phishing email was delivered, email authentication failed, the final URL was categorized as **Compromised Sites**, proxy logs confirmed user interaction, and Rahul Joshi generated a POST request.

The suspicious VPN authentication attempts increase the risk for Rahul Joshi. MFA prevented successful VPN access, but credential exposure cannot be ruled out.

This is not confirmed full account compromise because no successful VPN session, MFA approval, endpoint compromise, malware execution, or data exfiltration was observed in the provided evidence.

## Impact Analysis

| Area                     | Assessment                                                                               |
| ------------------------ | ---------------------------------------------------------------------------------------- |
| Email Delivery           | Confirmed delivered and allowed                                                          |
| Email Authentication     | SPF, DKIM, and DMARC failed                                                              |
| User Interaction         | Confirmed through proxy GET requests                                                     |
| Possible Form Submission | POST request observed from Rahul Joshi                                                   |
| Credential Exposure      | Possible, not fully confirmed                                                            |
| VPN Abuse Attempt        | Suspicious VPN MFA failures observed for Rahul Joshi                                     |
| MFA Protection           | Effective; MFA failed                                                                    |
| Successful VPN Session   | Not observed                                                                             |
| Malware Download         | Not observed                                                                             |
| Endpoint Compromise      | Not confirmed from provided logs                                                         |
| Data Exfiltration        | Not observed                                                                             |
| Business Risk            | High due to phishing delivery, POST activity, and suspicious VPN authentication attempts |

## Recommended Actions

1. Isolate **Rahul Joshi’s endpoint** for investigation.
2. Reset **Rahul Joshi’s password**.
3. Revoke active sessions and refresh tokens for Rahul Joshi.
4. Review Rahul Joshi’s VPN, MFA, and authentication logs before and after the event.
5. Contact Rahul Joshi to confirm whether credentials, OTP, MFA code, or sensitive information were entered.
6. Contact Rachel Moore to confirm whether she interacted with the phishing page beyond opening it.
7. Quarantine or remove the phishing email from all recipient mailboxes.
8. Block **maxloglogistica.com** in proxy, DNS security, and IPS.
9. Block the full phishing URL in the email gateway, proxy, and IPS.
10. Add detection for the **secure.adnxs.com** redirect URL pattern if policy allows.
11. Block **68.67.160.76**, **186.23.212.74**, and **65.55.127.63** in firewall/IPS/VPN controls.
12. Block **5.62.56.113** if no business requirement exists.
13. Block **18.139.53.140** only if confirmed malicious or policy-approved.
14. Monitor Rahul Joshi and related IOCs for **2–3 days** after containment.
15. Escalate to SOC L2 / Incident Response for credential exposure validation.

## Escalation Decision

**Decision:** **Escalate to SOC L2 / Incident Response.**

**Reason:** This case includes a delivered phishing email, failed email authentication, compromised-site categorization, user interaction, POST activity, and suspicious VPN authentication attempts. Even though MFA failed and no successful VPN session was confirmed, possible credential exposure cannot be ruled out.

SOC L2 should validate:

1. Whether Rahul Joshi submitted credentials or MFA/OTP information.
2. Whether the VPN timestamp mismatch is due to timezone, ingestion delay, or a separate attack.
3. Whether any successful authentication occurred from suspicious IPs.
4. Whether additional users received or clicked the phishing link.
5. Whether the phishing URL was part of a larger campaign.
6. Whether the endpoint shows malware, suspicious browser activity, or credential theft indicators.

## Final Ticket Closure Comment

SOC investigated ticket **CS-047 — Phishing Email**. The phishing email used the subject **URGENT: confirm account activity** and appeared to come from `abc@zimbramail.serino.com`. Email authentication failed for SPF, DKIM, and DMARC. Email gateway logs confirmed delivery to **[rahul.joshi@abc.com](mailto:rahul.joshi@abc.com)**, **[rachel.moore@abc.com](mailto:rachel.moore@abc.com)**, and **[info@abc.com](mailto:info@abc.com)**. The email contained a redirect-based URL using **secure.adnxs.com**, leading to **maxloglogistica.com**, which was categorized as **Compromised Sites**. Proxy logs confirmed Rachel Moore generated a GET request and Rahul Joshi generated GET and POST requests to the phishing URL. The POST request from Rahul Joshi indicates possible form or credential submission. VPN logs showed suspicious authentication attempts for Rahul Joshi from **186.23.212.74**, where MFA challenges were initiated and failed due to incorrect OTP entries. No successful VPN session, malware execution, endpoint compromise, or data exfiltration was confirmed. Ticket closed as **True Positive — Phishing Email with Possible Credential Harvesting / Suspicious VPN Authentication Attempts Observed**, with endpoint isolation, password reset, session revocation, phishing email quarantine, IOC blocking, SOC L2 escalation, and 2–3 days of monitoring recommended.

## Skills Demonstrated

Phishing email triage, email authentication analysis, redirect URL investigation, compromised-site correlation, email gateway log review, proxy log analysis, VPN authentication review, MFA failure investigation, timeline reconstruction, IOC extraction, user risk classification, MITRE ATT&CK mapping, impact validation, containment planning, SOC L2 escalation decision-making, and SOC incident documentation.

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
