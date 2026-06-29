# SOC Analyst Investigation Report

## Ticket Overview

| Field              | Details                                                        |
| ------------------ | -------------------------------------------------------------- |
| Ticket ID          | CS-075                                                         |
| Alert Name         | VPN:- VPN Login from Unusual Location                          |
| Incident Category  | VPN / Unusual Location Login                                   |
| Ticket Status      | Closed                                                         |
| Priority / SLA     | Normal / Default SLA                                           |
| Department         | Support                                                        |
| Created Date       | 3/23/25 4:50 PM                                                |
| Closed By          | Ananda Das                                                     |
| Detection Source   | VPN Logs / SIEM Splunk                                         |
| Affected User      | `bhavin.kumar`                                                 |
| Affected Host      | ENDP-777                                                       |
| Device Type        | Windows 11                                                     |
| VPN Client Version | 9.1R14                                                         |
| Analyst Decision   | **False Positive / Benign — Likely Legitimate User VPN Login** |

## Executive Summary

A VPN security alert was triggered for user **bhavin.kumar** after a VPN login was observed from an unusual source IP:

`103.229.25.66`

The alert was generated because the login location differed from the user’s normal VPN login source. The user’s normal login source was identified as:

`203.200.5.53`

The unusual login source was located in **Nagpur, Maharashtra, India**, while the normal login source was identified as **Mumbai, Maharashtra, India**. Both locations are within India, and the source IP had **0% abuse confidence**, indicating no known malicious reputation during the investigation.

Splunk VPN logs showed authentication initiation, MFA activity, successful authentication, active VPN session creation with `FullAccess`, and later session timeout due to inactivity.

One MFA failure was observed, but the overall session behavior appeared normal because successful authentication and session creation followed. No blacklisted country, high-risk hosting source, brute-force pattern, impossible travel, endpoint compromise, lateral movement, or data exfiltration was observed from the provided evidence.

Final assessment: **Likely benign VPN login from an unusual but not malicious location. User validation was recommended, and no containment was required unless the user denied the activity.**

## Alert Details

| Field              | Value                                                                |
| ------------------ | -------------------------------------------------------------------- |
| Timestamp          | 3/20/2025 22:43                                                      |
| Source IP          | 103.229.25.66                                                        |
| Destination IP     | 10.0.2.12                                                            |
| User               | bhavin.kumar                                                         |
| Hostname           | ENDP-777                                                             |
| Device Type        | Windows 11                                                           |
| VPN Client Version | 9.1R14                                                               |
| VPN Device         | IvantiVPN01                                                          |
| VPN Realm          | Corporate_VPN                                                        |
| Session Status     | Authentication initiated                                             |
| Message            | User `bhavin.kumar` Realm `Corporate_VPN` - Authentication initiated |
| Ticket Flag        | Flagged as overdue by system on 3/24/25 11:01 AM                     |
| Final Verdict      | False Positive / Benign                                              |

## Source IP Reputation and Location Analysis

### Unusual Login Source

| Field            | Value               |
| ---------------- | ------------------- |
| Source IP        | 103.229.25.66       |
| Abuse Confidence | 0%                  |
| ISP              | ORANGEINFOCOM IN    |
| Usage Type       | Fixed Line ISP      |
| ASN              | AS55341             |
| Domain Name      | orangeinfocom.in    |
| Country          | India               |
| City             | Nagpur, Maharashtra |

### User Normal Login Source

| Field            | Value                                   |
| ---------------- | --------------------------------------- |
| Normal Source IP | 203.200.5.53                            |
| ISP              | Internet Service Provider               |
| Usage Type       | Fixed Line ISP                          |
| ASN              | AS4755                                  |
| Hostname         | 203.200.5.53.ill-bgl.static.vsnl.net.in |
| Domain Name      | tatacommunications.com                  |
| Country          | India                                   |
| City             | Mumbai, Maharashtra                     |

### Location Assessment

The unusual VPN login originated from **Nagpur, Maharashtra**, while the user’s normal VPN login location was **Mumbai, Maharashtra**. Both locations are in India, and the unusual source IP had **0% abuse confidence**.

The location difference required user validation, but the available evidence did not strongly indicate malicious activity.

## Affected Assets / Entities

| Asset / Entity     | Details                         |
| ------------------ | ------------------------------- |
| Affected User      | bhavin.kumar                    |
| Hostname           | ENDP-777                        |
| Device Type        | Windows 11                      |
| VPN Client Version | 9.1R14                          |
| VPN Device         | IvantiVPN01                     |
| VPN Destination IP | 10.0.2.12                       |
| VPN Realm          | Corporate_VPN                   |
| Unusual Source IP  | 103.229.25.66                   |
| Normal Source IP   | 203.200.5.53                    |
| Unusual Location   | Nagpur, Maharashtra, India      |
| Normal Location    | Mumbai, Maharashtra, India      |
| Final Assessment   | Likely legitimate user activity |

## IOCs / Indicators Identified

| Indicator Type       | Indicator                                                        |
| -------------------- | ---------------------------------------------------------------- |
| Unusual Source IP    | 103.229.25.66                                                    |
| Normal Source IP     | 203.200.5.53                                                     |
| Destination IP       | 10.0.2.12                                                        |
| Affected User        | bhavin.kumar                                                     |
| Hostname             | ENDP-777                                                         |
| Device Type          | Windows 11                                                       |
| VPN Device           | IvantiVPN01                                                      |
| VPN Realm            | Corporate_VPN                                                    |
| VPN Client Version   | 9.1R14                                                           |
| Unusual Location     | Nagpur, Maharashtra, India                                       |
| Normal Location      | Mumbai, Maharashtra, India                                       |
| Abuse Confidence     | 0%                                                               |
| Session Status       | Authentication Initiated / Authenticated / Active / Idle Timeout |
| Final Classification | False Positive / Benign User Activity                            |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN unusual-location alert for user `bhavin.kumar`. The alert indicated that the user logged in from a source IP different from the user’s normal VPN login source.

Because successful VPN access was observed, SOC validated whether the login was suspicious, malicious, or likely legitimate.

#### 2. Entity Identification

| Entity             | Value         |
| ------------------ | ------------- |
| User               | bhavin.kumar  |
| Hostname           | ENDP-777      |
| Device Type        | Windows 11    |
| VPN Client Version | 9.1R14        |
| Source IP          | 103.229.25.66 |
| Normal Source IP   | 203.200.5.53  |
| Destination IP     | 10.0.2.12     |
| VPN Device         | IvantiVPN01   |
| Realm              | Corporate_VPN |

#### 3. Splunk Query Used

```spl id="cs0272_vpn_query"
index=main "103.229.25.66" user="bhavin.kumar" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

#### 4. Full Unique Splunk Log Results

```text id="cs0272_vpn_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-03-23 23:30:00	Normal	None	10.0.2.12	IvantiVPN01	Windows 11	Idle Timeout	Idle Timeout	None	Corporate_VPN	ENDP-777	103.229.25.66	User 'bhavin.kumar' - Session timed out due to inactivity (30 minutes)	bhavin.kumar
2025-03-23 22:43:00	Normal	None	10.0.2.12	IvantiVPN01	Windows 11	None	Active	None	Corporate_VPN	ENDP-777	103.229.25.66	User 'bhavin.kumar' Realm 'Corporate_VPN' Role 'FullAccess' - Session started from device 'Windows 11' using client version '9.1R14'	bhavin.kumar
2025-03-22 22:43:00	Normal	None	10.0.2.12	IvantiVPN01	Windows 11	None	Authenticated	Success	Corporate_VPN	ENDP-777	103.229.25.66	User 'bhavin.kumar' Realm 'Corporate_VPN' - Authentication successful	bhavin.kumar
2025-03-21 22:43:00	Normal	MFA	10.0.2.12	IvantiVPN01	Windows 11	None	Pending Authentication	OTP Sent	Corporate_VPN	ENDP-777	103.229.25.66	User 'bhavin.kumar' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	bhavin.kumar
2025-03-21 22:43:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	Windows 11	Failed Authentication	None	Failed	Corporate_VPN	ENDP-777	103.229.25.66	User 'bhavin.kumar'' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	bhavin.kumar
2025-03-21 22:43:00	Normal	MFA	10.0.2.12	IvantiVPN01	Windows 11	None	Pending Authentication	OTP Sent	Corporate_VPN	ENDP-777	103.229.25.66	User 'bhavin.kumar' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	bhavin.kumar
2025-03-20 22:43:00	Normal	Password	10.0.2.12	IvantiVPN01	Windows 11	None	Authentication initiated	Prompted	Corporate_VPN	ENDP-777	103.229.25.66	User 'bhavin.kumar' Realm 'Corporate_VPN' - Authentication initiated	bhavin.kumar
```

**Evidence Note:** All unique VPN log rows provided for this ticket were preserved.

### 5. Authentication and Session Pattern Review

| Observation                               | Analyst Interpretation                                   |
| ----------------------------------------- | -------------------------------------------------------- |
| Login originated from unusual location    | Alert condition confirmed                                |
| Source IP had 0% abuse confidence         | No known malicious reputation observed                   |
| Source IP was fixed-line ISP              | Less suspicious than hosting/VPN/proxy infrastructure    |
| Location was within India                 | Not a blacklisted country or impossible travel by itself |
| MFA challenge was generated               | MFA workflow was triggered                               |
| One MFA failure occurred                  | Could be user OTP error or delayed OTP entry             |
| Authentication later succeeded            | User login completed successfully                        |
| Session started with `FullAccess` role    | VPN session was established                              |
| Session ended due to idle timeout         | Normal disconnect reason                                 |
| No malicious post-login activity observed | No confirmed compromise from provided logs               |

## Investigation Findings

1. VPN login activity was observed for user `bhavin.kumar`.
2. The login originated from source IP `103.229.25.66`.
3. The source IP belongs to a fixed-line ISP in India.
4. Abuse confidence for the source IP was **0%**.
5. The unusual login location was **Nagpur, Maharashtra**.
6. The user’s normal login location was identified as **Mumbai, Maharashtra**.
7. Both locations were within India.
8. VPN logs showed a successful authentication event.
9. VPN logs showed an active VPN session with `FullAccess`.
10. The session later timed out due to inactivity after 30 minutes.
11. One MFA failure was observed, but it was followed by successful authentication and normal session behavior.
12. No malicious IP reputation, blacklisted country, impossible travel, brute-force pattern, or confirmed compromise indicator was observed.
13. Activity appeared likely user-initiated but required user validation.

## Timeline of Events

| Time               | Event                                                                   |
| ------------------ | ----------------------------------------------------------------------- |
| 2025-03-20 22:43   | VPN authentication initiated for `bhavin.kumar` from `103.229.25.66`    |
| 2025-03-21 22:43   | MFA challenge initiated                                                 |
| 2025-03-21 22:43   | One MFA failure observed due to incorrect OTP                           |
| 2025-03-22 22:43   | Authentication successful                                               |
| 2025-03-23 16:50   | Ticket created by Microsoft Outlook                                     |
| 2025-03-23 22:43   | VPN session started with `FullAccess` role                              |
| 2025-03-23 23:30   | Session timed out due to inactivity after 30 minutes                    |
| 2025-03-24 11:01   | Ticket flagged as overdue by system                                     |
| Investigation Time | SOC reviewed VPN logs and source IP reputation                          |
| Validation Time    | User validation recommended to confirm whether the login was legitimate |
| Closure Time       | Ticket closed as no confirmed malicious activity was identified         |

## MITRE ATT&CK Mapping

| Tactic          | Technique                | ID    | Reason                                                                               |
| --------------- | ------------------------ | ----- | ------------------------------------------------------------------------------------ |
| Initial Access  | Valid Accounts           | T1078 | VPN login used a valid corporate account, but compromise was not confirmed           |
| Initial Access  | External Remote Services | T1133 | VPN service was accessed as an external remote service                               |
| Defense Evasion | Proxy                    | T1090 | External VPN/proxy usage should be validated only if user denies the location change |

**MITRE Assessment:** MITRE mapping is included for investigation reference only. Based on the available evidence, this incident is assessed as likely benign and not confirmed malicious.

## Analyst Assessment

**Assessment:** **False Positive / Benign — Likely Legitimate User VPN Login**

The alert was triggered due to a login from an unusual location. However, the evidence did not strongly support malicious activity.

The reasons are:

1. Source IP abuse confidence was **0%**.
2. Source IP belonged to a fixed-line ISP.
3. Source country was India.
4. The unusual location was Nagpur, Maharashtra.
5. The normal login location was Mumbai, Maharashtra.
6. Both locations were within India.
7. VPN authentication succeeded.
8. A VPN session started successfully from the Windows 11 endpoint.
9. The session ended due to idle timeout, not suspicious disconnect.
10. No blacklisted country, high-risk hosting infrastructure, or repeated brute-force pattern was observed.

One MFA failure was observed, but this may occur due to user error, delayed OTP entry, or incorrect OTP entry. Since successful authentication and normal session behavior followed, the activity was assessed as likely legitimate.

## Impact Analysis

| Impact Area               | Status                      |
| ------------------------- | --------------------------- |
| Unusual location login    | Confirmed                   |
| Source IP reputation      | Clean / 0% abuse confidence |
| Targeted user             | bhavin.kumar                |
| Successful authentication | Observed                    |
| Active VPN session        | Observed                    |
| Idle timeout              | Observed                    |
| Credential exposure       | Not confirmed               |
| MFA bypass                | Not observed                |
| Endpoint compromise       | Not observed                |
| Lateral movement          | Not observed                |
| Data exfiltration         | Not observed                |
| Business impact           | None observed               |
| Security impact           | Low                         |
| Residual risk             | Low after user validation   |

### Impact Summary

The VPN login from an unusual location was confirmed, but the activity appeared consistent with legitimate user behavior. No malicious reputation, suspicious country, brute-force pattern, endpoint compromise, lateral movement, or data exfiltration was observed from the provided logs.

## Containment and Remediation

| Scenario            | Action                                         |
| ------------------- | ---------------------------------------------- |
| User confirms login | Close as benign / no containment required      |
| User denies login   | Block source IP `103.229.25.66`                |
| User denies login   | Reset credentials for `bhavin.kumar`           |
| User denies login   | Terminate active VPN sessions                  |
| User denies login   | Validate endpoint `ENDP-777`                   |
| User denies login   | Escalate to Identity / Endpoint Team           |
| Monitoring          | Add user and source IP to short-term watchlist |

## User Validation Questions

SOC should contact user `bhavin.kumar` and confirm:

1. Did you attempt to log in to VPN from `103.229.25.66`?
2. Were you located in or near Nagpur, Maharashtra during the login?
3. Were you travelling or working from a different location?
4. Were you using a personal/home ISP or mobile hotspot?
5. Did you receive and complete the MFA prompt?
6. Was the one failed MFA attempt caused by entering an incorrect OTP?
7. Is `ENDP-777` your assigned Windows 11 device?
8. Did you notice any suspicious activity on your account?

If the user confirms the activity, the ticket can remain closed as benign. If the user denies the activity, containment and escalation should be initiated.

## Recommended Actions

1. Contact the user and confirm whether the login was legitimate.
2. Document the user’s confirmation in the ticket.
3. Do not block the IP if the user confirms the activity.
4. Block source IP `103.229.25.66` only if the user denies the login.
5. Reset user credentials if the activity was not user-initiated.
6. Terminate active VPN sessions if the user denies the login.
7. Validate endpoint `ENDP-777` if the user denies the activity.
8. Review whether the user commonly logs in from multiple Indian cities.
9. Tune unusual-location alerts to consider country, ISP type, distance, user travel pattern, and source IP reputation.
10. Monitor the user account for additional unusual logins.
11. Maintain MFA enforcement for all VPN access.

## Escalation Decision

**Decision:** **No escalation required after benign validation. Escalate only if user denies the login or new suspicious activity appears.**

**Reason:** The source IP had **0% abuse confidence**, the login location was within the same country, and the VPN session behavior appeared normal. No confirmed malicious activity was identified from the provided evidence.

Escalate to **SOC L2 / Identity / Endpoint Team** only if:

1. User denies the login.
2. User reports unexpected MFA prompts.
3. Login activity continues from unknown locations.
4. Source IP reputation changes to malicious.
5. Successful login is followed by suspicious internal activity.
6. Endpoint compromise indicators are found.
7. Additional users are targeted from the same IP.

## Final Ticket Closure Comment

SOC investigated ticket **CS-075 — VPN Login from Unusual Location** for user `bhavin.kumar`. VPN logs showed authentication initiation from source IP `103.229.25.66` toward destination `10.0.2.12` on VPN device `IvantiVPN01` under realm `Corporate_VPN`. The user’s normal login source was identified as `203.200.5.53`. The unusual source IP had **0% abuse confidence** and originated from Nagpur, Maharashtra, India, while the normal login source was associated with Mumbai, Maharashtra, India. Splunk evidence showed MFA activity, successful authentication, VPN session start with `FullAccess`, and later idle timeout due to inactivity. One MFA failure was observed, but no blacklisted country, high-risk hosting source, brute-force pattern, endpoint compromise, lateral movement, or data exfiltration was identified. User validation was recommended to confirm legitimacy. Ticket closed as **False Positive / Benign — Unusual Location Login Reviewed / No Confirmed Malicious Activity Observed**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, unusual-location alert triage, source IP reputation review, location comparison, authentication event analysis, MFA event review, VPN session validation, false-positive determination, user validation planning, MITRE ATT&CK reference mapping, containment decision-making, escalation criteria definition, and SOC ticket documentation.

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
