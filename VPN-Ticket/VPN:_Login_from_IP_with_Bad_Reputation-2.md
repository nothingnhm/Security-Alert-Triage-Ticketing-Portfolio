# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                                       |
| ----------------- | --------------------------------------------------------------------------------------------- |
| Ticket ID         | CS-065                                                                                       |
| Alert Name        | VPN:- Login from IP with Bad Reputation                                                       |
| Incident Category | VPN / Suspicious Authentication                                                               |
| Ticket Status     | Closed                                                                                        |
| Priority / SLA    | Normal / Default SLA                                                                          |
| Department        | Support                                                                                       |
| Created Date      | 3/23/25 2:31 PM                                                                               |
| Closed By         | Ananda Das                                                                                    |
| Detection Source  | VPN Logs / SIEM Splunk                                                                        |
| Affected User     | `david.patel`                                                                                 |
| Affected Host     | iPhone 15 TM                                                                                  |
| Analyst Decision  | **True Positive — Suspicious VPN Authentication Attempt / MFA Prevented Unauthorized Access** |

## Executive Summary

A VPN security alert was triggered for user **david.patel** after authentication attempts were observed from the external source IP:

`45.159.112.214`

The authentication attempt targeted the corporate VPN destination:

`10.0.2.12`

The VPN realm was:

`Corporate_VPN`

Splunk VPN logs confirmed password authentication initiation, MFA OTP challenge generation, and MFA failures due to incorrect OTP entries.

The source IP had **50% abuse confidence** and was associated with data center / web hosting infrastructure in Iran. The affected user is a high-value IT user, which increases the risk level of the incident.

No successful VPN session was observed in the provided logs. MFA prevented unauthorized access.

Final assessment: **True Positive suspicious VPN authentication attempt. MFA prevented unauthorized access, and no confirmed VPN compromise was observed.**

## Alert Details

| Field          | Value                                                               |
| -------------- | ------------------------------------------------------------------- |
| Timestamp      | 2/6/2025 8:29                                                       |
| Source IP      | 45.159.112.214                                                      |
| Destination IP | 10.0.2.12                                                           |
| User           | david.patel                                                         |
| Hostname       | iPhone 15 TM                                                        |
| Device Type    | iPhone                                                              |
| VPN Device     | IvantiVPN01                                                         |
| VPN Realm      | Corporate_VPN                                                       |
| Session Status | Authentication initiated                                            |
| Message        | User `david.patel` Realm `Corporate_VPN` - Authentication initiated |
| Final Verdict  | True Positive                                                       |

## Affected Assets

| Asset / Entity     | Details                                     |
| ------------------ | ------------------------------------------- |
| Affected User      | `david.patel`                               |
| User Role          | Head of IT                                  |
| Department         | IT                                          |
| User Criticality   | High                                        |
| Hostname           | iPhone 15 TM                                |
| User Device Type   | iPhone / iOS                                |
| VPN Device         | IvantiVPN01                                 |
| VPN Destination IP | 10.0.2.12                                   |
| VPN Server OS      | Windows Server 2022                         |
| VPN Realm          | Corporate_VPN                               |
| Source IP          | 45.159.112.214                              |
| Attack Type        | Suspicious VPN login from bad-reputation IP |

## Evidence Reviewed

### Source IP Reputation Analysis

| Field            | Value                                     |
| ---------------- | ----------------------------------------- |
| Source IP        | 45.159.112.214                            |
| Abuse Confidence | 50%                                       |
| ISP              | Green Web Samaneh Novin PJSC              |
| Usage Type       | Data Center / Web Hosting / Transit       |
| ASN              | AS61173                                   |
| Hostname         | static.214.112.159.45.clients.irandns.com |
| Domain Name      | greenweb.ir                               |
| Country          | Iran                                      |
| City             | Novin, Kurdistan Province                 |

### Source IP Assessment

The source IP `45.159.112.214` had a suspicious abuse reputation score of **50%** and was associated with data center / web hosting infrastructure. VPN login attempts from hosting infrastructure are suspicious, especially when targeting a high-value IT user account.

Because the authentication attempts resulted in MFA failures and no successful VPN session was observed, the activity was treated as attempted credential abuse, brute force, or credential stuffing.

## IOCs / Indicators Identified

| IOC Type         | Indicator                                            |
| ---------------- | ---------------------------------------------------- |
| Source IP        | 45.159.112.214                                       |
| Destination IP   | 10.0.2.12                                            |
| Affected User    | david.patel                                          |
| Hostname         | iPhone 15 TM                                         |
| VPN Device       | IvantiVPN01                                          |
| VPN Realm        | Corporate_VPN                                        |
| User Device Type | iPhone / iOS                                         |
| ISP              | Green Web Samaneh Novin PJSC                         |
| Source Hostname  | static.214.112.159.45.clients.irandns.com            |
| Source Domain    | greenweb.ir                                          |
| Source Country   | Iran                                                 |
| Attack Type      | Suspicious VPN Authentication / Possible Brute Force |
| MFA Status       | Failed                                               |
| Session Status   | No successful VPN session observed                   |
| Account Risk     | High-value IT user account                           |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN alert for user `david.patel`. The alert indicated VPN authentication activity from source IP `45.159.112.214`, which had bad reputation and was associated with hosting infrastructure.

The alert was treated as high-risk because the targeted account belongs to a high-value IT user, and the source IP was not confirmed as trusted.

#### 2. Entity Identification

| Entity         | Value          |
| -------------- | -------------- |
| User           | david.patel    |
| User Role      | Head of IT     |
| Department     | IT             |
| Hostname       | iPhone 15 TM   |
| Device Type    | iPhone / iOS   |
| Source IP      | 45.159.112.214 |
| Destination IP | 10.0.2.12      |
| VPN Device     | IvantiVPN01    |
| Realm          | Corporate_VPN  |

#### 3. Splunk Query Used

```spl id="cs0268_vpn_query"
index=main "45.159.112.214" "david.patel" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

#### 4. Full Unique Splunk Log Results

```text id="cs0268_vpn_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-02-06 08:30:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	iOS	Failed Authentication	None	Failed	Corporate_VPN	iPhone 15 TM	45.159.112.214	User 'david.patel' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	david.patel
2025-02-06 08:30:00	Normal	MFA	10.0.2.12	IvantiVPN01	iOS	None	Pending Authentication	OTP Sent	Corporate_VPN	iPhone 15 TM	45.159.112.214	User 'david.patel' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	david.patel
2025-02-06 08:30:00	suspiicous	Password	10.0.2.12	IvantiVPN01	iOS	None	Authentication initiated	Prompted	Corporate_VPN	iPhone 15 TM	45.159.112.214	User 'david.patel' Realm 'Corporate_VPN' - Authentication initiated	david.patel
2025-02-06 08:29:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	iOS	Failed Authentication	None	Failed	Corporate_VPN	iPhone 15 TM	45.159.112.214	User 'david.patel' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	david.patel
2025-02-06 08:29:00	Normal	MFA	10.0.2.12	IvantiVPN01	iOS	None	Pending Authentication	OTP Sent	Corporate_VPN	iPhone 15 TM	45.159.112.214	User 'david.patel' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	david.patel
2025-02-06 08:29:00	suspiicous	Password	10.0.2.12	IvantiVPN01	iOS	None	Authentication initiated	Prompted	Corporate_VPN	iPhone 15 TM	45.159.112.214	User 'david.patel' Realm 'Corporate_VPN' - Authentication initiated	david.patel
```

**Evidence Note:** Exact duplicate VPN log rows were removed from the final evidence table. Unique evidence was preserved.

### 5. VPN Authentication Pattern Review

| Observation                                 | Analyst Interpretation                       |
| ------------------------------------------- | -------------------------------------------- |
| Multiple VPN authentication events observed | Indicates repeated suspicious login attempts |
| Same source IP used                         | Supports single-source attack pattern        |
| Source IP tied to hosting infrastructure    | Suspicious for normal VPN user login         |
| High-value IT user targeted                 | Increases risk                               |
| MFA challenges generated                    | Authentication reached MFA workflow          |
| MFA failed due to incorrect OTP             | Unauthorized access was not completed        |
| No successful VPN session observed          | No confirmed VPN compromise                  |

### 6. Timeline of Events

| Time               | Event                                                                              |
| ------------------ | ---------------------------------------------------------------------------------- |
| 2025-02-06 08:29   | Password authentication initiated for `david.patel`                                |
| 2025-02-06 08:29   | MFA challenge initiated and OTP sent                                               |
| 2025-02-06 08:29   | MFA challenge failed due to incorrect OTP                                          |
| 2025-02-06 08:30   | Additional password authentication initiated                                       |
| 2025-02-06 08:30   | MFA challenge initiated and OTP sent again                                         |
| 2025-02-06 08:30   | MFA challenge failed due to incorrect OTP                                          |
| Investigation Time | SOC reviewed VPN logs in Splunk                                                    |
| Investigation Time | SOC reviewed source IP reputation                                                  |
| Containment Time   | Source IP was blocked and user password was reset                                  |
| Validation Time    | Forensic validation recommended for the user device                                |
| Closure Time       | Ticket closed after no successful VPN session or confirmed compromise was observed |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID    | Reason                                                                      |
| ----------------- | ---------------------------------------------- | ----- | --------------------------------------------------------------------------- |
| Credential Access | Brute Force                                    | T1110 | Repeated VPN authentication attempts were observed against a valid account  |
| Initial Access    | Valid Accounts                                 | T1078 | Attempted use of `david.patel` account against Corporate VPN was observed   |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | MFA OTP challenges were generated during suspicious authentication attempts |
| Initial Access    | External Remote Services                       | T1133 | VPN service was targeted as an external remote access service               |

**MITRE Note:** Suspicious VPN authentication and MFA challenge generation were observed. Successful VPN access, MFA bypass, lateral movement, endpoint compromise, and data exfiltration were not observed.

## Analyst Assessment

**Assessment:** **True Positive — Suspicious VPN Authentication Attempt / No Successful Login**

The alert is valid because repeated VPN authentication attempts were observed from a bad-reputation external source IP against a high-value IT user account.

The source IP reputation, hosting infrastructure classification, MFA challenge generation, and repeated failed OTP events indicate suspicious login behavior. The activity may represent credential abuse, brute force, or credential stuffing.

No confirmed compromise was observed because MFA failed and no successful VPN session was established.

## Forensic Validation Requirement

Because the affected account belongs to a high-value IT user and the hostname indicates an iPhone device, forensic validation should be performed to confirm whether the device or credentials were compromised.

### Forensics / Endpoint Security should validate:

1. Whether the iPhone belongs to `david.patel`.
2. Whether the user initiated the VPN login.
3. Whether the device shows signs of compromise.
4. Whether any suspicious VPN profile or configuration exists.
5. Whether suspicious apps, profiles, or certificates are installed.
6. Whether the user received unexpected OTP/MFA prompts.
7. Whether credentials were entered on any suspicious website.
8. Whether there are signs of phishing or credential theft.
9. Whether unusual login activity exists across other systems.
10. Whether device isolation is required.

**Isolation Decision:** Isolate the device only if forensic analysis confirms compromise or suspicious device behavior.

## Impact Analysis

| Impact Area                         | Status                        |
| ----------------------------------- | ----------------------------- |
| Suspicious VPN login                | Confirmed                     |
| Targeted user                       | david.patel                   |
| User criticality                    | High                          |
| Credential exposure                 | Possible                      |
| MFA challenge generated             | Confirmed                     |
| MFA failure                         | Confirmed                     |
| MFA bypass                          | Not observed                  |
| Successful VPN access               | Not observed                  |
| Active VPN session                  | Not observed                  |
| Endpoint / mobile device compromise | Not confirmed                 |
| Lateral movement                    | Not observed                  |
| Data exfiltration                   | Not observed                  |
| Business impact                     | Low                           |
| Security impact                     | Medium due to high-value user |

## Recommended Actions

1. Keep source IP `45.159.112.214` blocked on VPN/firewall controls.
2. Reset credentials for user `david.patel`.
3. Revoke any active VPN sessions for the affected user.
4. Review VPN logs for successful sessions from the same source IP.
5. Review VPN logs for the same source IP targeting other users.
6. Monitor `david.patel` for additional failed or successful VPN attempts.
7. Monitor authentication attempts from related IP ranges or the same hosting provider.
8. Keep MFA enforced for all VPN users.
9. Review conditional access policies for risky IP reputation and unusual geography.
10. Enable account lockout or rate limiting for repeated VPN failures.
11. Conduct forensic validation of the user’s iPhone.
12. Educate the user about phishing, credential reuse, and unexpected MFA prompts.

## Containment and Remediation

| Control Area               | Action                                                          |
| -------------------------- | --------------------------------------------------------------- |
| VPN / Firewall             | Block source IP `45.159.112.214`                                |
| Identity                   | Reset credentials for `david.patel`                             |
| VPN                        | Confirm no active session from suspicious IP                    |
| MFA                        | Confirm MFA prevented unauthorized access                       |
| Forensics                  | Validate whether user device is compromised                     |
| Endpoint / Mobile Security | Isolate device if compromise is confirmed                       |
| SIEM                       | Add source IP and user to monitoring/watchlist                  |
| SOC                        | Monitor for repeated attempts against same user                 |
| SOC                        | Monitor for similar attempts from related IP ranges or same ISP |

## User Validation Questions

SOC should contact user `david.patel` and confirm:

1. Were you attempting to log in to VPN around `2025-02-06 08:29–08:30`?
2. Was the login from your iPhone 15 device?
3. Did you receive unexpected OTP or MFA notifications?
4. Did you approve, reject, or ignore any MFA prompt?
5. Did you recently enter your VPN password on any suspicious website?
6. Have you reused your corporate password on any external service?
7. Did you notice any suspicious activity on your iPhone?
8. Did you install any new app, profile, certificate, or VPN configuration recently?

If the user confirms the activity was not initiated by them, the password reset, IP block, and forensic review should remain enforced.

## Escalation Decision

**Decision:** **Escalate to Forensics / Endpoint Security for device validation. No further SOC escalation required unless compromise is confirmed.**

**Reason:** The VPN attempt was suspicious and targeted a high-value IT user. MFA blocked access, and no successful VPN session was observed. However, because the device name indicates an iPhone and the user is high criticality, forensic validation is recommended to confirm whether the mobile device or credentials are compromised.

Escalate to **SOC L2 / Identity / Forensics** if any of the following are identified:

1. Successful VPN login from suspicious IP.
2. MFA approval from unknown source.
3. User confirms the login was not initiated by them.
4. Device compromise is identified.
5. Suspicious mobile profile, certificate, or VPN configuration is found.
6. Multiple users are targeted by the same source IP.
7. Repeated attempts continue after IP block.
8. Suspicious mailbox, endpoint, or cloud activity appears.
9. Evidence of credential theft is identified.

## Final Ticket Closure Comment

SOC investigated ticket **CS-065 — VPN Login from IP with Bad Reputation** for user `david.patel`. VPN logs showed repeated password authentication initiation from external source IP `45.159.112.214` toward VPN destination `10.0.2.12` on VPN device `IvantiVPN01` under realm `Corporate_VPN`. The activity generated MFA OTP challenges, followed by MFA failures due to incorrect OTP entries. The source IP had **50% abuse confidence** and was associated with data center / web hosting infrastructure in Iran. The affected user is a high-value IT user, increasing the risk of the event. No successful VPN session, MFA bypass, endpoint compromise, lateral movement, or data exfiltration was observed. Source IP `45.159.112.214` was blocked, credentials for `david.patel` were reset, forensic device validation was recommended, and continued monitoring was advised. Ticket closed as **True Positive — Suspicious VPN Authentication Attempt / MFA Prevented Unauthorized Access / No Confirmed Compromise**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, bad-reputation IP login triage, high-value user risk assessment, authentication event review, MFA failure analysis, source IP reputation review, IOC extraction, account compromise validation, forensic escalation planning, MITRE ATT&CK mapping, containment planning, user validation, escalation decision-making, and SOC ticket documentation.

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
