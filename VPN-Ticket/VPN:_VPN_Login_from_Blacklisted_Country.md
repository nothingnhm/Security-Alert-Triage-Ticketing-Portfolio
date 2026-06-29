# SOC Analyst Investigation Report

## Ticket Overview

| Field                       | Details                                                                                               |
| --------------------------- | ----------------------------------------------------------------------------------------------------- |
| Ticket ID                   | CS-073                                                                                               |
| Alert Name                  | VPN:- VPN Login from Blacklisted Country                                                              |
| Incident Category           | VPN / Suspicious Authentication                                                                       |
| Ticket Status               | Closed                                                                                                |
| Priority / SLA              | High / Default SLA                                                                                    |
| Department                  | Support                                                                                               |
| Created Date                | 3/23/25 3:48 PM                                                                                       |
| Closed By                   | Ananda Das                                                                                            |
| Detection Source            | VPN Logs / SIEM Splunk                                                                                |
| Primary Affected User       | `brian.lee`                                                                                           |
| Additional Users Identified | `sneha.khanna`, `rakesh.chauhan`                                                                      |
| Analyst Decision            | **True Positive — Suspicious VPN Login from Blacklisted Country / MFA Prevented Unauthorized Access** |

## Executive Summary

A VPN security alert was triggered after an authentication attempt for user **brian.lee** was observed from the external source IP:

`185.7.214.37`

The alert was generated because the VPN login originated from a **blacklisted country / restricted geo-location**. The authentication attempt targeted the corporate VPN destination:

`10.0.2.12`

The VPN realm was:

`Corporate_VPN`

Initial Splunk investigation confirmed repeated authentication attempts for **brian.lee**, including password authentication initiation, MFA OTP challenge generation, and MFA failures due to incorrect OTP entries.

During IOC scoping, SOC identified that the same source IP also targeted additional corporate users:

`Sneha Khanna`
`Rakesh Chauhan`

No successful VPN session was observed for any of the impacted users in the provided logs. MFA prevented unauthorized access.

Final assessment: **True Positive suspicious VPN authentication campaign from blacklisted geo-location. MFA blocked access, and no successful VPN session or confirmed compromise was observed.**

## Alert Details

| Field          | Value                                                             |
| -------------- | ----------------------------------------------------------------- |
| Timestamp      | 1/29/2025 11:05                                                   |
| Source IP      | 185.7.214.37                                                      |
| Destination IP | 10.0.2.12                                                         |
| User           | brian.lee                                                         |
| Hostname       | MAC-12432                                                         |
| Device Type    | MACOS                                                             |
| VPN Device     | IvantiVPN01                                                       |
| VPN Realm      | Corporate_VPN                                                     |
| Session Status | Authentication initiated                                          |
| Message        | User `brian.lee` Realm `Corporate_VPN` - Authentication initiated |
| Alert Reason   | VPN login from blacklisted country                                |
| Final Verdict  | True Positive                                                     |

## Affected Assets / Entities

| Entity                   | Details                                                      |
| ------------------------ | ------------------------------------------------------------ |
| Primary Affected User    | brian.lee                                                    |
| Additional Affected User | sneha.khanna                                                 |
| Additional Affected User | rakesh.chauhan                                               |
| Source IP                | 185.7.214.37                                                 |
| Destination IP           | 10.0.2.12                                                    |
| Hostname                 | MAC-12432                                                    |
| Device Type              | macOS / MACOS                                                |
| VPN Device               | IvantiVPN01                                                  |
| VPN Realm                | Corporate_VPN                                                |
| Attack Type              | Suspicious VPN authentication / possible credential stuffing |
| MFA Status               | Failed                                                       |
| Successful VPN Session   | Not observed                                                 |

## IOCs / Indicators Identified

| IOC Type                 | Indicator                                                 |
| ------------------------ | --------------------------------------------------------- |
| Source IP                | 185.7.214.37                                              |
| Destination IP           | 10.0.2.12                                                 |
| Primary Affected User    | brian.lee                                                 |
| Additional Affected User | sneha.khanna                                              |
| Additional Affected User | rakesh.chauhan                                            |
| Hostname                 | MAC-12432                                                 |
| Device Type              | macOS 13x                                                 |
| VPN Device               | IvantiVPN01                                               |
| VPN Realm                | Corporate_VPN                                             |
| Authentication Method    | Password / MFA                                            |
| MFA Status               | Failed                                                    |
| Session Status           | No successful VPN session observed                        |
| Alert Type               | VPN login from blacklisted country                        |
| Attack Pattern           | Multi-user VPN authentication attempt from same source IP |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN alert for user `brian.lee`. The alert indicated that authentication was initiated from a blacklisted or restricted geo-location.

Because the alert involved VPN access and a valid corporate user account, SOC treated the activity as a potential unauthorized access attempt.

#### 2. Primary User Investigation

SOC first investigated activity for the primary affected user `brian.lee`.

### Splunk Query Used — Primary User

```spl id="cs0269_primary_user_query"
index=main "185.7.214.37" "brian.lee" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

### Full Unique Splunk Log Results — brian.lee

```text id="cs0269_brian_lee_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-01-29 11:13:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	brian.lee
2025-01-29 11:12:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	brian.lee
2025-01-29 11:12:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - Authentication initiated	brian.lee
2025-01-29 11:07:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	brian.lee
2025-01-29 11:07:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	brian.lee
2025-01-29 11:07:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - Authentication initiated	brian.lee
2025-01-29 11:05:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	brian.lee
2025-01-29 11:05:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	brian.lee
2025-01-29 11:05:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - Authentication initiated	brian.lee
```

#### 3. IOC Scoping Across VPN Logs

SOC expanded the investigation to check whether the same source IP targeted other users.

### Splunk Query Used — Same Source IP

```spl id="cs0269_source_ip_scoping_query"
index=main "185.7.214.37" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

### Full Unique Splunk Log Results — Source IP 185.7.214.37

```text id="cs0269_source_ip_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-01-29 11:30:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'rakesh.chauhan' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	rakesh.chauhan
2025-01-29 11:30:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'rakesh.chauhan' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	rakesh.chauhan
2025-01-29 11:30:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'rakesh.chauhan' Realm 'Corporate_VPN' - Authentication initiated	rakesh.chauhan
2025-01-29 11:25:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	sneha.khanna
2025-01-29 11:25:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	sneha.khanna
2025-01-29 11:25:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - Authentication initiated	sneha.khanna
2025-01-29 11:21:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	sneha.khanna
2025-01-29 11:21:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	sneha.khanna
2025-01-29 11:21:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - Authentication initiated	sneha.khanna
2025-01-29 11:20:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	sneha.khanna
2025-01-29 11:20:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	sneha.khanna
2025-01-29 11:20:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - Authentication initiated	sneha.khanna
2025-01-29 11:13:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	brian.lee
2025-01-29 11:12:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	brian.lee
2025-01-29 11:12:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - Authentication initiated	brian.lee
2025-01-29 11:07:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	brian.lee
2025-01-29 11:07:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	brian.lee
2025-01-29 11:07:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - Authentication initiated	brian.lee
2025-01-29 11:05:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	brian.lee
2025-01-29 11:05:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	brian.lee
2025-01-29 11:05:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'brian.lee' Realm 'Corporate_VPN' - Authentication initiated	brian.lee
```

**Evidence Note:** Exact duplicate VPN log rows were removed from the final evidence table. Unique evidence was preserved.

## Investigation Findings

1. VPN authentication attempts were first identified for user `brian.lee`.
2. The source IP was `185.7.214.37`.
3. The alert triggered due to VPN login from a blacklisted country / restricted geo-location.
4. Multiple password authentication attempts were observed.
5. MFA OTP challenges were generated.
6. MFA failures occurred due to incorrect OTP entries.
7. No successful VPN session was observed for `brian.lee`.
8. IOC scoping confirmed the same source IP also targeted `sneha.khanna` and `rakesh.chauhan`.
9. The same VPN destination `10.0.2.12` and VPN device `IvantiVPN01` were involved.
10. All observed sessions failed at MFA.
11. No successful VPN access was confirmed for any impacted user.
12. Activity is consistent with credential stuffing, brute-force, or unauthorized VPN login campaign.
13. MFA successfully prevented unauthorized access.

## Affected User Summary

| User           | First Observed Time | Last Observed Time | MFA Status | Successful VPN Session |
| -------------- | ------------------: | -----------------: | ---------- | ---------------------- |
| brian.lee      |    2025-01-29 11:05 |   2025-01-29 11:13 | Failed     | No                     |
| sneha.khanna   |    2025-01-29 11:20 |   2025-01-29 11:25 | Failed     | No                     |
| rakesh.chauhan |    2025-01-29 11:30 |   2025-01-29 11:30 | Failed     | No                     |

## Timeline of Events

| Time               | Event                                                                         |
| ------------------ | ----------------------------------------------------------------------------- |
| 2025-01-29 11:05   | Password authentication initiated for `brian.lee`                             |
| 2025-01-29 11:05   | MFA challenge initiated and failed for `brian.lee`                            |
| 2025-01-29 11:07   | Additional authentication attempt and MFA failure observed for `brian.lee`    |
| 2025-01-29 11:12   | Another authentication attempt observed for `brian.lee`                       |
| 2025-01-29 11:13   | MFA failure observed for `brian.lee`                                          |
| 2025-01-29 11:20   | Authentication attempt observed for `sneha.khanna`                            |
| 2025-01-29 11:21   | Additional MFA failure observed for `sneha.khanna`                            |
| 2025-01-29 11:25   | Additional authentication attempt and MFA failure observed for `sneha.khanna` |
| 2025-01-29 11:30   | Authentication attempt and MFA failure observed for `rakesh.chauhan`          |
| Investigation Time | SOC reviewed VPN logs and performed IOC scoping                               |
| Containment Time   | Source IP block, user validation, and credential reset recommended            |
| Closure Time       | Ticket closed after no successful VPN session was observed                    |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID    | Reason                                                                                         |
| ----------------- | ---------------------------------------------- | ----- | ---------------------------------------------------------------------------------------------- |
| Initial Access    | Valid Accounts                                 | T1078 | Attempted login against valid corporate VPN accounts was observed                              |
| Initial Access    | External Remote Services                       | T1133 | Corporate VPN service was targeted as an external remote access service                        |
| Credential Access | Brute Force                                    | T1110 | Multiple authentication attempts were observed against multiple users                          |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | MFA OTP challenges were generated during suspicious VPN authentication attempts                |
| Defense Evasion   | Proxy                                          | T1090 | Possible use of proxy/VPN infrastructure should be validated; not confirmed from provided logs |

**MITRE Note:** The observed behavior confirms suspicious authentication activity, MFA challenge generation, and attempted access through VPN. Successful VPN login, MFA bypass, endpoint compromise, lateral movement, and data exfiltration were not observed.

## Analyst Assessment

**Assessment:** **True Positive — Suspicious VPN Authentication Campaign / MFA Blocked Access**

The alert is valid because VPN login attempts originated from a blacklisted country / restricted geo-location and targeted multiple valid corporate VPN users from the same source IP.

The same source IP `185.7.214.37` attempted authentication for at least three users within a short time window. Each attempt generated MFA activity and failed due to incorrect OTP entry. No successful VPN session was observed.

This pattern is consistent with possible credential stuffing, password spraying, brute-force activity, or unauthorized use of exposed credentials. MFA prevented unauthorized access.

## User Validation Required

SOC should contact the affected users:

`brian.lee`
`sneha.khanna`
`rakesh.chauhan`

Users should be asked:

1. Were you attempting to log in to VPN during the observed time window?
2. Were you using any third-party VPN, proxy, or privacy service?
3. Were you travelling or working from an unusual location?
4. Did you receive unexpected OTP or MFA notifications?
5. Did you approve, reject, or ignore any MFA request?
6. Did you recently enter corporate credentials on any suspicious website?
7. Is `MAC-12432` your assigned device?
8. Did you notice any unusual activity on your Mac device?
9. Did you install any suspicious application, VPN profile, certificate, or browser extension recently?

If users deny the activity, treat the event as unauthorized credential abuse and proceed with credential reset, source IP block, and endpoint validation.

## Endpoint / Forensic Validation

Since the same hostname `MAC-12432` appears in the observed VPN logs, endpoint validation should be performed if users deny the activity or if hostname mapping is unclear.

### Endpoint / Forensics Team Should Validate

1. Whether `MAC-12432` is a valid corporate asset.
2. Which user is assigned to `MAC-12432`.
3. Recent VPN client activity on the device.
4. Recently installed VPN/proxy tools.
5. Suspicious browser extensions.
6. Suspicious applications or persistence items.
7. Unusual login, keychain, or credential access events.
8. Any signs of malware, credential theft, or remote access tools.
9. Whether the hostname appears incorrectly due to VPN logging normalization.
10. Whether device isolation is required.

**Isolation Decision:** Isolate `MAC-12432` only if compromise is suspected or confirmed.

## Impact Analysis

| Impact Area               | Status                                  |
| ------------------------- | --------------------------------------- |
| Suspicious VPN login      | Confirmed                               |
| Blacklisted country login | Confirmed by alert logic                |
| Multiple users targeted   | Confirmed                               |
| Targeted users            | brian.lee, sneha.khanna, rakesh.chauhan |
| Credential exposure       | Possible                                |
| MFA challenge generated   | Confirmed                               |
| MFA failure               | Confirmed                               |
| MFA bypass                | Not observed                            |
| Successful VPN access     | Not observed                            |
| Active VPN session        | Not observed                            |
| Endpoint compromise       | Not confirmed                           |
| Lateral movement          | Not observed                            |
| Data exfiltration         | Not observed                            |
| Business impact           | Low                                     |
| Security impact           | Medium                                  |
| Residual risk             | Low after containment and validation    |

## Recommended Actions

1. Block source IP `185.7.214.37` on VPN/firewall controls.
2. Reset credentials for impacted users if the activity is not confirmed legitimate.
3. Revoke any active VPN sessions for impacted users.
4. Contact affected users and validate whether the activity was expected.
5. Confirm whether any affected user was travelling or using external VPN/proxy services.
6. Review VPN logs for the same source IP targeting additional users.
7. Review VPN logs for successful sessions from the same source IP.
8. Add source IP and impacted users to SIEM watchlists for short-term monitoring.
9. Monitor for additional attempts from the same source IP, related IP range, or blacklisted geo-location.
10. Enforce MFA for all VPN access.
11. Apply geo-restriction controls for blacklisted countries if business policy allows.
12. Conduct endpoint validation for `MAC-12432` if user validation fails or hostname mapping is unclear.
13. Educate users on suspicious MFA prompts, phishing, and credential reuse.

## Containment and Remediation

| Control Area         | Action                                                                     |
| -------------------- | -------------------------------------------------------------------------- |
| VPN / Firewall       | Block source IP `185.7.214.37`                                             |
| Identity             | Reset credentials for impacted users if unauthorized activity is confirmed |
| VPN                  | Confirm no active session from suspicious IP                               |
| MFA                  | Confirm MFA prevented unauthorized access                                  |
| User Validation      | Confirm whether users initiated the VPN logins                             |
| Endpoint / Forensics | Validate `MAC-12432` if users deny activity                                |
| Endpoint / Network   | Isolate device only if compromise is suspected or confirmed                |
| SIEM                 | Add source IP and affected users to monitoring/watchlist                   |
| SOC                  | Monitor for repeated attempts against same users                           |
| SOC                  | Monitor for similar attempts from blacklisted regions                      |

## Escalation Decision

**Decision:** **User validation required. Escalate to Identity / Endpoint Forensics if users deny activity or compromise indicators are found.**

**Reason:** The login attempts came from a blacklisted country and targeted multiple valid corporate VPN accounts. MFA blocked all observed attempts, and no successful VPN session was identified. The next step is to validate whether the activity was caused by legitimate travel/proxy usage or unauthorized credential abuse.

Escalate to **SOC L2 / Identity / Endpoint Forensics** if any of the following occur:

1. Any user denies the login attempt.
2. Any user confirms unexpected MFA prompts.
3. Users confirm they were not using any VPN/proxy service.
4. Endpoint compromise indicators are found on `MAC-12432`.
5. Suspicious VPN profile, certificate, application, or browser extension is found.
6. Successful VPN login from the same source IP is later observed.
7. MFA approval from an unknown source is observed.
8. Repeated attempts continue after IP block.
9. Additional users are targeted by the same source IP.

## Final Ticket Closure Comment

SOC investigated ticket **CS-074 — VPN Login from Blacklisted Country** for user `brian.lee`. VPN logs showed password authentication initiation from source IP `185.7.214.37` toward destination `10.0.2.12` on VPN device `IvantiVPN01` under realm `Corporate_VPN`. The alert triggered because the login originated from a blacklisted country / restricted geo-location. Splunk investigation confirmed repeated authentication attempts, MFA OTP challenge generation, and MFA failures due to incorrect OTP entries for `brian.lee`. IOC scoping confirmed that the same source IP also targeted `sneha.khanna` and `rakesh.chauhan`. No successful VPN session, MFA bypass, endpoint compromise, lateral movement, or data exfiltration was observed. MFA prevented unauthorized access. Source IP blocking, impacted user validation, credential reset if unauthorized, and endpoint validation for `MAC-12432` were recommended. Ticket closed as **True Positive — Suspicious VPN Authentication Campaign from Blacklisted Country / MFA Prevented Unauthorized Access / No Successful VPN Session Observed**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, blacklisted country login triage, IOC scoping, multi-user authentication campaign analysis, MFA failure analysis, suspicious login investigation, MITRE ATT&CK mapping, identity risk validation, endpoint validation planning, containment recommendation, escalation decision-making, and SOC ticket documentation.

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
