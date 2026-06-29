# SOC Analyst Investigation Report

## Ticket Overview

| Field                    | Details                                                                                    |
| ------------------------ | ------------------------------------------------------------------------------------------ |
| Ticket ID                | CS-070                                                                                    |
| Alert Name               | VPN:- User Login from TOR Exit Node Detected                                               |
| Incident Category        | VPN / TOR Exit Node Login                                                                  |
| Ticket Status            | Closed                                                                                     |
| Priority / SLA           | Normal / Default SLA                                                                       |
| Department               | Support                                                                                    |
| Created Date             | 3/25/25 10:16 AM                                                                           |
| Closed By                | Ananda Das                                                                                 |
| Detection Source         | VPN Logs / SIEM Splunk                                                                     |
| Primary Affected User    | `sneha.nair`                                                                               |
| Additional User Observed | `anjali.chauhan`                                                                           |
| Affected Host            | MACDeB                                                                                     |
| Analyst Decision         | **True Positive — Successful VPN Login from TOR Exit Node / Account Compromise Suspected** |

## Executive Summary

A VPN security alert was triggered for user **sneha.nair** after a successful VPN login was observed from a confirmed TOR exit node:

`185.220.101.40`

The source IP had **100% abuse confidence** and was identified as a TOR exit node with hostname:

`tor-exit-40.for-privacy.net`

The login originated from **Berlin, Germany**, while the user’s usual VPN source was identified as:

`49.37.255.12`

This usual source IP was associated with **Reliance Jio** in **Chennai, Tamil Nadu, India**.

Splunk VPN logs confirmed password authentication initiation, MFA challenge generation, successful authentication, and an active VPN session with:

`FullAccess`

The session later ended due to idle timeout.

IOC scoping showed that the same TOR exit node also attempted authentication against another user:

`anjali.chauhan`

For `anjali.chauhan`, failed password authentication events were observed. No successful VPN session was identified for that user in the provided logs.

Because a successful VPN session was established from a TOR exit node with `FullAccess`, SOC assessed this as a **true positive high-risk VPN security event**. The account should be treated as potentially compromised until user validation, MFA review, session review, and endpoint forensic validation are completed.

## Alert Details

| Field          | Value                                                                                               |
| -------------- | --------------------------------------------------------------------------------------------------- |
| Timestamp      | 3/9/2025 23:10                                                                                      |
| Source IP      | 185.220.101.40                                                                                      |
| Destination IP | 10.0.2.12                                                                                           |
| User           | sneha.nair                                                                                          |
| Hostname       | MACDeB                                                                                              |
| Device Type    | macOS 13x                                                                                           |
| VPN Device     | IvantiVPN01                                                                                         |
| VPN Realm      | Corporate_VPN                                                                                       |
| VPN Role       | FullAccess                                                                                          |
| Session Status | Active                                                                                              |
| Message        | User `sneha.nair` Realm `Corporate_VPN` Role `FullAccess` - Session started from device `macOS 13x` |
| Final Verdict  | True Positive                                                                                       |

## Source IP Reputation and TOR Analysis

### User Usual Login Source

| Field           | Value                         |
| --------------- | ----------------------------- |
| Usual Source IP | 49.37.255.12                  |
| ISP             | Reliance Jio Infocomm Limited |
| Usage Type      | Fixed Line ISP                |
| ASN             | AS55836                       |
| Domain Name     | jio.com                       |
| Country         | India                         |
| City            | Chennai, Tamil Nadu           |
| Assessment      | User usual login source       |

### Suspicious TOR Source

| Field            | Value                        |
| ---------------- | ---------------------------- |
| Source IP        | 185.220.101.40               |
| Abuse Confidence | 100%                         |
| TOR Status       | Confirmed TOR exit node      |
| ISP              | Network for Tor-Exit traffic |
| Usage Type       | Commercial                   |
| ASN              | AS60729                      |
| Hostname         | tor-exit-40.for-privacy.net  |
| Domain Name      | for-privacy.net              |
| Country          | Germany                      |
| City             | Berlin, State of Berlin      |

### Source IP Assessment

The source IP `185.220.101.40` is a confirmed **TOR exit node** with **100% abuse confidence**. VPN login from TOR infrastructure is highly suspicious because TOR can be used to hide the true origin of the user or attacker.

The risk is elevated because the VPN login was successful, MFA completed, and the user received a `FullAccess` VPN session.

## Affected Assets / Entities

| Asset / Entity            | Details                      |
| ------------------------- | ---------------------------- |
| Primary Affected User     | sneha.nair                   |
| Additional Targeted User  | anjali.chauhan               |
| Hostname                  | MACDeB                       |
| Device Type               | macOS 13x                    |
| VPN Device                | IvantiVPN01                  |
| VPN Destination IP        | 10.0.2.12                    |
| VPN Realm                 | Corporate_VPN                |
| VPN Role                  | FullAccess                   |
| TOR Exit Node IP          | 185.220.101.40               |
| Usual Source IP           | 49.37.255.12                 |
| Suspicious Source Country | Germany                      |
| Usual Source Country      | India                        |
| Final Assessment          | Account compromise suspected |

## IOCs / Indicators Identified

| IOC Type                 | Indicator                              |
| ------------------------ | -------------------------------------- |
| TOR Exit Node IP         | 185.220.101.40                         |
| TOR Hostname             | tor-exit-40.for-privacy.net            |
| TOR Domain               | for-privacy.net                        |
| Usual Source IP          | 49.37.255.12                           |
| Destination IP           | 10.0.2.12                              |
| VPN Device               | IvantiVPN01                            |
| VPN Realm                | Corporate_VPN                          |
| Primary Affected User    | sneha.nair                             |
| Additional Targeted User | anjali.chauhan                         |
| Hostname                 | MACDeB                                 |
| Device Type              | macOS 13x                              |
| Suspicious Country       | Germany                                |
| User Usual Country       | India                                  |
| VPN Role                 | FullAccess                             |
| Authentication Result    | Successful for `sneha.nair`            |
| Failed Authentication    | Observed for `anjali.chauhan`          |
| Attack Type              | TOR-Based VPN Login / Credential Abuse |
| Final Assessment         | Account compromise suspected           |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN alert for user `sneha.nair`. The alert indicated a successful VPN login from a TOR exit node.

Because TOR exit nodes are commonly used to anonymize traffic, and the VPN session received `FullAccess`, SOC treated the event as high-risk.

#### 2. Primary User Investigation

SOC first investigated VPN activity for `sneha.nair` from source IP `185.220.101.40`.

### Splunk Query Used — Primary User

```spl id="cs0276_primary_user_query"
index=main "sneha.nair" "185.220.101.40" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

### Full Unique Splunk Log Results — sneha.nair

```text id="cs0276_sneha_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-03-10 02:20:00	Normal	None	10.0.2.12	IvantiVPN01	macOS 13x	Idle Timeout	Idle Timeout	Success	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' - Session timed out due to inactivity (30 minutes)	sneha.nair
2025-03-09 23:10:00	Normal	None	10.0.2.12	IvantiVPN01	macOS 13x	None	Active	Success	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' Realm 'Corporate_VPN' Role 'FullAccess' - Session started from device 'macOS 13x'	sneha.nair
2025-03-09 23:10:00	Normal	None	10.0.2.12	IvantiVPN01	macOS 13x	None	Authenticated	Success	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' Realm 'Corporate_VPN' - Authentication successful	sneha.nair
2025-03-09 23:10:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	sneha.nair
2025-03-09 23:10:00	Normal	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' Realm 'Corporate_VPN' - Authentication initiated	sneha.nair
```

#### 3. IOC Scoping Across VPN Logs

SOC expanded the investigation to identify whether the same TOR exit node targeted other users.

### Splunk Query Used — Same Source IP

```spl id="cs0276_tor_scoping_query"
index=main "185.220.101.40" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

### Full Unique Splunk Log Results — Source IP 185.220.101.40

```text id="cs0276_tor_scoping_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-03-10 02:20:00	Normal	None	10.0.2.12	IvantiVPN01	macOS 13x	Idle Timeout	Idle Timeout	Success	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' - Session timed out due to inactivity (30 minutes)	sneha.nair
2025-03-09 23:10:00	Normal	None	10.0.2.12	IvantiVPN01	macOS 13x	None	Active	Success	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' Realm 'Corporate_VPN' Role 'FullAccess' - Session started from device 'macOS 13x'	sneha.nair
2025-03-09 23:10:00	Normal	None	10.0.2.12	IvantiVPN01	macOS 13x	None	Authenticated	Success	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' Realm 'Corporate_VPN' - Authentication successful	sneha.nair
2025-03-09 23:10:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	sneha.nair
2025-03-09 23:10:00	Normal	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MACDeB	185.220.101.40	User 'sneha.nair' Realm 'Corporate_VPN' - Authentication initiated	sneha.nair
2025-03-09 14:34:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MACDeB	185.220.101.40	User 'anjali.chauhan' Realm 'Corporate_VPN' - Authentication initiated	anjali.chauhan
2025-03-09 14:34:00	Normal	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Failed Authentication	Failed	Corporate_VPN	MACDeB	185.220.101.40	User 'anjali.chauhan' Realm 'Corporate_VPN' - Authentication failed: Incorrect password entered	anjali.chauhan
2025-03-09 11:21:00	Normal	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Failed Authentication	Failed	Corporate_VPN	MACDeB	185.220.101.40	User 'anjali.chauhan' Realm 'Corporate_VPN' - Authentication failed: Incorrect password entered	anjali.chauhan
```

**Evidence Note:** Exact duplicate VPN log rows for `anjali.chauhan` were removed. All unique activity was preserved.

## Investigation Findings

1. Successful VPN login was observed for user `sneha.nair`.
2. The login originated from source IP `185.220.101.40`.
3. The source IP is a confirmed TOR exit node.
4. The source IP had **100% abuse confidence**.
5. The TOR exit node was associated with hostname `tor-exit-40.for-privacy.net`.
6. The source country was Germany.
7. The user’s usual login source was `49.37.255.12` from Chennai, India.
8. Password authentication was initiated for `sneha.nair`.
9. MFA challenge was generated.
10. Authentication was successful.
11. VPN session became active with `FullAccess`.
12. The session later timed out due to inactivity.
13. IOC scoping confirmed the same TOR exit node was also used in failed authentication attempts against `anjali.chauhan`.
14. Failed password authentication was observed for `anjali.chauhan`.
15. No successful VPN session for `anjali.chauhan` was observed in the provided logs.
16. Activity indicates possible credential abuse across multiple users.
17. Because `sneha.nair` had a successful VPN login from TOR, account compromise is suspected.

## Affected User Summary

| User           | Source IP      | Authentication Result          | VPN Session                    | Assessment                         |
| -------------- | -------------- | ------------------------------ | ------------------------------ | ---------------------------------- |
| sneha.nair     | 185.220.101.40 | Successful                     | FullAccess session observed    | Account compromise suspected       |
| anjali.chauhan | 185.220.101.40 | Failed password authentication | No successful session observed | Credential attack attempt observed |

## Timeline of Events

| Time               | Event                                                                                     |
| ------------------ | ----------------------------------------------------------------------------------------- |
| 2025-03-09 11:21   | Failed password authentication observed for `anjali.chauhan` from TOR IP `185.220.101.40` |
| 2025-03-09 14:34   | Additional authentication attempt and failed password event observed for `anjali.chauhan` |
| 2025-03-09 23:10   | Password authentication initiated for `sneha.nair` from TOR IP `185.220.101.40`           |
| 2025-03-09 23:10   | MFA challenge initiated for `sneha.nair`                                                  |
| 2025-03-09 23:10   | Authentication successful for `sneha.nair`                                                |
| 2025-03-09 23:10   | VPN session started for `sneha.nair` with `FullAccess`                                    |
| 2025-03-10 02:20   | VPN session timed out due to inactivity                                                   |
| Investigation Time | SOC reviewed VPN logs for `sneha.nair`                                                    |
| Investigation Time | SOC performed IOC scoping for source IP `185.220.101.40`                                  |
| Containment Time   | Isolation, credential reset, IP/domain blocking, and network review recommended           |
| Closure Time       | Ticket closed after containment recommendations were documented                           |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID        | Reason                                                                 |
| ----------------- | ---------------------------------------------- | --------- | ---------------------------------------------------------------------- |
| Initial Access    | Valid Accounts                                 | T1078     | Successful VPN login was observed using `sneha.nair`                   |
| Initial Access    | External Remote Services                       | T1133     | Corporate VPN was accessed as an external remote service               |
| Defense Evasion   | Proxy                                          | T1090     | Login originated from a TOR exit node used to anonymize traffic        |
| Credential Access | Brute Force                                    | T1110     | Failed password attempts were observed against `anjali.chauhan`        |
| Credential Access | Password Guessing                              | T1110.001 | Incorrect password attempts were observed for `anjali.chauhan`         |
| Credential Access | Multi-Factor Authentication Request Generation | T1621     | MFA challenge was generated during the VPN login flow for `sneha.nair` |

**MITRE Note:** Successful VPN access from TOR was observed for `sneha.nair`. Failed authentication attempts were observed for `anjali.chauhan`. Lateral movement and data exfiltration were not confirmed from the provided logs.

## Analyst Assessment

**Assessment:** **True Positive — Successful VPN Login from TOR Exit Node / Account Compromise Suspected**

The incident is high-risk because a successful VPN login occurred from a confirmed TOR exit node.

The evidence supporting this assessment includes:

1. VPN login originated from a known TOR exit node.
2. Source IP had **100% abuse confidence**.
3. Successful authentication was observed for `sneha.nair`.
4. VPN session started with `FullAccess`.
5. The source country differed from the user’s usual login source.
6. Same TOR exit node was used for failed authentication attempts against `anjali.chauhan`.
7. Activity involved multiple corporate users.
8. TOR usage for corporate VPN access is highly suspicious and not expected for normal user behavior.

Because `sneha.nair` successfully authenticated from a TOR exit node, the account should be treated as compromised until proven otherwise. Endpoint `MACDeB` should also be isolated and reviewed to determine whether the VPN login came from the legitimate user device or an unauthorized source using the user’s credentials.

## Internal Network Activity Review

Because `sneha.nair` had a successful VPN session with `FullAccess`, SOC should review activity during and after the session.

### Recommended Splunk Checks

```spl id="cs0276_post_vpn_user_activity"
index=main "sneha.nair" earliest="2025-03-09 23:10:00" latest="2025-03-10 02:20:00"
| table _time sourcetype source_ip destination_ip user action Message
```

```spl id="cs0276_tor_activity_by_sourcetype"
index=main source_ip="185.220.101.40" earliest="2025-03-09 23:10:00" latest="2025-03-10 02:20:00"
| stats count values(user) as users values(destination_ip) as destinations values(action) as actions by sourcetype
```

```spl id="cs0276_cross_log_review"
index=main user="sneha.nair" (sourcetype=windows_logs OR sourcetype=edr_logs OR sourcetype=firewall_logs OR sourcetype=proxy_logs)
| table _time sourcetype user source_ip destination_ip action process_name url Message
```

### Activity to Validate

1. Internal system access after VPN login.
2. Access to file servers, AD, or sensitive applications.
3. Failed or successful lateral movement attempts.
4. Unusual SMB, RDP, or SSH activity.
5. Unusual DNS or proxy activity.
6. File download or upload activity.
7. EDR alerts from `MACDeB`.
8. Privilege escalation or suspicious process execution.
9. Unusual authentication events linked to `sneha.nair`.
10. Any activity involving `anjali.chauhan`.

## Endpoint / Forensic Validation

Endpoint `MACDeB` should be isolated and reviewed because it was linked to the successful TOR-originated VPN session.

### Forensics Team Should Validate

1. Whether `MACDeB` belongs to `sneha.nair`.
2. Whether the device initiated the VPN session.
3. Whether TOR browser, proxy tools, VPN tools, or tunneling tools are installed.
4. Whether suspicious browser extensions are present.
5. Whether credential theft indicators exist.
6. Whether malware or remote access tools are present.
7. Whether suspicious persistence items exist.
8. Whether the user received and approved MFA.
9. Whether any phishing email or suspicious website was accessed before the login.
10. Whether corporate data was accessed during the VPN session.

**Isolation Decision:** `MACDeB` should remain isolated until endpoint compromise is ruled out or remediation is completed.

## User Validation Questions

SOC should contact user `sneha.nair` and confirm:

1. Did you attempt to log in to VPN on `2025-03-09 23:10`?
2. Were you using TOR, a privacy browser, proxy, or third-party VPN service?
3. Were you located in Germany at the time of login?
4. Did you receive and approve the MFA prompt?
5. Did you recently enter corporate credentials on any suspicious website?
6. Is `MACDeB` your assigned Mac device?
7. Did you notice any suspicious activity on your account or device?
8. Did you install any new VPN, proxy, or browser privacy tool recently?

SOC should also contact user `anjali.chauhan` and confirm:

1. Did you attempt to log in to VPN on `2025-03-09 11:21` or `14:34`?
2. Did you receive any suspicious login notification?
3. Did you recently enter your corporate password on any suspicious website?
4. Did you notice any account lockout or failed login notification?
5. Was any password reset already completed?

## Impact Analysis

| Impact Area                    | Status                                                       |
| ------------------------------ | ------------------------------------------------------------ |
| TOR exit node login            | Confirmed                                                    |
| Successful VPN authentication  | Confirmed for `sneha.nair`                                   |
| FullAccess VPN session         | Confirmed                                                    |
| Additional user targeted       | anjali.chauhan                                               |
| Failed authentication attempts | Confirmed for `anjali.chauhan`                               |
| Credential exposure            | Likely / suspected                                           |
| MFA bypass                     | Not confirmed, but MFA success observed                      |
| Endpoint compromise            | Suspected, requires validation                               |
| Lateral movement               | Not confirmed from provided logs                             |
| Data exfiltration              | Not confirmed from provided logs                             |
| Business impact                | Medium                                                       |
| Security impact                | High                                                         |
| Residual risk                  | High until containment and forensic validation are completed |

### Impact Summary

The incident is high-risk because a successful VPN session was established from a TOR exit node with `FullAccess`. This could provide unauthorized internal access if the account was compromised. No lateral movement or data exfiltration was confirmed from the provided logs, but post-login internal activity review is required.

## Containment and Remediation

| Control Area           | Action                                                     |
| ---------------------- | ---------------------------------------------------------- |
| VPN / Firewall         | Block source IP `185.220.101.40`                           |
| VPN / Firewall         | Block TOR exit node access to corporate VPN                |
| DNS / Proxy / Firewall | Block or monitor `for-privacy.net` where applicable        |
| Identity               | Reset password for `sneha.nair`                            |
| Identity               | Reset password for `anjali.chauhan`                        |
| Identity               | Revoke active sessions for `sneha.nair`                    |
| MFA                    | Review MFA approval for `sneha.nair`                       |
| MFA                    | Force MFA re-registration for `sneha.nair` if unauthorized |
| Endpoint               | Isolate `MACDeB`                                           |
| Endpoint / Forensics   | Perform forensic review of `MACDeB`                        |
| SIEM                   | Add source IP, domain, users, and endpoint to watchlist    |
| SOC                    | Review internal activity after successful VPN login        |

## Recommended Actions

1. Block `185.220.101.40` at VPN/firewall controls.
2. Block TOR exit node access to corporate VPN.
3. Block or monitor domain `for-privacy.net`.
4. Reset credentials for `sneha.nair`.
5. Reset credentials for `anjali.chauhan`.
6. Revoke all active VPN sessions for `sneha.nair`.
7. Review MFA activity for `sneha.nair`.
8. Force MFA re-registration for `sneha.nair` if the login was unauthorized.
9. Isolate and investigate `MACDeB`.
10. Review VPN, firewall, proxy, EDR, and Windows/macOS logs for post-login activity.
11. Review whether any sensitive internal resources were accessed during the session.
12. Monitor for additional attempts from TOR infrastructure.
13. Review VPN policy to block TOR exit nodes by default.
14. Add TOR exit node detection to SIEM correlation rules.
15. Educate users about suspicious MFA prompts and credential phishing.

## Escalation Decision

**Decision:** **Escalate to SOC L2 / Identity / Endpoint Forensics.**

**Reason:** This incident involved a successful VPN login from a confirmed TOR exit node with `FullAccess`. The same TOR IP also attempted authentication against another user. This indicates possible credential abuse and requires deeper investigation beyond SOC L1 closure.

Escalation is required for:

1. Account compromise validation.
2. Endpoint isolation and forensic review.
3. Internal network activity review.
4. MFA activity validation.
5. Credential reset and session revocation.
6. TOR access policy enforcement.

## Final Ticket Closure Comment

SOC investigated ticket **CS-070 — User Login from TOR Exit Node Detected** for user `sneha.nair`. VPN logs showed password authentication initiation from confirmed TOR exit node `185.220.101.40` toward destination `10.0.2.12` on VPN device `IvantiVPN01` under realm `Corporate_VPN`. The source IP had **100% abuse confidence** and hostname `tor-exit-40.for-privacy.net`. Splunk evidence confirmed MFA challenge generation, successful authentication, active `FullAccess` VPN session, and idle timeout. The user’s usual VPN source was `49.37.255.12` from Chennai, India. IOC scoping confirmed the same TOR exit node also generated failed password authentication attempts against `anjali.chauhan`. No lateral movement or data exfiltration was confirmed from the provided logs, but successful VPN access from TOR is high-risk. SOC recommended treating `sneha.nair` as potentially compromised, isolating `MACDeB`, resetting credentials for `sneha.nair` and `anjali.chauhan`, revoking sessions, blocking `185.220.101.40`, blocking/monitoring `for-privacy.net`, reviewing internal activity, and escalating to SOC L2 / Identity / Endpoint Forensics. Ticket closed as **True Positive — Successful VPN Login from TOR Exit Node / Account Compromise Suspected**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, TOR exit node detection, source IP reputation review, successful authentication validation, MFA event analysis, IOC scoping, multi-user credential attack analysis, account compromise assessment, internal activity review planning, endpoint forensic escalation, MITRE ATT&CK mapping, containment recommendation, escalation decision-making, and SOC ticket documentation.

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
