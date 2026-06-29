# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                                       |
| ----------------- | --------------------------------------------------------------------------------------------- |
| Ticket ID         | CS-0267                                                                                       |
| Alert Name        | VPN:- Login from IP with Bad Reputation                                                       |
| Incident Category | VPN / Suspicious Authentication                                                               |
| Ticket Status     | Closed                                                                                        |
| Priority / SLA    | High / Default SLA                                                                            |
| Department        | Support                                                                                       |
| Created Date      | 3/23/25 2:30 PM                                                                               |
| Closed By         | Ananda Das                                                                                    |
| Detection Source  | VPN Logs / SIEM Splunk                                                                        |
| Affected User     | `rahul.joshi`                                                                                 |
| Affected Host     | Dstldfnd                                                                                      |
| Analyst Decision  | **True Positive — Suspicious VPN Authentication Attempt / MFA Prevented Unauthorized Access** |

## Executive Summary

A VPN security alert was triggered for user **rahul.joshi** after an authentication attempt was observed from an external IP address with bad reputation:

`186.23.212.74`

The authentication attempt targeted the corporate VPN destination:

`10.0.2.12`

The VPN realm was:

`Corporate_VPN`

Splunk VPN logs confirmed that password authentication was initiated, followed by an MFA OTP challenge. The MFA challenge failed because an incorrect OTP was entered.

The source IP had **50% abuse confidence** and was associated with an external location in Argentina. No successful VPN session was observed in the provided logs.

SOC classified the activity as a **True Positive suspicious VPN authentication attempt**, potentially related to credential abuse, brute force, or credential stuffing. MFA prevented unauthorized access. The source IP was blocked, the user password was reset, and the ticket was closed after confirming no successful compromise.

## Alert Details

| Field          | Value                                                               |
| -------------- | ------------------------------------------------------------------- |
| Timestamp      | 2/23/2025 8:29                                                      |
| Source IP      | 186.23.212.74                                                       |
| Destination IP | 10.0.2.12                                                           |
| User           | rahul.joshi                                                         |
| Hostname       | Dstldfnd                                                            |
| Device Type    | Windows 11                                                          |
| VPN Device     | IvantiVPN01                                                         |
| VPN Realm      | Corporate_VPN                                                       |
| Session Status | Authentication initiated                                            |
| Message        | User `rahul.joshi` Realm `Corporate_VPN` - Authentication initiated |
| Final Verdict  | True Positive                                                       |

## Affected Assets

| Asset / Entity     | Details                                     |
| ------------------ | ------------------------------------------- |
| Affected User      | `rahul.joshi`                               |
| Hostname           | Dstldfnd                                    |
| User Device Type   | Windows 11                                  |
| VPN Device         | IvantiVPN01                                 |
| VPN Destination IP | 10.0.2.12                                   |
| VPN Server OS      | Windows Server 2022                         |
| VPN Realm          | Corporate_VPN                               |
| Source IP          | 186.23.212.74                               |
| Attack Type        | Suspicious VPN login from bad-reputation IP |

## Evidence Reviewed

### Source IP Reputation Analysis

| Field            | Value                                        |
| ---------------- | -------------------------------------------- |
| Source IP        | 186.23.212.74                                |
| Abuse Confidence | 50%                                          |
| ISP              | Telecentro S.A.                              |
| Usage Type       | Fixed Line ISP                               |
| ASN              | AS27747                                      |
| Hostname / PTR   | cpe-186-23-212-74.telecentro-reversos.com.ar |
| Domain Name      | telecentro.com.ar                            |
| Country          | Argentina                                    |
| City             | Jose C. Paz, Buenos Aires                    |

### Source IP Assessment

The source IP `186.23.212.74` had a suspicious abuse reputation score of **50%**. The login originated from an external location that was not confirmed as trusted for the affected user. Because the attempt triggered MFA and failed due to incorrect OTP entry, the activity was treated as suspicious and potentially related to credential abuse or unauthorized login attempt.

## IOCs / Indicators Identified

| IOC Type         | Indicator                                                 |
| ---------------- | --------------------------------------------------------- |
| Source IP        | 186.23.212.74                                             |
| Destination IP   | 10.0.2.12                                                 |
| Affected User    | rahul.joshi                                               |
| Hostname         | Dstldfnd                                                  |
| VPN Device       | IvantiVPN01                                               |
| VPN Realm        | Corporate_VPN                                             |
| User Device Type | Windows 11                                                |
| ISP              | Telecentro S.A.                                           |
| Hostname / PTR   | cpe-186-23-212-74.telecentro-reversos.com.ar              |
| Domain           | telecentro.com.ar                                         |
| Country          | Argentina                                                 |
| Attack Type      | Suspicious VPN Authentication / Possible Credential Abuse |
| MFA Status       | Failed                                                    |
| Session Status   | No successful VPN session observed                        |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN alert for user `rahul.joshi`. The alert indicated that a VPN authentication attempt was initiated from source IP `186.23.212.74`, which had bad reputation.

The alert was treated as suspicious because the source IP was external, had abuse reputation, and triggered MFA activity against a valid corporate VPN account.

#### 2. Entity Identification

| Entity         | Value         |
| -------------- | ------------- |
| User           | rahul.joshi   |
| Hostname       | Dstldfnd      |
| Device Type    | Windows 11    |
| Source IP      | 186.23.212.74 |
| Destination IP | 10.0.2.12     |
| VPN Device     | IvantiVPN01   |
| Realm          | Corporate_VPN |

#### 3. Splunk Query Used

```spl id="cs0267_vpn_query"
index=main "186.23.212.74" "rahul.joshi" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

#### 4. Full Unique Splunk Log Results

```text id="cs0267_vpn_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-02-23 08:29:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	Windows 11	Failed Authentication	None	Failed	Corporate_VPN	Dstldfnd	186.23.212.74	User 'rahul.joshi' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	rahul.joshi
2025-02-23 08:29:00	Normal	MFA	10.0.2.12	IvantiVPN01	Windows 11	None	Pending Authentication	OTP Sent	Corporate_VPN	Dstldfnd	186.23.212.74	User 'rahul.joshi' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	rahul.joshi
2025-02-23 08:29:00	suspiicous	Password	10.0.2.12	IvantiVPN01	Windows 11	None	Authentication initiated	Prompted	Corporate_VPN	Dstldfnd	186.23.212.74	User 'rahul.joshi' Realm 'Corporate_VPN' - Authentication initiated	rahul.joshi
```

**Evidence Note:** Exact duplicate VPN log rows were observed in the provided evidence. Duplicate rows were removed from the final evidence table, while all unique activity was preserved.

### 5. VPN Authentication Pattern Review

| Observation                                | Analyst Interpretation                |
| ------------------------------------------ | ------------------------------------- |
| Authentication initiated for a valid user  | Possible credential abuse attempt     |
| Source IP had bad reputation               | Suspicious external login source      |
| MFA challenge generated                    | Authentication reached MFA workflow   |
| MFA failed due to incorrect OTP            | Unauthorized access was not completed |
| No successful VPN session observed         | No confirmed VPN compromise           |
| Source IP located outside expected context | Requires user validation              |

### 6. Timeline of Events

| Time               | Event                                                              |
| ------------------ | ------------------------------------------------------------------ |
| 2025-02-23 08:29   | Password authentication initiated for `rahul.joshi`                |
| 2025-02-23 08:29   | MFA challenge initiated and OTP sent                               |
| 2025-02-23 08:29   | MFA challenge failed due to incorrect OTP                          |
| Investigation Time | SOC reviewed VPN logs in Splunk                                    |
| Investigation Time | SOC reviewed source IP reputation                                  |
| Containment Time   | Source IP was blocked and user credentials were reset              |
| Closure Time       | Ticket closed after no successful VPN session or harm was observed |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID    | Reason                                                                    |
| ----------------- | ---------------------------------------------- | ----- | ------------------------------------------------------------------------- |
| Credential Access | Brute Force                                    | T1110 | VPN authentication attempt against a valid user account was observed      |
| Initial Access    | Valid Accounts                                 | T1078 | Attempted use of `rahul.joshi` account against Corporate VPN was observed |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | MFA challenge was generated during the suspicious login attempt           |
| Initial Access    | External Remote Services                       | T1133 | VPN service was targeted as an external remote access service             |

**MITRE Note:** Suspicious VPN authentication and MFA challenge generation were observed. Successful VPN access, MFA bypass, lateral movement, endpoint compromise, and data exfiltration were not observed.

## Analyst Assessment

**Assessment:** **True Positive — Suspicious VPN Authentication Attempt / No Successful Login**

The alert is valid because a VPN authentication attempt was initiated from an external IP with bad reputation against a valid corporate user account.

The source IP reputation, external geography, MFA challenge generation, and failed OTP event indicate suspicious login behavior. The activity may represent credential abuse, brute-force, or credential-stuffing activity.

No confirmed compromise was observed because MFA failed and no successful VPN session was established.

## Impact Analysis

| Impact Area             | Status                        |
| ----------------------- | ----------------------------- |
| Suspicious VPN login    | Confirmed                     |
| Targeted user           | rahul.joshi                   |
| Credential exposure     | Possible                      |
| MFA challenge generated | Confirmed                     |
| MFA failure             | Confirmed                     |
| MFA bypass              | Not observed                  |
| Successful VPN access   | Not observed                  |
| Active VPN session      | Not observed                  |
| Endpoint compromise     | Not observed                  |
| Lateral movement        | Not observed                  |
| Data exfiltration       | Not observed                  |
| Business impact         | Low                           |
| Security impact         | Limited due to MFA protection |

## Recommended Actions

1. Keep source IP `186.23.212.74` blocked on VPN/firewall controls.
2. Reset credentials for user `rahul.joshi`.
3. Revoke any active VPN sessions for the affected user.
4. Review VPN logs for successful sessions from the same source IP.
5. Review VPN logs for the same source IP targeting other users.
6. Monitor `rahul.joshi` for additional failed login attempts.
7. Monitor authentication attempts from related IP ranges or the same ISP.
8. Keep MFA enforced for all VPN users.
9. Review conditional access policies for risky IP reputation and unusual geography.
10. Enable account lockout or rate limiting for repeated VPN failures.
11. Educate the user about phishing, password reuse, and unexpected MFA prompts.
12. Add source IP, user, and VPN realm to SIEM watchlists for short-term monitoring.

## Containment and Remediation

| Control Area   | Action                                                          |
| -------------- | --------------------------------------------------------------- |
| VPN / Firewall | Block source IP `186.23.212.74`                                 |
| Identity       | Reset credentials for `rahul.joshi`                             |
| VPN            | Confirm no active session from suspicious IP                    |
| MFA            | Confirm MFA prevented unauthorized access                       |
| SIEM           | Add source IP and user to monitoring/watchlist                  |
| SOC            | Monitor for repeated attempts against same user                 |
| SOC            | Monitor for similar attempts from related IP ranges or same ISP |

## User Validation Questions

SOC should contact user `rahul.joshi` and confirm:

1. Were you attempting to log in to VPN at `2025-02-23 08:29`?
2. Did you receive an unexpected OTP or MFA notification?
3. Did you approve, reject, or ignore any MFA prompt?
4. Did you recently enter your password on any suspicious website?
5. Have you reused this password on any external website?
6. Did you notice any suspicious activity on your account or endpoint?
7. Was travel or remote work from Argentina expected at the time of the login attempt?

If the user confirms the activity was not initiated by them, the password reset and source IP block should remain enforced.

## Escalation Decision

**Decision:** **No further escalation required after containment.**

**Reason:** The incident was confirmed as a suspicious VPN login attempt, but MFA prevented unauthorized access. No successful VPN session, MFA bypass, endpoint compromise, lateral movement, or data exfiltration was observed from the provided logs.

Escalate to **SOC L2 / Identity Team** if any of the following are identified:

1. Successful VPN login from suspicious IP.
2. MFA approval from unknown source.
3. Multiple users targeted by the same source IP.
4. Repeated attempts continue after IP block.
5. Suspicious mailbox, endpoint, or cloud activity appears.
6. Evidence of credential theft is identified.
7. User confirms the login attempt was not legitimate and additional suspicious activity is found.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0267 — VPN Login from IP with Bad Reputation** for user `rahul.joshi`. VPN logs showed password authentication initiation from external source IP `186.23.212.74` toward VPN destination `10.0.2.12` on VPN device `IvantiVPN01` under realm `Corporate_VPN`. The activity generated an MFA OTP challenge, followed by MFA failure due to incorrect OTP entry. The source IP had **50% abuse confidence** and was associated with suspicious external login behavior from Argentina. No successful VPN session, MFA bypass, endpoint compromise, lateral movement, or data exfiltration was observed. Source IP `186.23.212.74` was blocked, credentials for `rahul.joshi` were reset, and continued monitoring was recommended. Ticket closed as **True Positive — Suspicious VPN Authentication Attempt / MFA Prevented Unauthorized Access / No Confirmed Compromise**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, bad-reputation IP login triage, authentication event review, MFA failure analysis, source IP reputation review, IOC extraction, account compromise validation, MITRE ATT&CK mapping, containment planning, user validation, escalation decision-making, and SOC ticket documentation.
