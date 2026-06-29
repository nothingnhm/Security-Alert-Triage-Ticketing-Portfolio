# SOC Analyst Investigation Report

## Ticket Overview

| Field                  | Details                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| Ticket ID              | CS-078                                                                  |
| Alert Name             | Linux:- Unauthorized or Suspicious Privileged Account Creation          |
| Incident Category      | Linux / Privileged Account Creation                                     |
| Ticket Status          | Closed                                                                  |
| Priority / SLA         | Normal / Default SLA                                                    |
| Department             | Support                                                                 |
| Created Date           | 5/12/25 6:45 PM                                                         |
| Closed By              | Ananda Das                                                              |
| Detection Source       | Linux Logs / SIEM Splunk                                                |
| Affected Host          | LinHRWebServer03                                                        |
| Host IP                | 10.0.14.12                                                              |
| Operating System       | Linux - RHEL 8                                                          |
| User Performing Action | Aditi Mehra                                                             |
| Analyst Decision       | **Suspicious Privileged Account Creation — User Verification Required** |

## Executive Summary

A Linux security alert was generated on host **LinHRWebServer03** after a new Linux user account was created and then added to the sudo group.

The affected host was:

`LinHRWebServer03 / 10.0.14.12`

The suspicious activity involved two successful administrative actions:

`useradd webadmin`

`gpasswd -a webadmin sudo`

The activity was performed by user:

`Aditi Mehra`

from source address:

`10.1.4.123`

The first command created a new account named `webadmin`. The second command added the newly created account to the `sudo` group, which may allow elevated command execution.

Because privileged account creation can be used for persistence, privilege escalation, or unauthorized access, SOC classified the event as suspicious until validated. However, the activity was performed by a user identified as a Linux Admin, so this may also be legitimate administrative activity.

Final assessment: **User verification and change approval validation are required. No direct evidence of compromise was observed in the provided logs, but the privileged account creation is high-risk if unauthorized.**

## Alert Details

| Field             | Value                    |
| ----------------- | ------------------------ |
| First Event Time  | 5/9/2025 10:00           |
| Second Event Time | 5/9/2025 10:02           |
| Hostname          | LinHRWebServer03         |
| IP Address        | 10.0.14.12               |
| OS                | Linux - RHEL 8           |
| User              | Aditi Mehra              |
| Source Address    | 10.1.4.123               |
| First Process     | useradd                  |
| First Executable  | /usr/sbin/useradd        |
| First Command     | useradd webadmin         |
| First Result      | success                  |
| First Event Key   | log_user_creation        |
| Second Process    | gpasswd                  |
| Second Executable | /usr/bin/gpasswd         |
| Second Command    | gpasswd -a webadmin sudo |
| Second Result     | success                  |
| Second Event Key  | log_group_addition       |
| Log Path          | /etc/webadmin            |

## Affected Asset Details

| Field                                | Value            |
| ------------------------------------ | ---------------- |
| Hostname                             | LinHRWebServer03 |
| IP Address                           | 10.0.14.12       |
| Operating System                     | Linux - RHEL 8   |
| Platform                             | Linux            |
| Server Function                      | Web Server       |
| Hosting Environment                  | AWS Cloud        |
| Account Management Commands Observed | useradd, gpasswd |
| New Account Created                  | webadmin         |
| Privileged Group Added               | sudo             |
| Log Path                             | /etc/webadmin    |

## IOCs / Indicators Identified

| Indicator Type         | Indicator                                          |
| ---------------------- | -------------------------------------------------- |
| Source Address         | 10.1.4.123                                         |
| Destination Host       | LinHRWebServer03                                   |
| Destination IP         | 10.0.14.12                                         |
| User Performing Action | Aditi Mehra                                        |
| User Role              | Linux Admin                                        |
| New Account Created    | webadmin                                           |
| Privileged Group Added | sudo                                               |
| Command                | useradd webadmin                                   |
| Command                | gpasswd -a webadmin sudo                           |
| Executable             | /usr/sbin/useradd                                  |
| Executable             | /usr/bin/gpasswd                                   |
| Working Directory      | /home/aditi                                        |
| Log Path               | /etc/webadmin                                      |
| Event Key              | log_user_creation                                  |
| Event Key              | log_group_addition                                 |
| Result                 | success                                            |
| Risk Type              | Privileged Account Creation / Account Manipulation |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the Linux privileged account creation alert for host `LinHRWebServer03`. The alert indicated that a new user account was created and then added to the sudo group.

Because sudo group membership can provide elevated privileges, SOC treated the activity as a potential persistence or privilege escalation event until validated.

#### 2. Entity Identification

| Entity                 | Value            |
| ---------------------- | ---------------- |
| Hostname               | LinHRWebServer03 |
| Host IP                | 10.0.14.12       |
| OS                     | Linux - RHEL 8   |
| User Performing Action | Aditi Mehra      |
| Source Address         | 10.1.4.123       |
| New Account            | webadmin         |
| Privileged Group       | sudo             |
| Commands Observed      | useradd, gpasswd |

#### 3. Splunk Query Used

```spl id="privileged_account_creation_query"
index=main sourcetype="linux_logs" "10.1.4.123"
| table _time hostname ip_address os platform user user_role pid ppid comm exe cmd cwd addr ses success res path key
```

#### 4. Full Unique Splunk Log Results

```text id="privileged_account_creation_results"
_time	hostname	ip_address	os	platform	user	user_role	pid	ppid	comm	exe	cmd	cwd	addr	ses	success	res	path	key
2025-05-09 10:02:00	LinHRWebServer03	10.0.14.12	Linux - RHEL 8	Linux	Aditi Mehra	Linux Admin	4862	884	gpasswd	/usr/bin/gpasswd	gpasswd -a webadmin sudo	/home/aditi	10.1.4.123	1	yes	success	/etc/webadmin	log_group_addition
2025-05-09 10:00:00	LinHRWebServer03	10.0.14.12	Linux - RHEL 8	Linux	Aditi Mehra	Linux Admin	1287	525	useradd	/usr/sbin/useradd	useradd webadmin	/home/aditi	10.1.4.123	1	yes	success	/etc/webadmin	log_user_creation
```

**Evidence Note:** All unique Linux account management log rows provided for this ticket were preserved.

## Investigation Findings

1. A new Linux user account named `webadmin` was created.
2. The account creation occurred on host `LinHRWebServer03`.
3. The affected server IP was `10.0.14.12`.
4. The server was running `Linux - RHEL 8`.
5. The server function was `Web Server`.
6. The environment was identified as `AWS Cloud`.
7. The activity was performed by user `Aditi Mehra`.
8. The user role was identified as `Linux Admin`.
9. The source address was `10.1.4.123`.
10. The command `useradd webadmin` executed successfully.
11. The command `gpasswd -a webadmin sudo` executed successfully.
12. The new account `webadmin` was added to the `sudo` group.
13. The activity resulted in a privileged account being created.
14. No failed execution was observed.
15. No direct evidence of compromise was provided in the logs.
16. User verification and change approval validation are required.

## Timeline of Events

| Time               | Event                                                               |
| ------------------ | ------------------------------------------------------------------- |
| 2025-05-09 10:00   | User `Aditi Mehra` executed `useradd webadmin`                      |
| 2025-05-09 10:00   | Account `webadmin` was created successfully                         |
| 2025-05-09 10:02   | User `Aditi Mehra` executed `gpasswd -a webadmin sudo`              |
| 2025-05-09 10:02   | Account `webadmin` was added to the sudo group successfully         |
| Investigation Time | SOC reviewed Linux account creation logs in Splunk                  |
| Investigation Time | SOC confirmed successful privileged account creation                |
| Validation Time    | User verification with Aditi Mehra recommended                      |
| Closure Time       | Ticket closed after documenting validation and containment guidance |

## MITRE ATT&CK Mapping

| Tactic                             | Technique                         | ID        | Reason                                                                |
| ---------------------------------- | --------------------------------- | --------- | --------------------------------------------------------------------- |
| Persistence                        | Create Account: Local Account     | T1136.001 | A new local Linux account `webadmin` was created                      |
| Persistence / Privilege Escalation | Account Manipulation              | T1098     | The newly created account was modified by adding it to the sudo group |
| Privilege Escalation               | Abuse Elevation Control Mechanism | T1548     | Adding the account to sudo may allow elevated command execution       |
| Initial Access / Persistence       | Valid Accounts                    | T1078     | If unauthorized, the new account could be used for persistent access  |

**MITRE Note:** The observed behavior matches account creation and privilege assignment. The event is not confirmed malicious unless the activity is denied by the admin user or lacks an approved change record.

## Analyst Assessment

**Assessment:** **Suspicious Privileged Account Creation — User Verification Required**

The activity is suspicious because a new account was created and quickly granted sudo-level privileges.

The evidence supporting the alert includes:

1. `useradd webadmin` was executed successfully.
2. `gpasswd -a webadmin sudo` was executed successfully.
3. The new account `webadmin` received sudo group membership.
4. The commands were executed on a Linux web server.
5. The activity originated from source address `10.1.4.123`.
6. Privileged account creation can be used for persistence, privilege escalation, or unauthorized access.

However, the commands were performed by a user identified as a **Linux Admin**, so this may be legitimate administrative activity. User verification is required before confirming compromise.

## User Verification Questions

SOC should contact **Aditi Mehra** and confirm:

1. Did you create the `webadmin` account on `LinHRWebServer03`?
2. Was the account creation part of an approved change request?
3. What is the business purpose of the `webadmin` account?
4. Why was the account added to the `sudo` group?
5. Is `10.1.4.123` your assigned workstation or approved jump host?
6. Was this activity performed from `/home/aditi`?
7. Was this account required for web server administration?
8. Is there an approved ticket or change record for this activity?
9. Should the `webadmin` account remain active?
10. Should `webadmin` retain sudo privileges?

### Validation Decision

If Aditi Mehra confirms the activity and provides a valid change reference, document the approval and close the ticket as authorized administrative activity.

If Aditi Mehra denies the activity, treat the admin account as potentially compromised and immediately contain the affected account, source device, and newly created privileged user.

## Impact Analysis

| Impact Area               | Status                                    |
| ------------------------- | ----------------------------------------- |
| New account created       | Confirmed                                 |
| Privileged group addition | Confirmed                                 |
| Account added to sudo     | Confirmed                                 |
| Target host               | LinHRWebServer03                          |
| Host IP                   | 10.0.14.12                                |
| Host function             | Web Server                                |
| Account created           | webadmin                                  |
| Admin user involved       | Aditi Mehra                               |
| Source address            | 10.1.4.123                                |
| Successful execution      | Confirmed                                 |
| Account compromise        | Not confirmed                             |
| Privilege escalation risk | High if unauthorized                      |
| Persistence risk          | High if unauthorized                      |
| Business impact           | Low if authorized                         |
| Security impact           | High until verified                       |
| Residual risk             | Low if authorized; High if denied by user |

### Impact Summary

The event involved successful creation of a privileged Linux account. If authorized, this is normal administrative activity. If unauthorized, it may indicate admin account compromise, persistence creation, or privilege escalation on a Linux web server.

## Containment and Remediation

| Scenario               | Action                                                 |
| ---------------------- | ------------------------------------------------------ |
| User confirms activity | Document user confirmation and change reference        |
| User confirms activity | Validate whether `webadmin` still requires sudo access |
| User confirms activity | Close as authorized admin activity                     |
| User denies activity   | Disable or remove `webadmin` immediately               |
| User denies activity   | Remove `webadmin` from sudo group                      |
| User denies activity   | Isolate or disable Aditi Mehra’s account               |
| User denies activity   | Reset Aditi Mehra’s credentials                        |
| User denies activity   | Isolate and investigate source host `10.1.4.123`       |
| User denies activity   | Review successful logins and command history           |
| User denies activity   | Escalate to SOC L2 / Linux Team / Incident Response    |

## Additional Splunk Queries for Follow-Up

### Check Login Activity for Newly Created Account

```spl id="webadmin_login_activity_check"
index=main sourcetype="linux_logs" hostname="LinHRWebServer03" user="webadmin"
| table _time hostname ip_address user comm exe cmd addr success res path key
| sort _time
```

### Check Command Activity by Aditi Mehra

```spl id="aditi_command_activity_check"
index=main sourcetype="linux_logs" hostname="LinHRWebServer03" user="Aditi Mehra"
| table _time hostname ip_address user comm exe cmd cwd addr success res path key
| sort _time
```

### Check Additional User or Group Changes on Same Host

```spl id="user_group_change_review"
index=main sourcetype="linux_logs" hostname="LinHRWebServer03" (comm="useradd" OR comm="usermod" OR comm="gpasswd" OR comm="passwd")
| table _time hostname user comm exe cmd addr success res path key
| sort _time
```

### Check Events from Same Source Address

```spl id="same_source_activity_check"
index=main sourcetype="linux_logs" addr="10.1.4.123"
| table _time hostname ip_address user comm exe cmd cwd addr success res path key
| sort _time
```

## Recommended Actions

1. Contact Aditi Mehra and validate whether the account creation was authorized.
2. Confirm whether there is an approved change request for `webadmin`.
3. Review whether `webadmin` requires sudo privileges.
4. Disable or remove `webadmin` if no approval exists.
5. Remove `webadmin` from the sudo group if elevated access is not required.
6. Validate source host `10.1.4.123`.
7. Review command history and authentication logs for Aditi Mehra.
8. Review all user and group changes on `LinHRWebServer03`.
9. Monitor for login activity using the `webadmin` account.
10. Enforce approval workflow for privileged Linux account creation.
11. Alert on new user creation followed by sudo group addition.
12. Review least-privilege access for Linux admin accounts.
13. Ensure sudo group membership is reviewed periodically.

## Escalation Decision

**Decision:** **User verification required. Escalate if Aditi Mehra denies the activity or no approved change exists.**

**Reason:** The activity involved successful creation of a new account and assignment to the sudo group. This is high-risk if unauthorized. Since the action was performed by a Linux Admin account, confirmation is required before classifying the event as benign.

Escalate to **SOC L2 / Linux Team / Incident Response** if:

1. Aditi Mehra denies creating the account.
2. No approved change request exists.
3. `webadmin` logs in or executes commands unexpectedly.
4. Additional unauthorized accounts are created.
5. Source host `10.1.4.123` is not approved.
6. Suspicious command execution is observed.
7. Persistence, privilege escalation, or lateral movement indicators are found.

## Final Ticket Closure Comment

SOC investigated a Linux privileged account creation alert on `LinHRWebServer03 / 10.0.14.12`. Splunk logs showed that user `Aditi Mehra` executed `useradd webadmin` from source address `10.1.4.123` at `2025-05-09 10:00`, successfully creating the `webadmin` account. At `2025-05-09 10:02`, the same user executed `gpasswd -a webadmin sudo`, successfully adding `webadmin` to the sudo group. Both events were successful and recorded with event keys `log_user_creation` and `log_group_addition`. No direct evidence of compromise was observed in the provided logs; however, privileged account creation on a web server is high-risk if unauthorized. SOC recommended validating the activity with Aditi Mehra and confirming an approved change request. If authorized, document the approval and close as administrative activity. If denied, remove or disable `webadmin`, remove sudo privileges, reset Aditi Mehra’s credentials, investigate source host `10.1.4.123`, and escalate to SOC L2 / Linux Team. Ticket closed as **Suspicious Privileged Account Creation — User Verification Required / Privileged Account Created Successfully**.

## Skills Demonstrated

Linux log analysis, privileged account creation triage, Splunk investigation, useradd/gpasswd command review, sudo group membership analysis, account manipulation detection, IOC extraction, MITRE ATT&CK mapping, user verification planning, change approval validation, containment planning, escalation criteria definition, and SOC ticket documentation.

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
