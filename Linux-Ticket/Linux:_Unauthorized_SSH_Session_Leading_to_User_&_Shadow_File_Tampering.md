# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                  |
| ----------------- | ------------------------------------------------------------------------ |
| Ticket ID         | CS-080                                                                   |
| Alert Name        | Linux:- Unauthorized SSH Session Leading to User & Shadow File Tampering |
| Incident Category | Linux / Unauthorized SSH Access / Credential File Tampering              |
| Ticket Status     | Closed                                                                   |
| Priority / SLA    | Emergency / Default SLA                                                  |
| Department        | Support                                                                  |
| Created Date      | 5/12/25 6:45 PM                                                          |
| Closed By         | Ananda Das                                                               |
| Detection Source  | Linux Logs / SIEM Splunk                                                 |
| Affected Host     | LinFDWebServer04                                                         |
| Host IP           | 10.0.11.8                                                                |
| Operating System  | Linux - RHEL 8                                                           |
| Analyst Decision  | **True Positive — Confirmed Linux Server Compromise**                    |

## Executive Summary

A critical Linux security alert was triggered on **LinFDWebServer04** after a successful unauthorized SSH session was followed by suspicious local account creation and access to sensitive Linux authentication files.

The affected server was:

`LinFDWebServer04 / 10.0.11.8`

The suspicious activity originated from external source IP:

`62.76.142.12`

The source IP had **100% abuse confidence** and was associated with data center / web hosting / transit infrastructure in Russia.

Splunk logs confirmed the following sequence:

1. Successful unauthorized SSH login using account `webacc`.
2. Creation of a new local account named `admin`.
3. Access to `/etc/passwd`.
4. Access to `/etc/shadow`.

The files `/etc/passwd` and `/etc/shadow` are sensitive Linux authentication files. Access to these files after unauthorized SSH activity strongly indicates possible credential tampering, credential harvesting, persistence creation, or privilege escalation activity.

Final assessment: **Confirmed Linux server compromise. Immediate host isolation, credential reset, source IP blocking, unauthorized account removal, sensitive file integrity validation, and escalation to SOC L2 / Linux Team / Incident Response are required.**

## Alert Details

| Time             | Hostname         | Host IP   | OS             | User    | Process | Command                | Source IP    | Success | Result  | Path        | Event Key         |
| ---------------- | ---------------- | --------- | -------------- | ------- | ------- | ---------------------- | ------------ | ------- | ------- | ----------- | ----------------- |
| 2025-05-10 16:00 | LinFDWebServer04 | 10.0.11.8 | Linux - RHEL 8 | unknown | sshd    | sshd: webacc [preauth] | 62.76.142.12 | yes     | success | /tmp        | log_unauth_login  |
| 2025-05-10 16:01 | LinFDWebServer04 | 10.0.11.8 | Linux - RHEL 8 | unknown | useradd | useradd admin          | 62.76.142.12 | yes     | success | /tmp        | log_user_creation |
| 2025-05-10 16:02 | LinFDWebServer04 | 10.0.11.8 | Linux - RHEL 8 | unknown | vi      | vi /etc/passwd         | 62.76.142.12 | yes     | success | /etc/passwd | log_passwd_access |
| 2025-05-10 16:03 | LinFDWebServer04 | 10.0.11.8 | Linux - RHEL 8 | unknown | vi      | vi /etc/shadow         | 62.76.142.12 | yes     | success | /etc/shadow | log_shadow_access |

## Source IP Reputation Analysis

| Field            | Value                               |
| ---------------- | ----------------------------------- |
| Source IP        | 62.76.142.12                        |
| Abuse Confidence | 100%                                |
| ISP              | QWARTA LLC                          |
| Usage Type       | Data Center / Web Hosting / Transit |
| ASN              | AS208427                            |
| Hostname         | mail.aesergeev.ru                   |
| Domain Name      | qwarta.ru                           |
| Country          | Russian Federation                  |
| City             | Moscow, Moscow                      |

### Source IP Assessment

The source IP `62.76.142.12` had **100% abuse confidence** and belonged to hosting/transit infrastructure. Successful SSH access followed by account creation and sensitive file access from this source is highly suspicious.

This event should be treated as a confirmed compromise, not only an attempted attack.

## Affected Asset Details

| Field                      | Value                    |
| -------------------------- | ------------------------ |
| Hostname                   | LinFDWebServer04         |
| IP Address                 | 10.0.11.8                |
| Operating System           | Linux - RHEL 8           |
| Platform                   | Linux                    |
| Server Function            | Web Server               |
| Hosting Environment        | AWS Cloud                |
| Log Source                 | Linux Logs               |
| Suspicious Account Used    | webacc                   |
| New Account Created        | admin                    |
| Sensitive Files Accessed   | /etc/passwd, /etc/shadow |
| Working Directory Observed | /tmp                     |

## IOCs / Indicators Identified

| IOC Type                | Indicator                                                              |
| ----------------------- | ---------------------------------------------------------------------- |
| Malicious Source IP     | 62.76.142.12                                                           |
| Source Hostname         | mail.aesergeev.ru                                                      |
| Source Domain           | qwarta.ru                                                              |
| Source Country          | Russian Federation                                                     |
| Source ASN              | AS208427                                                               |
| Source ISP              | QWARTA LLC                                                             |
| Destination Host        | LinFDWebServer04                                                       |
| Destination IP          | 10.0.11.8                                                              |
| Suspicious SSH Account  | webacc                                                                 |
| New Account Created     | admin                                                                  |
| Sensitive File Accessed | /etc/passwd                                                            |
| Sensitive File Accessed | /etc/shadow                                                            |
| Process                 | sshd                                                                   |
| Process                 | useradd                                                                |
| Process                 | vi                                                                     |
| Executable              | /usr/sbin/sshd                                                         |
| Executable              | /usr/sbin/useradd                                                      |
| Executable              | /usr/bin/vi                                                            |
| Working Directory       | /tmp                                                                   |
| Event Key               | log_unauth_login                                                       |
| Event Key               | log_user_creation                                                      |
| Event Key               | log_passwd_access                                                      |
| Event Key               | log_shadow_access                                                      |
| Attack Type             | Unauthorized SSH Access / Account Creation / Credential File Tampering |
| Final Assessment        | Server compromise confirmed                                            |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the Linux alert for unauthorized SSH activity on `LinFDWebServer04`. The alert indicated that an unauthorized SSH session was followed by account creation and access to Linux authentication files.

Because the activity involved successful access and post-login system changes, SOC treated the event as a confirmed compromise.

#### 2. Entity Identification

| Entity                 | Value                    |
| ---------------------- | ------------------------ |
| Hostname               | LinFDWebServer04         |
| Host IP                | 10.0.11.8                |
| Source IP              | 62.76.142.12             |
| OS                     | Linux - RHEL 8           |
| Suspicious SSH Account | webacc                   |
| New Account Created    | admin                    |
| Sensitive Files        | /etc/passwd, /etc/shadow |
| User Context           | unknown                  |
| Working Directory      | /tmp                     |

#### 3. Splunk Query Used

```spl id="cs0341_linux_compromise_query"
index=main sourcetype="linux_logs" "62.76.142.12"
| table _time hostname ip_address os platform user user_role pid ppid comm exe cmd cwd addr ses success res path key
```

#### 4. Full Unique Splunk Log Results

```text id="cs0341_linux_compromise_results"
_time	hostname	ip_address	os	platform	user	user_role	pid	ppid	comm	exe	cmd	cwd	addr	ses	success	res	path	key
2025-05-10 16:03:00	LinFDWebServer04	10.0.11.8	Linux - RHEL 8	Linux	unknown	unknown	2659	1157	vi	/usr/bin/vi	vi /etc/shadow	/tmp	62.76.142.12	5	yes	success	/etc/shadow	log_shadow_access
2025-05-10 16:02:00	LinFDWebServer04	10.0.11.8	Linux - RHEL 8	Linux	unknown	unknown	6637	1410	vi	/usr/bin/vi	vi /etc/passwd	/tmp	62.76.142.12	5	yes	success	/etc/passwd	log_passwd_access
2025-05-10 16:01:00	LinFDWebServer04	10.0.11.8	Linux - RHEL 8	Linux	unknown	unknown	5271	1398	useradd	/usr/sbin/useradd	useradd admin	/tmp	62.76.142.12	5	yes	success	/tmp	log_user_creation
2025-05-10 16:00:00	LinFDWebServer04	10.0.11.8	Linux - RHEL 8	Linux	unknown	unknown	2632	1423	sshd	/usr/sbin/sshd	sshd: webacc [preauth]	/tmp	62.76.142.12	2	yes	success	/tmp	log_unauth_login
```

**Evidence Note:** All unique Linux compromise log rows provided for this ticket were preserved.

## Investigation Findings

1. A successful unauthorized SSH session was observed on `LinFDWebServer04`.
2. The source IP was `62.76.142.12`.
3. The source IP had **100% abuse confidence**.
4. The source IP belonged to data center / hosting / transit infrastructure.
5. SSH activity involved account `webacc`.
6. The user field was recorded as `unknown`.
7. The working directory observed was `/tmp`.
8. After the SSH session, the command `useradd admin` was executed.
9. A new account named `admin` was created successfully.
10. The file `/etc/passwd` was accessed using `vi`.
11. The file `/etc/shadow` was accessed using `vi`.
12. Both `/etc/passwd` and `/etc/shadow` are sensitive Linux authentication files.
13. All suspicious actions showed `success=yes` and `res=success`.
14. The sequence indicates unauthorized access followed by account creation and credential file tampering.
15. The affected server should be treated as compromised.
16. Immediate isolation, credential reset, and forensic review are required.

## Timeline of Events

| Time               | Event                                                                         |
| ------------------ | ----------------------------------------------------------------------------- |
| 2025-05-10 16:00   | Successful unauthorized SSH login observed using `webacc` from `62.76.142.12` |
| 2025-05-10 16:01   | New account `admin` created using `useradd admin`                             |
| 2025-05-10 16:02   | `/etc/passwd` accessed using `vi`                                             |
| 2025-05-10 16:03   | `/etc/shadow` accessed using `vi`                                             |
| Investigation Time | SOC reviewed Linux logs in Splunk                                             |
| Investigation Time | SOC confirmed successful suspicious activity                                  |
| Investigation Time | SOC confirmed source IP reputation as 100% abuse confidence                   |
| Containment Time   | Server isolation, IP block, and credential reset recommended                  |
| Closure Time       | Ticket closed after documenting compromise and containment actions            |

## MITRE ATT&CK Mapping

| Tactic                             | Technique                                          | ID        | Reason                                                                                         |
| ---------------------------------- | -------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------- |
| Initial Access                     | Valid Accounts                                     | T1078     | Successful SSH session was observed using account `webacc`                                     |
| Initial Access / Lateral Movement  | Remote Services: SSH                               | T1021.004 | SSH was used to access the Linux host                                                          |
| Persistence                        | Create Account: Local Account                      | T1136.001 | New local account `admin` was created                                                          |
| Persistence / Privilege Escalation | Account Manipulation                               | T1098     | User and authentication files were accessed after login                                        |
| Credential Access                  | OS Credential Dumping: /etc/passwd and /etc/shadow | T1003.008 | `/etc/passwd` and `/etc/shadow` were accessed                                                  |
| Defense Evasion                    | File and Directory Permissions Modification        | T1222     | If authentication files were modified, permissions or account access may have been manipulated |
| Impact                             | Account Access Removal                             | T1531     | Unauthorized modification of authentication files could impact legitimate account access       |

**MITRE Note:** Successful unauthorized SSH access, local account creation, and access to sensitive authentication files were observed. This is sufficient to assess the host as compromised. Data exfiltration and lateral movement were not confirmed from the provided logs.

## Analyst Assessment

**Assessment:** **True Positive — Linux Server Compromise Confirmed**

The incident is confirmed as a Linux server compromise because successful unauthorized SSH access was followed by account creation and access to sensitive authentication files.

The evidence supporting this conclusion includes:

1. Successful SSH session from a high-risk external IP.
2. Source IP `62.76.142.12` had **100% abuse confidence**.
3. Source IP was associated with hosting/transit infrastructure in Russia.
4. SSH session used account `webacc`.
5. Activity was recorded under `unknown` user context.
6. New account `admin` was created immediately after login.
7. `/etc/passwd` was accessed.
8. `/etc/shadow` was accessed.
9. All suspicious actions completed successfully.
10. Activity occurred in a short sequence consistent with post-compromise activity.

Access to `/etc/passwd` and `/etc/shadow` after unauthorized SSH login indicates possible credential harvesting, password hash access, persistence setup, or local account tampering.

## Impact Analysis

| Impact Area               | Status                                                   |
| ------------------------- | -------------------------------------------------------- |
| Unauthorized SSH login    | Confirmed                                                |
| New account creation      | Confirmed                                                |
| Sensitive file access     | Confirmed                                                |
| `/etc/passwd` access      | Confirmed                                                |
| `/etc/shadow` access      | Confirmed                                                |
| Server compromise         | Confirmed                                                |
| Persistence risk          | High                                                     |
| Credential exposure risk  | High                                                     |
| Privilege escalation risk | High                                                     |
| Lateral movement risk     | High                                                     |
| Data exfiltration         | Not confirmed from provided logs                         |
| Business impact           | High                                                     |
| Security impact           | Critical                                                 |
| Residual risk             | High until containment and forensic review are completed |

### Impact Summary

The server should be treated as compromised because unauthorized SSH access was followed by account creation and access to sensitive authentication files. The attacker may have created persistence, modified local accounts, accessed password hashes, or prepared for further internal movement.

## Immediate Containment Actions

| Control Area              | Action                                                         |
| ------------------------- | -------------------------------------------------------------- |
| Host Isolation            | Isolate `LinFDWebServer04` from the network                    |
| Firewall / Security Group | Block source IP `62.76.142.12`                                 |
| Identity                  | Reset all local and related credentials                        |
| Linux Host                | Disable or remove unauthorized `admin` account                 |
| Linux Host                | Validate and remove suspicious `webacc` access if unauthorized |
| Linux Host                | Review `/etc/passwd` and `/etc/shadow` integrity               |
| Sessions                  | Terminate active SSH sessions                                  |
| Forensics                 | Preserve logs and disk evidence before full remediation        |
| SIEM                      | Add IP, domain, user, and host to watchlist                    |
| Incident Response         | Escalate for full forensic investigation                       |

## Internal Network Activity Review

Because a successful unauthorized SSH session occurred, SOC should review post-compromise activity from the affected server.

### Recommended Splunk Queries

#### Check All Activity from the Compromised Host

```spl id="cs0341_compromised_host_activity"
index=main hostname="LinFDWebServer04" earliest="2025-05-10 16:00:00" latest="2025-05-10 23:59:59"
| table _time sourcetype hostname ip_address user comm exe cmd addr success res path key
| sort _time
```

#### Check Successful SSH Sessions on the Host

```spl id="cs0341_successful_ssh_sessions"
index=main sourcetype="linux_logs" hostname="LinFDWebServer04" comm="sshd" (success="yes" OR res="success")
| table _time hostname ip_address user comm exe cmd addr success res path key
| sort _time
```

#### Check User and Group Modification Events

```spl id="cs0341_user_group_changes"
index=main sourcetype="linux_logs" hostname="LinFDWebServer04" (comm="useradd" OR comm="usermod" OR comm="gpasswd" OR comm="passwd")
| table _time hostname user comm exe cmd addr success res path key
| sort _time
```

#### Check Access to Sensitive Authentication Files

```spl id="cs0341_sensitive_file_access"
index=main sourcetype="linux_logs" hostname="LinFDWebServer04" (path="/etc/passwd" OR path="/etc/shadow")
| table _time hostname user comm exe cmd addr success res path key
| sort _time
```

## Forensic Validation Required

The Linux / IR team should validate:

1. Whether account `webacc` is legitimate.
2. Whether account `admin` was newly created by the attacker.
3. Whether `/etc/passwd` was modified.
4. Whether `/etc/shadow` was modified.
5. Whether password hashes were accessed or copied.
6. Whether any new SSH keys were added.
7. Whether `/root/.ssh/authorized_keys` was modified.
8. Whether cron jobs or systemd services were created.
9. Whether suspicious binaries or scripts exist in `/tmp`.
10. Whether outbound connections were made after compromise.
11. Whether the attacker attempted privilege escalation.
12. Whether lateral movement occurred from this server.
13. Whether web application files were modified.
14. Whether AWS security groups or cloud metadata were accessed.

## Recommended Actions

1. Keep `LinFDWebServer04` isolated until forensic review is completed.
2. Block source IP `62.76.142.12` at firewall/security group level.
3. Reset all local account passwords on the affected host.
4. Reset credentials for accounts that accessed this server.
5. Disable or remove unauthorized `admin` account.
6. Validate whether `webacc` is authorized.
7. Review and restore `/etc/passwd` and `/etc/shadow` from a known-good backup if tampering is confirmed.
8. Check `/root/.ssh/authorized_keys` and all user SSH authorized keys.
9. Rotate SSH keys if exposure is suspected.
10. Review web server files for backdoors or web shells.
11. Review AWS cloud logs for related suspicious activity.
12. Rebuild the server from a clean image if integrity cannot be trusted.
13. Restrict SSH access to approved jump hosts or VPN only.
14. Disable password-based SSH authentication where possible.
15. Enable EDR and File Integrity Monitoring for Linux servers.
16. Monitor for further activity involving `62.76.142.12`, `webacc`, `admin`, `/etc/passwd`, and `/etc/shadow`.

## Escalation Decision

**Decision:** **Escalate to SOC L2 / Linux Team / Incident Response immediately.**

**Reason:** The event involved successful unauthorized SSH access, local account creation, and access to `/etc/passwd` and `/etc/shadow`. These are strong indicators of compromise and require deeper forensic investigation, containment, and system integrity validation.

Escalation is required for:

1. Server isolation.
2. Credential reset.
3. Account review.
4. Sensitive file integrity validation.
5. Post-compromise activity review.
6. Malware or persistence hunting.
7. Recovery or rebuild decision.

## Final Ticket Closure Comment

SOC investigated ticket **CS-080 — Unauthorized SSH Session Leading to User & Shadow File Tampering** for host `LinFDWebServer04 / 10.0.11.8`. Linux logs showed a successful unauthorized SSH session from source IP `62.76.142.12` using account `webacc`, followed by successful execution of `useradd admin`, access to `/etc/passwd`, and access to `/etc/shadow`. The source IP had **100% abuse confidence** and was associated with `mail.aesergeev.ru / qwarta.ru` in the Russian Federation. The sequence of successful SSH access, local account creation, and sensitive authentication file access confirms compromise. SOC recommended isolating `LinFDWebServer04`, blocking `62.76.142.12`, resetting credentials, removing unauthorized accounts, validating `/etc/passwd` and `/etc/shadow` integrity, reviewing post-compromise activity, and escalating to SOC L2 / Linux Team / Incident Response. Ticket closed as **True Positive — Confirmed Linux Server Compromise / Unauthorized SSH Access Successful / User and Shadow File Tampering Observed**.

## Skills Demonstrated

Linux log analysis, Splunk investigation, unauthorized SSH session triage, post-compromise activity analysis, account creation detection, `/etc/passwd` and `/etc/shadow` review, source IP reputation analysis, IOC extraction, MITRE ATT&CK mapping, containment planning, forensic validation planning, escalation decision-making, and SOC incident documentation.

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
