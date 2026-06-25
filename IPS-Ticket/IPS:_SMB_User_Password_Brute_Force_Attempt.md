# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                    |
| ---------------- | ------------------------------------------ |
| Ticket ID        | CS-017                                     |
| Alert Name       | IPS: SMB User Password Brute Force Attempt |
| Ticket Status    | Closed                                     |
| Priority / SLA   | High / Default SLA                         |
| Department       | IT / Cyber Security Department             |
| Created Date     | 4/25/25 3:52 PM                            |
| Closed By        | Ananda das                                 |
| Analyst Decision | **True Positive — Prevented by IPS**       |

## Executive Summary

An IPS alert was triggered for **SMB User Password Brute Force Attempt** involving inbound SMB traffic from external source IP **45.229.19.137** to internal destination **10.0.14.29 / WinHRFileServer1** on **445/TCP**.

Firewall logs showed the SMB traffic as **allowed**, but IPS logs detected the brute-force activity and **blocked** it. Splunk review confirmed **27 IPS-blocked events** and **27 firewall-allowed events** for the same source, destination, and SMB port. No successful SMB authentication, account compromise, file access, host compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field             | Value                                                          |
| ----------------- | -------------------------------------------------------------- |
| Receive Time      | 2/11/2025 19:10                                                |
| Source IP         | 45.229.19.137                                                  |
| Destination IP    | 10.0.14.29                                                     |
| Destination Port  | 445                                                            |
| Service           | SMB / Windows File Sharing                                     |
| Protocol          | TCP                                                            |
| Direction         | Inbound                                                        |
| Threat Name       | SMB User Password Brute Force Attempt                          |
| Severity          | Medium                                                         |
| Firewall Action   | Allowed                                                        |
| IPS Action        | Blocked                                                        |
| Targeted User     | clara.deb                                                      |
| IPS Device        | IPS_01                                                         |
| Source Reputation | 100% abuse confidence                                          |
| Source Details    | TURBONET S.A.; AS271967; maxitel.ec; Vinces, Los Rios, Ecuador |

## Affected Assets

| Asset Field          | Details                                                        |
| -------------------- | -------------------------------------------------------------- |
| Destination IP       | 10.0.14.29                                                     |
| Hostname             | WinHRFileServer1                                               |
| Operating System     | Windows Server 2019                                            |
| Platform             | Windows                                                        |
| Asset Role           | File Server                                                    |
| Asset Type           | VM                                                             |
| Business Criticality | Not Provided                                                   |
| Exposure Concern     | External inbound SMB traffic was allowed before IPS inspection |

## Evidence Reviewed

| Evidence Source       | Observation                                                 |
| --------------------- | ----------------------------------------------------------- |
| IPS Alert             | SMB brute-force attempt detected against user **clara.deb** |
| Firewall Logs         | Same inbound SMB traffic shown as **allowed**               |
| IPS Logs              | SMB brute-force activity shown as **blocked**               |
| Splunk Result         | **27 IPS-blocked** and **27 firewall-allowed** events       |
| Successful SMB Login  | Not Observed                                                |
| Account Compromise    | Not Observed                                                |
| File Access Evidence  | Not Observed                                                |
| Endpoint/EDR Evidence | Not Provided                                                |
| Service Impact        | Not Provided                                                |

## SIEM / Splunk Analysis

```spl id="x9m4ka"
index=main srcIP="45.229.19.137" dstIP="10.0.14.29"
| stats count by sourcetype, srcIP, dstIP, dstPort, Threat_Name, Severity, Action, Protocol, Direction
| sort - count
```

| sourcetype    | srcIP         | dstIP      | dstPort | Threat_Name                           | Severity | Action  | Protocol | Direction | Count |
| ------------- | ------------- | ---------- | ------: | ------------------------------------- | -------- | ------- | -------- | --------- | ----: |
| IPS_logs      | 45.229.19.137 | 10.0.14.29 |     445 | SMB User Password Brute Force Attempt | medium   | blocked | tcp      | Inbound   |    27 |
| firewall_logs | 45.229.19.137 | 10.0.14.29 |     445 | NA                                    | NA       | allowed | tcp      | Inbound   |    27 |

**Analysis Note:** Firewall policy allowed the SMB flow, but IPS inspection blocked the suspicious brute-force behavior. No successful authentication is confirmed from the provided logs.

## MITRE ATT&CK Mapping

| Tactic            | Technique                                 | ID        | Reason                                                          |
| ----------------- | ----------------------------------------- | --------- | --------------------------------------------------------------- |
| Credential Access | Brute Force                               | T1110     | IPS detected SMB password brute-force activity                  |
| Credential Access | Password Guessing                         | T1110.001 | Targeted user **clara.deb** was observed; success not confirmed |
| Lateral Movement  | Remote Services: SMB/Windows Admin Shares | T1021.002 | SMB/445 was targeted; authenticated access not confirmed        |

## Analyst Assessment

**Assessment:** **True Positive — Prevented SMB Brute-Force Attempt**

The alert is valid because IPS detected and blocked repeated SMB password brute-force activity from a high-risk external source. The target was a Windows file server, and the username **clara.deb** was observed in the alert.

This is **not a confirmed compromise**. No successful SMB login, account misuse, file access, or endpoint impact was observed.

## Impact Analysis

| Area            | Assessment                                                                 |
| --------------- | -------------------------------------------------------------------------- |
| Confidentiality | No unauthorized file access observed                                       |
| Integrity       | No file modification or system change confirmed                            |
| Availability    | No service disruption reported                                             |
| Business Impact | No confirmed impact; elevated concern due to file server and SMB targeting |
| Current Risk    | Reduced by IPS block, but firewall rule update is required                 |

## Recommended Actions

1. Block **45.229.19.137 → 10.0.14.29:445/TCP** at the firewall.
2. Add **45.229.19.137** to a watchlist/blocklist as per policy.
3. Review and restrict any firewall rule allowing inbound SMB to **10.0.14.29**.
4. Deny direct internet-to-SMB access unless explicitly approved.
5. Keep IPS prevention enabled for SMB brute-force detection.
6. Review Windows Security logs for **4625**, **4624**, **4776**, and **4740** if required.
7. Escalate only if successful SMB authentication, account lockout, endpoint alert, repeated attempts after blocking, or service impact is observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall rule update.**

**Reason:** IPS blocked the SMB brute-force activity, and no successful authentication, account compromise, file access, host compromise, or service impact was confirmed from the reviewed evidence. Firewall rule review is required because the firewall initially allowed inbound SMB traffic.

## Final Ticket Closure Comment

SOC investigated ticket **CS-017 — IPS: SMB User Password Brute Force Attempt**. Inbound SMB traffic from **45.229.19.137** to **10.0.14.29 / WinHRFileServer1** on **445/TCP** was allowed by firewall policy but blocked by IPS as SMB password brute-force activity. Splunk confirmed **27 IPS-blocked events** and **27 firewall-allowed events**. The targeted user was **clara.deb**. No successful SMB authentication, account compromise, file access, host compromise, or service impact was observed. Ticket closed as **True Positive — Prevented by IPS**, with firewall rule update and source IP block recommended.

## Skills Demonstrated

Firewall and IPS correlation, SMB brute-force investigation, Windows file server risk assessment, source reputation review, authentication evidence validation, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
