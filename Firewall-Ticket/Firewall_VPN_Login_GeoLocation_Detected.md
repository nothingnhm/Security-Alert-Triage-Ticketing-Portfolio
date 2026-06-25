# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                   |
| ---------------- | ----------------------------------------- |
| Ticket ID        | CS-0291                                   |
| Alert Name       | IPS: SSH Connection from Unusual Location |
| Ticket Status    | Closed                                    |
| Priority / SLA   | Normal / Critical                         |
| Created Date     | 4/25/25 3:52 PM                           |
| Closed By        | ananda das                                |
| Analyst Decision | **True Positive — Prevented by IPS**      |

## Executive Summary

An IPS alert was triggered for **SSH Connection from Unusual Location** involving inbound SSH traffic from external source IP **210.209.137.144** to internal destination **10.0.11.11 / LinFDWebServer07**.

Firewall logs show the SSH flow on **22/TCP** was **allowed**, but IPS logs detected the activity as **SSH Connection from Unusual Location** and **blocked** it. The source IP has **100% abuse confidence** and is associated with **VEE TIME CORP.** in Taiwan.

No successful SSH login, command execution, compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field             | Value                                                 |
| ----------------- | ----------------------------------------------------- |
| Receive Time      | 4/22/2025 19:31                                       |
| Source IP         | 210.209.137.144                                       |
| Destination IP    | 10.0.11.11                                            |
| Destination Port  | 22                                                    |
| Service           | SSH                                                   |
| Protocol          | TCP                                                   |
| Direction         | Inbound                                               |
| Threat Name       | SSH Connection from Unusual Location                  |
| Severity          | Critical in alert / High in IPS aggregation           |
| Firewall Action   | Allowed                                               |
| IPS Action        | Blocked                                               |
| User              | admin                                                 |
| IPS Device        | IPS_01                                                |
| Source Reputation | 100% abuse confidence                                 |
| Source Details    | VEE TIME CORP.; AS17809; vee.com.tw; Taichung, Taiwan |

## Affected Assets

| Asset Field          | Details          |
| -------------------- | ---------------- |
| Destination IP       | 10.0.11.11       |
| Hostname             | LinFDWebServer07 |
| Operating System     | Linux - RHEL 8   |
| Platform             | Linux            |
| Asset Role           | Web Server       |
| Hosting              | AWS Cloud        |
| Business Criticality | Not Provided     |

## Evidence Reviewed

| Evidence Source      | Observation                                                                 |
| -------------------- | --------------------------------------------------------------------------- |
| IPS Alert            | SSH unusual-location activity detected for **210.209.137.144 → 10.0.11.11** |
| Firewall Logs        | SSH traffic on **22/TCP** was **Allowed**                                   |
| IPS Logs             | SSH unusual-location activity was **Blocked**                               |
| Additional Traffic   | **5 allowed 443/TCP web traffic events** observed                           |
| Successful SSH Login | Not Observed                                                                |
| Command Execution    | Not Observed                                                                |
| Host Compromise      | Not Observed                                                                |
| Service Impact       | Not Provided                                                                |

## SIEM / Splunk Analysis

```spl id="yzt23p"
index=main (sourcetype="firewall_logs" OR sourcetype="IPS_logs") srcIP="210.209.137.144" dstIP="10.0.11.11"
| stats count by sourcetype, srcIP, dstIP, dstPort, Threat_Name, Severity, Action, Protocol, Direction
| sort - count
```

| sourcetype    | srcIP           | dstIP      | dstPort | Threat_Name                          | Severity | Action  | Protocol | Direction | Count |
| ------------- | --------------- | ---------- | ------: | ------------------------------------ | -------- | ------- | -------- | --------- | ----: |
| IPS_logs      | 210.209.137.144 | 10.0.11.11 |     443 | Web Traffic                          | NA       | allowed | tcp      | Inbound   |     5 |
| firewall_logs | 210.209.137.144 | 10.0.11.11 |     443 | NA                                   | NA       | Allowed | tcp      | Inbound   |     5 |
| IPS_logs      | 210.209.137.144 | 10.0.11.11 |      22 | SSH Connection from Unusual Location | high     | blocked | tcp      | Inbound   |     1 |
| firewall_logs | 210.209.137.144 | 10.0.11.11 |      22 | NA                                   | NA       | Allowed | tcp      | Inbound   |     1 |

**Analysis Note:** Firewall policy allowed the SSH connection attempt, but IPS inspection blocked the suspicious SSH activity. Allowed **443/TCP** traffic may be expected for a web server, but should be monitored due to the source reputation.

## MITRE ATT&CK Mapping

| Tactic            | Technique                | ID        | Reason                                                                   |
| ----------------- | ------------------------ | --------- | ------------------------------------------------------------------------ |
| Initial Access    | External Remote Services | T1133     | External source attempted SSH access to a cloud-hosted Linux server      |
| Lateral Movement  | Remote Services: SSH     | T1021.004 | SSH service was targeted; successful authentication not confirmed        |
| Credential Access | Valid Accounts           | T1078     | Username **admin** was observed; successful account use is not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Prevented by IPS**

The alert is valid because IPS detected and blocked SSH access from an unusual high-risk external source. The activity targeted the **admin** user on a Linux web server. No evidence confirms successful authentication, shell access, command execution, persistence, or compromise.

The main security gap is that firewall policy allowed inbound SSH before IPS enforcement.

## Impact Analysis

| Area            | Assessment                                             |
| --------------- | ------------------------------------------------------ |
| Confidentiality | No unauthorized access observed                        |
| Integrity       | No command execution or modification confirmed         |
| Availability    | No service disruption reported                         |
| Business Impact | No confirmed impact; elevated risk due to SSH exposure |
| Current Risk    | Reduced by IPS block; firewall rule update required    |

## Recommended Actions

1. Block **210.209.137.144 → 10.0.11.11:22/TCP** at the firewall.
2. Add **210.209.137.144** to a watchlist/blocklist as per policy.
3. Restrict SSH access to approved VPN, bastion host, jump server, or trusted admin IPs only.
4. Review Linux SSH logs on **LinFDWebServer07** around **4/22/2025 19:31**.
5. Validate whether direct SSH login for user **admin** is allowed; disable if not required.
6. Monitor allowed **443/TCP** traffic from the same source for suspicious web requests.
7. Escalate only if successful SSH login, suspicious commands, endpoint alerts, repeated attempts, or service impact are observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall rule update.**

**Reason:** IPS blocked the suspicious SSH attempt and no successful login, host compromise, command execution, or service impact was observed from the reviewed evidence. Firewall rule update and source IP blocking are required because the firewall initially allowed the SSH flow.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0291 — IPS: SSH Connection from Unusual Location**. Inbound SSH traffic from **210.209.137.144** to **10.0.11.11 / LinFDWebServer07** on **22/TCP** was allowed by firewall policy but blocked by **IPS_01**. The source IP has **100% abuse confidence** and is associated with VEE TIME CORP. in Taiwan. No successful SSH login, command execution, compromise, or service impact was observed. Ticket closed as **True Positive — Prevented by IPS**, with firewall rule update and source IP block recommended.

## Skills Demonstrated

Firewall and IPS correlation, SSH investigation, unusual-location alert triage, Linux web server risk assessment, source reputation review, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.


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
