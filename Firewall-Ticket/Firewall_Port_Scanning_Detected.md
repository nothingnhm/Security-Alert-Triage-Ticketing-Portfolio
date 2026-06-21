# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                            |
| ---------------- | -------------------------------------------------- |
| Ticket ID        | CS-0193                                            |
| Alert Name       | Firewall: Port Scanning Detected                   |
| Ticket Status    | Closed                                             |
| Ticket Priority  | High                                               |
| Alert Severity   | Medium                                             |
| SLA Plan         | Medium                                             |
| Created Date     | 3/2/25 7:45 PM                                     |
| Closed By        | ananda das                                         |
| Close Date       | 6/21/26 2:51 PM                                    |
| Analyst Decision | **True Positive — Blocked Port Scanning Activity** |

## Executive Summary

A firewall alert was generated for **Port Scanning Detected** involving inbound TCP traffic from external source IP **178.217.170.36** to internal destination IP **10.0.2.28**.

The firewall detected the activity as **Port Scanning detected** and blocked the traffic. Splunk analysis confirmed **4,820 blocked events** with **4,562 unique source ports**, indicating repeated inbound probing behavior. No successful connection, allowed traffic, host compromise, or service impact was observed from the provided evidence.

## Alert Details

| Field                            | Value                                                                           |
| -------------------------------- | ------------------------------------------------------------------------------- |
| Receive Time                     | 2/16/2025 08:55                                                                 |
| Source IP                        | 178.217.170.36                                                                  |
| Source Port                      | 18073                                                                           |
| Destination IP                   | 10.0.2.28                                                                       |
| Destination Port - Initial Event | 20                                                                              |
| Destination Port - Splunk Result | 3389                                                                            |
| Protocol                         | TCP                                                                             |
| Direction                        | Inbound                                                                         |
| Threat Name                      | Port Scanning detected                                                          |
| Severity                         | Medium                                                                          |
| Firewall Action                  | Blocked                                                                         |
| Source Details                   | KRENA - Kyrgyz Research and Education Network Association; krena.kg; Kyrgyzstan |

## Affected Assets

| Asset            | Details                                                      |
| ---------------- | ------------------------------------------------------------ |
| Destination IP   | 10.0.2.28                                                    |
| Hostname         | Not Provided                                                 |
| Operating System | Windows Server 2022                                          |
| Asset Role       | Exchange Server                                              |
| Exposure Concern | External probing observed against sensitive network services |

## Evidence Reviewed

| Evidence Source          | Observation                                                  |
| ------------------------ | ------------------------------------------------------------ |
| Ticket Screenshot        | Firewall alert for **Port Scanning detected**                |
| Firewall Logs            | Inbound TCP traffic from **178.217.170.36** to **10.0.2.28** |
| Firewall Action          | **Blocked**                                                  |
| Splunk Result            | **4,820 blocked events**                                     |
| Unique Source Ports      | **4,562**                                                    |
| Allowed Traffic          | Not Observed                                                 |
| Host Compromise Evidence | Not Observed                                                 |
| Endpoint/EDR Evidence    | Not Provided                                                 |
| Service Impact           | Not Provided                                                 |

## SIEM / Splunk Analysis

```spl
index=main sourcetype="firewall_logs" srcIP="178.217.170.36" dstIP="10.0.2.28" Threat_Name="Port Scanning detected"
| stats count as total_events dc(srcPort) as unique_srcPort_count by srcIP dstIP dstPort Threat_Name Action
```

| srcIP          | dstIP     | dstPort | Threat_Name            | Action  | total_events | unique_srcPort_count |
| -------------- | --------- | ------: | ---------------------- | ------- | -----------: | -------------------: |
| 178.217.170.36 | 10.0.2.28 |    3389 | Port Scanning detected | blocked |         4820 |                 4562 |

**Analysis Note:** The initial firewall event shows destination port **20**, while the Splunk aggregation shows destination port **3389/RDP**. This should be validated as a field-normalization or event-sampling difference. All reviewed events were blocked.

## MITRE ATT&CK Mapping

| Tactic         | Technique                 | ID        | Reason                                                              |
| -------------- | ------------------------- | --------- | ------------------------------------------------------------------- |
| Reconnaissance | Active Scanning           | T1595     | External source performed repeated inbound probing activity         |
| Reconnaissance | Scanning IP Blocks        | T1595.001 | Activity targeted an internal asset from an external network source |
| Discovery      | Network Service Discovery | T1046     | Port/service probing behavior was detected by the firewall          |

## Analyst Assessment

**Assessment:** **True Positive — Blocked Port Scanning Activity**

The alert is valid because firewall and Splunk evidence confirm repeated inbound scanning/probing activity from **178.217.170.36** toward **10.0.2.28**. The activity was blocked at the firewall, and no successful connection or compromise was confirmed.

This is assessed as a **blocked external reconnaissance attempt**, not a confirmed security breach.

## Impact Analysis

| Area            | Assessment                                                             |
| --------------- | ---------------------------------------------------------------------- |
| Confidentiality | No unauthorized data access observed                                   |
| Integrity       | No modification or exploitation observed                               |
| Availability    | No confirmed service disruption                                        |
| Business Impact | No confirmed impact; elevated concern due to Exchange Server targeting |
| Current Risk    | Reduced because firewall blocked all observed traffic                  |

## Recommended Actions

1. Validate the destination port mismatch between the initial alert and Splunk aggregation.
2. Continue monitoring for repeated activity from **178.217.170.36**.
3. Check whether the same source IP targeted other internal hosts or ports.
4. Confirm that external access to sensitive services such as **RDP/3389** is blocked unless explicitly approved.
5. Review Windows/Exchange logs if available for related authentication failures or service errors.
6. Consider perimeter blocklisting of the source IP if activity continues, following organizational policy.

## Escalation Decision

**Decision:** **No escalation required; ticket closed as blocked/no impact observed.**

**Reason:** The firewall blocked the observed inbound activity, Splunk confirmed the events were blocked, and no allowed traffic, successful connection, compromise, or service impact was identified from the provided evidence.

**Escalate if:** allowed traffic is observed, scanning volume increases, multiple internal hosts are targeted, RDP/Exchange services are externally exposed, or endpoint logs show suspicious activity.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0193 — Firewall: Port Scanning Detected**. Inbound TCP traffic from external source IP **178.217.170.36** to internal destination IP **10.0.2.28** was detected as **Port Scanning detected**. Splunk review confirmed **4,820 blocked events** with **4,562 unique source ports**. No allowed traffic, successful connection, host compromise, or service impact was observed in the provided evidence. Ticket closed as **True Positive — Blocked**, with continued monitoring recommended for recurrence or allowed traffic.

## Skills Demonstrated

Firewall alert triage, Splunk log analysis, port scanning investigation, reconnaissance detection, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
