# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                              |
| ---------------- | ------------------------------------ |
| Ticket ID        | CS-019                               |
| Alert Name       | IPS: IOC Hits                        |
| Ticket Status    | Closed                               |
| Priority / SLA   | Low / Default SLA                    |
| Created Date     | 4/25/25 3:52 PM                      |
| Closed By        | Ananda Das                           |
| Analyst Decision | **True Positive — Prevented by IPS** |

## Executive Summary

An IPS alert was triggered for **IOC Hits** involving inbound VPN-related traffic from external source IP **194.0.234.35** to internal destination **10.0.2.12 / IvantiVPN01** on destination port **4500**.

Firewall logs showed the traffic as **allowed**, but IPS logs detected the source as an IOC match and **blocked** the activity. Splunk review confirmed **1 IPS-blocked event** and **1 firewall-allowed event** for the same source and destination.

No successful VPN authentication, host compromise, internal access, or service impact was confirmed from the provided evidence.

## Alert Details

| Field                | Value                                                                           |
| -------------------- | ------------------------------------------------------------------------------- |
| Receive Time         | 3/1/2025 10:22                                                                  |
| Source IP            | 194.0.234.35                                                                    |
| Destination IP       | 10.0.2.12                                                                       |
| Destination Port     | 4500                                                                            |
| Service              | VPN / IPsec NAT-Traversal                                                       |
| Protocol             | UDP / VPN-related traffic                                                       |
| Direction            | Inbound                                                                         |
| Threat Name          | IOC hits                                                                        |
| Initial Severity     | NA                                                                              |
| Splunk Severity      | High                                                                            |
| Recommended Severity | High                                                                            |
| Firewall Action      | Allowed                                                                         |
| IPS Action           | Blocked                                                                         |
| User                 | NA                                                                              |
| IPS Device           | IPS_01                                                                          |
| Source Reputation    | 100% abuse confidence                                                           |
| Source Details       | Audit Data; Data Center/Web Hosting/Transit; audit-data.info; Chisinau, Moldova |

## Affected Assets

| Asset Field          | Details                                                      |
| -------------------- | ------------------------------------------------------------ |
| Destination IP       | 10.0.2.12                                                    |
| Hostname             | IvantiVPN01                                                  |
| Operating System     | Windows Server 2022                                          |
| Platform             | Windows                                                      |
| Asset Role           | VPN Server                                                   |
| Asset Type           | VM                                                           |
| Business Criticality | Not Provided                                                 |
| Exposure Concern     | VPN service received inbound traffic from IOC-matched source |

## Evidence Reviewed

| Evidence Source          | Observation                                           |
| ------------------------ | ----------------------------------------------------- |
| IPS Alert                | IOC hit detected for **194.0.234.35 → 10.0.2.12**     |
| Firewall Logs            | Same inbound VPN-related traffic shown as **allowed** |
| IPS Logs                 | IOC-matched traffic shown as **blocked**              |
| Splunk Result            | **1 IPS-blocked** and **1 firewall-allowed** event    |
| Successful VPN Login     | Not Observed                                          |
| Host Compromise Evidence | Not Observed                                          |
| VPN Service Impact       | Not Provided                                          |
| Endpoint/EDR Evidence    | Not Provided                                          |

## SIEM / Splunk Analysis

```spl id="bmx81q"
index=main "194.0.234.35" "10.0.2.12"
| stats count by _time, sourcetype, Action, srcIP, dstIP, dstPort, Threat_Name, Severity
| sort - count
```

| _time               | sourcetype    | Action  | srcIP        | dstIP     | dstPort | Threat_Name | Severity | count |
| ------------------- | ------------- | ------- | ------------ | --------- | ------: | ----------- | -------- | ----: |
| 2025-03-01 10:22:00 | IPS_logs      | blocked | 194.0.234.35 | 10.0.2.12 |    4500 | IOC hits    | high     |     1 |
| 2025-03-01 10:22:00 | firewall_logs | allowed | 194.0.234.35 | 10.0.2.12 |    4500 | NA          | NA       |     1 |

**Analysis Note:** Firewall policy allowed the VPN-related flow, but IPS blocked it based on IOC detection. No successful VPN authentication is confirmed from the provided logs.

## MITRE ATT&CK Mapping

| Tactic         | Technique                | ID    | Reason                                                                                  |
| -------------- | ------------------------ | ----- | --------------------------------------------------------------------------------------- |
| Initial Access | External Remote Services | T1133 | IOC-matched external source contacted VPN remote access infrastructure                  |
| Reconnaissance | Active Scanning          | T1595 | External IOC source probed or contacted exposed VPN service; exploitation not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Prevented IOC-Matched Traffic**

The alert is valid because IPS detected traffic from a high-risk IOC source and blocked it. The destination was a VPN server, which is a sensitive remote access asset.

This is **not a confirmed compromise**. No successful VPN login, internal access, endpoint compromise, or service impact was observed.

## Impact Analysis

| Area            | Assessment                                                    |
| --------------- | ------------------------------------------------------------- |
| Confidentiality | No unauthorized access observed                               |
| Integrity       | No system modification confirmed                              |
| Availability    | No VPN service disruption reported                            |
| Business Impact | No confirmed impact; elevated concern due to VPN targeting    |
| Current Risk    | Reduced by IPS block, but firewall rule update is recommended |

## Recommended Actions

1. Block **194.0.234.35 → 10.0.2.12:4500/UDP** at the firewall.
2. Add **194.0.234.35** to a watchlist/blocklist as per policy.
3. Review firewall rules allowing inbound VPN traffic to **IvantiVPN01**.
4. Keep IPS IOC blocking enabled.
5. Confirm no successful VPN authentication occurred from this source IP.
6. Review VPN/firewall logs for any other activity from **194.0.234.35**.
7. Escalate only if successful VPN login, repeated attempts after blocking, VPN service impact, or additional compromise indicators are observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall rule update.**

**Reason:** IPS blocked the IOC-matched traffic, and no successful VPN authentication, host compromise, internal access, or service impact was confirmed from the reviewed evidence. Firewall rule review is required because the firewall initially allowed the inbound VPN-related traffic.

## Final Ticket Closure Comment

SOC investigated ticket **CS-019 — IPS: IOC Hits**. Inbound VPN-related traffic from **194.0.234.35** to **10.0.2.12 / IvantiVPN01** on destination port **4500** was allowed by firewall policy but blocked by IPS as an IOC hit. Splunk confirmed **1 IPS-blocked event** and **1 firewall-allowed event**. The source IP has **100% abuse confidence** and is associated with Audit Data infrastructure in Moldova. No successful VPN authentication, host compromise, or service impact was observed. Ticket closed as **True Positive — Prevented by IPS**, with firewall rule update and source IP block recommended.

## Skills Demonstrated

Firewall and IPS correlation, IOC hit investigation, VPN traffic analysis, source reputation review, remote access risk assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
