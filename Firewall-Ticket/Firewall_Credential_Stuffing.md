# SOC Analyst Investigation Report

## Ticket Overview

| Field                | Details                              |
| -------------------- | ------------------------------------ |
| Ticket ID            | CS-010                               |
| Alert Name           | Firewall: Credential Stuffing        |
| Ticket Status        | Not Provided                         |
| Initial Severity     | Low                                  |
| Recommended Severity | **High**                             |
| Analyst Decision     | **True Positive — Prevented by IPS** |

## Executive Summary

A firewall alert was triggered for **Credential Stuffing** involving inbound TCP/RDP traffic from external source IP **115.231.78.11** to internal destination **10.0.2.45 / WinITFileServer1** on port **3389**.

The firewall traffic log showed the session as **allowed** under rule **Allow_RDP**. However, correlated IPS logs identified a **Critical** RDP vulnerability signature and blocked the suspicious traffic. No successful RDP login, malware execution, host compromise, data access, or service impact was confirmed from the provided evidence.

## Alert Details

| Field            | Value                                                                                               |
| ---------------- | --------------------------------------------------------------------------------------------------- |
| Receive Time     | 2/12/2025 01:47                                                                                     |
| Source IP        | 115.231.78.11                                                                                       |
| Source Port      | 26149                                                                                               |
| Destination IP   | 10.0.2.45                                                                                           |
| Destination Port | 3389                                                                                                |
| Service          | RDP                                                                                                 |
| Protocol         | TCP                                                                                                 |
| Direction        | Inbound                                                                                             |
| Threat Name      | Credential Stuffing                                                                                 |
| Firewall Action  | Allowed                                                                                             |
| IPS Action       | Blocked                                                                                             |
| Firewall Rule    | Allow_RDP                                                                                           |
| Source Details   | Hangzhou Duchuang Keji Co.,Ltd; Data Center/Web Hosting/Transit; AS58461; hz.zj.cn; Hangzhou, China |

## Affected Assets

| Asset Field          | Details                                                  |
| -------------------- | -------------------------------------------------------- |
| Destination IP       | 10.0.2.45                                                |
| Hostname             | WinITFileServer1                                         |
| Operating System     | Windows Server 2019                                      |
| Asset Role           | File Server                                              |
| Business Criticality | Not Provided                                             |
| Exposure Concern     | External RDP/3389 traffic was allowed by firewall policy |

## Evidence Reviewed

| Evidence Source          | Observation                                                                                        |
| ------------------------ | -------------------------------------------------------------------------------------------------- |
| Firewall Logs            | Inbound RDP traffic from **115.231.78.11** to **10.0.2.45:3389**                                   |
| Firewall Rule            | **Allow_RDP** permitted the traffic flow                                                           |
| IPS Logs                 | Critical RDP vulnerability signature matched                                                       |
| IPS Signature            | RDP: Microsoft Windows Remote Desktop Protocol Server WebSocketServer Use/After/Free Vulnerability |
| IPS Action               | **Blocked**                                                                                        |
| Successful RDP Login     | Not Observed                                                                                       |
| Endpoint/EDR Evidence    | Not Provided                                                                                       |
| Host Compromise Evidence | Not Observed                                                                                       |
| Service Impact           | Not Provided                                                                                       |

## SIEM / Splunk Analysis

```spl id="n8r6va"
index=main sourcetype="firewall_logs" srcIP="115.231.78.11" dstIP="10.0.2.45" dstPort=3389
| table ReceiveTime, srcIP, dstIP, srcPort, dstPort, Threat_Name, Severity, Action, Direction
| sort - ReceiveTime
```

| ReceiveTime     | srcIP         | dstIP     | srcPort | dstPort | Threat_Name | Severity | Action  | Direction | Count |
| --------------- | ------------- | --------- | ------: | ------: | ----------- | -------- | ------- | --------- | ----: |
| 2/12/2025 01:47 | 115.231.78.11 | 10.0.2.45 |   26149 |    3389 | NA          | NA       | allowed | Inbound   |     1 |

```spl id="i7mtq4"
index=main sourcetype IN ("firewall_logs","ips_logs") srcIP="115.231.78.11" dstIP="10.0.2.45"
| eventstats count by srcIP dstIP Threat_Name Severity
| dedup sourcetype srcIP dstIP Threat_Name Severity
| table _time sourcetype srcIP dstIP Action Threat_Name Severity count
```

| Source        | Threat / Signature                               | Severity | Action  |
| ------------- | ------------------------------------------------ | -------- | ------- |
| IPS Logs      | RDP WebSocketServer Use/After/Free Vulnerability | Critical | Blocked |
| Firewall Logs | NA                                               | NA       | Allowed |

## MITRE ATT&CK Mapping

| Tactic            | Technique                       | ID        | Reason                                                                     |
| ----------------- | ------------------------------- | --------- | -------------------------------------------------------------------------- |
| Credential Access | Credential Stuffing             | T1110.004 | Firewall alert was categorized as credential stuffing against RDP          |
| Initial Access    | External Remote Services        | T1133     | External source attempted inbound access to RDP/3389                       |
| Lateral Movement  | Exploitation of Remote Services | T1210     | IPS detected exploit-like RDP vulnerability traffic; success not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Prevented by IPS**

The alert is valid because inbound RDP traffic from an external source reached an allowed firewall rule and then matched a **Critical** IPS signature. The IPS blocked the suspicious RDP exploit-related traffic, preventing confirmed delivery or execution.

This is not confirmed compromise. The main security gap is the **Allow_RDP** firewall rule allowing external RDP exposure.

## Impact Analysis

| Area            | Assessment                                                              |
| --------------- | ----------------------------------------------------------------------- |
| Confidentiality | No unauthorized access observed                                         |
| Integrity       | No code execution or modification confirmed                             |
| Availability    | No service disruption reported                                          |
| Business Impact | No confirmed impact; elevated concern due to exposed RDP on file server |
| Current Risk    | Reduced by IPS block, but firewall rule review is required              |

## Recommended Actions

1. Review and restrict firewall rule **Allow_RDP**.
2. Block inbound traffic from **115.231.78.11** to **10.0.2.45:3389**.
3. Restrict RDP access to approved VPN, jump server, or trusted admin IP ranges only.
4. Review Windows Security logs for Event IDs **4624**, **4625**, **4776**, and RDP event **1149** if available.
5. Validate whether **10.0.2.45** requires any internet-facing RDP access.
6. Continue monitoring for repeated activity from the same source IP.
7. Escalate only if successful login, endpoint alert, allowed exploit traffic, or service impact is later observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required at this time.**

**Reason:** Although the firewall allowed the RDP flow, the IPS blocked the critical suspicious traffic. No successful RDP login, endpoint compromise, malware execution, file access, or service impact was observed from the provided evidence.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0184 — Firewall: Credential Stuffing**. Inbound TCP/RDP traffic from **115.231.78.11** to **10.0.2.45 / WinITFileServer1** on port **3389** was allowed by firewall rule **Allow_RDP**, but correlated IPS logs detected a **Critical** RDP vulnerability signature and blocked the suspicious traffic. No successful RDP login, compromise, data access, or service impact was observed. Ticket can be closed as **True Positive — Prevented by IPS**, with firewall rule review required to restrict external RDP exposure.

## Skills Demonstrated

Firewall and IPS log correlation, RDP attack investigation, credential attack triage, severity reassessment, firewall rule review, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
