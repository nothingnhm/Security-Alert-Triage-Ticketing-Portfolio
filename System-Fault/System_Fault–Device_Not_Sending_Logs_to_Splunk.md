# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                  |
| ----------------- | ------------------------------------------------------------------------ |
| Ticket ID         | CS-0408                                                                  |
| Alert Name        | System Fault – Device Not Sending Logs to Splunk                         |
| Incident Category | System Fault / Log Forwarding Interruption                               |
| Ticket Status     | Closed                                                                   |
| Priority / SLA    | Normal / Default SLA                                                     |
| Department        | Support                                                                  |
| Created Date      | 9/15/25 7:37 PM                                                          |
| Closed By         | Ananda Das                                                               |
| Detection Source  | Automated Monitoring / Splunk                                            |
| Analyst Decision  | **True Positive — WAF Log Forwarding Interruption Confirmed / Resolved** |

## Executive Summary

A system fault alert was triggered because the security device **ImpWAF01** stopped sending logs to Splunk for more than **60 minutes**.

The affected device is a Web Application Firewall with IP address:

`10.0.2.10`

ImpWAF01 is a high-severity security device responsible for web application protection and visibility into application-layer attacks. Loss of WAF logs reduces SOC visibility into suspicious HTTP traffic, web exploitation attempts, blocked requests, policy violations, and attack trends.

SOC validated the alert in Splunk and confirmed that no new logs were received from **ImpWAF01** after the reported last log time:

`9/21/2025 18:54`

SOC also reviewed Splunk ingestion health and confirmed that Splunk infrastructure was functioning normally. Other WAF and security devices continued forwarding logs successfully, which confirmed that the issue was isolated to **ImpWAF01**.

The case was escalated to the **Security Engineering Team** for device-side validation. After the WAF logging/log-forwarding service was restarted and configuration was verified, SOC confirmed that logs resumed successfully in Splunk.

Final assessment: **Resolved system fault caused by temporary WAF log forwarding interruption on ImpWAF01. No malicious activity, Splunk platform issue, or network-wide outage was identified.**

## Alert Details

| Field             | Value                                                       |
| ----------------- | ----------------------------------------------------------- |
| Device Name       | ImpWAF01                                                    |
| Host IP           | 10.0.2.10                                                   |
| Device Type       | Security Device                                             |
| Server Function   | WAF                                                         |
| Splunk Index      | main                                                        |
| Asset Severity    | High                                                        |
| Custodian         | Security Engineering                                        |
| Last Log Time     | 9/21/2025 18:54                                             |
| Alert Condition   | Device did not send logs to Splunk for more than 60 minutes |
| Impacted Platform | Splunk                                                      |
| Initial Status    | No new logs observed                                        |
| Final Status      | Log forwarding restored                                     |

## Data Quality Note

The ticket create date is listed as **9/15/25 7:37 PM**, while the reported **LastLogTime** is **9/21/2025 18:54**. This timestamp order appears inconsistent and should be validated against the ticketing system, timezone settings, or alert generation source.

The investigation still treats the alert as valid because the alert condition states that **ImpWAF01 did not send logs to Splunk for more than 60 minutes**, and SOC validation confirmed missing logs for the device.

## Affected Asset

| Parameter         | Details                                                   |
| ----------------- | --------------------------------------------------------- |
| Asset Name        | ImpWAF01                                                  |
| IP Address        | 10.0.2.10                                                 |
| Asset Type        | Security Device                                           |
| Device Role       | Web Application Firewall                                  |
| Splunk Index      | main                                                      |
| Asset Severity    | High                                                      |
| Custodian / Owner | Security Engineering Team                                 |
| Affected Function | WAF log forwarding to Splunk                              |
| Security Impact   | Temporary WAF visibility gap                              |
| Business Impact   | Reduced monitoring visibility for web application traffic |

## Evidence Reviewed

### Alert Evidence

| Field               | Observed Value                    |
| ------------------- | --------------------------------- |
| Alert Type          | System Fault                      |
| Alert Reason        | Device not sending logs to Splunk |
| Detection Threshold | More than 60 minutes without logs |
| Affected Device     | ImpWAF01                          |
| Last Log Time       | 9/21/2025 18:54                   |
| Asset Severity      | High                              |
| Custodian           | Security Engineering              |

### Initial Splunk Validation Query

```spl id="cs0408_initial_validation"
index=main host=ImpWAF01
```

### Initial SOC Findings

| Check                               | Result                 |
| ----------------------------------- | ---------------------- |
| Recent logs from ImpWAF01           | Not observed initially |
| Last known log timestamp            | 9/21/2025 18:54        |
| Alert validity                      | Confirmed              |
| Delayed indexing evidence           | Not observed           |
| Other WAF/security device ingestion | Working                |
| Scope                               | Isolated to ImpWAF01   |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the automated monitoring alert and confirmed that the alert condition was related to missing logs from **ImpWAF01** for more than 60 minutes.

Because the affected device is a **WAF**, the alert was treated as important from a security monitoring perspective. Missing WAF logs can reduce visibility into web-based attacks such as SQL injection, XSS, directory traversal, brute force activity, malicious file uploads, and other application-layer threats.

#### 2. Asset Identification

| Field                 | Details                   |
| --------------------- | ------------------------- |
| Hostname              | ImpWAF01                  |
| IP Address            | 10.0.2.10                 |
| Device Classification | Security Device           |
| Device Role           | WAF                       |
| Splunk Index          | main                      |
| Custodian             | Security Engineering Team |
| Asset Severity        | High                      |

#### 3. Splunk Evidence Validation

SOC searched Splunk for logs from ImpWAF01:

```spl id="cs0408_host_search"
index=main host=ImpWAF01
```

The search confirmed that no new logs were received after the last reported log timestamp. This validated the alert as a genuine log forwarding interruption.

#### 4. Splunk Infrastructure Review

SOC reviewed whether the issue was related to Splunk ingestion or platform health.

| Component / Check          | Result             |
| -------------------------- | ------------------ |
| Splunk indexers            | Operational        |
| Splunk ingestion services  | Operational        |
| Splunk index `main`        | Available          |
| Port 9993                  | Open and listening |
| Other WAF logs             | Received normally  |
| Other security device logs | Received normally  |
| Delayed indexing           | Not observed       |
| Splunk-wide issue          | Not identified     |

#### 5. Network and Scope Validation

SOC reviewed whether the issue was caused by broader network connectivity failure.

| Check                               | Result                       |
| ----------------------------------- | ---------------------------- |
| Network outage                      | Not reported                 |
| Connectivity issue                  | Not identified               |
| Other devices in same security zone | Forwarding logs successfully |
| Splunk receiver reachability        | Available                    |
| Network-wide issue                  | Not identified               |
| Final scope                         | Isolated to ImpWAF01         |

The evidence showed that Splunk was healthy and other security devices were forwarding logs normally. Therefore, the issue was not caused by Splunk infrastructure or network-wide failure.

## Device-Level Investigation

SOC escalated the case to the **Security Engineering Team** and requested device-side validation for ImpWAF01.

The Security Engineering Team was asked to validate:

1. WAF logging service status.
2. Log forwarding/syslog service status.
3. Syslog or log-forwarding process availability.
4. Connectivity from ImpWAF01 to the Splunk receiver.
5. Recent WAF configuration changes.
6. Recent maintenance or restart activity.
7. WAF logging policy status.
8. Whether logging service restart was required.

## Corrective Action

The Security Engineering Team completed device-side remediation and confirmed the following actions:

1. Restarted the WAF logging/log-forwarding service.
2. Verified log forwarding configuration.
3. Confirmed connectivity to the Splunk receiver.
4. Requested SOC to validate log ingestion after remediation.

## Post-Remediation Verification

SOC rechecked Splunk after remediation using:

```spl id="cs0408_post_remediation"
index=main host=ImpWAF01
```

### Verification Outcome

| Check                         | Result    |
| ----------------------------- | --------- |
| Logs resumed                  | Confirmed |
| Continuous ingestion          | Confirmed |
| WAF visibility restored       | Confirmed |
| Security Engineering informed | Yes       |
| Ticket closure approved       | Yes       |

## Timeline of Events

| Time / Phase          | Event                                                             |
| --------------------- | ----------------------------------------------------------------- |
| 9/21/2025 18:54       | Last reported log timestamp for ImpWAF01                          |
| 9/15/2025 7:37 PM     | Ticket created for missing logs from ImpWAF01                     |
| Initial SOC Review    | SOC searched Splunk for ImpWAF01 logs                             |
| Initial SOC Review    | No logs observed after the reported LastLogTime                   |
| Infrastructure Review | Splunk ingestion and indexer health validated                     |
| Infrastructure Review | Port 9993 confirmed open and listening                            |
| Scope Validation      | Other WAF/security devices confirmed forwarding logs normally     |
| Escalation            | SOC escalated the issue to Security Engineering Team              |
| Remediation           | Security Engineering restarted WAF logging/log-forwarding service |
| Post-Remediation      | SOC confirmed logs resumed in Splunk                              |
| Closure               | Ticket closed after successful validation                         |

## Root Cause Analysis

| Area                  | Finding                                                          |
| --------------------- | ---------------------------------------------------------------- |
| Root Cause            | Temporary interruption of WAF log forwarding service on ImpWAF01 |
| Affected Component    | WAF logging / syslog forwarding service                          |
| Splunk Infrastructure | No issue identified                                              |
| Network-Wide Outage   | Not identified                                                   |
| Device Scope          | Isolated to ImpWAF01                                             |
| Permanent Data Loss   | Not confirmed from provided evidence                             |
| Final RCA             | Device-side WAF log forwarding interruption                      |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID  | Reason                                                                     |
| ------ | --------- | --- | -------------------------------------------------------------------------- |
| N/A    | N/A       | N/A | No malicious activity confirmed                                            |
| N/A    | N/A       | N/A | Incident was caused by system/log forwarding fault, not adversary behavior |

**MITRE Note:** No MITRE ATT&CK mapping is assigned because this was an operational logging fault, not an attack.

## Analyst Assessment

**Assessment:** **True Positive — WAF Device Not Sending Logs to Splunk**

The alert was valid. ImpWAF01 stopped sending logs to Splunk for more than 60 minutes, and SOC confirmed the log gap through direct Splunk validation.

The issue was not related to Splunk infrastructure because Splunk services were operational and other security devices continued forwarding logs. The issue was isolated to ImpWAF01 and required Security Engineering remediation.

No evidence of malicious activity, WAF compromise, unauthorized configuration change, Splunk infrastructure failure, or network-wide outage was identified from the provided evidence.

## Impact Analysis

| Impact Area             | Status                                                 |
| ----------------------- | ------------------------------------------------------ |
| WAF Log Forwarding      | Interrupted                                            |
| WAF Visibility          | Temporarily unavailable                                |
| Web Attack Monitoring   | Reduced during outage window                           |
| Security Event Tracking | Limited for ImpWAF01                                   |
| Threat Detection        | Reduced visibility for web application attacks         |
| Splunk Infrastructure   | No impact observed                                     |
| Other Security Devices  | No impact observed                                     |
| Network Availability    | No outage confirmed                                    |
| Data Integrity          | No permanent data loss confirmed                       |
| Business Impact         | Low to Medium                                          |
| Security Impact         | Temporary monitoring gap for a high-severity WAF asset |

## Recommended Actions

1. Monitor ImpWAF01 log ingestion for the next 24–48 hours.
2. Add ImpWAF01 to a WAF log ingestion health dashboard.
3. Maintain a Splunk alert for high-severity security devices not sending logs for more than 60 minutes.
4. Consider reducing alert threshold to 15–30 minutes for critical/high-severity security devices.
5. Review WAF logging service stability and restart history.
6. Validate log forwarding configuration persistence after appliance restart or maintenance.
7. Review recent WAF configuration changes or maintenance activity around the outage window.
8. Configure redundant log forwarding destination if supported.
9. Document WAF log forwarding restart and validation steps in the Security Engineering runbook.
10. Track repeated log gaps from ImpWAF01 as a reliability issue.

## Suggested Splunk Detection Query

```spl id="waf_log_gap_detection"
index=main host=ImpWAF01
| stats latest(_time) as last_seen by host
| eval minutes_since_last_log=round((now()-last_seen)/60,2)
| where minutes_since_last_log > 60
| convert ctime(last_seen)
```

## Escalation Decision

**Decision:** **Escalated to Security Engineering Team and resolved. No SOC L2 security escalation required.**

**Reason:** SOC confirmed that Splunk infrastructure and network connectivity were healthy. Since the issue was isolated to the WAF device logging/log-forwarding service, Security Engineering was the correct resolver group.

No SOC L2 escalation was required after log ingestion was restored and no compromise indicators were observed.

Escalate further only if:

1. ImpWAF01 stops forwarding logs again.
2. WAF log forwarding repeatedly fails.
3. Unauthorized WAF configuration changes are identified.
4. WAF connectivity becomes unstable.
5. Evidence of tampering or compromise appears.
6. Logs do not resume after Security Engineering remediation.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0408 — System Fault: Device Not Sending Logs to Splunk** after automated monitoring detected that **ImpWAF01** had not sent logs to Splunk for more than 60 minutes. The affected device was identified as a high-severity WAF with IP **10.0.2.10**, using Splunk index `main`, and owned by the **Security Engineering Team**. SOC validated the alert using `index=main host=ImpWAF01` and confirmed no new logs after the reported last log timestamp **9/21/2025 18:54**. Splunk indexers, ingestion services, and port **9993** were verified as operational. Other WAF/security devices continued forwarding logs successfully, confirming that the issue was isolated to ImpWAF01. The case was escalated to Security Engineering for WAF-side logging/syslog validation. Security Engineering restarted the WAF logging/log-forwarding service and verified the forwarding configuration. SOC revalidated Splunk ingestion and confirmed that logs resumed successfully. Ticket closed as **Resolved — Temporary WAF Log Forwarding Service Interruption**, with no evidence of Splunk infrastructure failure, network-wide outage, malicious activity, or confirmed permanent data loss.

## Skills Demonstrated

System fault triage, Splunk log validation, WAF log monitoring, security device log forwarding investigation, SIEM health validation, log gap analysis, infrastructure issue scoping, Security Engineering escalation, post-remediation verification, root cause analysis, impact assessment, evidence limitation handling, closure documentation, and SOC operational monitoring.

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
