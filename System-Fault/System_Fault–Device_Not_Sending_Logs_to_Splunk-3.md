# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                     |
| ----------------- | --------------------------------------------------------------------------- |
| Ticket ID         | CS-061                                                                     |
| Alert Name        | System Fault – Device Not Sending Logs to Splunk                            |
| Incident Category | System Fault / Log Forwarding Interruption                                  |
| Ticket Status     | Closed                                                                      |
| Priority / SLA    | Normal / Default SLA                                                        |
| Department        | Support                                                                     |
| Created Date      | 9/15/25 7:31 PM                                                             |
| Closed By         | Ananda Das                                                                  |
| Detection Source  | Automated Monitoring / Splunk                                               |
| Analyst Decision  | **True Positive — Switch Log Forwarding Interruption Confirmed / Resolved** |

## Executive Summary

A system fault alert was triggered because the network device **CiscoSwitch07** stopped forwarding logs to Splunk for more than **60 minutes**.

CiscoSwitch07 is a network switch with **Medium asset severity**. Logs from this device are important for monitoring network activity, switch events, configuration changes, operational issues, and possible security-related activity.

SOC validated the alert in Splunk and confirmed that no logs were received from CiscoSwitch07 after the reported last log time:

`9/19/2025 13:34`

SOC also reviewed Splunk ingestion health and confirmed that Splunk infrastructure was operational. Other network devices continued forwarding logs successfully, confirming that the issue was isolated to **CiscoSwitch07**.

The case was escalated to the **Network Team** for device-level validation. The Network Team revalidated the syslog/log forwarding configuration, restarted the logging service, and confirmed connectivity to the Splunk receiver. SOC then confirmed that logs resumed successfully in Splunk.

Final assessment: **Resolved system fault caused by temporary syslog/log forwarding disruption from CiscoSwitch07. No malicious activity, Splunk infrastructure failure, or network-wide outage was identified.**

## Alert Details

| Field             | Value                                                       |
| ----------------- | ----------------------------------------------------------- |
| Device Name       | CiscoSwitch07                                               |
| Host IP           | 192.168.1.7                                                 |
| Device Type       | Network                                                     |
| Server Function   | Switch                                                      |
| Splunk Index      | main                                                        |
| Asset Severity    | Medium                                                      |
| Custodian         | Network Team                                                |
| Last Log Time     | 9/19/2025 13:34                                             |
| Alert Condition   | Device did not send logs to Splunk for more than 60 minutes |
| Impacted Platform | Splunk                                                      |
| Initial Status    | No new logs observed                                        |
| Final Status      | Log forwarding restored                                     |

## Data Quality Note

The ticket create date is listed as **9/15/25 7:31 PM**, while the reported **LastLogTime** is **9/19/2025 13:34**. This timestamp order appears inconsistent and should be validated against the ticketing platform, timezone settings, or alert generation source.

The investigation still treats the alert as valid because the alert condition stated that **CiscoSwitch07 did not send logs to Splunk for more than 60 minutes**, and SOC validation confirmed missing logs for the device.

## Affected Asset

| Parameter         | Details                                         |
| ----------------- | ----------------------------------------------- |
| Asset Name        | CiscoSwitch07                                   |
| IP Address        | 192.168.1.7                                     |
| Asset Type        | Network Device                                  |
| Device Role       | Switch                                          |
| Splunk Index      | main                                            |
| Asset Severity    | Medium                                          |
| Custodian / Owner | Network Team                                    |
| Affected Function | Syslog/log forwarding to Splunk                 |
| Monitoring Impact | Temporary switch visibility gap                 |
| Business Impact   | Reduced monitoring visibility for switch events |

## IOCs / Technical Indicators Identified

| Indicator Type      | Indicator / Value                          |
| ------------------- | ------------------------------------------ |
| Affected Device     | CiscoSwitch07                              |
| Affected IP Address | 192.168.1.7                                |
| Device Type         | Network Device                             |
| Device Function     | Switch                                     |
| Splunk Index        | main                                       |
| Log Destination     | Splunk                                     |
| Log Source Type     | Syslog / Network Device Logs               |
| Asset Severity      | Medium                                     |
| Responsible Team    | Network Team                               |
| Root Cause Type     | Temporary syslog/log forwarding disruption |

**IOC Assessment:** This was a system fault incident, not a malicious IOC-based security incident. The indicators above represent the affected asset, logging path, and monitoring components.

## Evidence Reviewed

### Alert Evidence

| Field               | Observed Value                    |
| ------------------- | --------------------------------- |
| Alert Type          | System Fault                      |
| Alert Reason        | Device not sending logs to Splunk |
| Detection Threshold | More than 60 minutes without logs |
| Affected Device     | CiscoSwitch07                     |
| Last Log Time       | 9/19/2025 13:34                   |
| Asset Severity      | Medium                            |
| Custodian           | Network Team                      |

### Initial Splunk Validation Query

```spl id="cs0406_initial_validation"
index=main host=CiscoSwitch07
```

### Initial SOC Findings

| Check                          | Result                    |
| ------------------------------ | ------------------------- |
| Recent logs from CiscoSwitch07 | Not observed initially    |
| Last known log timestamp       | 9/19/2025 13:34           |
| Alert validity                 | Confirmed                 |
| Delayed indexing evidence      | Not observed              |
| Other network device ingestion | Working                   |
| Scope                          | Isolated to CiscoSwitch07 |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the automated monitoring alert and confirmed that the alert condition was related to missing logs from **CiscoSwitch07** for more than 60 minutes.

Because the affected asset is a network switch, the alert was important from an operational monitoring and visibility perspective. Switch logs can help identify interface issues, device events, configuration changes, network instability, and possible suspicious activity.

#### 2. Asset Identification

| Field                 | Details       |
| --------------------- | ------------- |
| Hostname              | CiscoSwitch07 |
| IP Address            | 192.168.1.7   |
| Device Classification | Network       |
| Device Role           | Switch        |
| Splunk Index          | main          |
| Custodian             | Network Team  |
| Asset Severity        | Medium        |

#### 3. Splunk Evidence Validation

SOC searched Splunk for logs from CiscoSwitch07:

```spl id="cs0406_host_search"
index=main host=CiscoSwitch07
```

The search confirmed that no new logs were received after the reported LastLogTime. This validated the alert as a genuine log forwarding interruption.

#### 4. Splunk Infrastructure Review

SOC reviewed whether the issue was related to Splunk ingestion or platform health.

| Component / Check                    | Result             |
| ------------------------------------ | ------------------ |
| Splunk indexer status                | Operational        |
| Splunk ingestion services            | Operational        |
| Splunk index `main`                  | Available          |
| Port 9993                            | Open and listening |
| Other network device logs            | Received normally  |
| Splunk server issue                  | Not identified     |
| Central logging infrastructure issue | Not identified     |

#### 5. Network and Scope Validation

SOC reviewed whether the issue was caused by a wider connectivity problem.

| Check                                         | Result                    |
| --------------------------------------------- | ------------------------- |
| Network-wide outage                           | Not reported              |
| Connectivity between Splunk and other devices | Normal                    |
| Other network devices                         | Sending logs successfully |
| Splunk receiver reachability                  | Available                 |
| Network-wide failure                          | Not identified            |
| Final scope                                   | Isolated to CiscoSwitch07 |

The evidence showed that Splunk was healthy and other network devices were forwarding logs normally. Therefore, the issue was not caused by Splunk infrastructure or a network-wide outage.

## Device-Level Investigation

SOC escalated the case to the **Network Team** and requested device-level validation for CiscoSwitch07.

The Network Team was asked to validate:

1. Syslog configuration on CiscoSwitch07.
2. Syslog/log forwarding service status.
3. Logging destination configuration.
4. Connectivity from CiscoSwitch07 to the Splunk receiver.
5. Temporary network disruption.
6. Recent configuration changes.
7. Recent maintenance activity.
8. Whether a logging/syslog service restart was required.

## Corrective Action

The Network Team completed device-side remediation and confirmed the following actions:

1. Revalidated the syslog/log forwarding configuration on CiscoSwitch07.
2. Restarted the logging/syslog service on the switch.
3. Confirmed connectivity to the Splunk receiver.
4. Requested SOC to recheck log ingestion.

## Post-Remediation Verification

SOC revalidated logs in Splunk using:

```spl id="cs0406_post_remediation"
index=main host=CiscoSwitch07
```

### Verification Outcome

| Check                                  | Result    |
| -------------------------------------- | --------- |
| Logs resumed                           | Confirmed |
| Continuous ingestion                   | Confirmed |
| Network monitoring visibility restored | Confirmed |
| Network Team informed                  | Yes       |
| Ticket closure approved                | Yes       |

## Timeline of Events

| Time / Phase          | Event                                                        |
| --------------------- | ------------------------------------------------------------ |
| 9/19/2025 13:34       | Last reported log timestamp for CiscoSwitch07                |
| 9/15/2025 19:31       | Ticket created for missing logs from CiscoSwitch07           |
| Initial SOC Review    | SOC searched Splunk for CiscoSwitch07 logs                   |
| Initial SOC Review    | No logs observed after the reported LastLogTime              |
| Infrastructure Review | Splunk indexer and ingestion health validated                |
| Infrastructure Review | Port 9993 confirmed open and listening                       |
| Scope Validation      | Other network devices confirmed forwarding logs normally     |
| Escalation            | SOC escalated the issue to Network Team                      |
| Remediation           | Network Team revalidated syslog/log forwarding configuration |
| Remediation           | Network Team restarted logging/syslog service on the switch  |
| Post-Remediation      | SOC confirmed logs resumed in Splunk                         |
| Closure               | Ticket closed after successful validation                    |

## Root Cause Analysis

| Area                           | Finding                                                          |
| ------------------------------ | ---------------------------------------------------------------- |
| Root Cause                     | Temporary disruption in syslog/log forwarding from CiscoSwitch07 |
| Affected Component             | Switch syslog/log forwarding service                             |
| Splunk Infrastructure          | No issue identified                                              |
| Central Logging Infrastructure | No issue identified                                              |
| Network-Wide Outage            | Not identified                                                   |
| Device Scope                   | Isolated to CiscoSwitch07                                        |
| Permanent Data Loss            | Not confirmed from provided evidence                             |
| Final RCA                      | Device-side switch log forwarding disruption                     |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID  | Reason                                                                     |
| ------ | --------- | --- | -------------------------------------------------------------------------- |
| N/A    | N/A       | N/A | No malicious activity confirmed                                            |
| N/A    | N/A       | N/A | Incident was caused by system/log forwarding fault, not adversary behavior |

**MITRE Note:** No MITRE ATT&CK mapping is assigned because this was an operational logging fault, not an attack.

## Analyst Assessment

**Assessment:** **True Positive — Switch Device Not Sending Logs to Splunk**

The alert was valid. CiscoSwitch07 stopped sending logs to Splunk for more than 60 minutes, and SOC confirmed the log gap through direct Splunk validation.

The issue was not related to Splunk infrastructure because Splunk services were operational and other network devices continued forwarding logs. The issue was isolated to CiscoSwitch07 and required Network Team remediation.

No evidence of malicious activity, switch compromise, unauthorized configuration change, Splunk infrastructure failure, or network-wide outage was identified from the provided evidence.

## Impact Analysis

| Impact Area                     | Status                                |
| ------------------------------- | ------------------------------------- |
| Switch Log Forwarding           | Interrupted                           |
| Network Monitoring              | Temporarily reduced                   |
| Security Monitoring             | Limited for CiscoSwitch07 events      |
| Configuration Change Visibility | Temporarily reduced                   |
| Operational Troubleshooting     | Temporarily impacted for this device  |
| Splunk Infrastructure           | No impact observed                    |
| Other Network Devices           | No impact observed                    |
| Network Availability            | No outage confirmed                   |
| Data Integrity                  | No permanent data loss confirmed      |
| Business Impact                 | Low                                   |
| Security Impact                 | Moderate due to medium asset severity |

## Recommended Actions

1. Monitor CiscoSwitch07 log ingestion for the next 24–48 hours.
2. Add CiscoSwitch07 to a network device log ingestion health dashboard.
3. Maintain missing-log alerts for medium and higher severity network devices.
4. Review device CPU, memory, and disk utilization around the outage window.
5. Validate syslog configuration persistence after restart or maintenance.
6. Review recent configuration changes on CiscoSwitch07.
7. Document switch logging restart and validation steps in the Network Team runbook.
8. Perform periodic log source health checks for routers and switches.
9. Consider redundant log forwarding destinations if supported.
10. Track repeated log gaps from CiscoSwitch07 as a device reliability issue.

## Suggested Splunk Detection Query

```spl id="switch_log_gap_detection"
index=main host=CiscoSwitch07
| stats latest(_time) as last_seen by host
| eval minutes_since_last_log=round((now()-last_seen)/60,2)
| where minutes_since_last_log > 60
| convert ctime(last_seen)
```

## Escalation Decision

**Decision:** **Escalated to Network Team and resolved. No SOC L2 security escalation required.**

**Reason:** SOC confirmed that Splunk infrastructure and general network connectivity were healthy. Since the issue was isolated to the switch syslog/log forwarding service, the Network Team was the correct resolver group.

No SOC L2 escalation was required after log ingestion was restored and no compromise indicators were observed.

Escalate further only if:

1. CiscoSwitch07 stops forwarding logs again.
2. Switch log forwarding repeatedly fails.
3. Unauthorized switch configuration changes are identified.
4. Switch connectivity becomes unstable.
5. Evidence of tampering or compromise appears.
6. Logs do not resume after Network Team remediation.

## Final Ticket Closure Comment

SOC investigated ticket **CS-061 — System Fault: Device Not Sending Logs to Splunk** after automated monitoring detected that **CiscoSwitch07** had not sent logs to Splunk for more than 60 minutes. The affected device was identified as a medium-severity network switch with IP **192.168.1.7**, using Splunk index `main`, and owned by the **Network Team**. SOC validated the alert using `index=main host=CiscoSwitch07` and confirmed no new logs after the reported last log timestamp **9/19/2025 13:34**. Splunk indexer and ingestion services were verified as operational, port **9993** was open and listening, and other network devices continued forwarding logs successfully. The issue was confirmed as isolated to CiscoSwitch07 and escalated to the Network Team for switch-side syslog/log forwarding validation. The Network Team revalidated the configuration, restarted the logging/syslog service, and confirmed connectivity to the Splunk receiver. SOC rechecked Splunk and confirmed that logs resumed successfully. Ticket closed as **Resolved — Temporary Switch Syslog/Log Forwarding Disruption**, with no evidence of Splunk infrastructure failure, network-wide outage, malicious activity, or confirmed permanent data loss.

## Skills Demonstrated

System fault triage, Splunk log validation, network switch log monitoring, syslog/log forwarding investigation, SIEM health validation, log gap analysis, infrastructure issue scoping, Network Team escalation, post-remediation verification, root cause analysis, impact assessment, evidence limitation handling, closure documentation, and SOC operational monitoring.

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
