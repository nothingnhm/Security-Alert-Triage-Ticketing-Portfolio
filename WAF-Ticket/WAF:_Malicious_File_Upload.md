# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                 |
| ---------------- | ------------------------------------------------------- |
| Ticket ID        | CS-028                                                  |
| Alert Name       | WAF: Malicious File Upload                              |
| Ticket Status    | Closed                                                  |
| Priority / SLA   | High / Default SLA                                      |
| Created Date     | 3/2/25 7:45 PM                                          |
| Closed By        | ananda das                                              |
| Analyst Decision | **Needs Escalation — Potential Successful File Upload** |

## Executive Summary

A WAF alert was triggered for **Malicious File Upload** involving inbound HTTPS traffic from external source IP **48.207.20.146** to internal web server **10.0.11.10 / LinFDWebServer06** on **443/TCP**.

The request targeted **finance.abc.com/admin** using HTTP method **PUT** with the matched string `PUT /uploads/shell.php`. The WAF was in **Monitoring** mode, the action was **Allowed**, and the response code was **200**. This means the upload request may have been processed successfully by the application.

No confirmed execution, web shell access, outbound callback, malware activity, or host compromise was proven from the provided WAF log alone. However, because the suspected file name is **shell.php**, this ticket should be treated as a potential web shell upload until server-side validation is completed.

## Alert Details

| Field            | Value                                                                                             |
| ---------------- | ------------------------------------------------------------------------------------------------- |
| Receive Time     | 2/16/2025 23:38                                                                                   |
| Source IP        | 48.207.20.146                                                                                     |
| Source Port      | 41769                                                                                             |
| Destination IP   | 10.0.11.10                                                                                        |
| Destination Port | 443                                                                                               |
| Site Name        | finance.abc.com                                                                                   |
| URL              | /admin                                                                                            |
| HTTP Method      | PUT                                                                                               |
| Threat Name      | Malicious File Upload                                                                             |
| Severity         | Critical                                                                                          |
| Matched String   | `PUT /uploads/shell.php`                                                                          |
| WAF Action       | Allowed                                                                                           |
| WAF Mode         | Monitoring                                                                                        |
| Response Code    | 200                                                                                               |
| Source Details   | Microsoft Limited; Data Center/Web Hosting/Transit; AS8075; microsoft.com; Amsterdam, Netherlands |
| Abuse Confidence | 0%                                                                                                |

## Affected Assets

| Asset Field          | Details                                                                 |
| -------------------- | ----------------------------------------------------------------------- |
| Destination IP       | 10.0.11.10                                                              |
| Hostname             | LinFDWebServer06                                                        |
| Operating System     | Linux - RHEL 8                                                          |
| Platform             | Linux                                                                   |
| Asset Role           | Web Server                                                              |
| Hosting              | AWS Cloud                                                               |
| Business Criticality | Not Provided                                                            |
| Exposure Concern     | Public finance web application may have accepted a PHP web shell upload |

## Evidence Reviewed

| Evidence Source         | Observation                    |
| ----------------------- | ------------------------------ |
| WAF Alert               | Malicious file upload detected |
| Upload Path             | `/uploads/shell.php`           |
| HTTP Method             | PUT                            |
| WAF Action              | Allowed                        |
| WAF Mode                | Monitoring                     |
| Response Code           | 200                            |
| File Execution Evidence | Not Observed                   |
| Web Shell Access        | Not Observed                   |
| Endpoint/EDR Evidence   | Not Provided                   |
| Service Impact          | Not Provided                   |

## SIEM / Splunk Analysis

```spl
index=main "48.207.20.146" "10.0.11.10" sourcetype=waf_logs Threat_Name="Malicious File Upload"
| table _time, srcIP, dstIP, Action, http_method, matched_string, response_code, URL, user_agent, waf_mode
```

| _time               | srcIP         | dstIP      | Action  | Method | Matched String           | Response | URL    | WAF Mode   |
| ------------------- | ------------- | ---------- | ------- | ------ | ------------------------ | -------: | ------ | ---------- |
| 2025-02-16 23:38:00 | 48.207.20.146 | 10.0.11.10 | Allowed | PUT    | `PUT /uploads/shell.php` |      200 | /admin | Monitoring |

**Analysis Note:** This is not a blocked/no-impact event. The WAF allowed the request and the server returned HTTP **200**, so file existence and execution must be validated on the web server.

## MITRE ATT&CK Mapping

| Tactic         | Technique                                     | ID        | Reason                                                                                    |
| -------------- | --------------------------------------------- | --------- | ----------------------------------------------------------------------------------------- |
| Initial Access | Exploit Public-Facing Application             | T1190     | Upload attempt targeted a public-facing web application                                   |
| Persistence    | Server Software Component: Web Shell          | T1505.003 | File name `shell.php` indicates possible web shell upload; execution not confirmed        |
| Execution      | Command and Scripting Interpreter: Unix Shell | T1059.004 | Potential follow-on risk if uploaded PHP shell is executed; not observed in provided logs |

## Analyst Assessment

**Assessment:** **Needs Escalation — Possible Successful Web Shell Upload**

The alert is high risk because the request attempted to upload **shell.php**, the WAF was only in Monitoring mode, the action was **Allowed**, and the response code was **200**.

This is **not confirmed compromise** from WAF evidence alone. However, successful upload cannot be ruled out. The ticket requires SOC L2 and server/application team validation before closure.

## Impact Analysis

| Area            | Assessment                                                   |
| --------------- | ------------------------------------------------------------ |
| Confidentiality | Potential data exposure if web shell exists and was executed |
| Integrity       | Potential unauthorized file creation under `/uploads/`       |
| Availability    | No service disruption reported                               |
| Business Impact | High if finance web server accepted executable upload        |
| Current Risk    | High until `shell.php` existence and execution are validated |

## Recommended Actions

1. Escalate to **SOC L2 / Incident Response**.
2. Validate whether `/uploads/shell.php` exists on **10.0.11.10**.
3. If present, quarantine/remove the file according to IR policy and preserve hash, path, owner, permissions, and timestamps.
4. Search web access logs for requests to `/uploads/shell.php` after **2025-02-16 23:38**.
5. Review EDR/server logs for web server child processes such as `bash`, `sh`, `curl`, `wget`, `python`, `perl`, or `nc`.
6. Review outbound connections from **10.0.11.10** after the upload time.
7. Disable HTTP **PUT** on `/admin` if not required.
8. Move the WAF malicious file upload rule from **Monitoring** to **Blocking**.
9. Block or monitor **48.207.20.146** as per organizational policy.
10. Reassess severity after file existence, execution, and endpoint checks are complete.

## Escalation Decision

**Decision:** **Escalate to SOC L2.**

**Reason:** The upload request was allowed and returned HTTP **200**. The matched string references **shell.php**, which may indicate a web shell upload attempt. Successful upload and execution are not confirmed, but they cannot be ruled out from the provided evidence.

## Final Ticket Closure Comment

SOC investigated ticket **CS-028 — WAF: Malicious File Upload**. Inbound HTTPS traffic from **48.207.20.146** to **10.0.11.10 / LinFDWebServer06** targeted **finance.abc.com/admin** using HTTP **PUT** with matched string `PUT /uploads/shell.php`. The WAF was in Monitoring mode, action was Allowed, and the response code was **200**. No execution, callback, malware activity, or host compromise was confirmed from the WAF log alone. Because the request may have uploaded a PHP web shell, SOC L2 validation is required to confirm file existence, check execution/access logs, review EDR and outbound traffic, and enforce WAF blocking for malicious file uploads.

## Skills Demonstrated

WAF alert triage, malicious upload investigation, web shell risk assessment, Splunk log review, Linux web server validation planning, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
