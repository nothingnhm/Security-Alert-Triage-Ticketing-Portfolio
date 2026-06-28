# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                                     |
| ---------------- | ----------------------------------------------------------------------------------------------------------- |
| Ticket ID        | CS-048                                                                                                      |
| Alert Name       | Email Gateway: Detection of Suspicious Embedded Macros in Attachments from External Domain                  |
| Ticket Status    | Closed                                                                                                      |
| Priority / SLA   | Normal / Medium                                                                                             |
| Created Date     | 3/16/25 4:16 PM                                                                                             |
| Closed By        | Ananda Das                                                                                                  |
| Severity         | High                                                                                                        |
| Analyst Decision | **True Positive — Suspicious/Malicious Office Attachment Delivered / User Interaction Validation Required** |

## Executive Summary

An email gateway alert was triggered for a suspicious attachment containing embedded macros from an external sender domain.

The email was sent from:

`Accounts.Avi Enterprises <accounts@avienterprise.com>`

The email was delivered to:

`info@abc.com`

The subject of the email was:

`Due Payments Release`

The email gateway action was **allowed**, and the status was **Delivered**, meaning the message reached the recipient mailbox. The email contained an Excel attachment:

`ACCOUNTS STATEMENT.xls`

The attachment hash observed in the email logs was:

`0c022982324f9c68037f2a3677492695`

Additional file reputation evidence showed a malicious Excel sample detected by **26/54 security vendors**, with detections related to **Trojan**, **Downloader**, **Microsoft Office exploit behavior**, **CVE-2017-0199**, and suspicious OLE content.

The original email file was not provided, so full header analysis, attachment extraction, macro review, sandbox detonation, and exact file verification could not be completed. However, based on the delivered status, external sender, payment-themed subject, suspicious Excel attachment, macro detection, and malicious vendor reputation, this case should be handled as a **high-risk malicious Office attachment incident pending user and endpoint validation**.

## Alert Details

| Field           | Value                                                   |
| --------------- | ------------------------------------------------------- |
| Timestamp       | 2025-03-05 09:46:22-08:00                               |
| Sender          | `Accounts.Avi Enterprises <accounts@avienterprise.com>` |
| Sender Email    | `accounts@avienterprise.com`                            |
| Sender Domain   | avienterprise.com                                       |
| Recipient       | `info@abc.com`                                          |
| Email Subject   | Due Payments Release                                    |
| Sender IP       | 52.101.194.10                                           |
| Status          | Delivered                                               |
| Action          | allowed                                                 |
| Reason          | NA                                                      |
| Attachment Name | ACCOUNTS STATEMENT.xls                                  |
| Attachment Hash | 0c022982324f9c68037f2a3677492695                        |
| Alert Type      | Suspicious embedded macros in attachment                |
| Log Source      | Email Gateway / Splunk                                  |

## Affected Assets

| Asset / Entity      | Details                                               |
| ------------------- | ----------------------------------------------------- |
| Recipient Mailbox   | `info@abc.com`                                        |
| Sender              | `accounts@avienterprise.com`                          |
| Sender Domain       | avienterprise.com                                     |
| Sender IP           | 52.101.194.10                                         |
| Attachment          | ACCOUNTS STATEMENT.xls                                |
| Attachment Hash     | 0c022982324f9c68037f2a3677492695                      |
| Endpoint            | Not Provided                                          |
| User Interaction    | Not Confirmed                                         |
| Original Email File | Not Provided                                          |
| Current Impact      | Delivery confirmed; endpoint compromise not confirmed |

## Evidence Reviewed

### Investigation Flow

#### 1. Alert Review

The alert was reviewed as a suspicious macro-enabled attachment case because the email gateway detected embedded macros in an attachment from an external sender domain.

Key alert indicators:

| Indicator        | Observation                         |
| ---------------- | ----------------------------------- |
| External Sender  | `accounts@avienterprise.com`        |
| Subject Theme    | Payment / due payments              |
| Attachment Type  | Excel spreadsheet                   |
| Gateway Status   | Delivered                           |
| Gateway Action   | allowed                             |
| Macro Risk       | Suspicious embedded macros detected |
| User Interaction | Not confirmed                       |

The email subject **Due Payments Release** is financially themed and may be designed to convince the recipient to open the attachment.

#### 2. Sender and Source Review

The sender IP was identified as **52.101.194.10**.

| Field               | Value                           |
| ------------------- | ------------------------------- |
| IP Address          | 52.101.194.10                   |
| Confidence of Abuse | 50%                             |
| ISP                 | Microsoft Corporation           |
| Usage Type          | Data Center/Web Hosting/Transit |
| ASN                 | AS8075                          |
| Domain Name         | microsoft.com                   |
| Country             | United States of America        |
| City                | Chicago, Illinois               |

The sender IP reputation alone does not prove malicious activity because shared cloud/email infrastructure may be abused. The stronger risk indicators are the delivered malicious-style attachment, macro detection, and file reputation.

#### 3. Attachment Review

The email log confirmed the attachment:

| Field           | Value                                                |
| --------------- | ---------------------------------------------------- |
| Attachment Name | ACCOUNTS STATEMENT.xls                               |
| Attachment Hash | 0c022982324f9c68037f2a3677492695                     |
| File Type       | Excel Spreadsheet                                    |
| Risk            | Suspicious embedded macros / possible Office exploit |

Additional reputation evidence showed a related malicious Excel sample:

| Field             | Value                                                            |
| ----------------- | ---------------------------------------------------------------- |
| Detection Ratio   | 26/54 security vendors flagged as malicious                      |
| SHA256            | 2e971027b80cdb93379285f33ce200da6b73fc544748706d8f282234e9e6231d |
| File Name         | Rush Order.xls                                                   |
| File Size         | 1.13 MB                                                          |
| Detection Name    | trojan.office/cve170199                                          |
| Threat Categories | Trojan, Downloader                                               |
| Family Labels     | office, cve170199, ahlw                                          |
| Exploit Reference | CVE-2017-0199                                                    |

#### 4. Evidence Limitation

The original email file was not provided. Because of this, the following could not be fully validated:

| Missing Evidence              | Impact                                     |
| ----------------------------- | ------------------------------------------ |
| Original `.eml` / `.msg` file | Full header and MIME review not possible   |
| Attachment sample             | Macro code review not possible             |
| Sandbox detonation            | Runtime behavior not confirmed             |
| Endpoint telemetry            | User execution not confirmed               |
| Process logs                  | Excel child-process activity not confirmed |
| Network callbacks             | Payload download or C2 not confirmed       |
| User confirmation             | Attachment open status not confirmed       |

#### 5. Hash / File Name Mismatch Note

The email gateway log showed:

`ACCOUNTS STATEMENT.xls`
`0c022982324f9c68037f2a3677492695`

The additional reputation sample showed:

`Rush Order.xls`
`2e971027b80cdb93379285f33ce200da6b73fc544748706d8f282234e9e6231d`

Because the attachment name and hash differ, the original email and attachment should be collected from the email gateway or mailbox to confirm whether the samples are the same file family, a renamed variant, or separate malicious Office documents.

## SIEM / Splunk Analysis

### Email Gateway Query

```spl id="cs0249_email_query"
index=main sourcetype="email_logs" "accounts@avienterprise.com"
| table _time Attachment_Hash Attachment_Name Sender SenderIP Recipient Email_Subject URL Status Action
```

### Full Unique Splunk Log Result

```text id="cs0249_email_results"
_time	Attachment_Hash	Attachment_Name	Sender	SenderIP	Recipient	Email_Subject	URL	Status	Action
2025-03-05 08:00:00	0c022982324f9c68037f2a3677492695	ACCOUNTS STATEMENT.xls	Accounts.Avi Enterprises <accounts@avienterprise.com>	52.101.194.10	info@abc.com	Due Payments Release	NA	Delivered	allowed
```

### Initial Email Gateway Alert Evidence

| Timestamp                 | Sender                                                  | Recipient      | Email Subject        | Sender IP     | Status    | Action  | Reason |
| ------------------------- | ------------------------------------------------------- | -------------- | -------------------- | ------------- | --------- | ------- | ------ |
| 2025-03-05 09:46:22-08:00 | Accounts.Avi Enterprises `<accounts@avienterprise.com>` | `info@abc.com` | Due Payments Release | 52.101.194.10 | Delivered | allowed | NA     |

### Vendor Detection Summary

The file reputation result showed **26/54 security vendors** flagged the Excel sample as malicious.

| Vendor                   | Detection                                     |
| ------------------------ | --------------------------------------------- |
| AliCloud                 | Exploit:Win/CVE-2017-0199.C                   |
| ALYac                    | Exploit.CVE-2017-0199.05.Gen                  |
| Arcabit                  | Exploit.CVE-2017-0199.05.Gen                  |
| CTX                      | Xls.trojan.office                             |
| Cynet                    | Malicious, score 99                           |
| Emsisoft                 | Exploit.CVE-2017-0199.05.Gen                  |
| eScan                    | Exploit.CVE-2017-0199.05.Gen                  |
| ESET-NOD32               | Probably Win32/Exploit.CVE-2017-0199.C Trojan |
| Fortinet                 | MSExcel/CVE_2017_0199.G1!exploit              |
| GData                    | Exploit.CVE-2017-0199.05.Gen                  |
| Ikarus                   | Trojan-Downloader.Office.Doc                  |
| K7AntiVirus              | Trojan                                        |
| K7GW                     | Trojan                                        |
| Lionic                   | Trojan.MSExcel.Office.4!c                     |
| McAfee Scanner           | Trojan:Office/Downloader.JHJ                  |
| Rising                   | Exploit.CVE-2017-0199                         |
| SentinelOne Static ML    | Static AI - Suspicious OLE                    |
| Sophos                   | Troj/DocDl-AHLW                               |
| Symantec                 | Scr.Malcode!gen59                             |
| TACHYON                  | Downloader/W97.CVE-2017-0199                  |
| TrendMicro               | HEUR_CVE170199.L                              |
| TrendMicro-HouseCall     | HEUR_CVE170199.L                              |
| Varist                   | CVE170199                                     |
| VIPRE                    | Exploit.CVE-2017-0199.05.Gen                  |
| ViRobot                  | XLS.Z.Agent.1186816                           |
| ZoneAlarm by Check Point | Troj/DocDl-AHLW                               |

### Timeline Reconstruction

| Time                      | Event                                                                                               |
| ------------------------- | --------------------------------------------------------------------------------------------------- |
| 2025-03-05 08:00:00       | Email log observed for sender `accounts@avienterprise.com` with attachment `ACCOUNTS STATEMENT.xls` |
| 2025-03-05 09:46:22-08:00 | Email gateway alert triggered for suspicious embedded macros in the attachment                      |
| 2025-03-05 09:46:22-08:00 | Email was delivered and allowed to `info@abc.com`                                                   |
| Investigation Time        | File reputation check showed 26/54 vendors flagged a related Excel sample as malicious              |
| Investigation Time        | Further analysis limited because original email file was not provided                               |

### Evidence Interpretation

| Observation                                 | Analyst Interpretation                                    |
| ------------------------------------------- | --------------------------------------------------------- |
| External sender used payment-themed subject | Common phishing/social engineering pattern                |
| Email was delivered and allowed             | User mailbox exposure confirmed                           |
| Excel attachment was present                | Potential macro/exploit delivery mechanism                |
| Embedded macro alert triggered              | High-risk attachment behavior                             |
| Vendor detections reference CVE-2017-0199   | Possible Office exploit/downloader behavior               |
| Original email file not available           | Full technical verification still required                |
| User interaction not confirmed              | Endpoint impact cannot be confirmed from email logs alone |

## MITRE ATT&CK Mapping

| Tactic              | Technique                         | ID        | Reason                                                                                            |
| ------------------- | --------------------------------- | --------- | ------------------------------------------------------------------------------------------------- |
| Initial Access      | Phishing                          | T1566     | External email delivered to user mailbox                                                          |
| Initial Access      | Spearphishing Attachment          | T1566.001 | Email contained suspicious Excel attachment                                                       |
| Execution           | User Execution: Malicious File    | T1204.002 | Attachment would require user opening/enabling content; execution not confirmed                   |
| Defense Evasion     | Obfuscated Files or Information   | T1027     | Suspicious OLE/macro-style documents may hide malicious logic; confirmed macro code not available |
| Command and Control | Ingress Tool Transfer             | T1105     | Office downloader behavior may retrieve second-stage payload; not confirmed in provided logs      |
| Exploitation        | Exploitation for Client Execution | T1203     | Vendor detections reference CVE-2017-0199 Office exploit behavior                                 |

## Analyst Assessment

**Assessment:** **True Positive — Suspicious/Malicious Office Attachment Delivered**

The alert is valid because the email gateway detected suspicious embedded macros in an Excel attachment from an external sender, and the email was delivered to the recipient mailbox.

The case should be treated as high risk because the attachment is an Excel file with macro/exploit indicators, and external file reputation shows strong malicious detection coverage. However, endpoint compromise is **not confirmed** because there is no evidence showing the recipient opened the attachment, enabled macros, executed payloads, or triggered malicious child processes.

The strongest current conclusion is:

**Malicious/suspicious Excel attachment delivered; user interaction and endpoint impact require validation.**

## Impact Analysis

| Impact Area                        | Status        |
| ---------------------------------- | ------------- |
| Suspicious external email received | Confirmed     |
| Email delivered to recipient       | Confirmed     |
| Gateway action allowed             | Confirmed     |
| Excel attachment present           | Confirmed     |
| Suspicious macro-related detection | Confirmed     |
| Malicious vendor detections        | Confirmed     |
| User opened attachment             | Not Confirmed |
| User enabled macros                | Not Confirmed |
| Payload downloaded                 | Not Confirmed |
| Malware executed                   | Not Confirmed |
| Credential theft                   | Not Confirmed |
| Endpoint compromise                | Not Confirmed |
| Data exfiltration                  | Not Confirmed |

Current impact: **Mailbox exposure confirmed. Endpoint impact not confirmed.**

## Recommended Actions

1. Contact the mailbox owner of `info@abc.com` and confirm whether the email was opened.
2. Confirm whether `ACCOUNTS STATEMENT.xls` was downloaded or opened.
3. Confirm whether the user clicked **Enable Content**, enabled macros, or interacted with the attachment.
4. Request the original email file in `.eml` or `.msg` format for deeper analysis.
5. Quarantine or remove the delivered email from the mailbox.
6. Search all mailboxes for the same sender, subject, attachment name, and attachment hash.
7. Block `accounts@avienterprise.com` in the email gateway if not business-required.
8. Block or quarantine emails from `avienterprise.com` if no business requirement exists.
9. Add `0c022982324f9c68037f2a3677492695` to SIEM/EDR watchlist.
10. Add `2e971027b80cdb93379285f33ce200da6b73fc544748706d8f282234e9e6231d` to EDR/SIEM watchlist as the related malicious SHA256 sample.
11. Block sender IP `52.101.194.10` only if policy approves and no business impact exists.
12. If the attachment was opened, run endpoint EDR/AV scan and review process execution.
13. If macros were enabled or suspicious execution is found, isolate the endpoint and escalate to SOC L2.
14. Reset password and revoke sessions only if credential exposure, macro execution, malware execution, or compromise indicators are confirmed.

### Endpoint Validation Checklist

If the user opened the attachment, validate the endpoint for:

| Validation Item                                                                                        | Purpose                                              |
| ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| Excel process execution                                                                                | Confirm attachment opening                           |
| Excel child processes                                                                                  | Detect macro or exploit execution                    |
| `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe` | Identify suspicious Office-spawned execution         |
| Recent downloads                                                                                       | Detect second-stage payload                          |
| Proxy/DNS connections                                                                                  | Identify callback or payload download infrastructure |
| Scheduled tasks                                                                                        | Check persistence                                    |
| Registry run keys                                                                                      | Check persistence                                    |
| EDR/AV detections                                                                                      | Confirm malware behavior                             |
| File creation events                                                                                   | Identify dropped payloads                            |
| Network callbacks                                                                                      | Detect C2 or downloader activity                     |

## Escalation Decision

**Decision:** **Conditional escalation to SOC L2.**

**Reason:** The email attachment is high risk and likely malicious based on macro detection and vendor reputation, but user interaction and endpoint impact are not confirmed from the available evidence.

Escalate to **SOC L2 / Incident Response** if any of the following are confirmed:

1. User opened the attachment.
2. User enabled macros or clicked **Enable Content**.
3. User clicked a link inside the attachment.
4. User provided credentials, OTP, payment details, or sensitive information.
5. EDR detects malicious activity.
6. Excel spawned suspicious child processes.
7. Second-stage payload download is observed.
8. Suspicious network callbacks are observed.
9. The original attachment hash matches the malicious reputation sample.
10. Additional users received or opened the same attachment.

If the user confirms the attachment was not opened and email removal is completed, close as **Malicious Attachment Delivered / No Endpoint Impact Confirmed**.

## Final Ticket Closure Comment

SOC investigated ticket **CS-048 — Email Gateway: Detection of Suspicious Embedded Macros in Attachments from External Domain**. The email was sent from external sender `accounts@avienterprise.com` to `info@abc.com` with subject **Due Payments Release**. The email gateway marked the status as **Delivered** and action as **allowed**. Splunk email logs confirmed the Excel attachment `ACCOUNTS STATEMENT.xls` with attachment hash `0c022982324f9c68037f2a3677492695`. Additional file reputation evidence showed a related Excel sample flagged by **26/54 security vendors** as malicious, with detections related to Trojan, downloader, suspicious OLE content, Office exploit behavior, and **CVE-2017-0199**. The original email file was not provided, so full header analysis, macro review, sandbox detonation, and exact attachment verification could not be completed. Ticket closed as **True Positive — Suspicious/Malicious Office Attachment Delivered / User Interaction Validation Required**, with email quarantine, sender/domain blocking, hash-based hunting, user validation, endpoint review, and conditional SOC L2 escalation recommended if the attachment was opened or endpoint compromise indicators are found.

## Skills Demonstrated

Email gateway alert triage, suspicious attachment investigation, macro-enabled Office document analysis, malicious file reputation review, IOC extraction, Splunk email log analysis, evidence limitation handling, user validation planning, endpoint investigation planning, MITRE ATT&CK mapping, impact validation, containment planning, escalation decision-making, and SOC incident documentation.
