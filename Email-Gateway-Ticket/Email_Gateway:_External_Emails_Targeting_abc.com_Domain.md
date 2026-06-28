# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                     |
| ---------------- | --------------------------------------------------------------------------- |
| Ticket ID        | CS-049                                                                      |
| Alert Name       | Email Gateway: External Emails Targeting abc.com Domain                     |
| Ticket Status    | Closed                                                                      |
| Priority / SLA   | High / Medium                                                               |
| Created Date     | 3/16/25 3:59 PM                                                             |
| Closed By        | Ananda Das                                                                  |
| Analyst Decision | **True Positive — Phishing Email Delivered / No Confirmed User Compromise** |

## Executive Summary

An email gateway alert was triggered for an external email targeting the **abc.com** domain. The email impersonated internal mailbox administration using the display name:

`abc.com Administration`

The email was sent from:

`postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com`

The email was delivered to:

`info@abc.com`

The subject was:

`MailBox Requesting Authentication! For info@abc.com`

The message contained an IPFS-hosted suspicious URL:

`https://bafybeietpey3dhxq55w6cxjunu6pb2jpjslmcmauy2dxbrwbep3oxsgfpq.ipfs.dweb.link/?filename=vback.html#info@abc.com`

The URL was flagged by **14/92 security vendors** as malicious/phishing. The email gateway marked the message as **Delivered** and **allowed**, meaning the phishing email reached the recipient mailbox.

No proxy click logs, endpoint alerts, credential submission evidence, suspicious authentication activity, or endpoint compromise evidence was provided. Therefore, the confirmed impact is limited to phishing email delivery, and user compromise is not confirmed.

## Alert Details

| Field               | Value                                                              |
| ------------------- | ------------------------------------------------------------------ |
| Timestamp           | 2025-01-07 17:45:14-08:00                                          |
| Sender Display Name | `abc.com Administration`                                           |
| Sender Email        | `postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com` |
| Sender Domain       | hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com              |
| Recipient           | `info@abc.com`                                                     |
| Email Subject       | `MailBox Requesting Authentication! For info@abc.com`              |
| Sender IP           | 52.101.194.10                                                      |
| Status              | Delivered                                                          |
| Action              | allowed                                                            |
| Reason              | NA                                                                 |
| Message ID          | `<20250107174514.1F1F56C50C1FA920@solosin.com>`                    |
| URL Detection Ratio | 14/92 security vendors flagged malicious/phishing                  |

## Affected Assets

| Asset / Entity        | Details                                                                    |
| --------------------- | -------------------------------------------------------------------------- |
| Targeted Mailbox      | `info@abc.com`                                                             |
| Impersonated Entity   | `abc.com Administration`                                                   |
| Sender Email          | `postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com`         |
| Sender IP             | 52.101.194.10                                                              |
| Phishing Domain       | bafybeietpey3dhxq55w6cxjunu6pb2jpjslmcmauy2dxbrwbep3oxsgfpq.ipfs.dweb.link |
| Endpoint              | Not Provided                                                               |
| User Click Activity   | Not Confirmed                                                              |
| Credential Submission | Not Confirmed                                                              |
| Current Impact        | Phishing email delivered; user compromise not confirmed                    |

## Evidence Reviewed

### IOC Summary

| IOC Type             | Indicator                                                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Sender Email         | `postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com`                                                     |
| Sender Domain        | `hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com`                                                                |
| Sender IP            | `52.101.194.10`                                                                                                        |
| Recipient            | `info@abc.com`                                                                                                         |
| Email Subject        | `MailBox Requesting Authentication! For info@abc.com`                                                                  |
| Phishing URL         | `https://bafybeietpey3dhxq55w6cxjunu6pb2jpjslmcmauy2dxbrwbep3oxsgfpq.ipfs.dweb.link/?filename=vback.html#info@abc.com` |
| URL Without Fragment | `https://bafybeietpey3dhxq55w6cxjunu6pb2jpjslmcmauy2dxbrwbep3oxsgfpq.ipfs.dweb.link/?filename=vback.html`              |
| Phishing Domain      | `bafybeietpey3dhxq55w6cxjunu6pb2jpjslmcmauy2dxbrwbep3oxsgfpq.ipfs.dweb.link`                                           |
| Message ID           | `<20250107174514.1F1F56C50C1FA920@solosin.com>`                                                                        |

### Sender IP Reputation

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

### URL Reputation

| Field                | Value                                                                                                                  |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| URL                  | `https://bafybeietpey3dhxq55w6cxjunu6pb2jpjslmcmauy2dxbrwbep3oxsgfpq.ipfs.dweb.link/?filename=vback.html#info@abc.com` |
| URL Without Fragment | `https://bafybeietpey3dhxq55w6cxjunu6pb2jpjslmcmauy2dxbrwbep3oxsgfpq.ipfs.dweb.link/?filename=vback.html`              |
| Domain               | `bafybeietpey3dhxq55w6cxjunu6pb2jpjslmcmauy2dxbrwbep3oxsgfpq.ipfs.dweb.link`                                           |
| Status               | 410                                                                                                                    |
| Detection Ratio      | 14/92 vendors flagged malicious                                                                                        |
| Classification       | Phishing / Malicious                                                                                                   |
| Primary Risk         | Credential harvesting / mailbox authentication phishing                                                                |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The alert was reviewed as a phishing email incident because the message targeted the **abc.com** domain and impersonated internal mailbox administration.

Key suspicion indicators:

| Indicator        | Observation                    |
| ---------------- | ------------------------------ |
| Display Name     | `abc.com Administration`       |
| Sender Type      | External sender                |
| Sender Domain    | AWS ELB-style external domain  |
| Subject Theme    | Mailbox authentication request |
| Recipient        | `info@abc.com`                 |
| Email Status     | Delivered                      |
| Email Action     | allowed                        |
| URL Type         | IPFS-hosted URL                |
| Vendor Detection | 14/92 malicious/phishing       |

The subject **MailBox Requesting Authentication! For [info@abc.com](mailto:info@abc.com)** is strongly aligned with credential-harvesting phishing because it attempts to make the recipient authenticate their mailbox.

#### 2. Sender and Impersonation Review

The display name attempted to impersonate the internal domain administration team, while the actual sender address was external:

`postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com`

This mismatch between the display name and sender domain is a strong phishing indicator.

#### 3. URL Review

The message contained an IPFS-hosted URL with the recipient email included in the URL fragment:

`#info@abc.com`

This is suspicious because phishing kits commonly include the target email address in the URL to pre-fill login pages or personalize credential-harvesting pages.

#### 4. Email Delivery Validation

The email gateway allowed and delivered the message. This confirms mailbox exposure and requires mailbox cleanup/quarantine.

#### 5. User Interaction Validation

No proxy logs, endpoint logs, or authentication logs were provided to confirm whether the recipient clicked the link, submitted credentials, or triggered suspicious login activity.

The correct conclusion is:

**Phishing email delivered and confirmed malicious by reputation, but user compromise is not confirmed from the provided evidence.**

### Email Gateway Query

```spl id="cs0248_email_query"
index=main sourcetype="email_logs" "postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com"
| table Sender SenderIP Recipient Email_Subject URL Status Action MessageID
```

### Full Unique Splunk Log Result

```text id="cs0248_email_result"
Sender	SenderIP	Recipient	Email_Subject	URL	Status	Action	MessageID
"abc.com  Administration"  <postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com>	52.101.194.10	info@abc.com	MailBox Requesting Authentication! For info@abc.com	https://bafybeietpey3dhxq55w6cxjunu6pb2jpjslmcmauy2dxbrwbep3oxsgfpq.ipfs.dweb.link/?filename=vback.html#info@abc.com"	Delivered	allowed	<20250107174514.1F1F56C50C1FA920@solosin.com>
```

### Initial Email Gateway Alert Evidence

| Timestamp                 | Sender                                                                                        | Recipient      | Email Subject                                         | Sender IP     | Status    | Action  | Reason |
| ------------------------- | --------------------------------------------------------------------------------------------- | -------------- | ----------------------------------------------------- | ------------- | --------- | ------- | ------ |
| 2025-01-07 17:45:14-08:00 | `"abc.com Administration" <postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com>` | `info@abc.com` | `MailBox Requesting Authentication! For info@abc.com` | 52.101.194.10 | Delivered | allowed | NA     |

### Security Vendor Detection Summary

The phishing URL was flagged by **14/92 security vendors**.

| Vendor           | Detection |
| ---------------- | --------- |
| ADMINUSLabs      | Malicious |
| alphaMountain.ai | Phishing  |
| BitDefender      | Phishing  |
| Chong Lua Dao    | Malicious |
| CyRadar          | Phishing  |
| ESET             | Phishing  |
| Fortinet         | Phishing  |
| G-Data           | Phishing  |
| Kaspersky        | Phishing  |
| Lionic           | Phishing  |
| Seclookup        | Malicious |
| Sophos           | Phishing  |
| VIPRE            | Phishing  |
| Webroot          | Malicious |

### Timeline Reconstruction

| Time                      | Event                                                                                   |
| ------------------------- | --------------------------------------------------------------------------------------- |
| 2025-01-07 17:45:14-08:00 | Email gateway alert triggered for external email targeting `info@abc.com`               |
| 2025-01-07 17:45:14-08:00 | Email was delivered and allowed by the email gateway                                    |
| Investigation Time        | URL reputation showed 14/92 vendors flagged the URL as malicious/phishing               |
| Investigation Time        | Sender IP reputation reviewed for `52.101.194.10`                                       |
| Investigation Time        | No proxy, endpoint, or authentication activity was provided to confirm user interaction |

### Evidence Interpretation

| Observation                                       | Analyst Interpretation                            |
| ------------------------------------------------- | ------------------------------------------------- |
| Sender impersonated `abc.com Administration`      | Internal administration spoofing attempt          |
| Sender address used external AWS ELB-style domain | Suspicious sender identity mismatch               |
| Subject requested mailbox authentication          | Credential-harvesting lure                        |
| URL contained `#info@abc.com`                     | Possible targeted phishing page pre-fill          |
| IPFS-hosted URL used                              | Commonly abused hosting method for phishing pages |
| 14/92 vendors flagged URL                         | Reputation supports phishing classification       |
| Email delivered and allowed                       | Mailbox exposure confirmed                        |
| No proxy/auth evidence provided                   | User compromise not confirmed                     |

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                                |
| ------------------- | ----------------------------------------- | --------- | ------------------------------------------------------------------------------------- |
| Initial Access      | Phishing                                  | T1566     | External phishing email was delivered to the target mailbox                           |
| Initial Access      | Spearphishing Link                        | T1566.002 | Email contained a phishing URL requesting mailbox authentication                      |
| Credential Access   | Input Capture                             | T1056     | Possible credential-harvesting page; credential submission not confirmed              |
| Defense Evasion     | Masquerading                              | T1036     | Sender display name impersonated internal administration                              |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Phishing infrastructure was accessed via web URL if clicked; user click not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Phishing Email Delivered**

The alert is valid because the email impersonated internal mailbox administration, targeted `info@abc.com`, contained an IPFS-hosted phishing URL, and the URL was flagged by multiple security vendors as malicious/phishing.

This is **not confirmed credential compromise** based on the available evidence. No proxy click logs, credential submission evidence, suspicious authentication activity, mailbox rule creation, endpoint alert, or data exfiltration was provided.

## Impact Analysis

| Impact Area                        | Status        |
| ---------------------------------- | ------------- |
| External phishing email received   | Confirmed     |
| Targeted mailbox                   | Confirmed     |
| Email delivered to mailbox         | Confirmed     |
| Email gateway allowed message      | Confirmed     |
| Suspicious IPFS URL present        | Confirmed     |
| URL flagged malicious/phishing     | Confirmed     |
| User clicked URL                   | Not Confirmed |
| Credentials entered                | Not Confirmed |
| Suspicious authentication activity | Not Confirmed |
| Malware execution                  | Not Confirmed |
| Endpoint compromise                | Not Confirmed |
| Data exfiltration                  | Not Confirmed |

Current impact: **Phishing email delivery confirmed. User compromise not confirmed.**

## Recommended Actions

1. Quarantine or remove the delivered email from `info@abc.com`.
2. Search all mailboxes for the same sender, subject, URL, and Message ID.
3. Block the phishing URL in the email gateway.
4. Block the IPFS phishing domain in proxy/SWG and DNS security controls.
5. Block sender email `postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com` if not business-required.
6. Block sender domain `hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com` if not business-required.
7. Block sender IP `52.101.194.10` only if policy approves and no business impact exists.
8. Review proxy logs to confirm whether the phishing URL was clicked.
9. Review authentication logs for `info@abc.com` after email delivery.
10. Review mailbox forwarding rules and inbox rules only if click or suspicious login activity is found.
11. Reset credentials only if user click, credential submission, or suspicious authentication activity is confirmed.
12. Add sender, URL, domain, and Message ID to SIEM watchlist.
13. Educate mailbox owner/user about mailbox authentication phishing emails.

## Escalation Decision

**Decision:** **No immediate SOC L2 escalation required from provided logs; conditional escalation if user activity is found.**

**Reason:** The email is confirmed phishing and was delivered, but no evidence was provided showing user click activity, credential submission, suspicious login, MFA prompts, endpoint compromise, or data exposure.

Escalate to **SOC L2 / Identity Team** if any of the following are identified:

1. User clicked the phishing URL.
2. User entered credentials.
3. Suspicious login activity is detected.
4. MFA prompts, MFA failures, or impossible travel events are observed.
5. Mailbox forwarding or suspicious inbox rules are created.
6. Endpoint compromise indicators are found.
7. Similar emails are delivered to multiple users.
8. Security controls fail to remove or block the email.

## Final Ticket Closure Comment

SOC investigated ticket **CS-049 — Email Gateway: External Emails Targeting abc.com Domain**. The email impersonated `abc.com Administration` and was sent from external sender `postmaster@hdr-nlb7-aebd5d615260636b.elb.us-east-1.amazonaws.com` to `info@abc.com`. The subject was `MailBox Requesting Authentication! For info@abc.com`. Email gateway logs confirmed the message was **Delivered** and **allowed**. The email contained an IPFS-hosted phishing URL that included the target mailbox in the URL fragment and was flagged by **14/92 security vendors** as malicious/phishing. No proxy click logs, credential submission evidence, suspicious authentication activity, endpoint compromise, or data exfiltration was provided. Ticket closed as **True Positive — Phishing Email Delivered / No Confirmed User Compromise**, with email quarantine, IOC blocking, mailbox-wide hunting, proxy/authentication review, and conditional credential reset recommended only if click activity or suspicious authentication is confirmed.

## Skills Demonstrated

Email gateway alert triage, phishing email investigation, sender impersonation analysis, IPFS phishing URL review, URL reputation analysis, IOC extraction, Splunk email log analysis, evidence limitation handling, MITRE ATT&CK mapping, impact validation, containment planning, conditional escalation decision-making, and SOC ticket documentation.
