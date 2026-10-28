# Shadow File Read Via Command Line Utility

## Goal

Detect a command line utility that reads /etc/shadow or /etc/gshadow, the files with password hashes.

## Categorization

[Credential Access](https://attack.mitre.org/tactics/TA0006/) / [OS Credential Dumping: /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/)

Platforms

- Linux

Tooling

- auditd, EXECVE record (program start)

## Strategy Abstract

- auditd EXECVE records are the only data source. No enrichment.
- The rule fires when the program in `a0` is a tool from a fixed list, such as cat, less, grep or cp, and `a1`, `a2` or `a3` is exactly /etc/shadow, /etc/gshadow or one of their backups.
- The rule has no filters, see False Positives.

## Technical Context

/etc/shadow holds the password hashes of local accounts. /etc/gshadow holds the hashes of group passwords. Ordinary users cannot read them. An attacker who copies them can crack the hashes offline.

With an audit rule on execve, auditd writes an EXECVE record for each program start. `a0` is the program as it was called, `a1` and the next fields are its arguments. `sudo cat /etc/shadow` gives two records. The rule matches the one for cat. From the test data:

```
type: EXECVE
argc: 2
a0: cat
a1: /etc/shadow
```

The EXECVE record is written when the program starts, before it opens the file. The rule fires even if the read then fails.

## Blind Spots and Assumptions

Blind spots

- A program that opens the file itself without the path in its arguments.
- Tools outside the list, such as python, perl, dd, tar or rsync.
- A relative or rewritten path: `cat shadow` run in /etc, /etc//shadow, a symlink to the file.
- The path in `a4` or a later argument.

Assumptions

- auditd runs on the host with a rule that logs execve for the accounts in question.
- audit.log reaches the SIEM unchanged, and `a0`, `a1` and the other arguments are extracted as fields.

A blind spot appears whenever one of these assumptions breaks, for example when an attacker stops auditd or deletes its rules.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| Administrator reading the file by hand | sudo before the tool, `AUID` of an administrator and a terminal in `tty` of the SYSCALL record | not seen in the test logs. Confirm with the administrator, no exclusion |
| Backup or configuration scripts copying the file | cp with /etc/shadow, no terminal (`tty=(none)`), the same command at regular times | not seen in the test logs. Add a `filter_optional_*` block with the target path of the copy |

## Validation

In an isolated VM restored from a snapshot, load an execve audit rule and run the [Atomic Red Team T1003.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.008/T1003.008.md) test "Access /etc/shadow (Local)". It needs no downloads. Run the rule's search in the SIEM over the test time. The search returns the EXECVE record of cat with `a1` /etc/shadow, started by sudo. In the CAM-LDS video server log the same command, `sudo cat /etc/shadow`, gave one such record.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). [tools/goodlog.sh](../../../tools/goodlog.sh) checks rules on clean Windows baselines only. There is no clean Linux baseline.

| Data | Result |
|---|---|
| CAM-LDS scenario 1, video server (sudo cat, linPEAS cat) | 2 hits |
| CAM-LDS scenario 3, repository server (cat) | 1 hit |
| CAM-LDS scenario 1, DNS server (no attack step, stat on the shadow files) | 0 hits |

The Splunk search converted from the rule returns the same counts on these three logs.

## Priority

Medium in all cases.

## Response

1. Join the SYSCALL record with the same `msg`, the time and serial number of the event: `AUID` (the account that logged in), `uid`, `euid`, `exe`, `tty` and `ses`.
2. If the audit rules watch /etc/shadow, find the open of the file by the same `pid`. `success=no` with `exit=-13` means the read failed.
3. List the other commands of the same session (`ses`) before and after the read.
4. Look for copies of the file: the cp target and files created by the session (PATH records with `nametype=CREATE`).
5. If an administrator read the file or a known script copied it, confirm it with the owner.
6. If steps 1–5 do not explain the read, escalate it as credential theft: isolate the host, reset the passwords of the accounts in the file and look for logons with them on other hosts.

## Additional Resources

- [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html)
- [SigmaHQ: Local System Accounts Discovery - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_local_account.yml), a similar rule. It reads the command line of process creation events and also fires on /etc/passwd and /etc/sudoers.
- [Elastic: Potential Shadow File Read via Command Line Utilities](https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_shadow_file_read.toml), a similar rule on Elastic Defend data. It accepts any program with /etc/shadow as an argument and alerts only when that program did not do it in the previous 5 days.
- [Splunk: Linux Auditd Possible Access To Credential Files](https://github.com/splunk/security_content/blob/develop/detections/endpoint/linux_auditd_possible_access_to_credential_files.yml), a similar rule. It searches `proctitle`, which a raw audit.log writes as hex.
