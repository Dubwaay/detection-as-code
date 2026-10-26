# Command Output Redirected To Hidden Admin Share Via cmd.exe

## Goal

Detect cmd.exe writing command output to a hidden admin share, the way remote execution tools do.

## Categorization

[Lateral Movement](https://attack.mitre.org/tactics/TA0008/) / [Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

Platforms

- Windows

Tooling

- Sysmon, event 1 (process creation)

## Strategy Abstract

- Sysmon event 1 with `Image` cmd.exe is the only data source. No enrichment.
- The rule fires when `CommandLine` has three parts: ` /Q `, `>` followed by a UNC path (`\\`), and `$\` anywhere in the line.
- That combination is how Impacket wmiexec, dcomexec and smbexec return command output.
- The rule has no filters, see False Positives.

## Technical Context

wmiexec, dcomexec and smbexec run each command through cmd.exe. The output goes to a file on a hidden admin share of the victim itself, `ADMIN$` (`C:\Windows`) or `C$` (the C drive). The attacker reads the file over SMB and deletes it. `/Q` turns echo off.

Each command gives Sysmon event 1 for cmd.exe with the redirect in `CommandLine`. `ParentImage` shows the tool: WmiPrvSE.exe for wmiexec, explorer.exe or mmc.exe for dcomexec, services.exe for smbexec. smbexec writes the command into a .bat file and runs it with a second cmd.exe. Only the first cmd.exe carries the redirect. wmiexec with `-shell-type powershell` still starts cmd.exe with the redirect, so the rule fires. wmiexec from the test data, shortened:

```
User:        ATTACKRANGE\Administrator
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
Image:       C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /Q /c calc.exe 1> \\127.0.0.1\ADMIN$\__1682093952.9918194 2>&1
```

wmiexec names the output file `__` plus the Unix time when the script started and keeps the name for the whole run. dcomexec keeps the first five digits, `__16820` in the test data. smbexec writes to `__output_<8 random letters>`, older versions to `__output`.

## Blind Spots and Assumptions

Blind spots

- wmiexec and dcomexec with `-nooutput` or `-silentcommand`, no output file is written.
- A share picked with the `-share` key that has no `$` in its name.
- A renamed cmd.exe.
- Impacket atexec, which redirects to `%windir%\Temp\<random>.tmp` and reads the file through `ADMIN$`.

Assumptions

- Sysmon runs on the host and logs event 1 for cmd.exe.
- `CommandLine` is captured for these events.
- The events are forwarded to the SIEM and indexed.

A blind spot appears whenever one of these assumptions breaks, for example when an attacker stops Sysmon on the victim before running the tools.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| Admin or inventory scripts | cmd.exe `/Q` with the redirect, the same `ParentImage` and `User` on every run of the script | not seen in the test logs, goodlog or BOTS. Exclude by `ParentImage` and `User` together in a `filter_optional_*` |

## Validation

In an isolated VM restored from a snapshot, run the [Atomic Red Team T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) test "Execute command writing output to local Admin Share" as administrator. It needs no downloads. Run the rule's search in the SIEM over the test time. The search returns Sysmon event 1 with `Image` `C:\Windows\System32\cmd.exe` and `\\127.0.0.1\ADMIN$\output.txt` in `CommandLine`.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). goodlog runs it over five clean baselines from [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) v0.8.5 with [tools/goodlog.sh](../../../tools/goodlog.sh). What it finds is listed in False Positives.

| Data | Result |
|---|---|
| attack_data T1021.002 Impacket log (wmiexec, dcomexec, smbexec) | 7 hits: WmiPrvSE.exe 5, explorer.exe 1, services.exe 1 |
| attack_data T1021.002 smbexec log | 1 hit, services.exe |
| attack_data T1547.001 Atomic run | 0 hits |
| BOTS v1 to v3 | 0 hits |

The Splunk search converted from the rule returns the same counts on the three attack_data logs. The BOTS check used a Splunk search that follows the rule logic.

## Priority

High in all cases.

## Response

1. Read `ParentImage`: WmiPrvSE.exe is WMI, explorer.exe or mmc.exe is DCOM, services.exe is a temporary service.
2. Find the source host and account in Security event 4624 logon type 3 on the host at the alert time, if Security logs are collected. `User` in the alert is not always that account.
3. Find what was run: cmd.exe events with the same output file name in `CommandLine`, sorted by `UtcTime`.
4. An admin or inventory script confirmed with its owner explains the alert.
5. If steps 1–4 do not explain the alert, escalate it as remote execution: isolate the host, reset the account of the network logon and search other hosts for cmd.exe with the same redirect.

## Additional Resources

- [Impacket](https://github.com/fortra/impacket)
- [cmd](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)
- [SigmaHQ: HackTool - Potential Impacket Lateral Movement Activity](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_impacket_lateral_movement.yml), a similar rule. It needs one of four parent processes and `\\127.0.0.1\` in the line, so recent smbexec, which writes to `\\<host name>\C$\`, does not match.
