# Cmd Or PowerShell Started By WmiPrvSE.exe Or services.exe

## Goal

Detect cmd.exe or PowerShell started by the WMI provider host or the service control manager, the way remote execution tools do.

## Categorization

[Execution](https://attack.mitre.org/tactics/TA0002/) / [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/), [System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)

Platforms

- Windows

Tooling

- Sysmon, event 1 (process creation)

## Strategy Abstract

- Sysmon event 1 is the only data source. No enrichment.
- The rule fires when `ParentImage` is WmiPrvSE.exe or services.exe and the child is cmd.exe or PowerShell (powershell.exe, pwsh.exe).
- The child is matched by file name or `OriginalFileName`, so a renamed copy fires too.
- One filter excludes Nessus credentialed scans. The False Positives section lists them and the other sources.

## Technical Context

wmiexec runs commands through the WMI method `Win32_Process.Create`. Windows starts such a process from WmiPrvSE.exe, the WMI provider host. `Invoke-WmiMethod -Class Win32_Process -Name Create` in PowerShell does the same. smbexec creates a service with a cmd.exe command line as the binary path, and services.exe starts it. A service from the test data, shortened:

```
User:             NT AUTHORITY\SYSTEM
ParentImage:      C:\Windows\System32\services.exe
Image:            C:\Windows\System32\cmd.exe
OriginalFileName: Cmd.Exe
CommandLine:      C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};...
```

cmd.exe starts PowerShell in a hidden window and exits. PowerShell starts its 32-bit copy, which decodes a base64 string, unpacks it with gzip and runs the result.

`OriginalFileName` is the original file name stored in the file's version resource. It stays `Cmd.Exe` or `PowerShell.EXE` when the file is copied under another name, so a renamed copy still fires.

## Blind Spots and Assumptions

Blind spots

- Remote execution under another parent: dcomexec (explorer.exe, mmc.exe), PowerShell remoting (wsmprovhost.exe), winrs (winrshost.exe), scheduled tasks.
- A child other than cmd.exe or PowerShell: wscript, cscript, mshta, or a program that WMI starts directly, as wmiexec `-silentcommand` does.
- A service whose binary is the attacker's own program, as with Impacket psexec (RemComSvc) and Sysinternals PsExec (PSEXESVC.exe or the name set with `-r`).
- A command under WmiPrvSE.exe with `\TEMP\nessus_` in the line. `filter_optional_nessus` drops it, and an attacker can add the string on purpose.

Assumptions

- Sysmon runs on the host and logs event 1 for processes started by WmiPrvSE.exe and services.exe.
- `ParentImage` and `CommandLine` are captured.
- `OriginalFileName` is captured. Without it a renamed copy is missed.
- The events are forwarded to the SIEM and indexed.

A blind spot appears whenever one of these assumptions breaks, for example when Sysmon is stopped on the host.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| Nessus credentialed scans | cmd.exe under WmiPrvSE.exe writing to `\TEMP\nessus_*` | excluded by `filter_optional_nessus`. 11 commands cut in BOTS v1 |
| Management and monitoring agents | PowerShell or cmd.exe under WmiPrvSE.exe, agent script or path in `CommandLine`, agent service account in `User` | not seen in the test logs, goodlog or BOTS. Exclude by `CommandLine` and `User` together in a `filter_optional_*` |
| Vulnerability scanners other than Nessus | cmd.exe under WmiPrvSE.exe, scanner file names in `CommandLine`, Security event 4624 from the scanner host | not seen in the test logs, goodlog or BOTS. Exclude by the `CommandLine` pattern, as `filter_optional_nessus` does |
| Services with a shell as the binary path | services.exe parent, command line matches `Service File Name` in Security event 4697 or System event 7045 | not seen in the test logs, goodlog or BOTS. Confirm with the service owner |

## Validation

In an isolated VM restored from a snapshot, run the [Atomic Red Team T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) test "Execute a Command as a Service" as administrator. It needs no downloads. Run the rule's search in the SIEM over the test time. The search returns Sysmon event 1 with `ParentImage` `C:\Windows\System32\services.exe` and `Image` `C:\Windows\System32\cmd.exe`.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). goodlog runs it over five clean baselines from [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) v0.8.5 with [tools/goodlog.sh](../../../tools/goodlog.sh). What it finds is listed in False Positives.

| Data | Result |
|---|---|
| attack_data T1021.002 Impacket log (wmiexec, dcomexec, smbexec) | 6 hits: WmiPrvSE.exe 5, services.exe 1 |
| attack_data T1021.002 smbexec log | 1 hit, services.exe |
| attack_data T1543.003 lateral_movement_powershell log | 1 hit, services.exe |
| attack_data T1547.001 Atomic run | 0 hits |
| BOTS v1 to v3 | 4 hits, PowerShell started by WmiPrvSE.exe (3 hosts in v2, 1 in v3). 11 Nessus commands in v1 excluded by `filter_optional_nessus` |

The Splunk search converted from the rule returns the same counts on the four attack_data logs. The BOTS check used a Splunk search that follows the rule logic. BOTS has no `OriginalFileName`, so only the file name branch was checked there.

## Priority

Medium by default. High under the following conditions:

- `CommandLine` runs PowerShell with `-enc`, base64 or gzip.
- Security event 4624 logon type 3 from another host comes right before the alert.

## Response

1. Read `ParentImage`: services.exe points to a service, WmiPrvSE.exe to a WMI call.
2. Find the source host and account in Security event 4624 logon type 3 on the host at the alert time, if Security logs are collected. For a service, `User` is the service account, not the account that came in.
3. For a service, System event 7045 or Security event 4697 gives its name and binary path.
4. Decode the PowerShell command line: `-enc` values, base64 and gzip layers.
5. Find other commands of the same WMI session by `LogonId`. Find what the shell did by `ProcessGuid`: child processes and network connections, Sysmon event 3.
6. A management agent or a scanner run confirmed with its owner explains the alert.
7. If steps 1–6 do not explain the alert, escalate it as remote execution: isolate the host, reset the account of the network logon and search other hosts for the same command line or service name.

## Additional Resources

- [Create method of the Win32_Process class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-process)
- [SigmaHQ: Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmiprvse_spawns_powershell.yml), a similar rule. It covers only PowerShell under WmiPrvSE.exe.
- [SigmaHQ: Suspicious WmiPrvSE Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmiprvse_susp_child_processes.yml), a similar rule. It also catches wscript, cscript, mshta and rundll32 under WmiPrvSE.exe, but takes cmd.exe only with an interpreter name in the command line.
