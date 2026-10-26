# Scheduled Task Created With Interpreter Or Proxy Binary Via Schtasks.EXE

## Goal

Detect a scheduled task registered or changed through schtasks whose action runs a script interpreter or a proxy binary.

## Categorization

[Execution](https://attack.mitre.org/tactics/TA0002/), [Persistence](https://attack.mitre.org/tactics/TA0003/), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) / [Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

Platforms

- Windows

Tooling

- Sysmon, event 1 (process creation)

## Strategy Abstract

- Sysmon event 1 for schtasks.exe is the only data source. No enrichment.
- The rule fires when `CommandLine` has `/Create` or `/Change` and an interpreter, proxy binary or downloader from a fixed list.
- schtasks.exe is matched by file name or `OriginalFileName`, so a renamed copy fires too.
- The rule has no filters, see False Positives.

## Technical Context

schtasks `/Create` and `/Change` set the task action in `/TR`. The Task Scheduler service runs the action later, as the account in `/RU`. The alert fires when the task is registered. The payload starts later, on the schedule set by `/SC`. Event from the test data, shortened:

```
User:             ATTACKRANGE\Administrator
ParentImage:      C:\Windows\System32\cmd.exe
Image:            C:\Windows\System32\schtasks.exe
OriginalFileName: sctasks.exe
CommandLine:      "C:\Windows\System32\schtasks.exe" /Create /F /TN "SoundIentifier" /TR "wmic process call create "C:\Users\Public\Disk101.ini:59e9c935"" /SC Once /ST 10:05
```

The task runs `wmic process call create` on the NTFS stream path `C:\Users\Public\Disk101.ini:59e9c935`. On Server 2016 (schtasks.exe 10.0.14393) `OriginalFileName` is `sctasks.exe`, as in this event, and the rule accepts both names.

The list holds script interpreters, downloaders and proxy binaries: signed Windows programs that run code passed to them, such as rundll32, mshta or wmic. It is matched anywhere in `CommandLine`, so a task name like `/TN "PowerShell Update"` fires too.

Tasks that run an executable from a user-writable folder are left out because installers register such tasks too. In goodlog the TeamViewer installer registers `TVInstallRestore` with `/TR` on `TeamViewer_.exe` in `%TEMP%`.

## Blind Spots and Assumptions

Blind spots

- Tasks defined with `/XML`, the action lives in the XML file.
- Tasks registered without schtasks.exe: PowerShell `Register-ScheduledTask`, the COM API, the WMI class `PS_ScheduledTask`, Impacket atexec, direct registry writes as GhostTask does.
- Interpreters and proxy binaries missing from the list.
- A document in `/TR` that opens through a file association, like `compmgmt.msc`.
- cmd.exe written in a form the list does not spell: with no switch, as a quoted path, with two spaces before the switch, with no space after it, or with another switch before `/c`, like `cmd /d /c`.
- A task that runs an executable from a user-writable folder directly.

Security event 4698 and the Microsoft-Windows-TaskScheduler/Operational log, when enabled, cover part of this gap.

Assumptions

- Sysmon runs on the host and logs event 1 for schtasks.exe.
- `Image`, `OriginalFileName` and `CommandLine` are captured.
- The events are forwarded to the SIEM and indexed.

A blind spot appears whenever one of these assumptions breaks, for example when Sysmon is stopped on the host before the task is registered.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| Admin scripts | `/Create` or `/Change` with powershell or cmd in `/TR`, `ParentImage` is a deployment agent | not seen in the test logs, goodlog or BOTS. Exclude by `ParentImage` and `User` together in a `filter_optional_*` |
| Installers and updaters | `/Create` with rundll32 or a script interpreter in `/TR`, `ParentImage` is an installer | not seen in the test logs, goodlog or BOTS. Task names are set by the creator, so exclude by `ParentImage` and the `/TR` path in a `filter_optional_*` |

## Validation

In an isolated VM restored from a snapshot, run the [Atomic Red Team T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) test "Scheduled Task Startup Script" as administrator. It needs no downloads. Run the rule's search in the SIEM over the test time. The search returns two Sysmon events 1 with `Image` `C:\Windows\System32\schtasks.exe`, one for each task, with `cmd.exe /c calc.exe` in `CommandLine`.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). goodlog runs it over five clean baselines from [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) v0.8.5 with [tools/goodlog.sh](../../../tools/goodlog.sh). What it finds is listed in False Positives.

| Data | Result |
|---|---|
| attack_data T1053.005 schtasks run | 2 hits |
| attack_data T1547.001 Atomic run | 0 hits |
| BOTS v1 to v3, 7404 task creations and changes by schtasks.exe | 4 hits, all the Empire `Updater` task on four hosts |

The Splunk search converted from the rule returns the same counts on the two attack_data logs. The BOTS check used a Splunk search that follows the rule logic. BOTS has no `OriginalFileName`, so only the `Image` branch was checked there.

## Priority

Medium by default. High under the following conditions:

- `/RU` is `SYSTEM`, `NT AUTHORITY\SYSTEM` or `""`. All three mean the System account.
- `/TR` points to `C:\Users\Public`, a temp folder or an NTFS stream.

## Response

1. Parse `CommandLine`: `/TN` gives the task name, `/TR` the action, `/SC` the schedule, `/RU` the run-as account, `/S` a remote host.
2. Check the file in `/TR`: does it exist and which process created it, Sysmon event 11.
3. Check whether the task already ran: a process with the `/TR` command line whose parent is the Task Scheduler svchost.exe, `svchost.exe -k netsvcs -p` with or without `-s Schedule`.
4. Read `ParentImage` and `User` of the alerting event. A deployment agent or an admin shell with a change record explains it, confirm with the owner.
5. If steps 1–4 do not explain the alert, escalate it as persistence: save the task definition with `schtasks /Query /TN <name> /XML`, disable the task and look for the same task name or action on other hosts.

## Additional Resources

- [LOLBAS](https://lolbas-project.github.io/)
- [schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [SigmaHQ: Suspicious Command Patterns In Scheduled Task Creation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_schtasks_susp_pattern.yml), a similar rule. It needs cmd with `/sc minute` or `/ru system`, an encoded or download command, or a script host with a user folder.
- [SigmaHQ: Schtasks From Suspicious Folders](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_schtasks_folder_combos.yml), a similar rule. It needs PowerShell or cmd together with `C:\ProgramData` in the line.
- [SigmaHQ: Suspicious Modification Of Scheduled Tasks](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_schtasks_change.yml), a similar rule. It covers `/Change` only and needs a suspicious folder together with a binary from its list.
