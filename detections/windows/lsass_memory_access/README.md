# Potential Credential Dumping Via LSASS Process Access

## Goal

Detect a process that opens lsass.exe with memory read access or through a minidump function, the way credential dumping tools do.

## Categorization

[Credential Access](https://attack.mitre.org/tactics/TA0006/) / [OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

Platforms

- Windows

Tooling

- Sysmon, event 10 (process access)

## Strategy Abstract

- Sysmon event 10 with `TargetImage` lsass.exe is the only data source. No enrichment.
- The rule fires when `CallTrace` contains dbgcore.dll, dbghelp.dll or comsvcs.dll, the libraries that write minidumps.
- It also fires on a mask used by Mimikatz (0x1010, 0x1438, 0x143a) or on full access (0x1fffff, 0x1f3fff, 0x1f1fff).
- Known false positives are excluded in the rule by process path and call stack. The False Positives section lists them.

## Technical Context

LSASS keeps NTLM hashes, Kerberos tickets and sometimes clear text passwords of users who logged on to the host. A tool opens lsass.exe with read access. Mimikatz parses its memory in place. ProcDump, Task Manager "Create dump file" and comsvcs.dll MiniDump save it to a minidump file for offline parsing.

Two fields of Sysmon event 10 are used here. `GrantedAccess` is the access the process got. `CallTrace` is the call stack of the open call. To find the caller, skip the frames of ntdll, kernel32 and kernelbase, and the wow64 frames of 32-bit programs. The next frame shows which module made the call. ProcDump from the test data, shortened:

```
SourceImage:   C:\AtomicRedTeam\atomics\T1003.001\bin\procdump64.exe
TargetImage:   C:\Windows\system32\lsass.exe
GrantedAccess: 0x1fffff
CallTrace:     C:\Windows\SYSTEM32\ntdll.dll+a5a94|C:\Windows\SYSTEM32\ntdll.dll+6cd1a|
               C:\Windows\System32\KERNEL32.DLL+1cff8|C:\Windows\System32\KERNEL32.DLL+25a87|
               C:\Windows\SYSTEM32\dbgcore.DLL+15a38|...
```

Here that frame is dbgcore.dll, the minidump library, so ProcDump opened lsass to write a dump.

In `GrantedAccess`, 0x1fffff, 0x1f3fff and 0x1f1fff all mean full access to the process. Older programs show up with the last two. 0x1010, 0x1438 and 0x143a are the masks Mimikatz uses.

The rule ignores 0x1410, which lets a process read memory and basic process information, because legitimate software asks for it often: .NET programs that list process modules, and in the clean baselines mostly MRT.exe, DropboxUpdate.exe, msiexec.exe and WmiPrvSE.exe. A dumping tool that asks only for 0x1410 is caught only when a minidump library shows up in `CallTrace`.

## Blind Spots and Assumptions

Blind spots

- A handle to lsass obtained from another process instead of opening lsass directly.
- Kernel drivers, which read lsass memory without opening it as a process.
- Code injected into wininit.exe or csrss.exe.
- Code running inside msiexec.exe or Sysmon64.exe whose call stack holds one of the excluded modules.
- A tool that reads memory with 0x1410 and no minidump library, such as some Mimikatz builds from late 2016 and early 2017 and NanoDump on Windows 8.1 and older.
- NanoDump fork and snapshot modes, which open lsass with 0x1080 (0x1480 on Windows 8.1 and older) to clone it.

Assumptions

- Sysmon runs on the host and logs event 10 when a process opens lsass.exe.
- `CallTrace` is recorded for these events.
- The events are forwarded to the SIEM and indexed.

A blind spot appears whenever one of these assumptions breaks, for example when an attacker stops Sysmon or changes its config.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| wininit.exe and csrss.exe | `SourceImage` in `C:\Windows\System32`, 0x1fffff | excluded by `filter_main_system`. 1 to 3 events of each on every baseline |
| msiexec.exe with perfproc.dll | `SourceImage` `C:\Windows\System32\msiexec.exe`, `C:\Windows\System32\perfproc.dll` in `CallTrace` | excluded by `filter_main_msiexec`. 14 events on win10-client, 49 on win11-client |
| Sysmon64.exe | `SourceImage` `C:\Windows\Sysmon64.exe`, Sysmon64.exe frames in `CallTrace`, 0x1fffff | excluded by `filter_main_sysmon`. 11 events on win2022-ad |
| Installer custom actions | `SourceImage` msiexec.exe, vendor CustomAction.dll in `CallTrace` | the Zoom installer is excluded by `filter_optional_zoom`, 1 event on win10-client and 1 on win11-client. Others by `CallTrace` in a `filter_optional_*` |
| Process Explorer run as administrator | procexp64.exe, 0x1fffff about every 1.3 seconds while it runs, procexp64.exe as the first frame after the system libraries in `CallTrace` | kept: Process Explorer opens lsass with the same access as a dumping tool. Listed in `tools/goodlog-known-fps.csv` |
| Administrator dumping lsass for troubleshooting | taskmgr.exe or ProcDump in an interactive admin session, a .dmp file written by it or its child (Sysmon event 11) | confirm with the administrator, no exclusion |
| Antivirus, EDR and backup agents | `SourceImage` under the vendor folder in Program Files, full access | not seen in the test logs or goodlog. Exclude by full path in a `filter_optional_*` |

## Validation

In an isolated VM restored from a snapshot, run the [Atomic Red Team T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) test "Dump LSASS.exe Memory using comsvcs.dll" as administrator. It needs no downloads. Run the rule's search in the SIEM over the test time. The search returns Sysmon event 10 with `SourceImage` `C:\Windows\System32\rundll32.exe`. In the attack_data T1003.001 Atomic run the same test gave two such events.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). goodlog runs it over five clean baselines from [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) v0.8.5 with [tools/goodlog.sh](../../../tools/goodlog.sh). What it finds is listed in False Positives.

| Data | Result |
|---|---|
| attack_data T1003.001 Atomic run (ProcDump, comsvcs, Dumpert, WCE, Task Manager) | 53 hits |
| attack_data T1003.001 creddump run (Mimikatz, comsvcs, xordump) | 5 hits |
| attack_data T1547.001 Atomic run | 0 hits |

The Splunk search converted from the rule returns the same counts on these three logs.

## Priority

High in all cases.

## Response

1. Check `SourceImage`: path, signature, whether it is a known security or backup agent.
2. Pivot on `SourceProcessGUID` to the process creation event: parent, command line, user.
3. Look for a .dmp file written by the same process or its child (Sysmon event 11).
4. If an administrator ran Task Manager, ProcDump or Process Explorer, confirm it with them.
5. If steps 1–4 do not explain the access, escalate it as credential theft: isolate the host, reset credentials of accounts that logged on to the host before the access and look for logons with those accounts from other hosts.

## Additional Resources

- [Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Credentials processes in Windows authentication](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication)
- [SigmaHQ: Potential Credential Dumping Activity Via LSASS](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_memdump.yml), a similar rule. It does not check 0x1010 and skips processes running as NT AUTHORITY.
