# Command Or Script Interpreter Running Under Another Name

## Goal

Detect a command or script interpreter running from a file under a different name.

## Categorization

[Stealth](https://attack.mitre.org/tactics/TA0005/) / [Masquerading: Rename Legitimate Utilities](https://attack.mitre.org/techniques/T1036/003/)

Platforms

- Windows

Tooling

- Sysmon 10 or later, event 1 (process creation) with `OriginalFileName`

## Strategy Abstract

- Sysmon event 1 with `OriginalFileName` is the only data source. No enrichment.
- The rule fires when `OriginalFileName` names one of six interpreters, cmd.exe, PowerShell, pwsh, wscript, cscript or mshta, and the file name in `Image` is not one of their usual names.
- The rule has no filters, see False Positives.

## Technical Context

`OriginalFileName` comes from the version resource of the PE file. Copying and renaming a binary leaves the resource untouched, so a copy of cmd.exe named lsass.exe still reports `Cmd.Exe`. In the test data Sysmon once logged the field with a `.MUI` tail, so the rule compares the start of the value. Event from the Atomic Red Team T1036.003 test data, shortened:

```
User:              ATTACKRANGE\Administrator
ParentImage:       C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\system32\cmd.exe" /c "copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe & %SystemRoot%\Temp\lsass.exe /B"
Image:             C:\Windows\Temp\lsass.exe
OriginalFileName:  Cmd.Exe
CommandLine:       C:\Windows\Temp\lsass.exe /B
```

The parent command first copies cmd.exe to `C:\Windows\Temp\lsass.exe`, then starts the copy.

The list is limited to interpreters on purpose. In the false positive test data four ordinary system and agent programs have a file name that differs from `OriginalFileName`, like dfsrs.exe (`dfsr.exe`) and unsecapp.exe (`unsecapp.dll`). A check across every binary would turn them into alerts.

## Blind Spots and Assumptions

Blind spots

- One interpreter renamed to another, like cscript.exe as wscript.exe.
- An edited `OriginalFileName`.
- Other programs under system names.
- Double extensions on files that are not interpreters (T1036.007).
- Interpreters missing from the list, like powershell_ise.exe.
- A binary without a version resource, where Sysmon logs `OriginalFileName` as `-`.
- A copy under its own name in another folder, like `C:\Users\Public\cmd.exe`.

Assumptions

- Sysmon 10 or later runs on the host and logs event 1.
- `OriginalFileName` is written for these events.
- The events are forwarded to the SIEM and indexed.

A blind spot appears whenever one of these assumptions breaks, for example an old Sysmon agent that does not report `OriginalFileName`.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| Portable or vendor tools | a renamed cmd.exe or PowerShell inside the tool folder, vendor path in `Image` | not seen in the test logs or goodlog. Exclude by the full `Image` path in a `filter_optional_*` |

## Validation

In an isolated VM restored from a snapshot, run the [Atomic Red Team T1036.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md) test "Masquerading as Windows LSASS process". It needs no downloads. Invoke-AtomicTest waits for its 120-second timeout before the test ends. Run the rule's search in the SIEM over the test time. The search returns Sysmon event 1 with `Image` `C:\Windows\Temp\lsass.exe` and `OriginalFileName` `Cmd.Exe`. The same test gave one such event in the attack_data T1036.003 Atomic run.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). goodlog runs it over five clean baselines from [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) v0.8.5 with [tools/goodlog.sh](../../../tools/goodlog.sh). What it finds is listed in False Positives.

| Data | Result |
|---|---|
| attack_data T1036.003 Atomic run | 6 hits: cmd.exe as lsass.exe, lsm.exe and svchost.exe, PowerShell as taskhostw.exe, wscript.exe as svchost.exe, cscript.exe as notepad.exe |
| attack_data T1547.001 Atomic run | 0 hits |

The Splunk search converted from the rule returns the same counts on the two attack_data logs.

## Priority

High in all cases.

## Response

1. Compare `Image` and `OriginalFileName`: `OriginalFileName` is the real program, `Image` is the name it runs under. If `Hashes` is written, compare it with the hash of that interpreter on the same host.
2. Find how the copy was made: the copy command in `ParentCommandLine` or one process higher, and Sysmon event 11 for the file creation.
3. Follow the process by `ProcessGuid`: child processes and network connections, Sysmon event 3. Look for autostart entries that reference the path.
4. A vendor tool with a bundled renamed copy confirmed with its owner explains the alert.
5. If steps 1–4 do not explain the alert, escalate it as masquerading: isolate the host and search other hosts for the same `Hashes` value under other names.

## Additional Resources

- [Rename System Utilities, Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/rename-system-utilities/)
- [SigmaHQ: Potential Defense Evasion Via Rename Of Highly Relevant Binaries](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_renamed_binary_highly_relevant.yml), a similar rule. It covers more binaries, among them certutil, rundll32, PsExec and powershell_ise.exe, but leaves out cmd.exe.
- [SigmaHQ: Potential Defense Evasion Via Binary Rename](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_renamed_binary.yml), a similar rule. It covers a renamed cmd.exe together with archivers and net, netsh and wevtutil.
