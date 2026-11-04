# Change Of The ld.so.preload File

## Goal

Detect a change of /etc/ld.so.preload, the file that makes every program on a host load the libraries it lists.

## Categorization

[Stealth](https://attack.mitre.org/tactics/TA0005/) / [Hijack Execution Flow: Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/), [Execution](https://attack.mitre.org/tactics/TA0002/) / [Hijack Execution Flow: Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/)

Platforms

- Linux

Tooling

- auditd, PATH record of a file watch

## Strategy Abstract

- auditd PATH records from a watch on the file are the only data source. No enrichment in the SIEM.
- The rule fires when `name` in a PATH record ends with ld.so.preload.
- A watch with `-p wa` gives no record for a read. The False Positives section lists what is left.

## Technical Context

/etc/ld.so.preload lists shared libraries. The dynamic linker loads them into every program started on the host. An attacker with root adds the path of a library to this file, and the next program loads it. The library can override functions of other libraries. The file stays after a reboot, so the library keeps loading until the line is removed.

A watch on the file makes auditd log each change. The PATH record holds the name as the program passed it and `nametype` tells what happened to that name. A record from the test data:

```
type: PATH
name: /etc/ld.so.preload
nametype: CREATE
```

A program running in /etc can write the file by its short name. `name` is then ld.so.preload and the folder is in `cwd` of the CWD record with the same `msg`.

The program is in the SYSCALL record with the same `msg`.

[Shell Redirect Into ld.so.preload](../ld_so_preload_shell_redirect/README.md) catches the same change in EXECVE records and needs no watch on the file. One `bash -c` write on a host with both gives two alerts.

## Blind Spots and Assumptions

Blind spots

- The LD_PRELOAD environment variable, which needs no file change.
- Replacement of a library already listed in the file.
- A patched dynamic linker that reads another file.

Assumptions

- auditd has a watch on the file without `r` in its permissions: `-w /etc/ld.so.preload -p wa`.
- PATH records reach the SIEM unchanged, with `type`, `name`, `nametype` and `msg` extracted as fields.

A blind spot appears whenever one of these assumptions breaks, for example when an attacker stops auditd or deletes its rules.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| Administrator or configuration management adding a memory allocator or hardening library, such as [libhardened_malloc.so](https://github.com/GrapheneOS/hardened_malloc) | the library comes from a package or a known path, a login session in `AUID` of the SYSCALL record | not seen in the test logs. Confirm with the change owner, no exclusion |
| Watch with `r` in its permissions | `nametype` NORMAL, the SYSCALL record shows a program that only opens the file for reading | not seen in the test logs. Remove `r` from the watch |

## Validation

Run the Atomic Red Team test "Shared Library Injection via /etc/ld.so.preload" from [T1574.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.006/T1574.006.md) in an isolated VM restored from a snapshot, with the watch from the Assumptions loaded. Run the rule's search in the SIEM over the test time. The search returns a PATH record with `name` /etc/ld.so.preload.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). [tools/goodlog.sh](../../../tools/goodlog.sh) has clean baselines for Windows only.

| Data | Result |
|---|---|
| attack_data T1574.006, raw audit.log excerpt (full path in `name`) | 4 hits |
| attack_data T1574.006, ausearch -i excerpt of a run in /etc (no folder in `name`) | 3 hits |
| CAM-LDS scenario 2, video server, variant rootkit (no watch on the file) | 0 hits |

The Splunk search converted from the rule returns the same counts on these three logs.

## Priority

High in all cases.

## Response

1. Read `name` and `nametype`. For a name without a folder, read `cwd` in the CWD record with the same `msg`.
2. Join the SYSCALL record with the same `msg`: `exe`, `comm`, `AUID`, `UID`, `tty` and `ppid`.
3. Read the file and check each library it lists: `dpkg -S` or `rpm -qf` for the owner, and its hash against a clean host. A loaded library can hide lines from programs on this host, so a disk image is the better source.
4. Follow `ppid` up the chain and list program starts around the alert to see how the library arrived. A `bash -c` command with spaces is in hex. Decode it to see all its steps.
5. If an administrator or a change explains the write, confirm it with its owner.
6. If steps 1–5 do not explain the change, escalate it as dynamic linker hijacking: isolate the host, keep the file and the library for analysis, and look for the same library hash on other hosts.

## Additional Resources

- [ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html)
- [SigmaHQ: Modification of ld.so.preload](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/path/lnx_auditd_ld_so_preload_mod.yml), a similar rule. It compares `name` with the full path, so a name without a folder does not match.
- [Splunk ESCU: Linux Auditd Preload Hijack Via Preload File](https://github.com/splunk/security_content/blob/develop/detections/endpoint/linux_auditd_preload_hijack_via_preload_file.yml), a similar search. It joins PATH and CWD to rebuild the full path.
