# Shell Redirect Into ld.so.preload

## Goal

Detect a shell command string that redirects output into /etc/ld.so.preload, the file that makes every program on a host load the libraries it lists.

## Categorization

[Stealth](https://attack.mitre.org/tactics/TA0005/) / [Hijack Execution Flow: Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/), [Execution](https://attack.mitre.org/tactics/TA0002/) / [Hijack Execution Flow: Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/)

Platforms

- Linux

Tooling

- auditd, EXECVE record (program arguments)

## Strategy Abstract

- auditd EXECVE records of program starts are the only data source. No enrichment in the SIEM.
- The rule fires when an argument in `a1` to `a8` holds `>` right before /etc/ld.so.preload, with or without a space.
- A command that only reads the file has no `>` in its arguments. The False Positives section lists what is left.

## Technical Context

/etc/ld.so.preload lists shared libraries. The dynamic linker loads them into every program started on the host. An attacker with root adds the path of a library to this file, and the next program loads it. The library can override functions of other libraries. The file stays after a reboot, so the library keeps loading until the line is removed.

`bash -c` and `sh -c` take a whole command as one argument, so a redirect inside it reaches the EXECVE record. The kernel writes an argument in hex when it has a space, a double quote or a byte outside printable ASCII, so the rule has masks for the hex form and the text form. A record from the test data:

```
type: EXECVE
a0: bash
a1: -c
a2: 6563686F202F7573722F6C69622F73656C696E75782E736F2E33203E3E202F6574632F6C642E736F2E7072656C6F6164
```

`a2` decodes to `echo /usr/lib/selinux.so.3 >> /etc/ld.so.preload`.

[Change Of The ld.so.preload File](../ld_so_preload_modified/README.md) catches the same change in PATH records of a file watch and sees a write by any program. One `bash -c` write on a host with both gives two alerts.

## Blind Spots and Assumptions

Blind spots

- A write without a redirect in the arguments: tee, cp, mv, sed -i, dd or a program of its own.
- A redirect typed in an open shell or kept in a script file. The shell does it without a new program, so no EXECVE record holds it.
- A redirect to the short name from /etc: `echo x > ld.so.preload`.
- A quote, a tab or a second space between `>` and the path.
- A command string built at run time or encoded, such as base64 piped to sh.

Assumptions

- auditd logs execve for root, for example `-a always,exit -F arch=b64 -S execve -F euid=0`.
- EXECVE records reach the SIEM unchanged, with `type` and `a0` to `a8` extracted as fields.

A blind spot appears whenever one of these assumptions breaks, for example when an attacker stops auditd or deletes its rules.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| Administrator or configuration management adding a memory allocator or hardening library, such as [libhardened_malloc.so](https://github.com/GrapheneOS/hardened_malloc) | the decoded string names a library from a package or a known path, a login session in `AUID` of the SYSCALL record | not seen in the test logs. Confirm with the change owner, no exclusion |

## Validation

Run the Atomic Red Team test "Shared Library Injection via /etc/ld.so.preload" from [T1574.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.006/T1574.006.md) in an isolated VM restored from a snapshot, with the execve audit rule loaded. Run the rule's search in the SIEM over the test time. The search returns two EXECVE records: `a0` sudo with the string in `a3` and `a0` sh with the string in `a2`.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). [tools/goodlog.sh](../../../tools/goodlog.sh) has clean baselines for Windows only.

| Data | Result |
|---|---|
| CAM-LDS scenario 2, video server, variant rootkit (bash -c with a redirect) | 1 hit |
| CAM-LDS scenario 1, video server, variant sudo + localaccount (cat reads the file) | 0 hits |

The Splunk search converted from the rule returns the same counts on these two logs.

## Priority

High in all cases.

## Response

1. Decode the string from hex and read which library it adds.
2. Join the SYSCALL record with the same `msg`: `exe`, `AUID`, `UID`, `tty` and `ppid`.
3. Read the file and check each library it lists: `dpkg -S` or `rpm -qf` for the owner, and its hash against a clean host. A loaded library can hide lines from programs on this host, so a disk image is the better source.
4. Follow `ppid` up the chain and list program starts around the alert to see how the library arrived.
5. If an administrator or a change explains the command, confirm it with its owner.
6. If steps 1–5 do not explain the command, escalate it as dynamic linker hijacking: isolate the host, keep the file and the library for analysis, and look for the same library hash on other hosts.

## Additional Resources

- [ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html)
- [Linux kernel: audit_string_contains_control](https://github.com/torvalds/linux/blob/master/kernel/audit.c)
- [SigmaHQ: Modification of ld.so.preload](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/path/lnx_auditd_ld_so_preload_mod.yml), a similar rule on PATH records. It needs a watch on the file.
