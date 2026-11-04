# PAM Module File In Command Line Arguments

## Goal

Detect a command that names a PAM module file in its arguments, the way an attacker replaces pam_unix.so with a backdoored copy.

## Categorization

[Credential Access](https://attack.mitre.org/tactics/TA0006/) / [Modify Authentication Process: Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003/), [Persistence](https://attack.mitre.org/tactics/TA0003/) / [Modify Authentication Process: Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003/), [Defense Impairment](https://attack.mitre.org/tactics/TA0112/) / [Modify Authentication Process: Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003/)

Platforms

- Linux

Tooling

- auditd, EXECVE record (program arguments)

## Strategy Abstract

- auditd EXECVE records of program starts are the only data source. No enrichment in the SIEM.
- The rule fires when an argument of any program ends with a file named pam_*.so or a .so file in a folder named security.
- The .so ending leaves out the settings in /etc/security. The False Positives section lists what is left.

## Technical Context

PAM is the library that sshd, su, sudo and login call to check a login. Each service reads a list of modules from /etc/pam.d and loads every module as a shared library. pam_unix.so checks the password the user typed, so it receives that password in clear text.

An attacker with root can replace this file with a modified copy. The copy keeps working and can also save passwords or accept one extra password. The next `su` or `sudo` loads the new file.

A module name without a path in /etc/pam.d is looked up in the default module folder. That folder is /lib/security or /lib64/security by pam.d(5), and /lib/x86_64-linux-gnu/security or /usr/lib/x86_64-linux-gnu/security on Debian and Ubuntu. The rule accepts any folder named security. Settings live in /etc/security and do not end in .so, such as opasswd and pam_env.conf.

A replacement keeps the name of the old module, so a command names either the full path or the module file: `cp x /lib64/security/pam_unix.so`, `cp pam_unix.so /lib64/security/` or `mv /tmp/x pam_unix.so` from the module folder. The rule has one mask for each form. The name mask also matches a download of the file, such as `wget http://host/pam_unix.so`, and any .so file with pam_ inside its name, such as libpam_misc.so.

auditd writes each argument into its own field: `a0` is the program as it was typed, `a1` and later fields are the arguments. A longer command moves the path to a later field, so the rule checks `a1` to `a8`. `mv` from the test data:

```
type: EXECVE
a0: mv
a1: pam_unix.so
a2: /lib/x86_64-linux-gnu/security/pam_unix.so
```

The record does not say whether the program reads or writes the file. A program that only reads it or searches for its name also matches, and `a0` is the first thing to check. dpkg and rpm unpack module files by themselves, so a package update gives no such argument.

## Blind Spots and Assumptions

Blind spots

- A module outside a security folder with a name other than pam_*.so, named by its full path in /etc/pam.d, such as /tmp/x.so.
- A change in /etc/pam.d that adds a module, such as pam_exec.so.
- A new module with a name other than pam_*.so copied by a folder or relative path, such as `cp x.so /lib64/security/`.
- A write without the path in the arguments: a shell redirect, an archive or package that holds the file, a sync of a whole folder or a program with the path inside it.
- A path after `a8`.
- A path with a space or another special character, which auditd writes in hex.

Assumptions

- auditd logs execve for root, for example `-a always,exit -F arch=b64 -S execve -F euid=0`.
- EXECVE records reach the SIEM unchanged, with `type` and `a0` to `a8` extracted as fields.

A blind spot appears whenever one of these assumptions breaks, for example when an attacker stops auditd or deletes its rules.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| Administrator checking a module with ls, ldd or sha256sum or searching for its name with grep, find or dpkg -S | a program that only reads in `a0`, a login session in `AUID` of the SYSCALL record, a terminal | not seen in the test logs. Confirm with the administrator. If one such `a0` repeats, add a `filter_optional_*` block with it |
| Vulnerability scanner or integrity check script that names module files | the same command at regular times, no terminal | not seen in the test logs. Add a `filter_optional_*` block with its `a0` and path |
| Source build or vendor installer of a third party PAM module | install or cp in `a0`, a new module name, make or the installer in the `ppid` chain | not seen in the test logs. Confirm with the change owner, no exclusion |
| Command that names another library with pam_ inside its name, such as libpam_misc.so | the file is outside the module folders, such as /usr/lib/x86_64-linux-gnu/libpam_misc.so | not seen in the test logs. Add a `filter_optional_*` block with its name |

## Validation

In an isolated VM with Debian or Ubuntu restored from a snapshot, load an execve audit rule. As root, copy a module to a new name in the same folder: `cp /lib/x86_64-linux-gnu/security/pam_permit.so /lib/x86_64-linux-gnu/security/pam_test.so`. PAM does not load the copy until a file in /etc/pam.d names it. Run the rule's search in the SIEM over the test time. The search returns the EXECVE record with `a0` cp and both paths in `a1` and `a2`.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). [tools/goodlog.sh](../../../tools/goodlog.sh) has clean baselines for Windows only.

| Data | Result |
|---|---|
| CAM-LDS scenario 1, video server, variant sudo + pam (wget, then mv with `AUID` unset, no PATH record of the rename) | 2 hits: wget and mv |
| CAM-LDS scenario 1, video server, variant cron + pam (the same commands with `AUID` root, with a PATH record of the rename) | 2 hits: wget and mv |
| CAM-LDS scenario 1, video server, variant sudo + localaccount (the same exploit without the PAM step, linPEAS runs cat on /etc/pam.d/sshd) | 0 hits |
| CAM-LDS scenario 3, repository server (the Wazuh agent runs stat on /etc/security/opasswds) | 0 hits |
| CAM-LDS scenario 7, Docker host (the Wazuh agent runs cat on /etc/security/pwquality.conf and stat on /etc/security/opasswd) | 0 hits |

The Splunk search converted from the rule returns the same counts on these five logs.

## Priority

High in all cases.

## Response

1. Read `a0` and the arguments: which program ran, and whether it writes the module (mv, cp, install, dd), downloads it (wget, curl) or only reads it or searches for its name (ls, ldd, grep).
2. Join the SYSCALL record with the same `msg`: `exe`, `AUID`, `UID`, `tty` and `ppid`.
3. Compare the file with the package: `dpkg -V libpam-modules` or `rpm -V pam`. Use `dpkg -S` or `rpm -qf` to find a module that no package owns. Compare its hash with a clean host of the same version.
4. Follow `ppid` up the chain and list program starts around the alert with the same `pid` or `ppid` to see how the file arrived, such as wget, curl or scp. A `bash -c` command with spaces is in hex. Decode it to see all its steps, such as wget and mv. A terminal in `tty` alone does not mean an administrator: python3 with pty.spawn in the chain also gives a terminal.
5. Search /etc/pam.d for the module name to see which services load it.
6. If an administrator, a scanner or a change explains the command, confirm it with its owner.
7. If steps 1–6 do not explain the command, escalate it as a PAM backdoor: isolate the host, keep the file for analysis, reinstall the module from a trusted package, reset the passwords used on the host since the alert and look for the same file hash on other hosts.

## Additional Resources

- [pam.d(5)](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html)
- [Nextron Systems: Plague, a PAM-based backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [Elastic: Pluggable Authentication Module or Configuration Creation](https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_pluggable_authentication_module_creation.toml), a similar rule on Elastic Defend file events. It also sees writes without the name in the arguments and skips /usr/bin/install.
