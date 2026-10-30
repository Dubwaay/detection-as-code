# Suspicious Tool Or Terminal Process Under Web Server Account

## Goal

Detect commands that an attacker runs through a web application, such as a web shell or a command injection.

## Categorization

[Persistence](https://attack.mitre.org/tactics/TA0003/) / [Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/), [Execution](https://attack.mitre.org/tactics/TA0002/) / [Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)

Platforms

- Linux

Tooling

- auditd, SYSCALL record (program start)

## Strategy Abstract

- auditd SYSCALL records of program starts (`execve`) are the only data source. No enrichment in the SIEM.
- The rule fires when a web server account without a login session starts bash, Python, curl, nc or a similar tool, a program from a temporary directory, or any program with a terminal.
- `sh`, which web applications use, and administrators with a login session do not match. The False Positives section lists what is left.

## Technical Context

A web server runs its worker processes under a service account: www-data on Debian and Ubuntu, apache or nginx on RHEL. The code of the web application runs under the same account. Commands sent through a web shell or a command injection run under it too.

A web application starts programs by itself. PHP functions such as `shell_exec` run a command through `sh -c`. So `sh` under the web account is normal. The rule looks for three signs instead:

- A tool the web application usually does not need, such as Python, bash, curl, wget, nc, socat or base64. Attackers use them to start a loader or a reverse shell and to download tools.
- A program from /tmp, /var/tmp or /dev/shm. Any account can write to them, so attackers drop their own tools there.
- A terminal. A web server has none, its `tty` is `(none)`. An attacker who turns a reverse shell into a terminal gets one, such as `pts0`.

`exe` is the real file after all links. On Ubuntu 24.04 python3 is python3.12, socat is socat1 and telnet is inetutils-telnet, so the rule matches interpreter versions by pattern and lists other tools by their real file names. On RHEL `/bin/sh` is bash, so the rule takes bash only when `comm`, the name the program was started as, is bash.

`AUID` is the account a person logged in with. A web server started by systemd has no login session, its `AUID` is `unset`. An administrator who runs `sudo -u www-data bash` keeps their own `AUID`, so the rule skips them.

The rule matches account names (`EUID`) from the enriched part of the record. User IDs differ between distributions: www-data is 33 on Debian, apache is 48 on RHEL. Python started under www-data without a terminal, from the test data:

```
type: SYSCALL
SYSCALL: execve
EUID: www-data
AUID: unset
tty: (none)
exe: /usr/bin/python3.9
```

## Blind Spots and Assumptions

Blind spots

- Commands through `sh`, which the web application also uses, without a terminal and without the listed tools: a simple web shell or a reverse shell started as `sh`.
- Tools run through busybox, where `exe` is busybox.
- A listed tool copied under another name outside /tmp, /var/tmp and /dev/shm, or bash started through a link with another name.
- Interpreters left out of the list because web applications use them: perl, php, node.
- A web server under an account outside the list, such as the user of a php-fpm pool.
- Processes in containers when the host `/etc/passwd` has another name for the user ID.
- Commands after privilege escalation, when `EUID` is root.

Assumptions

- The web server is started by systemd or another service manager. Started from a login session, it inherits that `AUID`.
- auditd logs execve for processes without a login session. Audit rules with `-F auid!=unset` skip them.
- audit.log is in the enriched format and reaches the SIEM unchanged, with `SYSCALL`, `EUID`, `AUID`, `tty`, `comm` and `exe` extracted as fields.

A blind spot appears whenever one of these assumptions breaks, for example when an attacker stops auditd or deletes its rules.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| Web application that calls Python, bash or curl itself | the same `exe` on every request or at regular times, no terminal | not seen in the test logs. Confirm with the application owner. A `filter_optional_*` on this `exe` also hides an attacker who uses the same tool |
| Service or worker that runs scripts under the web server account | `ppid` 1 (started by systemd), the same `exe` at every start, no terminal | not seen in the test logs. Add a `filter_optional_*` block with its `exe` and `ppid` 1 |

## Validation

In an isolated VM with Debian or Ubuntu restored from a snapshot, load an execve audit rule and run a command under the web account the way a web application does, through `sh -c`: `systemd-run --uid=www-data --wait /bin/sh -c '/usr/bin/python3 -c "print(1)"'`. A process started by systemd has no login session, and Python gets `sh` as its parent. Run the rule's search in the SIEM over the test time. The search returns the SYSCALL record with `EUID` www-data and `exe` of python3.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). [tools/goodlog.sh](../../../tools/goodlog.sh) has clean baselines for Windows only.

| Data | Result |
|---|---|
| CAM-LDS scenario 1, video server, variant sudo (ZoneMinder exploit, Python loader, terminal) | 7831 hits: 5 without a terminal, 7826 with one |
| CAM-LDS scenario 1, video server, variant pwnkit (the same exploit, then PwnKit) | 7852 hits: 5 without a terminal, 7847 with one |
| CAM-LDS scenario 1, video server, variant racecondition (the same exploit, then the logrotate race condition) | 7908 hits: 6 without a terminal, 7902 with one |
| CAM-LDS scenario 5, video server (ZoneMinder background) | 0 hits |

The Splunk search converted from the rule returns the same counts on these four logs.

## Priority

Medium in all cases.

## Response

1. Join the EXECVE record with the same `msg` to see the command line. Arguments with spaces are written in hex.
2. Follow `ppid` up the chain. A web server process (apache2, php-fpm) in the chain points to the web application. A chain that ends at PID 1 without a web server is a service, see False Positives.
3. List all program starts under the web account on the host around the alert and find the first one outside the usual set.
4. Check the web server access log at that time for requests to a vulnerable page or a new script.
5. If a helper of the web application or a service explains the start, confirm it with the application owner.
6. If steps 1–5 do not explain the start, escalate it as a web server compromise: isolate the host, look for new files in the web root and for outbound connections from the web account, search other web servers for the same commands, and patch or remove the application.

## Additional Resources

- [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html)
- [SigmaHQ: Webshell Remote Command Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/syscall/lnx_auditd_web_rce.yml), a similar rule. It checks `euid` 33 only, so on Debian it fires on every program www-data starts and on RHEL it misses apache.
- [Elastic: Suspicious Child Execution via Web Server](https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_suspicious_child_execution.toml), a similar rule on Elastic Defend data. It matches a direct child of the web server from a list of tools or from /tmp, /var/tmp, /dev/shm, the web root and other unusual paths.
- [Elastic: Unusual Command Execution via Web Server](https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_unusual_command_execution.toml), a similar rule on Elastic Defend data. It alerts on a command line that a web server parent has not run on the host in the previous 7 days.
