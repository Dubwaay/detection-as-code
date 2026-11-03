# Host System File Accessed Through A Mounted Root

## Goal

Detect a process that opens the host's cron jobs, services, accounts or SSH keys through a mounted copy of the host root, the way an attacker escapes a container.

## Categorization

[Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) / [Escape to Host](https://attack.mitre.org/techniques/T1611/)

Platforms

- Linux

Tooling

- auditd, PATH record (file name of a watched file)

## Strategy Abstract

- auditd PATH records of watched files are the only data source. No enrichment in the SIEM.
- The rule fires when the name of a cron, systemd, sudoers, account or SSH key file does not start where the file lives on the host, such as /root/etc/cron.d/x instead of /etc/cron.d/x.
- Host paths, parent directory records and container image storage do not match. The False Positives section lists what is left.

## Technical Context

A container with the host root mounted inside it can change any host file. Docker gives such a container to anyone who can reach the Docker API: a bind mount of / is one option of `docker run`. The attacker then adds a cron job or a systemd unit that the host runs as root, or an account or SSH key to log in with.

auditd watches a file by its inode, so a watch on /etc/cron.d also fires when the directory is reached through a mount. The PATH record keeps the name the process used. A container with the host root at /root writes /root/etc/cron.d/x where a process on the host writes /etc/cron.d/x. The rule takes the first form: a known system path in the middle of a name that starts somewhere else.

From the test data, a container writes a cron job into the host /etc/cron.d:

```
type: PATH
name: /root/etc/cron.d/sysvz
nametype: CREATE
```

Creating or deleting a file also gives a PATH record for the parent directory (`nametype` PARENT). The rule skips it, so one new file gives one result.

## Blind Spots and Assumptions

Blind spots

- An escape through `nsenter` into the host mount namespace or through `chroot` into the mounted root. File names then look like host paths.
- A relative name, such as cron.d/x written from the mounted etc directory.
- A path with a space or another special character, which auditd writes in hex.
- Host files outside the list, such as /etc/profile.d, /etc/rc.local or kernel modules.
- A mount point under /etc, /home, /var/spool/cron or /root/.ssh, which the rule treats as host paths.
- Any other escape that does not touch the listed files, such as a kernel exploit.

Assumptions

- auditd watches the listed files and directories for writes, for example `-w /etc/cron.d -p wa`.
- PATH records reach the SIEM unchanged, with `name` and `nametype` extracted as fields.

A blind spot appears whenever one of these assumptions breaks, for example when an attacker stops auditd or deletes its rules.

## False Positives

| Source | How to recognise it | Handling |
|---|---|---|
| OS installers and image builders that write a system tree under another root | `exe` of debootstrap, a package manager or a build tool, the same root prefix in every `name` | not seen in the test logs. Add a `filter_optional_*` block with that root prefix |
| Backup restore into a mounted copy of a system | `exe` of the backup tool, a restore time window | not seen in the test logs. Confirm with the backup owner, no exclusion |
| Container image layers under Docker, containerd or Podman storage | `name` under /var/lib/docker, /var/lib/containerd or /var/lib/containers | excluded by `filter_main_container_storage`. Not seen in the test logs |

## Validation

In an isolated VM restored from a snapshot, add a watch on /etc/cron.d and run the [Atomic Red Team T1611](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1611/T1611.md) test "Mount host filesystem to escape privileged Docker container" inside a privileged container. Its prerequisites install mount and netcat if they are missing. Run the rule's search in the SIEM over the test time. The search returns PATH records with `name` /mnt/T1611.002/etc/cron.d/T1611_002, the first one with `nametype` CREATE.

Automated: pytest replays the rule over the logs in [tests.yml](tests.yml). [tools/goodlog.sh](../../../tools/goodlog.sh) has clean baselines for Windows only.

| Data | Result |
|---|---|
| CAM-LDS scenario 7, Docker host (open Docker API, container with the host root at /root, cron job written to the host) | 1 hit |
| CAM-LDS scenario 3, repository server (daily cron jobs, account changes, reads of /etc/shadow) | 0 hits |
| CAM-LDS scenario 1, video server (useradd, crontab reads) | 0 hits |

The Splunk search converted from the rule returns the same counts on these three logs and no results on four more CAM-LDS logs and one CasinoLimit log.

## Priority

High in all cases.

## Response

1. Join the SYSCALL record with the same `msg`: `exe`, `pid`, `ppid`, `UID`, `AUID` and `tty`.
2. Follow `ppid` up the chain. containerd-shim-runc-v2 or runc in the chain means a container. The `-id` argument of the shim names it. `subj` docker-default, where AppArmor is on, also means a container.
3. Read the file by its host path to see what was added: a cron job, systemd unit, account or SSH key.
4. Find how the container got the host root: Docker API on TCP (`dockerd -H tcp://`), a mounted docker.sock, a privileged container, a bind mount of /.
5. If an installer, image build or backup restore explains the write, confirm it with its owner.
6. If steps 1–5 do not explain the write, escalate it as a container escape: isolate the host, keep the container for analysis, close the Docker API, remove what was added, reset the accounts and keys that were changed and look for the same writes on other container hosts.

## Additional Resources

- [Docker Engine security: Docker daemon attack surface](https://docs.docker.com/engine/security/#docker-daemon-attack-surface)
- [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html)
- [Elastic: Potential Chroot Container Escape via Mount](https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_docker_mount_chroot_container_escape.toml), a similar rule on endpoint process data. It matches mount of a /dev/sd* disk followed by chroot from the same parent within 5 minutes, an escape this rule does not see.
- [Elastic: Privileged Docker Container Creation](https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_potentially_overly_permissive_container_creation.toml), a similar rule. It matches `docker run --privileged` run from the command line, so a container created through the Docker API does not match.
