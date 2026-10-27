"""The raw audit.log reader and the SQLite columns for its fields, on lines from CAM-LDS."""

from pathlib import Path

from tools import replay
from tools.logs import linux_audit_records

SYSCALL = (
    "type=SYSCALL msg=audit(1758539807.929:13085): arch=c000003e syscall=59 success=yes exit=0"
    ' auid=1003 uid=1003 euid=0 comm="sudo" exe="/usr/bin/sudo" key="T1078_Valid_Accounts"'
    '\x1dARCH=x86_64 SYSCALL=execve AUID="webadmin" UID="webadmin" EUID="root"'
)

RULE = """
title: Number And Name Of One Value
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        syscall: 59
        SYSCALL: execve
        euid: 0
        EUID: root
    condition: selection
"""


def read(tmp_path: Path, *lines: str) -> list[dict[str, str]]:
    path = tmp_path / "audit.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return list(linux_audit_records(path))


def test_number_and_name_are_two_fields(tmp_path: Path) -> None:
    (record,) = read(tmp_path, SYSCALL)
    assert (record["syscall"], record["SYSCALL"]) == ("59", "execve")
    assert (record["auid"], record["AUID"]) == ("1003", "webadmin")
    assert (record["exe"], record["key"]) == ("/usr/bin/sudo", "T1078_Valid_Accounts")


def test_hex_stays_hex(tmp_path: Path) -> None:
    proctitle, execve = read(
        tmp_path,
        "type=PROCTITLE msg=audit(1758539807.929:13085): "
        "proctitle=7375646F00636174002F6574632F736861646F77",
        'type=EXECVE msg=audit(1758547171.229:16763): argc=3 a0="sh" a1="-c" a2=6C73202D6C61',
    )
    assert proctitle["proctitle"] == "7375646F00636174002F6574632F736861646F77"
    assert (execve["a0"], execve["a2"]) == ("sh", "6C73202D6C61")


def test_bare_value_before_names(tmp_path: Path) -> None:
    (record,) = read(
        tmp_path,
        "type=LOGIN msg=audit(1758547171.213:16752): pid=18216 uid=0 old-auid=4294967295"
        ' auid=1001 res=1\x1dUID="root" OLD-AUID="unset" AUID="aecid"',
    )
    assert (record["res"], record["UID"]) == ("1", "root")
    assert (record["old-auid"], record["OLD-AUID"]) == ("4294967295", "unset")


def test_user_space_record(tmp_path: Path) -> None:
    (record,) = read(
        tmp_path,
        "type=USER_ACCT msg=audit(1758547171.385:16781): pid=18224 uid=1001 auid=1001 ses=36"
        ' msg=\'op=PAM:accounting acct="aecid" exe="/usr/bin/sudo" res=success\''
        '\x1dUID="aecid" AUID="aecid"',
    )
    assert (record["op"], record["acct"], record["res"]) == ("PAM:accounting", "aecid", "success")
    assert "msg" not in record


def test_rule_checks_number_and_name(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yml"
    rule.write_text(RULE, encoding="utf-8")
    assert len(replay.run(rule, read(tmp_path, SYSCALL))) == 1
