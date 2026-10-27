"""The auditd reader on lines in both formats found in splunk/attack_data."""

from pathlib import Path

from tools.logs import auditd_records


def read(tmp_path: Path, *lines: str) -> list[dict[str, str]]:
    path = tmp_path / "audit.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return list(auditd_records(path))


def test_raw_proctitle_is_decoded(tmp_path: Path) -> None:
    (record,) = read(
        tmp_path,
        "type=PROCTITLE msg=audit(1723042099.699:13368): proctitle=636174002F6574632F736861646F77",
    )
    assert record == {"type": "PROCTITLE", "proctitle": "cat /etc/shadow"}


def test_interpreted_proctitle_keeps_spaces(tmp_path: Path) -> None:
    (record,) = read(
        tmp_path,
        "type=PROCTITLE msg=audit(02/20/2025 13:06:22.750:103528) : proctitle=sudo chmod u+s vulnerable ",
    )
    assert record["proctitle"] == "sudo chmod u+s vulnerable"


def test_execve_in_both_formats(tmp_path: Path) -> None:
    raw, interpreted, encoded = read(
        tmp_path,
        'type=EXECVE msg=audit(1722955017.376:3780): argc=3 a0="setcap" a1="cap_setuid+ep" a2="./priv_esc"',
        "type=EXECVE msg=audit(02/20/2025 13:06:22.853:103562) : argc=3 a0=setcap a1=cap_setuid+ep a2=./escalate ",
        'type=EXECVE msg=audit(1722955017.376:3781): argc=3 a0="sh" a1="-c" a2=6C73202D6C61',
    )
    assert (raw["a0"], raw["a1"]) == ("setcap", "cap_setuid+ep")
    assert (interpreted["a0"], interpreted["a2"]) == ("setcap", "./escalate")
    assert encoded["a2"] == "ls -la"


def test_syscall_keeps_raw_fields(tmp_path: Path) -> None:
    (record,) = read(
        tmp_path,
        "type=SYSCALL msg=audit(1723035222.338:3147): arch=c000003e syscall=313 success=yes a1=561fd3c2ecd2"
        ' comm="insmod" exe="/usr/bin/kmod" key="modules"\x1dARCH=x86_64 SYSCALL=finit_module',
    )
    assert record["syscall"] == "313"
    assert record["a1"] == "561fd3c2ecd2"  # a syscall argument, not text
    assert (record["comm"], record["key"]) == ("insmod", "modules")
    assert "SYSCALL" not in record
