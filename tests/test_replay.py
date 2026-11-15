"""Replay of a correlation rule over XML events, and of a field absent from every event."""

from pathlib import Path

from tools import replay
from tools.readers import xml_events

EVENT = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<EventID>4769</EventID><TimeCreated SystemTime='{time}'/></System><EventData>"
    "<Data Name='TargetUserName'>{user}</Data><Data Name='ServiceName'>{service}</Data>"
    "</EventData></Event>"
)

CORRELATION = """
title: Service Ticket
name: service_ticket
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
    condition: selection
---
title: Service Tickets For Many Services
correlation:
    type: value_count
    rules:
        - service_ticket
    group-by:
        - TargetUserName
    timespan: 5m
    condition:
        field: ServiceName
        gte: 3
"""

NESTED = """
title: Nested Field
logsource:
    product: kubernetes
    service: audit
detection:
    selection:
        user.username|contains: admin
    condition: selection
"""


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_correlation_counts_in_time_windows(tmp_path: Path) -> None:
    # alice asks for three services within three seconds, bob for three an hour apart
    lines = [
        EVENT.format(time=f"2022-02-11T19:29:0{i}.1234567Z", user="alice", service=f"srv{i}")
        for i in range(3)
    ] + [
        EVENT.format(time=f"2022-02-11T1{i}:00:00.0000000Z", user="bob", service=f"srv{i}")
        for i in range(3)
    ]
    events = list(xml_events(write(tmp_path, "security.xml", "\n".join(lines))))
    assert events[0]["_time"] == "2022-02-11T19:29:00.1234567Z"
    (alert,) = replay.run(write(tmp_path, "rule.yml", CORRELATION), events)
    assert (alert["group_keys"], alert["metric_value"]) == ('{"TargetUserName":"alice"}', 3)


def test_absent_nested_field_does_not_match(tmp_path: Path) -> None:
    rule = write(tmp_path, "rule.yml", NESTED)
    assert replay.run(rule, [{"verb": "get"}]) == []
    assert len(replay.run(rule, [{"verb": "get", "user.username": "kubernetes-admin"}])) == 1
