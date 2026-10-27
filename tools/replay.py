"""Run a Sigma rule over log events in SQLite."""

import re
import sqlite3
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation


def columns(events: list[dict[str, str]]) -> dict[str, str]:
    """The SQLite column of each field name. SQLite ignores case in column names.

    Sysmon spells one field two ways in different events (SourceProcessGUID, SourceProcessGuid):
    both go into one column. auditd writes one value twice in a record, as a number and as a
    name (syscall=59, SYSCALL=execve): the second spelling gets a column of its own.
    """
    spellings: dict[str, list[str]] = {}  # lower-case name -> spellings in order of appearance
    together = set()  # lower-case names spelled two ways within one event
    for event in events:
        seen: dict[str, str] = {}
        for name in event:
            low = name.lower()
            names = spellings.setdefault(low, [])
            if name not in names:
                names.append(name)
            if seen.setdefault(low, name) != name:
                together.add(low)
    result = {}
    for low, names in spellings.items():
        for i, name in enumerate(names):
            result[name] = f"{name}_{i}" if low in together and i else names[0]
    return result


def run(rule_path: Path, events: list[dict[str, str]]) -> list[dict[str, str]]:
    """Events the rule matches."""
    rule = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    fields = columns(events)
    # pySigma writes the SQL; the Sysmon pipeline turns category process_access into EventID=10.
    pipeline = sysmon_pipeline()
    moved = {name: column for name, column in fields.items() if column.lower() != name.lower()}
    if moved:
        pipeline += ProcessingPipeline(
            items=[ProcessingItem(FieldMappingTransformation(moved), identifier="own_columns")]
        )
    (query,) = sqliteBackend(pipeline).convert(rule)

    order = list(dict.fromkeys(fields.values()))
    position = {column: i for i, column in enumerate(order)}
    rows = []
    for event in events:
        row: list[str | None] = [None] * len(order)
        for name, value in event.items():
            row[position[fields[name]]] = value
        rows.append(row)

    db = sqlite3.connect(":memory:")
    # SQLite has the REGEXP operator but no function behind it. |re in a rule needs one.
    db.create_function(
        "REGEXP",
        2,
        lambda pattern, value: value is not None and re.search(pattern, value) is not None,
    )
    # Sigma matches strings case-insensitively; NOCASE makes "=" do the same.
    spec = ", ".join(f'"{column}" TEXT COLLATE NOCASE' for column in order)
    db.execute(f"CREATE TABLE logs ({spec})")
    db.executemany(f"INSERT INTO logs VALUES ({', '.join('?' * len(order))})", rows)
    while True:
        try:
            cursor = db.execute(query)
            break
        except sqlite3.OperationalError as error:
            # A field the rule checks can be absent from every event, like a0 of EXECVE in a
            # log of PATH records. An empty column lets that part of the rule not match.
            missing = re.fullmatch(r"no such column: (\w+)", str(error))
            if not missing:
                raise
            db.execute(f'ALTER TABLE logs ADD COLUMN "{missing[1]}" TEXT COLLATE NOCASE')
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row, strict=True)) for row in cursor]
