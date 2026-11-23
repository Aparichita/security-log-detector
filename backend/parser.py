"""Common normalized event schema and JSONL parser for synthetic data."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    ip: str
    username: str
    event_type: str
    method: str | None = None
    path: str | None = None
    status: int | None = None
    response_size: int | None = None
    source: str = "synthetic"

    def to_dict(self) -> dict:
        return {"timestamp": self.timestamp.isoformat(), "ip": self.ip, "username": self.username,
                "event_type": self.event_type, "method": self.method, "path": self.path, "status": self.status,
                "response_size": self.response_size, "source": self.source}


def parse_line(line: str) -> LogEvent:
    """Parse one JSON-lines record; raise ValueError for malformed or incomplete records."""
    try:
        row = json.loads(line)
        timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
        ip, username, event_type = row["ip"], row.get("username", "unknown"), row["event_type"]
        if not all(isinstance(value, str) and value for value in (ip, username, event_type)):
            raise ValueError("ip, username, and event_type must be non-empty strings")
        if event_type not in {"login_success", "login_failure", "request"}:
            raise ValueError(f"unsupported event type: {event_type}")
        return LogEvent(timestamp, ip, username, event_type, row.get("method"), row.get("path"), row.get("status"), row.get("response_size"), "synthetic")
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"invalid log entry: {exc}") from exc


def parse_lines(lines: Iterable[str]) -> tuple[list[LogEvent], int]:
    events, malformed = [], 0
    for line in lines:
        if not line.strip():
            continue
        try:
            events.append(parse_line(line))
        except ValueError:
            malformed += 1
    return events, malformed


def read_log(path: str | Path) -> tuple[list[LogEvent], int]:
    with Path(path).open(encoding="utf-8") as handle:
        return parse_lines(handle)
