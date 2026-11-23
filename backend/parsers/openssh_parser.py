"""Streaming parser for Loghub's yearless syslog-style OpenSSH messages."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator
from parser import LogEvent

PREFIX = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s*(?P<message>.*)$")
ADDRESS = re.compile(r"\b(?:from\s+|rhost=)(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})\b")
USER = re.compile(r"(?:for\s+(?:invalid\s+user\s+)?|user[=\s]+)(?P<user>[^\s]+)")
FAILURE = re.compile(r"\b(?:Failed\s+(?:password|publickey|keyboard-interactive|none)|Invalid user|maximum authentication attempts)\b", re.I)
SUCCESS = re.compile(r"\bAccepted\s+(?:password|publickey|keyboard-interactive|hostbased)\b", re.I)

def parse_line(line: str, year: int = 2025) -> LogEvent | None:
    """Return a normalized auth event, None for valid irrelevant messages, or raise on malformed input."""
    match = PREFIX.match(line.rstrip("\r\n"))
    if not match:
        raise ValueError("not a recognized OpenSSH syslog record")
    try:
        timestamp = datetime.strptime(f"{year} {match['stamp']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"invalid syslog timestamp: {exc}") from exc
    message = match["message"]
    if SUCCESS.search(message):
        event_type = "login_success"
    elif re.search(r"\bFailed\s+(?:password|publickey|keyboard-interactive|none)\s+for\s+invalid\s+user\b", message, re.I):
        # The preceding "Invalid user" message already represents this attempt.
        return None
    elif FAILURE.search(message):
        event_type = "login_failure"
    else:
        return None
    addr = ADDRESS.search(message)
    user = USER.search(message)
    if addr is None:
        return None
    return LogEvent(timestamp, addr["ip"] if addr else "unknown", user["user"] if user else "unknown", event_type, source="openssh")

def iter_events(lines: Iterable[str], year: int = 2025) -> Iterator[LogEvent]:
    for line in lines:
        try:
            event = parse_line(line, year)
        except ValueError:
            continue
        if event is not None:
            yield event

def iter_file(path: str | Path, year: int = 2025) -> Iterator[LogEvent]:
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        yield from iter_events(handle, year)
