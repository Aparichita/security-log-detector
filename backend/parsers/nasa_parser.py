"""Streaming parser for NASA KSC access-log records, with host pseudonymization."""
from __future__ import annotations
import hashlib
import hmac
import secrets
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator
from parser import LogEvent

ACCESS = re.compile(r'^(?P<host>\S+)\s+\S+\s+\S+\s+\[(?P<stamp>[^]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)\s*$')
REQUEST = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/\d(?:\.\d)?)?$")
_ANONYMIZATION_KEY = secrets.token_bytes(32)

def anonymize_host(host: str) -> str:
    """Return a stable opaque token; raw hostnames/addresses are never part of the event."""
    digest = hmac.new(_ANONYMIZATION_KEY, host.casefold().encode("utf-8"), hashlib.sha256).hexdigest()
    return "host-" + digest[:12]

def parse_line(line: str) -> LogEvent:
    match = ACCESS.match(line.rstrip("\r\n"))
    if not match:
        raise ValueError("malformed NASA access-log line")
    try:
        timestamp = datetime.strptime(match["stamp"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError as exc:
        raise ValueError(f"invalid access-log timestamp: {exc}") from exc
    request = REQUEST.match(match["request"])
    if not request:
        raise ValueError("unsupported HTTP request field")
    return LogEvent(timestamp, anonymize_host(match["host"]), "redacted", "request",
                    request["method"], request["path"], int(match["status"]),
                    None if match["size"] == "-" else int(match["size"]), "nasa")

def iter_events(lines: Iterable[str]) -> Iterator[LogEvent]:
    for line in lines:
        try:
            yield parse_line(line)
        except ValueError:
            continue

def iter_file(path: str | Path) -> Iterator[LogEvent]:
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        yield from iter_events(handle)
