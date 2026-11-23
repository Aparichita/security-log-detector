"""Small, configurable rolling-window rule engine."""
from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable
from parser import LogEvent


@dataclass(frozen=True)
class Alert:
    ip: str
    rule_name: str
    severity: str
    timestamp: str
    description: str

    def to_dict(self) -> dict:
        return {"ip": self.ip, "rule_name": self.rule_name, "severity": self.severity,
                "timestamp": self.timestamp, "description": self.description}


def detect_alerts(events: Iterable[LogEvent], failed_threshold: int = 5,
                  failed_window: timedelta = timedelta(minutes=2),
                  request_threshold: int = 100,
                  request_window: timedelta = timedelta(seconds=60)) -> list[Alert]:
    failures: dict[str, deque] = defaultdict(deque)
    requests: dict[str, deque] = defaultdict(deque)
    alerts: list[Alert] = []
    seen: set[tuple[str, str]] = set()
    for event in sorted(events, key=lambda item: item.timestamp):
        ts = event.timestamp
        if event.event_type == "login_failure":
            window = failures[event.ip]
            window.append(ts)
            while window and ts - window[0] > failed_window:
                window.popleft()
            if len(window) >= failed_threshold and (event.ip, "brute_force") not in seen:
                seen.add((event.ip, "brute_force"))
                alerts.append(Alert(event.ip, "Brute-force login", "HIGH", ts.isoformat(),
                                    f"{len(window)} failed logins within {failed_window.total_seconds():g} seconds."))
        elif event.event_type == "login_success":
            window = failures[event.ip]
            while window and ts - window[0] > failed_window:
                window.popleft()
            if len(window) >= failed_threshold and (event.ip, "suspicious_success") not in seen:
                seen.add((event.ip, "suspicious_success"))
                alerts.append(Alert(event.ip, "Suspicious successful login", "CRITICAL", ts.isoformat(),
                                    f"Successful login followed {len(window)} failed attempts within 2 minutes."))
        elif event.event_type == "request":
            window = requests[event.ip]
            window.append(ts)
            while window and ts - window[0] > request_window:
                window.popleft()
            if len(window) >= request_threshold and (event.ip, "request_burst") not in seen:
                seen.add((event.ip, "request_burst"))
                alerts.append(Alert(event.ip, "High-volume request burst", "MEDIUM", ts.isoformat(),
                                    f"{len(window)} requests within {request_window.total_seconds():g} seconds."))
    return sorted(alerts, key=lambda alert: alert.timestamp)
