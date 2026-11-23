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


class WindowDetector:
    """Incremental detector for chronologically ordered events; memory follows active windows."""
    def __init__(self, failed_threshold: int = 5, failed_window: timedelta = timedelta(minutes=2),
                 request_threshold: int = 100, request_window: timedelta = timedelta(seconds=60)):
        if failed_threshold < 1 or request_threshold < 1:
            raise ValueError("detection thresholds must be positive")
        if failed_window.total_seconds() <= 0 or request_window.total_seconds() <= 0:
            raise ValueError("detection windows must be positive")
        self.failed_threshold, self.failed_window = failed_threshold, failed_window
        self.request_threshold, self.request_window = request_threshold, request_window
        self.failures: dict[str, deque] = defaultdict(deque)
        self.requests: dict[str, deque] = defaultdict(deque)
        self.seen: set[tuple[str, str]] = set()
        self.last_timestamp = None

    def process(self, event: LogEvent) -> list[Alert]:
        """Process one event and return newly triggered alerts."""
        ts = event.timestamp
        if self.last_timestamp is not None and ts < self.last_timestamp:
            raise ValueError("WindowDetector requires chronological events")
        self.last_timestamp = ts
        alerts: list[Alert] = []
        if event.event_type == "login_failure":
            window = self.failures[event.ip]
            window.append(ts)
            while window and ts - window[0] > self.failed_window:
                window.popleft()
            if len(window) >= self.failed_threshold and (event.ip, "brute_force") not in self.seen:
                self.seen.add((event.ip, "brute_force"))
                alerts.append(Alert(event.ip, "Brute-force login", "HIGH", ts.isoformat(),
                                    f"{len(window)} failed logins within {self.failed_window.total_seconds():g} seconds."))
            if not window:
                self.failures.pop(event.ip, None)
        elif event.event_type == "login_success":
            window = self.failures[event.ip]
            while window and ts - window[0] > self.failed_window:
                window.popleft()
            if len(window) >= self.failed_threshold and (event.ip, "suspicious_success") not in self.seen:
                self.seen.add((event.ip, "suspicious_success"))
                alerts.append(Alert(event.ip, "Suspicious successful login", "CRITICAL", ts.isoformat(),
                                    f"Successful login followed {len(window)} failed attempts within {self.failed_window.total_seconds():g} seconds."))
            if not window:
                self.failures.pop(event.ip, None)
        elif event.event_type == "request":
            window = self.requests[event.ip]
            window.append(ts)
            while window and ts - window[0] > self.request_window:
                window.popleft()
            if len(window) >= self.request_threshold and (event.ip, "request_burst") not in self.seen:
                self.seen.add((event.ip, "request_burst"))
                alerts.append(Alert(event.ip, "High-volume request burst", "MEDIUM", ts.isoformat(),
                                    f"{len(window)} requests within {self.request_window.total_seconds():g} seconds."))
            if not window:
                self.requests.pop(event.ip, None)
        return alerts


def detect_alerts(events: Iterable[LogEvent], failed_threshold: int = 5,
                  failed_window: timedelta = timedelta(minutes=2),
                  request_threshold: int = 100,
                  request_window: timedelta = timedelta(seconds=60)) -> list[Alert]:
    detector = WindowDetector(failed_threshold, failed_window, request_threshold, request_window)
    alerts = []
    for event in sorted(events, key=lambda item: item.timestamp):
        alerts.extend(detector.process(event))
    return sorted(alerts, key=lambda alert: alert.timestamp)
