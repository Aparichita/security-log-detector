"""One-pass dataset ingestion and cached, aggregate-only analysis snapshots."""
from __future__ import annotations
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter
from threading import RLock
from typing import Any

from config import settings
from detector import WindowDetector
from parser import LogEvent, parse_line as parse_synthetic_line
from parsers.openssh_parser import parse_line as parse_ssh_line
from parsers.nasa_parser import parse_line as parse_nasa_line

SOURCES = {
    "synthetic": {"name": "Synthetic Dataset", "type": "JSON Lines", "description": "Deterministic synthetic authentication and request events.", "url": "local generator"},
    "openssh": {"name": "Loghub OpenSSH", "type": "OpenSSH syslog authentication", "description": "OpenSSH authentication messages; sample or full archive supplied locally.", "url": "https://github.com/logpai/loghub/tree/master/OpenSSH"},
    "nasa": {"name": "NASA KSC HTTP", "type": "Apache-style HTTP access log", "description": "Aggregate request-pattern analysis only; host labels are anonymized.", "url": "https://ita.ee.lbl.gov/html/contrib/NASA-HTTP.html"},
}

@dataclass
class DatasetSnapshot:
    source: str
    status: str
    records_processed: int = 0
    valid_records: int = 0
    malformed_records: int = 0
    processing_seconds: float = 0.0
    date_start: str | None = None
    date_end: str | None = None
    event_types: list[str] | None = None
    stats: dict[str, Any] | None = None
    alerts: list[dict] | None = None
    ips: list[dict] | None = None
    logs: list[dict] | None = None
    activity: list[dict] | None = None
    message: str | None = None

    def info(self) -> dict:
        meta = SOURCES[self.source]
        return {"source": self.source, "name": meta["name"], "dataset_source": meta["description"], "source_url": meta["url"],
                "dataset_type": meta["type"], "records_processed": self.records_processed,
                "valid_records": self.valid_records, "malformed_records": self.malformed_records,
                "date_range": {"start": self.date_start, "end": self.date_end},
                "available_event_types": self.event_types or [], "processing_status": self.status,
                "processing_seconds": round(self.processing_seconds, 3), "message": self.message}

class DatasetManager:
    def __init__(self, source: str = "synthetic", paths: dict[str, list[Path]] | None = None):
        self.source = source if source in SOURCES else "synthetic"
        self.paths = paths or {}
        self._cache: dict[tuple, DatasetSnapshot] = {}
        self._lock = RLock()

    def select(self, source: str) -> DatasetSnapshot:
        if source not in SOURCES:
            raise ValueError(f"Unsupported source: {source}")
        with self._lock:
            self.source = source
            return self.get()

    def _files(self, source: str) -> list[Path]:
        if source in self.paths:
            return self.paths[source]
        if source == "synthetic":
            return [Path(__file__).resolve().parent / "auth.log"]
        if source == "openssh":
            return [settings.openssh_path]
        return [settings.nasa_july_path, settings.nasa_august_path]

    def _cache_key(self, source: str) -> tuple:
        files = self._files(source)
        fingerprints = tuple((str(p.resolve()), p.stat().st_size, p.stat().st_mtime_ns) if p.is_file() else (str(p.resolve()), None, None) for p in files)
        return (source, fingerprints, settings.openssh_year, settings.failed_threshold, settings.failed_window.total_seconds(), settings.request_threshold, settings.request_window.total_seconds())

    def get(self) -> DatasetSnapshot:
        with self._lock:
            key = self._cache_key(self.source)
            if key not in self._cache:
                for old_key in list(self._cache):
                    if old_key[0] == self.source:
                        del self._cache[old_key]
                self._cache[key] = self._process(self.source)
            return self._cache[key]

    def _missing(self, source: str) -> DatasetSnapshot:
        required = self._files(source)
        absent = [p.name for p in required if not p.is_file()]
        return DatasetSnapshot(source, "not_installed", event_types=[], stats={}, alerts=[], ips=[], logs=[], activity=[],
                               message=f"Dataset files not found: {', '.join(absent)}. See backend/datasets/README.md.")

    def _process(self, source: str) -> DatasetSnapshot:
        files = self._files(source)
        if any(not path.is_file() for path in files):
            return self._missing(source)
        begin = perf_counter()
        detector = WindowDetector(settings.failed_threshold, settings.failed_window, settings.request_threshold, settings.request_window)
        total = valid = malformed = 0
        counts: Counter = Counter()
        by_ip: dict[str, Counter] = defaultdict(Counter)
        alert_counts: Counter = Counter()
        alert_ips: dict[str, list[dict]] = defaultdict(list)
        all_alerts: list[dict] = []
        preview: deque[dict] = deque(maxlen=500)
        minute_counts: Counter = Counter()
        date_min: datetime | None = None
        date_max: datetime | None = None
        previous: datetime | None = None
        event_types: set[str] = set()

        for path in files:
            with path.open(encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    if not raw.strip():
                        continue
                    total += 1
                    event = None
                    try:
                        if source == "synthetic":
                            event = parse_synthetic_line(raw)
                        elif source == "openssh":
                            event = parse_ssh_line(raw, settings.openssh_year)
                        else:
                            event = parse_nasa_line(raw)
                    except ValueError:
                        malformed += 1
                        continue
                    valid += 1
                    if event is None:
                        continue
                    if previous is not None and event.timestamp < previous:
                        # Window rules require chronology; malformed ordering is excluded from analysis.
                        malformed += 1
                        valid -= 1
                        continue
                    previous = event.timestamp
                    counts[event.event_type] += 1
                    event_types.add(event.event_type)
                    by_ip[event.ip][event.event_type] += 1
                    bucket = event.timestamp.replace(minute=0, second=0, microsecond=0) if source == "nasa" else event.timestamp.replace(second=0, microsecond=0)
                    minute = bucket.isoformat()
                    minute_counts[minute] += 1
                    date_min = event.timestamp if date_min is None or event.timestamp < date_min else date_min
                    date_max = event.timestamp if date_max is None or event.timestamp > date_max else date_max
                    for alert in detector.process(event):
                        row = alert.to_dict()
                        all_alerts.append(row)
                        alert_counts[alert.ip] += 1
                        alert_ips[alert.ip].append(row)
                    if source != "nasa":
                        preview.append(event.to_dict())

        duration = perf_counter() - begin
        ips = []
        for ip, event_counts in by_ip.items():
            n_alerts = alert_counts[ip]
            critical = any(alert["severity"] == "CRITICAL" for alert in alert_ips[ip])
            ips.append({"ip": ip, "total_events": sum(event_counts.values()),
                        "failed_logins": event_counts["login_failure"], "successful_logins": event_counts["login_success"],
                        "requests": event_counts["request"], "alerts": n_alerts,
                        "risk_level": "critical" if critical else "high" if n_alerts else "low"})
        ips.sort(key=lambda row: (row["alerts"], row["total_events"]), reverse=True)
        severity_counts = Counter(alert["severity"] for alert in all_alerts)
        stats = {"total_logs": valid, "records_processed": total, "valid_records": valid,
                 "malformed_lines": malformed, "total_alerts": len(all_alerts),
                 "critical_alerts": severity_counts["CRITICAL"], "high_alerts": severity_counts["HIGH"],
                 "medium_alerts": severity_counts["MEDIUM"], "unique_ips": len(by_ip),
                 "failed_logins": counts["login_failure"], "successful_logins": counts["login_success"],
                 "request_events": counts["request"], "processing_seconds": round(duration, 3)}
        return DatasetSnapshot(source, "ready", total, valid, malformed, duration,
                               date_min.isoformat() if date_min else None, date_max.isoformat() if date_max else None,
                               sorted(event_types), stats, all_alerts, ips[:500], list(preview),
                               [{"timestamp": timestamp, "events": count} for timestamp, count in sorted(minute_counts.items())])

manager = DatasetManager(settings.source)
