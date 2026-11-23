"""FastAPI service for inspecting synthetic security logs and rule alerts."""
from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from detector import detect_alerts
from parser import LogEvent, read_log

BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = BASE_DIR / "auth.log"
app = FastAPI(title="Security Log Detector API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])


def dataset() -> tuple[list[LogEvent], int]:
    try:
        return read_log(LOG_PATH)
    except FileNotFoundError as exc:
        raise HTTPException(503, "Log dataset is missing. Run generate_logs.py first.") from exc


@app.get("/")
def root():
    return {"name": "Security Log Detector API", "message": "Service is running", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/alerts")
def alerts(severity: str | None = None):
    events, _ = dataset()
    rows = [item.to_dict() for item in detect_alerts(events)]
    if severity:
        rows = [row for row in rows if row["severity"].lower() == severity.lower()]
    return rows


@app.get("/stats")
def stats():
    events, malformed = dataset()
    counts = Counter(event.event_type for event in events)
    alert_counts = Counter(alert.severity for alert in detect_alerts(events))
    return {"total_logs": len(events), "malformed_lines": malformed, "total_alerts": sum(alert_counts.values()),
            "critical_alerts": alert_counts["CRITICAL"], "high_alerts": alert_counts["HIGH"], "medium_alerts": alert_counts["MEDIUM"],
            "unique_ips": len({event.ip for event in events}), "failed_logins": counts["login_failure"],
            "successful_logins": counts["login_success"], "request_events": counts["request"]}


@app.get("/logs")
def logs(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), event_type: str | None = None, ip: str | None = None):
    events, _ = dataset()
    if event_type and event_type not in {"login_success", "login_failure", "request"}:
        raise HTTPException(422, "Unsupported event_type")
    filtered = [event for event in events if (not event_type or event.event_type == event_type) and (not ip or event.ip == ip)]
    return {"items": [event.to_dict() for event in filtered[offset:offset + limit]], "total": len(filtered), "limit": limit, "offset": offset}


@app.get("/ips")
def ips():
    events, _ = dataset()
    detected = detect_alerts(events)
    alert_counts = Counter(alert.ip for alert in detected)
    critical_ips = {alert.ip for alert in detected if alert.severity == "CRITICAL"}
    grouped: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        grouped[event.ip].append(event)
    result = []
    for ip, items in grouped.items():
        counts = Counter(event.event_type for event in items)
        num_alerts = alert_counts[ip]
        risk = "critical" if ip in critical_ips else "high" if num_alerts else "low"
        result.append({"ip": ip, "total_events": len(items), "failed_logins": counts["login_failure"], "successful_logins": counts["login_success"], "requests": counts["request"], "alerts": num_alerts, "risk_level": risk})
    return sorted(result, key=lambda row: (row["alerts"], row["total_events"]), reverse=True)
