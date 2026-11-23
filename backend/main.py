"""FastAPI endpoints over cached, normalized dataset snapshots."""
from __future__ import annotations
import argparse
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from dataset_manager import SOURCES, manager

app = FastAPI(title="Security Log Detector API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])

class SourceSelection(BaseModel):
    source: str

def snapshot():
    return manager.get()

@app.get("/")
def root():
    return {"name": "Security Log Detector API", "message": "Service is running", "docs": "/docs"}

@app.get("/health")
def health():
    current = snapshot()
    return {"status": "ok", "dataset_status": current.status, "source": current.source}

@app.get("/datasets")
def datasets():
    current = snapshot()
    available = []
    for key, meta in SOURCES.items():
        files = manager._files(key)
        available.append({"source": key, "name": meta["name"], "installed": all(path.is_file() for path in files)})
    return {**current.info(), "available_datasets": available}

@app.get("/datasets/stats")
def dataset_stats():
    current = snapshot()
    return {"source": current.source, "status": current.status, **(current.stats or {})}

@app.post("/datasets/select")
def select_dataset(selection: SourceSelection):
    try:
        return manager.select(selection.source).info()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

@app.get("/alerts")
def alerts(severity: str | None = None):
    rows = snapshot().alerts or []
    if severity:
        rows = [row for row in rows if row["severity"].lower() == severity.lower()]
    return rows

@app.get("/stats")
def stats():
    return snapshot().stats or {}

@app.get("/activity")
def activity():
    return snapshot().activity or []

@app.get("/logs")
def logs(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), event_type: str | None = None, ip: str | None = None):
    current = snapshot()
    if current.source == "nasa":
        return {"items": [], "total": 0, "limit": limit, "offset": offset, "privacy_limited": True,
                "message": "NASA request-level records are withheld; only anonymous aggregates are available."}
    if event_type and event_type not in {"login_success", "login_failure", "request"}:
        raise HTTPException(422, "Unsupported event_type")
    rows = [row for row in (current.logs or []) if (not event_type or row["event_type"] == event_type) and (not ip or row["ip"] == ip)]
    return {"items": rows[offset:offset + limit], "total": len(rows), "limit": limit, "offset": offset}

@app.get("/ips")
def ips():
    return snapshot().ips or []

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the Security Log Detector API")
    parser.add_argument("--source", choices=sorted(SOURCES), default=manager.source)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    manager.select(args.source)
    uvicorn.run(app, host=args.host, port=args.port)
