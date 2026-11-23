"""Generate deterministic, synthetic JSON-lines security logs."""
from __future__ import annotations
import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

USERS = ["alex", "sam", "jordan", "casey", "taylor", "morgan"]
IPS = [f"192.0.2.{n}" for n in range(10, 20)]


def generate_events(seed: int = 42, normal_events: int = 360) -> list[dict]:
    rng = random.Random(seed)
    start = datetime(2025, 1, 15, 12, tzinfo=timezone.utc)
    events = []
    for i in range(normal_events):
        stamp = start + timedelta(seconds=i * 3 + rng.randrange(3))
        kind = "login_failure" if rng.random() < .08 else "login_success"
        events.append({"timestamp": stamp.isoformat(), "ip": rng.choice(IPS), "username": rng.choice(USERS), "event_type": kind})
        if i % 3 == 0:
            events.append({"timestamp": (stamp + timedelta(seconds=1)).isoformat(), "ip": rng.choice(IPS), "username": "-", "event_type": "request", "method": "GET", "path": rng.choice(["/", "/api/health", "/api/logs"]), "status": 200})
    attacker = "198.51.100.23"
    anchor = start + timedelta(minutes=25)
    for i in range(6):
        events.append({"timestamp": (anchor + timedelta(seconds=i * 12)).isoformat(), "ip": attacker, "username": "admin", "event_type": "login_failure"})
    events.append({"timestamp": (anchor + timedelta(seconds=75)).isoformat(), "ip": attacker, "username": "admin", "event_type": "login_success"})
    burst = start + timedelta(minutes=32)
    for i in range(110):
        events.append({"timestamp": (burst + timedelta(milliseconds=i * 400)).isoformat(), "ip": "203.0.113.77", "username": "-", "event_type": "request", "method": "GET", "path": "/api/search", "status": 200})
    return sorted(events, key=lambda event: event["timestamp"])


def write_logs(output: str | Path = "auth.log", seed: int = 42, normal_events: int = 360) -> int:
    rows = generate_events(seed, normal_events)
    with Path(output).open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")
    return len(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="auth.log")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--normal-events", type=int, default=360)
    args = parser.parse_args()
    print(f"Wrote {write_logs(args.output, args.seed, args.normal_events)} events to {args.output}")
