from datetime import datetime, timedelta, timezone
from detector import detect_alerts
from parser import LogEvent

BASE = datetime(2025, 1, 1, tzinfo=timezone.utc)
def event(seconds, kind, ip="192.0.2.1"):
    return LogEvent(BASE + timedelta(seconds=seconds), ip, "alice", kind)

def test_brute_force_triggers():
    alerts = detect_alerts([event(i * 10, "login_failure") for i in range(5)])
    assert any(a.rule_name == "Brute-force login" and a.severity == "HIGH" for a in alerts)

def test_fewer_than_threshold_no_brute_force():
    assert not detect_alerts([event(i * 10, "login_failure") for i in range(4)])

def test_failures_outside_window_do_not_trigger():
    assert not detect_alerts([event(i * 40, "login_failure") for i in range(5)])

def test_suspicious_success_is_critical():
    alerts = detect_alerts([event(i * 10, "login_failure") for i in range(5)] + [event(55, "login_success")])
    assert any(a.rule_name == "Suspicious successful login" and a.severity == "CRITICAL" for a in alerts)

def test_normal_success_has_no_alert():
    assert not detect_alerts([event(0, "login_success")])

def test_request_burst_triggers():
    assert any(a.rule_name == "High-volume request burst" for a in detect_alerts([event(i // 2, "request") for i in range(100)]))

def test_normal_requests_do_not_trigger():
    assert not detect_alerts([event(i * 2, "request") for i in range(20)])

def test_ips_are_independent():
    events = [event(i * 10, "login_failure", "192.0.2.1") for i in range(4)] + [event(5, "login_failure", "192.0.2.2")]
    assert not detect_alerts(events)

def test_alerts_are_deduplicated_per_rule_and_ip():
    events = [event(i * 5, "login_failure") for i in range(8)]
    assert sum(a.rule_name == "Brute-force login" for a in detect_alerts(events)) == 1

def test_events_are_processed_chronologically():
    events = [event(i * 5, "login_failure") for i in range(4, -1, -1)]
    assert detect_alerts(events)[0].timestamp.endswith("00:00:20+00:00")
