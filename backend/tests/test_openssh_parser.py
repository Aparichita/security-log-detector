from datetime import timezone
import pytest
from detector import detect_alerts
from parser import LogEvent
from parsers.openssh_parser import parse_line

def test_failed_password_normalizes_to_failure():
    event = parse_line("Dec 10 09:32:35 LabSZ sshd[24787]: Failed password for root from 192.0.2.7 port 22 ssh2", 2020)
    assert event.event_type == "login_failure" and event.ip == "192.0.2.7" and event.username == "root"

def test_successful_password_normalizes_to_success():
    event = parse_line("Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for alice from 192.0.2.9 port 49116 ssh2", 2020)
    assert event.event_type == "login_success" and event.username == "alice"

def test_public_key_authentication_normalizes_to_success():
    event = parse_line("Jun 14 15:16:01 host sshd[123]: Accepted publickey for sam from 198.51.100.4 port 22 ssh2", 2024)
    assert event.event_type == "login_success" and event.source == "openssh"

def test_syslog_year_is_assumed_from_configuration():
    event = parse_line("Dec 10 09:32:20 host sshd[1]: Accepted password for bob from 192.0.2.1 port 22 ssh2", 2018)
    assert event.timestamp.year == 2018 and event.timestamp.tzinfo == timezone.utc

def test_invalid_user_is_a_failed_attempt_and_duplicate_terminal_line_is_ignored():
    invalid = parse_line("Dec 10 09:32:35 host sshd[9]: Invalid user guest from 192.0.2.8", 2025)
    terminal = parse_line("Dec 10 09:32:37 host sshd[9]: Failed password for invalid user guest from 192.0.2.8 port 22 ssh2", 2025)
    assert invalid.event_type == "login_failure" and terminal is None

def test_malformed_syslog_is_handled():
    with pytest.raises(ValueError):
        parse_line("this is not an ssh syslog entry")

def test_normalized_openssh_events_trigger_brute_force_and_suspicious_success():
    base = "Jun 14 15:16:{:02d} host sshd[{}]: {}"
    lines = [base.format(i, i, f"Failed password for alice from 192.0.2.10 port 22 ssh2") for i in range(5)]
    events = [parse_line(line) for line in lines]
    success = parse_line("Jun 14 15:17:00 host sshd[20]: Accepted password for alice from 192.0.2.10 port 22 ssh2")
    alerts = detect_alerts(events + [success])
    assert {alert.severity for alert in alerts} == {"HIGH", "CRITICAL"}

def test_subthreshold_real_format_does_not_alert():
    events = [parse_line(f"Jun 14 15:16:0{i} host sshd[{i}]: Failed password for alice from 192.0.2.10 port 22 ssh2") for i in range(4)]
    assert detect_alerts(events) == []
