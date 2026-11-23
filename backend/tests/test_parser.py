import json
from parser import parse_line, parse_lines

def test_valid_log_parses():
    row = parse_line('{"timestamp":"2025-01-01T00:00:00+00:00","ip":"192.0.2.1","username":"alice","event_type":"login_success"}')
    assert row.ip == "192.0.2.1" and row.username == "alice" and row.event_type == "login_success"

def test_invalid_lines_are_counted_and_skipped():
    rows, malformed = parse_lines(['not json', '{"timestamp":"bad"}'])
    assert rows == [] and malformed == 2

def test_optional_fields_can_be_missing():
    row = parse_line('{"timestamp":"2025-01-01T00:00:00Z","ip":"192.0.2.1","event_type":"request"}')
    assert row.username == "unknown" and row.method is None

def test_blank_lines_are_ignored():
    rows, malformed = parse_lines(['', '  '])
    assert rows == [] and malformed == 0
