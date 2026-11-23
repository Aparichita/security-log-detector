from datetime import timedelta
import pytest
from dataset_manager import DatasetManager
from detector import detect_alerts
from parsers.nasa_parser import parse_line, anonymize_host
from pathlib import Path

SAMPLE = '199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /history/apollo/ HTTP/1.0" 200 6245'

def test_apache_style_line_extracts_normalized_fields_and_masks_host():
    event = parse_line(SAMPLE)
    assert event.event_type == "request" and event.source == "nasa"
    assert event.ip.startswith("host-") and "199.72" not in event.ip
    assert event.method == "GET" and event.path == "/history/apollo/"
    assert event.status == 200 and event.response_size == 6245 and event.username == "redacted"

def test_nasa_timestamp_conversion_preserves_timezone():
    event = parse_line(SAMPLE)
    assert event.timestamp.isoformat() == "1995-07-01T00:00:01-04:00"
    assert event.timestamp.utcoffset() == timedelta(hours=-4)

def test_missing_response_size_is_supported():
    event = parse_line(SAMPLE.rsplit(" ", 1)[0] + " -")
    assert event.response_size is None

def test_malformed_access_line_raises_value_error():
    with pytest.raises(ValueError):
        parse_line("bad access record")

def test_normalized_http_events_trigger_request_burst():
    base = '192.0.2.20 - - [01/Jul/1995:00:00:{:02d} -0400] "GET / HTTP/1.0" 200 12'
    events = [parse_line(base.format(i % 60)) for i in range(100)]
    alerts = detect_alerts(events, request_threshold=100, request_window=timedelta(seconds=60))
    assert len(alerts) == 1 and alerts[0].severity == "MEDIUM"
    assert alerts[0].ip.startswith("host-")

def test_different_anonymized_hosts_are_tracked_independently():
    from parsers.nasa_parser import parse_line as nasa_parse
    rows = [nasa_parse(f'192.0.2.{host} - - [01/Jul/1995:00:00:{i:02d} -0400] "GET / HTTP/1.0" 200 10') for host in (1, 2) for i in range(4)]
    assert anonymize_host("192.0.2.1") != anonymize_host("192.0.2.2")
    assert detect_alerts(rows, request_threshold=5) == []

def test_streaming_large_fixture_never_uses_read_all(tmp_path, monkeypatch):
    source = tmp_path / "nasa.log"
    with source.open("w", encoding="utf-8") as handle:
        for i in range(5000):
            sec = i % 60
            minute = (i // 60) % 60
            hour = (i // 3600) % 24
            handle.write(f'192.0.2.{i % 20 + 1} - - [01/Jul/1995:{hour:02d}:{minute:02d}:{sec:02d} -0400] "GET / HTTP/1.0" 200 10\n')
    original_open = Path.open
    class IteratorOnly:
        def __init__(self, path, *args, **kwargs): self.handle = original_open(path, *args, **kwargs)
        def __enter__(self): return self
        def __exit__(self, *args): return self.handle.__exit__(*args)
        def __iter__(self): return iter(self.handle)
        def read(self, *args, **kwargs): raise AssertionError("whole-file read is forbidden")
        def readlines(self, *args, **kwargs): raise AssertionError("whole-file read is forbidden")
    monkeypatch.setattr(Path, "open", lambda self, *args, **kwargs: IteratorOnly(self, *args, **kwargs))
    manager = DatasetManager("nasa", paths={"nasa": [source]})
    snapshot = manager.get()
    assert snapshot.records_processed == 5000 and snapshot.valid_records == 5000
    assert snapshot.stats["request_events"] == 5000
