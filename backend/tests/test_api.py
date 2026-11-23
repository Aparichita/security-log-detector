from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get('/health')
    assert response.status_code == 200 and response.json()['status'] == 'ok'

def test_alert_endpoint_returns_structured_json():
    response = client.get('/alerts')
    assert response.status_code == 200 and isinstance(response.json(), list)
    assert {'ip','rule_name','severity','timestamp','description'} <= response.json()[0].keys()

def test_severity_filter():
    assert all(row['severity'] == 'CRITICAL' for row in client.get('/alerts?severity=critical').json())

def test_stats_fields():
    data = client.get('/stats').json()
    assert {'total_logs','total_alerts','critical_alerts','high_alerts','medium_alerts','unique_ips','failed_logins','successful_logins','request_events'} <= data.keys()

def test_logs_pagination_and_filter():
    first = client.get('/logs?limit=5&offset=0').json()
    second = client.get('/logs?limit=5&offset=5').json()
    assert len(first['items']) == len(second['items']) == 5
    assert first['items'][0] != second['items'][0]
    failures = client.get('/logs?event_type=login_failure&limit=5').json()
    assert all(row['event_type'] == 'login_failure' for row in failures['items'])

def test_invalid_pagination_rejected():
    assert client.get('/logs?limit=0').status_code == 422

def test_ips_endpoint_returns_risk_summaries():
    rows = client.get('/ips').json()
    assert rows and {'ip','total_events','failed_logins','successful_logins','requests','alerts','risk_level'} <= rows[0].keys()
