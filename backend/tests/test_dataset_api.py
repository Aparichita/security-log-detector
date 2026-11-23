from fastapi.testclient import TestClient
from main import app
from dataset_manager import manager

client = TestClient(app)

def test_dataset_info_and_stats_are_exposed():
    manager.select("synthetic")
    info = client.get('/datasets').json()
    stats = client.get('/datasets/stats').json()
    assert info['source'] == 'synthetic' and info['processing_status'] == 'ready'
    assert info['records_processed'] == 597 and info['valid_records'] == 597
    assert stats['request_events'] > 0 and 'processing_seconds' in stats

def test_dataset_selection_and_not_installed_message():
    try:
        info = client.post('/datasets/select', json={'source':'nasa'}).json()
        assert info['source'] == 'nasa' and info['processing_status'] == 'not_installed'
        assert 'NASA_access_log' in info['message']
        detail = client.get('/logs').json()
        assert detail['privacy_limited'] is True and detail['items'] == []
        assert client.get('/activity').status_code == 200
    finally:
        manager.select('synthetic')

def test_unsupported_dataset_source_is_rejected():
    response = client.post('/datasets/select', json={'source':'other'})
    assert response.status_code == 422
