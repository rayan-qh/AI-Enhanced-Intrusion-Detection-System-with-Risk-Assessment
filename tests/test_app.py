import json
import time
from app import create_app, parse_snort


def test_idle_has_no_fabricated_prediction(tmp_path):
    client = create_app(tmp_path).test_client()
    assert client.get('/').status_code == 200
    result = client.get('/api/status').get_json()
    assert result['state'] == 'idle'
    assert result['prediction'] is None


def test_stale_and_malformed_results(tmp_path):
    path = tmp_path / 'prediction.json'
    path.write_text(json.dumps({'timestamp': time.time()-120, 'attack_type': 'BENIGN', 'class_probabilities': {'BENIGN': 1}}))
    client = create_app(tmp_path).test_client()
    assert client.get('/api/status').get_json()['state'] == 'stale'
    path.write_text('{broken')
    assert client.get('/api/status').get_json()['state'] == 'invalid'


def test_snort_has_no_model_confidence(tmp_path):
    (tmp_path/'alert_fast.txt').write_text('[**] [1:1000002:1] SYN activity [**] 10.0.0.1 -> 10.0.0.2')
    result = create_app(tmp_path).test_client().get('/api/status').get_json()
    assert result['snort']['message'] == 'SYN activity'
    assert result['snort']['confidence'] is None
    assert result['prediction'] is None
    assert parse_snort('broken') is None


def test_invalid_probabilities_and_future_time(tmp_path):
    path=tmp_path/'prediction.json'
    result={'timestamp':time.time()+3600,'attack_type':'BENIGN','class_probabilities':{'BENIGN':1}}
    path.write_text(json.dumps(result))
    client=create_app(tmp_path).test_client()
    assert client.get('/api/status').get_json()['state']=='stale'
    result['class_probabilities']['BENIGN']=99
    path.write_text(json.dumps(result))
    assert client.get('/api/status').get_json()['state']=='invalid'
