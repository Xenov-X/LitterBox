# tests/test_app_smoke.py
import io
import json
import os
import re



def _upload(client, name, data, **form):
    return client.post('/upload', data={'file': (io.BytesIO(data), name), **form},
                       content_type='multipart/form-data')


def test_health_and_pages(client):
    assert client.get('/health').status_code in (200, 503)
    for path in ('/', '/upload', '/summary', '/files'):
        assert client.get(path).status_code == 200, path


def test_upload_info_and_delete(client):
    r = _upload(client, 'hello.exe', b'not really a pe')
    assert r.status_code == 200, r.get_json()
    md5 = r.get_json()['file_info']['md5']
    assert client.get(f'/api/results/info/{md5}').status_code == 200
    assert client.get(f'/results/info/{md5}').status_code == 200
    assert client.delete(f'/file/{md5}').status_code == 200
    assert client.get(f'/api/results/info/{md5}').status_code == 404


def test_unparseable_pe_file_info_renders(client):
    # Starts with MZ, so it's classified as a PE, but pefile can't parse it:
    # file_info.pe_info is None and the page must still render.
    r = _upload(client, 'trunc.exe', b'MZ' + b'\x00' * 10)
    md5 = r.get_json()['file_info']['md5']
    assert r.get_json()['file_info'].get('pe_info') is None
    assert client.get(f'/results/info/{md5}').status_code == 200


def _write_results(app, md5, name, payload):
    from app.utils import path_manager
    folder = path_manager.find_file_by_hash(md5, app.config['utils']['result_folder'])
    with open(os.path.join(folder, name), 'w') as f:
        json.dump(payload, f)


def test_report_score_matches_api_with_edr(app, client):
    r = _upload(client, 'sample.exe', b'payload-bytes')
    md5 = r.get_json()['file_info']['md5']
    _write_results(app, md5, 'static_analysis_results.json', {
        'yara': {'status': 'completed', 'matches': [{'rule': 'x', 'metadata': {'severity': 75}, 'strings': []}]},
    })
    _write_results(app, md5, 'edr_lab_results.json', {
        'status': 'completed', 'alerts': [{'severity': 'critical'}],
        'summary': {'high_severity_alerts': 1},
    })
    api = client.get(f'/api/results/risk/{md5}').get_json()
    report = client.get(f'/api/report/{md5}')
    assert report.status_code == 200
    html = report.get_data(as_text=True)
    m = re.search(r'<span class="risk-score">(\d+)</span>', html)
    assert m, 'risk score not rendered'
    assert int(m.group(1)) == round(api['risk_score'])
