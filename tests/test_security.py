# tests/test_security.py
import io
import os

import pytest
import yaml

from app.services.security import allowed_hosts

MD5 = 'a' * 32


def _upload(client, name='s.exe', data=b'payload', **kw):
    return client.post('/upload', data={'file': (io.BytesIO(data), name)},
                       content_type='multipart/form-data', **kw)


def test_cross_site_post_rejected(client):
    r = _upload(client, headers={'Origin': 'https://evil.example'})
    assert r.status_code == 403
    r = client.post('/cleanup', headers={'Sec-Fetch-Site': 'cross-site'})
    assert r.status_code == 403
    r = client.post('/cleanup', headers={'Origin': 'null'})
    assert r.status_code == 403


def test_same_origin_and_non_browser_posts_allowed(client):
    assert _upload(client, headers={'Origin': 'http://localhost'}).status_code == 200
    assert _upload(client, headers={'Sec-Fetch-Site': 'same-origin'}).status_code == 200
    assert _upload(client).status_code == 200  # GrumpyCats: no Origin header


def test_dns_rebinding_host_rejected(client):
    r = client.get('/health', headers={'Host': 'attacker.example:1337'})
    assert r.status_code == 400
    assert client.get('/health', headers={'Host': '127.0.0.1:1337'}).status_code in (200, 503)


@pytest.mark.parametrize('host,extra,expected', [
    ('127.0.0.1', None, {'localhost', '127.0.0.1', '::1'}),
    ('192.168.1.5', None, {'localhost', '127.0.0.1', '::1', '192.168.1.5'}),
    ('0.0.0.0', None, None),
    ('0.0.0.0', ['lab.local'], {'localhost', '127.0.0.1', '::1', 'lab.local'}),
    ('127.0.0.1', ['*'], None),
])
def test_allowed_hosts(host, extra, expected):
    cfg = {'application': {'host': host, 'allowed_hosts': extra}}
    assert allowed_hosts(cfg) == expected


@pytest.mark.parametrize('path', [
    "/analyze/dynamic/x';alert(1);'",
    '/analyze/bogus/' + MD5,
    '/results/info/not-a-hash',
    '/api/results/edr/..%5C..%5Cx/' + MD5,
    '/file/dynamic',
])
def test_invalid_targets_do_not_route(client, path):
    method = client.delete if path.startswith('/file/') else client.get
    assert method(path).status_code == 404


def test_upload_size_limit(app, client):
    app.config['MAX_CONTENT_LENGTH'] = 1024
    r = _upload(client, data=b'x' * 4096)
    assert r.status_code == 413
    assert 'too large' in r.get_json()['error']


def test_bad_args_body_is_400(client):
    md5 = _upload(client).get_json()['file_info']['md5']
    r = client.post(f'/analyze/dynamic/{md5}', data='not json', content_type='application/json')
    assert r.status_code == 400
    r = client.post(f'/analyze/dynamic/{md5}', json={'args': 'notalist'})
    assert r.status_code == 400


def test_cleanup_honours_flags(app, client):
    _upload(client)
    uploads = app.config['utils']['upload_folder']
    results = app.config['utils']['result_folder']
    r = client.post('/cleanup', json={'cleanup_uploads': False, 'cleanup_results': False, 'cleanup_analysis': True})
    assert r.status_code == 200
    assert os.listdir(uploads) and os.listdir(results)
    r = client.post('/cleanup', json={'cleanup_uploads': True, 'cleanup_results': False, 'cleanup_analysis': False})
    assert not os.listdir(uploads) and os.listdir(results)
    assert client.post('/cleanup', json={'cleanup_uploads': 'yes'}).status_code == 400


def test_delete_pid_results_only(app, client):
    folder = os.path.join(app.config['utils']['result_folder'], 'dynamic_4242')
    os.makedirs(folder)
    other = os.path.join(app.config['utils']['result_folder'], 'dynamic_77')
    os.makedirs(other)
    assert client.delete('/file/4242').status_code == 200
    assert not os.path.exists(folder) and os.path.exists(other)


def test_unexpected_error_hides_message(app, client, monkeypatch):
    from app.utils import file_io
    monkeypatch.setattr(file_io, 'save_uploaded_file', lambda *a, **k: (_ for _ in ()).throw(OSError('C:\\secret\\path')))
    r = _upload(client)
    assert r.status_code == 500
    assert 'secret' not in r.get_json()['error']


def _write_profile(tmp_path, **fields):
    data = {'name': 'lab', 'display_name': 'Lab', 'agent_url': 'http://10.0.0.5:8080', 'kind': 'exec'}
    data.update(fields)
    path = tmp_path / 'lab.yml'
    path.write_text(yaml.safe_dump(data))
    return str(tmp_path)


def test_live_edr_fails_closed(tmp_path):
    from app.analyzers.edr.backend import discover_backends
    from app.analyzers.edr.profile import load_profiles
    discover_backends()
    (profile,) = load_profiles(_write_profile(tmp_path))
    assert profile.live_edr is True
    (profile,) = load_profiles(_write_profile(tmp_path, live_edr=False))
    assert profile.live_edr is False


@pytest.mark.parametrize('fields', [
    {'live_edr': 'no'},
    {'exec_timeout_seconds': '1m'},
    {'exec_timeout_seconds': 0},
    {'kind': 5},
    {'agent_url': 'ftp://x'},
    {'name': '../evil'},
    {'wait_seconds_for_alerts': None, 'live_edr': False, 'exec_timeout_seconds': -1},
])
def test_bad_profiles_are_skipped_not_fatal(tmp_path, fields):
    from app.analyzers.edr.backend import discover_backends
    from app.analyzers.edr.profile import load_profiles
    discover_backends()
    assert load_profiles(_write_profile(tmp_path, **fields)) == []
