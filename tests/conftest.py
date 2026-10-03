# tests/conftest.py
"""Shared fixtures. Tests run on any OS: analyzers that shell out to the
Windows scanners are disabled, and all runtime folders live in tmp_path."""
import copy
import os
import sys

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


@pytest.fixture(scope='session')
def base_config():
    with open(os.path.join(REPO_ROOT, 'Config', 'config.yaml')) as f:
        return yaml.safe_load(f)


@pytest.fixture
def app_config(base_config, tmp_path):
    cfg = copy.deepcopy(base_config)
    cfg['utils']['upload_folder'] = str(tmp_path / 'Uploads')
    cfg['utils']['result_folder'] = str(tmp_path / 'Results')
    cfg['utils']['malapi_path'] = os.path.join(REPO_ROOT, 'Utils', 'malapi.json')
    cfg['analysis']['doppelganger']['db']['path'] = str(tmp_path / 'DoppelgangerDB')
    for section in ('static', 'dynamic'):
        for tool in cfg['analysis'][section].values():
            tool['enabled'] = False
    cfg['analysis']['holygrail']['enabled'] = False
    cfg['TESTING'] = True
    return cfg


@pytest.fixture
def app(app_config, monkeypatch, tmp_path):
    from app.analyzers.edr import registry as edr_registry
    from app.services import edr_health

    # No EDR profiles and no background health poller in tests.
    profiles_dir = tmp_path / 'edr_profiles'
    profiles_dir.mkdir()
    real_init = edr_registry.init
    monkeypatch.setattr(edr_registry, 'init', lambda config, profiles_dir_=None: real_init(config, str(profiles_dir)))
    monkeypatch.setattr(edr_health, 'start_poller', lambda deps: None)

    from app import create_app
    application = create_app(app_config)
    return application


@pytest.fixture
def client(app):
    return app.test_client()
