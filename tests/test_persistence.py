# tests/test_persistence.py
import json
import os
import threading
import time

from app.services import summary_cache
from app.utils.json_helpers import load_json_file, write_json_atomic


def test_write_json_atomic_never_exposes_partial_file(tmp_path):
    path = tmp_path / 'r.json'
    write_json_atomic(str(path), {'v': 0})
    big = {'blob': 'x' * 2_000_000}
    stop = threading.Event()
    bad = []

    def reader():
        while not stop.is_set():
            try:
                with open(path) as f:
                    json.load(f)
            except json.JSONDecodeError:
                bad.append(1)
            except OSError:
                pass
            time.sleep(0.001)

    t = threading.Thread(target=reader)
    t.start()
    for i in range(20):
        write_json_atomic(str(path), {**big, 'v': i})
    stop.set()
    t.join()
    assert not bad
    assert load_json_file(str(path))['v'] == 19
    assert [p for p in os.listdir(tmp_path) if p.endswith('.tmp')] == []


def test_summary_cache_uses_pre_read_snapshot(tmp_path):
    item = tmp_path / 'abc'
    item.mkdir()
    (item / 'file_info.json').write_text('{}')
    sources = summary_cache.snapshot(str(item))
    # A source changes while the summary is being computed...
    os.utime(item / 'file_info.json', ns=(1, 1))
    summary_cache.store(str(item), {'score': 1}, sources)
    # ...so the stored entry must not be served for the new state.
    assert summary_cache.get_cached(str(item)) is None
    fresh = summary_cache.snapshot(str(item))
    summary_cache.store(str(item), {'score': 2}, fresh)
    assert summary_cache.get_cached(str(item), fresh) == {'score': 2}


def test_summary_cache_version_mismatch_is_a_miss(tmp_path):
    item = tmp_path / 'abc'
    item.mkdir()
    (item / 'file_info.json').write_text('{}')
    sources = summary_cache.snapshot(str(item))
    (item / summary_cache.CACHE_FILE).write_text(json.dumps({'_sources': sources, 'summary': {'old': True}}))
    assert summary_cache.get_cached(str(item), sources) is None
