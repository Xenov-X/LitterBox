# tests/test_process_lifecycle.py
"""Process lifecycle helpers (POSIX here; the Windows job object path is
exercised only on Windows)."""
import os
import subprocess
import sys
import textwrap
import time

import psutil
import pytest

from app.analyzers.process_utils import OutputDrain, build_argv, kill_tree, run_tool


def test_build_argv_keeps_spaced_paths_whole():
    argv = build_argv('{tool_path} -s -m {rules_path} {file_path}',
                      tool_path='/opt/John Doe/yara', rules_path='r.yar', file_path='/x y/s.exe')
    assert argv == ['/opt/John Doe/yara', '-s', '-m', 'r.yar', '/x y/s.exe']


def _spawner(tmp_path, sleep=60):
    """A tool that starts a grandchild and then hangs."""
    script = tmp_path / 'spawner.py'
    script.write_text(textwrap.dedent(f'''
        import subprocess, sys, time
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep({sleep})'])
        open(r'{tmp_path / "child.pid"}', 'w').write(str(child.pid))
        time.sleep({sleep})
    '''))
    return [sys.executable, str(script)]


@pytest.mark.skipif(os.name == 'nt', reason='POSIX process-tree semantics')
def test_run_tool_timeout_kills_tree(tmp_path):
    t0 = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_tool(_spawner(tmp_path), timeout=1.5)
    assert time.monotonic() - t0 < 15
    child_pid = int((tmp_path / 'child.pid').read_text())
    time.sleep(0.2)
    assert not psutil.pid_exists(child_pid) or psutil.Process(child_pid).status() == psutil.STATUS_ZOMBIE


def test_run_tool_decodes_utf8():
    out, err, rc = run_tool([sys.executable, '-c', 'import sys; sys.stdout.buffer.write("Н\\x9d".encode())'])
    assert rc == 0 and 'Н' in out


@pytest.mark.skipif(os.name == 'nt', reason='POSIX pipe semantics')
def test_output_drain_keeps_chatty_child_running():
    # 5 MB of output: without a drain the child blocks on a full pipe.
    proc = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdout.write("x" * 5_000_000); sys.stdout.flush()'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    drain = OutputDrain(proc, limit_bytes=1024)
    assert proc.wait(timeout=20) == 0
    drain.join()
    assert drain.truncated and len(drain.text('stdout')) == 1024


@pytest.mark.skipif(os.name == 'nt', reason='POSIX process-tree semantics')
def test_kill_tree(tmp_path):
    proc = subprocess.Popen(_spawner(tmp_path))
    for _ in range(50):
        if (tmp_path / 'child.pid').exists():
            break
        time.sleep(0.1)
    child_pid = int((tmp_path / 'child.pid').read_text())
    kill_tree(proc.pid)
    proc.wait(timeout=5)
    time.sleep(0.2)
    assert not psutil.pid_exists(child_pid) or psutil.Process(child_pid).status() == psutil.STATUS_ZOMBIE


@pytest.mark.skipif(os.name == 'nt', reason='POSIX process-tree semantics')
def test_manager_terminates_sample_and_captures_output(app_config, tmp_path):
    from app.analyzers.manager import AnalysisManager
    sample = tmp_path / 'sample.py'
    sample.write_text('import sys, time\nprint("hello from sample", flush=True)\ntime.sleep(60)\n')
    os.chmod(sample, 0o755)
    sample.write_text('#!' + sys.executable + '\n' + sample.read_text())
    app_config['analysis']['process'] = {'init_wait_time': 0.5}
    mgr = AnalysisManager(app_config)
    process, pid = mgr._create_new_process(str(sample), [])
    time.sleep(0.5)
    out = mgr._capture_process_output(process)
    assert 'hello from sample' in out['stdout']
    assert out['exit_code'] is None and process.poll() is not None


def test_dynamic_runs_are_serialised(app_config):
    from app.analyzers import manager as manager_mod
    mgr = manager_mod.AnalysisManager(app_config)
    with manager_mod._DYNAMIC_LOCK:
        result = mgr.run_dynamic_analysis('/nonexistent.exe')
    assert result['status'] == 'busy'
