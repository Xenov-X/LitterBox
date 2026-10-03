# app/analyzers/process_utils.py
"""Process helpers shared by the local analyzers.

- build_argv:   format a config command template into an argv list (no shell).
- run_tool:     run a scanner with a timeout that actually stops it — the
                whole process tree is killed and the pipes are reaped.
- kill_tree:    kill a process and all of its descendants.
- JobObject:    Windows job object with KILL_ON_JOB_CLOSE, so everything a
                detonated sample spawns dies with it.
- OutputDrain:  read a child's stdout/stderr into bounded buffers while it
                runs, so a chatty sample never blocks on a full pipe.
"""
import logging
import os
import subprocess
import threading

import psutil

logger = logging.getLogger(__name__)


def build_argv(template, **values):
    """Split a command template on whitespace, then substitute each token.

    Substituting first and splitting afterwards (or handing the string to
    a shell) breaks any value that contains a space, e.g. a repository
    under "C:\\Users\\John Doe\\".
    """
    argv = []
    for token in template.split():
        argv.append(token.format(**values).strip())
    return [a for a in argv if a]


def kill_tree(pid, timeout=5):
    """Kill `pid` and every descendant; wait up to `timeout` for them."""
    try:
        parent = psutil.Process(pid)
    except (psutil.NoSuchProcess, ValueError):
        return
    try:
        procs = parent.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        procs = []
    procs.append(parent)
    for proc in procs:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    psutil.wait_procs(procs, timeout=timeout)


def run_tool(argv, timeout=None, cwd=None):
    """Run a scanner and return (stdout, stderr, returncode).

    On timeout the scanner and all its children are killed and the pipes
    drained before subprocess.TimeoutExpired is re-raised, so a hung
    scanner can't keep running (and holding the sample open) in the
    background. Output is decoded as UTF-8 with replacement; the default
    locale codec (cp1252) raised on bytes such as 0x81/0x9D.
    """
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='utf-8',
        errors='replace',
        cwd=cwd,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_tree(process.pid)
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            # A grandchild inherited the pipes and survived; stop waiting.
            for pipe in (process.stdout, process.stderr):
                try:
                    pipe.close()
                except Exception:
                    pass
        raise
    return stdout, stderr, process.returncode


class OutputDrain:
    """Continuously read a Popen's stdout/stderr into bounded buffers.

    Without this the sample's output was only read after every analyzer
    finished; a sample writing more than the pipe buffer (~4 KB) blocked
    in WriteFile and the memory scanners observed a stalled process.
    """

    def __init__(self, process, limit_bytes=1024 * 1024):
        self.limit = limit_bytes
        self.truncated = False
        self._chunks = {'stdout': [], 'stderr': []}
        self._sizes = {'stdout': 0, 'stderr': 0}
        self._lock = threading.Lock()
        self._threads = []
        for name in ('stdout', 'stderr'):
            stream = getattr(process, name)
            if stream is None:
                continue
            t = threading.Thread(target=self._pump, args=(name, stream),
                                 name=f'sample-{name}', daemon=True)
            t.start()
            self._threads.append(t)

    def _pump(self, name, stream):
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                with self._lock:
                    room = self.limit - self._sizes[name]
                    if room > 0:
                        self._chunks[name].append(chunk[:room])
                        self._sizes[name] += min(len(chunk), room)
                    if len(chunk) > room:
                        self.truncated = True
        except (OSError, ValueError):
            pass  # pipe closed underneath us during cleanup

    def join(self, timeout=2.0):
        for t in self._threads:
            t.join(timeout)

    def text(self, name):
        with self._lock:
            data = b''.join(self._chunks[name])
        return data.decode('utf-8', errors='replace')


class JobObject:
    """Windows job object that terminates every process in it on close.

    No-op elsewhere. `assign()` failures are logged, not raised — the
    caller still has kill_tree() as a fallback.
    """

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _JobObjectExtendedLimitInformation = 9

    def __init__(self):
        self.handle = None
        if os.name != 'nt':
            return
        try:
            import ctypes
            from ctypes import wintypes

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in (
                    'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                    'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('PerProcessUserTimeLimit', wintypes.LARGE_INTEGER),
                    ('PerJobUserTimeLimit', wintypes.LARGE_INTEGER),
                    ('LimitFlags', wintypes.DWORD),
                    ('MinimumWorkingSetSize', ctypes.c_size_t),
                    ('MaximumWorkingSetSize', ctypes.c_size_t),
                    ('ActiveProcessLimit', wintypes.DWORD),
                    ('Affinity', ctypes.c_size_t),
                    ('PriorityClass', wintypes.DWORD),
                    ('SchedulingClass', wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ('IoInfo', IO_COUNTERS),
                    ('ProcessMemoryLimit', ctypes.c_size_t),
                    ('JobMemoryLimit', ctypes.c_size_t),
                    ('PeakProcessMemoryUsed', ctypes.c_size_t),
                    ('PeakJobMemoryUsed', ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
            kernel32.SetInformationJobObject.argtypes = (
                wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
            kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
            kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            self._kernel32 = kernel32

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error(), 'CreateJobObjectW failed')
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(
                    handle, self._JobObjectExtendedLimitInformation,
                    ctypes.byref(info), ctypes.sizeof(info)):
                kernel32.CloseHandle(handle)
                raise OSError(ctypes.get_last_error(), 'SetInformationJobObject failed')
            self.handle = handle
        except Exception as e:
            logger.warning(f"Job object unavailable ({e}); falling back to process-tree kill")
            self.handle = None

    def assign(self, process):
        """Put a subprocess.Popen into the job. Returns True on success."""
        if not self.handle:
            return False
        proc_handle = getattr(process, '_handle', None)
        if proc_handle is None or not self._kernel32.AssignProcessToJobObject(self.handle, int(proc_handle)):
            logger.warning(f"Could not assign PID {process.pid} to job object")
            return False
        return True

    def close(self):
        """Terminate every process in the job and release it."""
        if not self.handle:
            return
        try:
            self._kernel32.TerminateJobObject(self.handle, 1)
        finally:
            self._kernel32.CloseHandle(self.handle)
            self.handle = None
