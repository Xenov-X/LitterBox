# app/analyzers/manager.py

import logging
import os
import subprocess
import threading
import time
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Type, Optional, Tuple

# Import analyzers
from .static.yara_analyzer import YaraStaticAnalyzer
from .static.checkplz_analyzer import CheckPlzAnalyzer
from .static.stringnalyzer_analyzer import StringsAnalyzer
from .dynamic.yara_analyzer import YaraDynamicAnalyzer
from .dynamic.pe_sieve_analyzer import PESieveAnalyzer
from .dynamic.moneta_analyzer import MonetaAnalyzer
from .dynamic.patriot_analyzer import PatriotAnalyzer
from .dynamic.hsb_analyzer import HSBAnalyzer
from .dynamic.rededr_analyzer import RedEdrAnalyzer
from .base import BaseAnalyzer
from .process_utils import JobObject, OutputDrain, kill_tree

# Windows CreateProcess flag; the sample is resumed after it has been put
# in its job object so nothing it spawns can escape the job.
_CREATE_SUSPENDED = 0x00000004

# Only one dynamic analysis at a time: the samples share the host, and
# system-wide scanners (HollowsHunter) would observe each other's payloads.
_DYNAMIC_LOCK = threading.Lock()


class AnalysisManager:
    # Define analyzer mappings
    STATIC_ANALYZERS = {
        'yara': YaraStaticAnalyzer,
        'checkplz': CheckPlzAnalyzer,
        'stringnalyzer': StringsAnalyzer
    }

    DYNAMIC_ANALYZERS = {
        'yara': YaraDynamicAnalyzer,
        'pe_sieve': PESieveAnalyzer,
        'moneta': MonetaAnalyzer,
        'patriot': PatriotAnalyzer,
        'hsb': HSBAnalyzer,
        'rededr': RedEdrAnalyzer
    }

    # Analyzers that must run serially AFTER the parallel batch finishes.
    # HSB (Hunt-Sleeping-Beacons) measures the target's sleep / thread
    # timing — concurrent inspection by PE-Sieve / Moneta / Patriot
    # opens handles, walks VAD, and can briefly suspend threads, which
    # would distort the timing pattern HSB observes. Run it solo at the
    # end so its measurements are clean.
    _SERIAL_DYNAMIC_ANALYZERS = frozenset({'hsb'})

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.logger.debug("Initializing AnalysisManager")
        self.config = config
        self.static_analyzers: Dict[str, BaseAnalyzer] = {}
        self.dynamic_analyzers: Dict[str, BaseAnalyzer] = {}
        
        self._initialize_analyzers()

    def _initialize_analyzer(self, name: str, analyzer_class: Type[BaseAnalyzer], config_section: dict) -> Optional[BaseAnalyzer]:
        if not config_section.get('enabled', False):
            self.logger.debug(f"Analyzer {name} is disabled in config")
            return None

        self.logger.debug(f"Initializing {name}")
        try:
            analyzer = analyzer_class(self.config)
            self.logger.debug(f"{name} initialized successfully")
            return analyzer
        except Exception as e:
            self.logger.error(f"Failed to initialize {name}: {e}", exc_info=True)
            return None

    def _initialize_analyzers(self):
        self.logger.debug("Beginning analyzer initialization")
        
        # Initialize static analyzers
        static_config = self.config['analysis']['static']
        for name, analyzer_class in self.STATIC_ANALYZERS.items():
            if analyzer := self._initialize_analyzer(name, analyzer_class, static_config[name]):
                self.static_analyzers[name] = analyzer

        # Initialize dynamic analyzers
        dynamic_config = self.config['analysis']['dynamic']
        for name, analyzer_class in self.DYNAMIC_ANALYZERS.items():
            if analyzer := self._initialize_analyzer(name, analyzer_class, dynamic_config[name]):
                self.dynamic_analyzers[name] = analyzer

        self.logger.debug(f"Initialized static analyzers: {list(self.static_analyzers.keys())}")
        self.logger.debug(f"Initialized dynamic analyzers: {list(self.dynamic_analyzers.keys())}")
        self.logger.debug("Analyzer initialization completed")

    def _run_analyzers(self, analyzers: Dict[str, BaseAnalyzer], target, analysis_type: str) -> dict:
        """Run a group of analyzers and return their findings keyed by name.

        Static analyzers all run in parallel — they're independent
        subprocesses operating on the same on-disk file with their own
        output dirs / stdout. Wall time drops from sum(tools) to
        max(tools).

        Dynamic analyzers split into two groups: parallel-safe (yara,
        pe_sieve, moneta, patriot — read-only IOC scanners) and serial
        (anything in `_SERIAL_DYNAMIC_ANALYZERS`, currently just hsb,
        whose sleep-timing measurements are perturbed by concurrent
        process inspection from the others). The serial group runs AFTER
        the parallel batch completes so HSB sees a quiescent target.

        Each analyzer is wrapped so a single failure can't bring down
        the rest of the group — the failed entry gets a
        `{status: 'error', error: ...}` envelope and the others keep
        running.
        """
        results = {}
        if not analyzers:
            self.logger.warning(f"No {analysis_type} analyzers are enabled")
            return results

        # For dynamic analysis, verify process exists first
        if analysis_type == 'dynamic':
            if not self._validate_dynamic_target(target):
                return {'status': 'error', 'error': 'Process does not exist or is not running'}

        # Partition into parallel + serial groups. Static is fully
        # parallel; dynamic respects the _SERIAL_DYNAMIC_ANALYZERS set.
        if analysis_type == 'dynamic':
            parallel = {n: a for n, a in analyzers.items() if n not in self._SERIAL_DYNAMIC_ANALYZERS}
            serial   = {n: a for n, a in analyzers.items() if n in self._SERIAL_DYNAMIC_ANALYZERS}
        else:
            parallel = dict(analyzers)
            serial   = {}

        self.logger.debug(
            f"Running {analysis_type} analyzers — parallel: {list(parallel)}, "
            f"serial: {list(serial)}"
        )

        if parallel:
            results.update(self._run_in_parallel(parallel, target))
        for name, analyzer in serial.items():
            results[name] = self._run_one(name, analyzer, target)

        return results

    def _run_one(self, name: str, analyzer: BaseAnalyzer, target) -> dict:
        """Run one analyzer, catching exceptions so a single failure
        doesn't take down the rest of the batch. Logs start + completion
        with per-tool wall time so the operator can see progress in the
        debug log.

        A fresh instance runs each analysis: analyzers keep per-run state
        (target, results) on `self`, and the registered instances are
        shared by every request thread.
        """
        self.logger.debug(f"Running {name}")
        t0 = time.monotonic()
        try:
            instance = type(analyzer)(self.config)
            instance.analyze(target)
            result = instance.get_results()
        except Exception as e:
            self.logger.error(f"Error in {name}: {str(e)}")
            result = {'status': 'error', 'error': str(e)}
        elapsed = time.monotonic() - t0
        self.logger.debug(f"{name} finished in {elapsed:.2f}s")
        return result

    def _run_in_parallel(self, analyzers: Dict[str, BaseAnalyzer], target) -> dict:
        """Drive `analyzers` concurrently via a thread pool sized to the
        batch. All analyzers shell out to subprocesses, so the GIL doesn't
        bottleneck wall time — this gets us roughly max(per-tool wall
        time) instead of sum(per-tool wall time)."""
        results: Dict[str, dict] = {}
        max_workers = min(len(analyzers), 8) or 1
        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='analyzer') as pool:
            futures = {pool.submit(self._run_one, name, a, target): name
                       for name, a in analyzers.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    results[name] = fut.result()
                except Exception as e:
                    # _run_one already swallows exceptions; this is the
                    # belt-and-braces path for anything that escapes it.
                    self.logger.error(f"Error in {name}: {str(e)}")
                    results[name] = {'status': 'error', 'error': str(e)}
        self.logger.debug(
            f"Parallel batch finished in {time.monotonic() - t0:.2f}s: {list(results)}"
        )
        return results

    def _validate_dynamic_target(self, target) -> bool:
        """Validate that the target process exists for dynamic analysis"""
        try:
            process = psutil.Process(int(target))
            return process.is_running()
        except (ValueError, psutil.NoSuchProcess):
            self.logger.error(f"Process {target} does not exist")
            return False

    def _create_metadata(self, start_time: float, **kwargs) -> dict:
        """Create analysis metadata with common fields"""
        metadata = {
            'total_duration': time.time() - start_time,
            'timestamp': time.time()
        }
        metadata.update(kwargs)
        return metadata

    def run_static_analysis(self, file_path: str) -> dict:
        start_time = time.time()
        
        try:
            results = self._run_analyzers(self.static_analyzers, file_path, 'static')
            results['analysis_metadata'] = self._create_metadata(start_time)
            
        except Exception as e:
            self.logger.error(f"Error during static analysis: {str(e)}", exc_info=True)
            results = {'analysis_metadata': self._create_metadata(start_time, error=str(e))}
        
        self.logger.debug(f"Static analysis completed in {time.time() - start_time:.2f} seconds")
        return results

    def run_dynamic_analysis(self, target, is_pid: bool = False, cmd_args: list = None) -> dict:
        self.logger.debug(f"Starting dynamic analysis - Target: {target}, is_pid: {is_pid}, args: {cmd_args}")
        start_time = time.time()

        if not _DYNAMIC_LOCK.acquire(blocking=False):
            return {
                'status': 'busy',
                'error': {
                    'message': 'Another dynamic analysis is already running',
                    'details': 'Wait for it to finish, then retry.',
                },
            }
        try:
            if is_pid:
                return self._run_pid_analysis(target, start_time)
            else:
                return self._run_file_analysis(target, cmd_args, start_time)

        except Exception as e:
            self.logger.error(f"Error during dynamic analysis: {str(e)}", exc_info=True)
            return self._create_error_result(start_time, str(e), cmd_args)
        finally:
            _DYNAMIC_LOCK.release()

    def _run_pid_analysis(self, target: str, start_time: float) -> dict:
        """Handle PID-based analysis"""
        try:
            process, pid = self._validate_process(target, True)
            # RedEdr attaches ETW tracing before the payload is spawned, so it
            # can't observe an already-running PID. Report it as skipped
            # rather than "completed, 0 events".
            analyzers = {k: v for k, v in self.dynamic_analyzers.items() if k != 'rededr'}
            results = self._run_analyzers(analyzers, pid, 'dynamic')
            if 'rededr' in self.dynamic_analyzers and isinstance(results, dict) \
                    and results.get('status') != 'error':
                results['rededr'] = {
                    'status': 'skipped',
                    'reason': 'RedEdr traces payloads it launches; not available for PID analysis',
                }
            results['analysis_metadata'] = self._create_metadata(start_time, cmd_args=[])
            return results
        except Exception as e:
            return self._create_error_result(start_time, str(e))

    def _run_file_analysis(self, target: str, cmd_args: list, start_time: float) -> dict:
        """Handle file-based analysis with RedEdr integration.

        RedEdr cleanup is in `finally` so an orphaned RedEdr can never outlive
        a crashed/early-terminated payload. Whatever telemetry RedEdr managed
        to collect is also attached to the response on failure paths, so the
        user sees partial events instead of nothing.
        """
        results = {}
        process = None
        rededr = None
        response = None

        try:
            # 1. Start RedEdr if enabled
            rededr = self._initialize_rededr(target, results)

            # 2. Validate and start process
            try:
                process, pid = self._validate_process(target, False, cmd_args)
            except Exception as e:
                response = self._handle_process_startup_error(e, start_time, cmd_args)
                return response

            # 3. Run regular analyzers (excluding RedEdr)
            regular_analyzers = {k: v for k, v in self.dynamic_analyzers.items() if k != 'rededr'}
            other_results = self._run_analyzers(regular_analyzers, pid, 'dynamic')
            results.update(other_results)

            # 4. Capture process output
            results['process_output'] = self._capture_process_output(process)

            # 5. Get RedEdr results — cleanup is unconditional, in finally.
            if rededr:
                self.logger.debug("Getting RedEdr events")
                results['rededr'] = rededr.get_results()

            results['analysis_metadata'] = self._create_metadata(
                start_time,
                early_termination=False,
                analysis_started=True,
                cmd_args=cmd_args or []
            )
            response = results
            return response

        except Exception as e:
            response = self._create_error_result(start_time, str(e), cmd_args)
            return response

        finally:
            # Never leave the sample (or anything it spawned) running.
            if process is not None:
                self._terminate_sample(process)
            # Always tear down RedEdr — even on early return / exception —
            # so a crashed payload never leaves an orphaned RedEdr process.
            # Cleanup is idempotent, so calling it after the happy-path
            # get_results() is safe.
            if rededr is not None:
                # Attach partial RedEdr telemetry to the response on failure
                # paths (early termination, generic exception). The happy
                # path already populated results['rededr'] in step 5.
                if isinstance(response, dict) and 'rededr' not in response:
                    try:
                        response['rededr'] = rededr.get_results()
                    except Exception as e:
                        self.logger.error(f"Failed to capture partial RedEdr telemetry: {e}")
                try:
                    self._cleanup_rededr(rededr)
                except Exception as e:
                    self.logger.error(f"Error during RedEdr cleanup: {e}")

    def _initialize_rededr(self, target: str, results: dict):
        """Initialize RedEdr if enabled.

        Blocks until RedEdr logs that all ETW providers are attached
        (typically 1-3s), RedEdr exits, or `ready_timeout` (default 30s)
        passes — a RedEdr that stays alive without attaching must not hang
        the analysis before the payload is even launched.
        """
        rededr_config = self.config['analysis']['dynamic'].get('rededr', {})
        if not rededr_config.get('enabled'):
            return None

        self.logger.debug("Initializing RedEdr analyzer")
        try:
            # For DLL targets we spawn `rundll32.exe <dll>,<entry>` — the
            # actual running process is rundll32, not the DLL. RedEdr's
            # --trace filter takes a process name, so point it at
            # rundll32.exe to capture ETW from the DLL's host process.
            if target.lower().endswith('.dll'):
                target_name = 'rundll32.exe'
            else:
                target_name = target.split('\\')[-1]
            rededr = RedEdrAnalyzer(self.config)
            if not rededr.start_tool(target_name):
                self.logger.error("Failed to start RedEdr")
                results['rededr'] = {'status': 'error', 'error': 'Failed to start tool'}
                return None

            ready_timeout = float(rededr_config.get('ready_timeout', 30))
            ready_start = time.monotonic()
            signalled = rededr.wait_for_ready(timeout=ready_timeout)
            elapsed = time.monotonic() - ready_start
            if rededr.is_ready():
                self.logger.debug(
                    f"RedEdr ready in {elapsed:.2f}s (ETW providers attached)"
                )
                return rededr

            # RedEdr exited before signaling readiness, or never signaled.
            # Capture whatever output we collected for diagnostics.
            reason = (
                'RedEdr exited before ETW providers attached' if signalled
                else f'RedEdr did not attach ETW providers within {ready_timeout:.0f}s'
            )
            self.logger.error(f"{reason} (after {elapsed:.2f}s)")
            try:
                rededr.cleanup()
            except Exception:
                pass
            tail = '\n'.join(rededr.collected_output[-20:]) if rededr.collected_output else ''
            results['rededr'] = {
                'status': 'error',
                'error': reason,
                'last_output': tail,
            }
            return None
        except Exception as e:
            self.logger.error(f"Error initializing RedEdr: {e}")
            results['rededr'] = {'status': 'error', 'error': str(e)}
            return None

    def _cleanup_rededr(self, rededr):
        """Cleanup RedEdr analyzer"""
        self.logger.debug("Cleaning up RedEdr")
        try:
            rededr.cleanup()
        except Exception as e:
            self.logger.error(f"Error cleaning up RedEdr: {e}")

    def _capture_process_output(self, process) -> dict:
        """Stop the sample and return what it wrote.

        Output is read continuously by an OutputDrain from launch onwards
        (bounded to 1 MB per stream); here the sample's whole process tree
        is terminated and the drain is collected.
        """
        if not process:
            return {'had_output': False, 'error': 'No process to capture output from'}

        self.logger.debug("Capturing process output")
        exited_on_its_own = process.poll() is not None
        self._terminate_sample(process)

        drain = getattr(process, '_lb_drain', None)
        if drain is None:
            return {'had_output': False, 'error': 'Process output was not captured', 'output_truncated': False}
        drain.join(timeout=2)
        stdout = drain.text('stdout').strip()
        stderr = drain.text('stderr').strip()
        result = {
            'stdout': stdout,
            'stderr': stderr,
            'had_output': bool(stdout or stderr),
            'output_truncated': drain.truncated,
            # Only meaningful when the sample exited by itself.
            'exit_code': process.returncode if exited_on_its_own else None,
        }
        if not exited_on_its_own:
            result['note'] = 'Process terminated after analysis'
        return result

    def _terminate_sample(self, process):
        """Kill the sample and everything it spawned. Idempotent."""
        job = getattr(process, '_lb_job', None)
        if job is not None:
            try:
                job.close()
            except Exception as e:
                self.logger.error(f"Error terminating job object: {e}")
        try:
            kill_tree(process.pid)
        except Exception as e:
            self.logger.error(f"Error killing process tree {process.pid}: {e}")
        try:
            process.wait(timeout=5)
        except Exception:
            pass

    def _handle_process_startup_error(self, error: Exception, start_time: float, cmd_args: list) -> dict:
        """Handle errors during process startup"""
        error_msg = str(error)
        self.logger.error(f"Process startup failed: {error_msg}")
        
        if "terminated after" in error_msg:
            init_wait = self.config.get('analysis', {}).get('process', {}).get('init_wait_time', 5)
            return {
                'status': 'early_termination',
                'error': {
                    'message': f'Process terminated before initialization period ({init_wait}s)',
                    'details': error_msg,
                    'termination_time': error_msg.split('terminated after ')[1].split(' seconds')[0],
                    'cmd_args': cmd_args or []
                },
                'analysis_metadata': self._create_metadata(
                    start_time, 
                    early_termination=True, 
                    analysis_started=False, 
                    cmd_args=cmd_args or []
                )
            }
        else:
            return self._create_error_result(start_time, error_msg, cmd_args)

    def _create_error_result(self, start_time: float, error_msg: str, cmd_args: list = None) -> dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': {
                'message': 'Analysis failed',
                'details': error_msg,
                'cmd_args': cmd_args or []
            },
            'analysis_metadata': self._create_metadata(
                start_time, 
                error=error_msg, 
                early_termination=False, 
                analysis_started=False, 
                cmd_args=cmd_args or []
            )
        }

    def _validate_process(self, target, is_pid: bool, cmd_args: list = None) -> Tuple[subprocess.Popen, int]:
        if is_pid:
            return self._validate_existing_pid(target)
        else:
            return self._create_new_process(target, cmd_args)

    def _validate_existing_pid(self, target: str) -> Tuple[psutil.Process, int]:
        """Validate existing PID"""
        self.logger.debug(f"Validating PID: {target}")
        try:
            pid = int(target)
            process = psutil.Process(pid)
            if not process.is_running():
                raise Exception(f"Process with PID {pid} is not running")
            self.logger.debug(f"Successfully validated PID {pid}")
            return process, pid
        except (ValueError, psutil.NoSuchProcess) as e:
            self.logger.error(f"Invalid or non-existent PID {target}: {e}")
            raise Exception(f"Invalid or non-existent PID: {e}")

    def _create_new_process(self, target: str, cmd_args: list) -> Tuple[subprocess.Popen, int]:
        """Create and validate new process. DLL targets are wrapped with
        rundll32.exe — Windows can't directly Popen a .dll, and the
        operator's first cmd_arg is treated as the exported entry point
        (mandatory for DLLs)."""
        if target.lower().endswith('.dll'):
            if not cmd_args:
                raise Exception(
                    "DLL execution requires an entry point as the first "
                    "command-line argument (rundll32 syntax: <ExportName> "
                    "[args...])"
                )
            entry, *extra = cmd_args
            # rundll32.exe expects: <dll>,<entry> [args...]
            # The dll path and entry name are joined with a comma into a
            # single argv slot so rundll32 parses them as one target spec.
            command = ['rundll32.exe', f'{target},{entry}', *extra]
            self.logger.debug(f"DLL target — wrapping with rundll32: {command}")
        else:
            command = [target]
            if cmd_args:
                command.extend(cmd_args)
            self.logger.debug(f"Starting new process: {command}")
        
        popen_kwargs = {}
        job = JobObject()
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            popen_kwargs['startupinfo'] = startupinfo
            if job.handle:
                # Start suspended so the sample is in the job before it
                # can spawn anything.
                popen_kwargs['creationflags'] = _CREATE_SUSPENDED
        else:
            popen_kwargs['start_new_session'] = True

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **popen_kwargs,
            )
        except Exception as e:
            job.close()
            raise Exception(f"Failed to start process: {str(e)}")

        process._lb_job = job
        if popen_kwargs.get('creationflags', 0) & _CREATE_SUSPENDED:
            job.assign(process)
            try:
                psutil.Process(process.pid).resume()
            except Exception as e:
                self._terminate_sample(process)
                raise Exception(f"Failed to start process: could not resume suspended process: {e}")
        # Read stdout/stderr while the sample runs so it never blocks on a
        # full pipe during analysis.
        process._lb_drain = OutputDrain(process)

        pid = process.pid
        self.logger.debug(f"Process started with PID: {pid}")
        try:
            self._wait_for_process_initialization(process, pid, command)
        except Exception as e:
            raise Exception(f"Failed to start process: {str(e)}")
        return process, pid

    def _wait_for_process_initialization(self, process: subprocess.Popen, pid: int, command: list):
        """Wait for process to initialize and validate it's still running"""
        try:
            ps_process = psutil.Process(pid)
            if not ps_process.is_running():
                raise Exception(f"Process {pid} terminated immediately")
            
            init_wait = self.config.get('analysis', {}).get('process', {}).get('init_wait_time', 5)
            self.logger.debug(f"Waiting {init_wait} seconds for process initialization")
            
            wait_interval = 0.1
            elapsed = 0
            while elapsed < init_wait:
                time.sleep(wait_interval)
                elapsed += wait_interval
                
                if not ps_process.is_running():
                    cmd_str = ' '.join(command)
                    raise Exception(f"Process terminated after {elapsed:.1f} seconds (Command: {cmd_str})")
            
            if not ps_process.is_running():
                raise Exception("Process terminated during initialization")
                
        except psutil.NoSuchProcess:
            # The sample exited, but anything it spawned is still in its job.
            self._terminate_sample(process)
            cmd_str = ' '.join(command)
            raise Exception(f"Process {pid} terminated immediately after start (Command: {cmd_str})")
        except Exception:
            self._terminate_sample(process)
            raise
