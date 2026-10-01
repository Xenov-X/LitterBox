"""Shared exec spine for all EDR backends.

BaseEdrRunner owns the full Phase-1 lifecycle that is identical across every
backend: read payload, discover hostname, acquire lock, XOR-encode, upload,
wait for exit, kill, fetch logs, release lock, build phase-1 result.

Subclasses (the thin backend wrappers) only need to provide a
``_make_backend()`` factory that returns an ``EdrBackend`` instance. The
base runner calls ``backend.correlate()`` for Phase 2 if the backend
declares ``has_correlation = True``; otherwise it finalizes with exec-only
results immediately.
"""

import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import List, Optional

from app.analyzers.base import BaseAnalyzer

from .agent_client import AgentBusy, AgentClient, AgentError, AgentUnreachable
from .backend import EdrBackend
from .profile import EdrProfile


logger = logging.getLogger(__name__)


HIGH_SEVERITY = {"high", "critical"}


class BaseEdrRunner(BaseAnalyzer):
    """Shared orchestrator for every EDR backend kind.

    Per-dispatch lifecycle:
      Phase 1 (sync):  get_info → lock → exec → wait → kill → logs → unlock
      Phase 2 (async): backend.correlate() — or skip for exec-only kinds
    """

    def __init__(self, config: dict, profile: EdrProfile, backend: EdrBackend):
        super().__init__(config)
        self.profile = profile
        self.backend = backend
        self.agent = AgentClient(profile.agent_url)

    # ---- BaseAnalyzer contract -------------------------------------------

    def analyze(self, target):
        try:
            self.results = self._run(target, executable_args=None)
        except Exception as exc:
            logger.exception("EDR run failed for %s", self.profile.name)
            self.results = {
                "status": "error",
                "error": str(exc),
                "profile": self.profile.name,
            }

    def cleanup(self):
        self.backend.cleanup()

    # ---- Public split-phase API ------------------------------------------

    def run_exec(self, payload_path: str, executable_args: Optional[str] = None):
        """Phase 1. Returns (phase_1_dict, continuation | None)."""
        try:
            return self._run_exec_phase(payload_path, executable_args)
        except Exception as exc:
            logger.exception("EDR Phase 1 failed for %s", self.profile.name)
            return {
                "status": "error",
                "error": str(exc),
                "profile": self.profile.name,
            }, None

    def run_correlation(self, continuation: dict) -> dict:
        """Phase 2. Delegates to backend.correlate()."""
        try:
            return self._correlate_and_finalize(
                continuation["outcome"],
                continuation["agent_info"],
                continuation["hostname"],
                continuation["run_start"],
                continuation.get("file_name"),
            )
        except Exception as exc:
            logger.exception("EDR Phase 2 failed for %s", self.profile.name)
            return {
                **(continuation.get("phase_1", {})),
                "status": "error",
                "error": f"alert correlation failed: {exc}",
            }

    # ---- core flow -------------------------------------------------------

    def _run(self, payload_path: str, executable_args: Optional[str]) -> dict:
        phase_1, continuation = self._run_exec_phase(payload_path, executable_args)
        if continuation is None:
            return phase_1
        return self._correlate_and_finalize(
            continuation["outcome"],
            continuation["agent_info"],
            continuation["hostname"],
            continuation["run_start"],
            continuation.get("file_name"),
        )

    def _run_exec_phase(self, payload_path: str, executable_args: Optional[str]):
        if not os.path.isfile(payload_path):
            return {
                "status": "error",
                "error": f"payload not found: {payload_path}",
                "profile": self.profile.name,
            }, None

        with open(payload_path, "rb") as f:
            file_bytes = f.read()
        filename = os.path.basename(payload_path)

        try:
            info = self.agent.get_info()
        except AgentUnreachable as exc:
            return self._unreachable_result(exc), None
        except AgentError as exc:
            return {
                "status": "error",
                "error": f"agent /api/info failed: {exc}",
                "profile": self.profile.name,
            }, None

        hostname = info.get("hostname")
        if not hostname:
            return {
                "status": "error",
                "error": "agent did not report a hostname",
                "profile": self.profile.name,
                "agent_info": info,
            }, None
        logger.info(
            "EDR run [%s] on %s (agent %s, OS %s)",
            self.profile.kind,
            hostname,
            info.get("agent_version"),
            info.get("os_version"),
        )

        try:
            self.agent.lock_acquire()
        except AgentBusy as exc:
            return {
                "status": "busy",
                "error": (
                    "the agent is currently running another payload; retry once it "
                    "finishes (or call /api/lock/release if it appears stuck)"
                ),
                "profile": self.profile.name,
                "detail": str(exc),
            }, None
        except (AgentUnreachable, AgentError) as exc:
            return {
                "status": "error",
                "error": f"lock_acquire failed: {exc}",
                "profile": self.profile.name,
            }, None

        run_start = datetime.now(timezone.utc)
        try:
            exec_outcome = self._run_locked(
                file_bytes, filename, executable_args, hostname, run_start, info
            )
        finally:
            try:
                self.agent.lock_release()
            except (AgentUnreachable, AgentError) as exc:
                logger.error(
                    "lock_release failed for profile %s: %s",
                    self.profile.name,
                    exc,
                )

        if exec_outcome.get("_final"):
            terminal = dict(exec_outcome)
            terminal.pop("_final", None)
            return terminal, None

        kind = exec_outcome["kind"]
        is_blocked = (kind == "virus")
        max_wait = (
            self.profile.av_block_wait_seconds if is_blocked
            else self.profile.wait_seconds_for_alerts
        )
        exec_logs = exec_outcome.get("exec_logs", {})
        killed_by_edr = (
            False if is_blocked
            else self._classify_kill(exec_logs, filename=filename)
        )
        raw_exec_status = exec_logs.get("status")
        exec_status_label = (
            "virus" if is_blocked
            else ("killed_by_edr" if killed_by_edr else raw_exec_status)
        )

        has_correlation = self.backend.has_correlation

        if not has_correlation:
            phase_1_status = "executed"
        else:
            phase_1_status = "polling_alerts"

        phase_1 = {
            "status": phase_1_status,
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "kind": self.profile.kind,
            "agent_info": info,
            "hostname": hostname,
            "execution": {
                "pid": exec_outcome.get("pid"),
                "stdout": exec_logs.get("stdout", ""),
                "stderr": exec_logs.get("stderr", ""),
                "exit_code": exec_logs.get("exit_code"),
                "exec_status": exec_status_label,
                "agent_exec_status": raw_exec_status,
                "killed_by_edr": killed_by_edr,
                "message": exec_outcome.get("exec_resp", {}).get("message"),
            },
            "alerts": [],
            "summary": {
                "total_alerts": 0,
                "high_severity_alerts": 0,
                "killed_by_edr": killed_by_edr,
                "run_start": run_start.isoformat(),
                "run_end": None,
                "wait_seconds_for_alerts": max_wait,
                "blocked_by_av": is_blocked,
            },
        }

        if not has_correlation:
            phase_1["coverage"] = "not_configured"
            phase_1["summary"]["run_end"] = datetime.now(timezone.utc).isoformat()
            return phase_1, None

        continuation = {
            "outcome": exec_outcome,
            "agent_info": info,
            "hostname": hostname,
            "run_start": run_start,
            "phase_1": phase_1,
            "file_name": filename,
        }
        return phase_1, continuation

    def _run_locked(
        self,
        file_bytes: bytes,
        filename: str,
        executable_args: Optional[str],
        hostname: str,
        run_start: datetime,
        agent_info: dict,
    ) -> dict:
        xor_key = secrets.randbelow(256)
        xor_table = bytes(b ^ xor_key for b in range(256))
        xored = file_bytes.translate(xor_table)
        try:
            exec_resp = self.agent.exec(
                file_bytes=xored,
                filename=filename,
                drop_path=self.profile.drop_path,
                executable_args=executable_args,
                xor_key=xor_key,
            )
        except AgentUnreachable as exc:
            return {**self._unreachable_result(exc), "_final": True}
        except AgentError as exc:
            return {
                "status": "error",
                "error": f"exec failed: {exc}",
                "profile": self.profile.name,
                "agent_info": agent_info,
                "_final": True,
            }

        exec_status = exec_resp.get("status")
        pid = exec_resp.get("pid")

        if exec_status == "virus":
            return {
                "kind": "virus",
                "exec_resp": exec_resp,
                "exec_logs": {},
                "pid": None,
                "exec_end": datetime.now(timezone.utc),
            }

        if exec_status != "ok" or pid is None:
            return {
                "status": "error",
                "error": f"unexpected exec response: {exec_resp}",
                "profile": self.profile.name,
                "agent_info": agent_info,
                "_final": True,
            }

        self._wait_for_exit(self.profile.exec_timeout_seconds)
        exec_end = datetime.now(timezone.utc)

        try:
            self.agent.kill()
        except (AgentUnreachable, AgentError) as exc:
            logger.warning("kill request failed (non-fatal): %s", exc)

        try:
            exec_logs = self.agent.get_execution_logs()
        except (AgentUnreachable, AgentError) as exc:
            logger.warning("get_execution_logs failed: %s", exc)
            exec_logs = {}

        return {
            "kind": "exec_completed",
            "exec_resp": exec_resp,
            "exec_logs": exec_logs,
            "pid": pid,
            "exec_end": exec_end,
        }

    def _correlate_and_finalize(
        self,
        outcome: dict,
        agent_info: dict,
        hostname: str,
        run_start: datetime,
        file_name: Optional[str] = None,
    ) -> dict:
        kind = outcome["kind"]
        max_wait = (
            self.profile.av_block_wait_seconds if kind == "virus"
            else self.profile.wait_seconds_for_alerts
        )

        poll_result = self.backend.correlate(
            hostname=hostname,
            run_start=run_start,
            run_end_factory=lambda: datetime.now(timezone.utc),
            file_name=file_name,
            max_wait_seconds=max_wait,
            outcome=outcome,
        )

        alerts = poll_result.get("alerts", [])
        run_end_str = poll_result.get("run_end") or datetime.now(timezone.utc).isoformat()
        error = poll_result.get("error")

        if isinstance(run_end_str, datetime):
            run_end = run_end_str
        else:
            run_end = datetime.fromisoformat(run_end_str)

        if error and not alerts:
            return self._partial_result(
                error["sub_status"],
                error["message"],
                agent_info,
                outcome.get("exec_logs", {}),
                outcome.get("pid"),
                run_start,
                run_end,
                hostname,
                alerts=[],
            )

        if kind == "virus":
            return self._virus_blocked_result(
                outcome["exec_resp"], agent_info, run_start, run_end,
                alerts, hostname,
            )

        return self._success_result(
            agent_info, outcome["exec_logs"], outcome["pid"],
            run_start, run_end, hostname, alerts, file_name=file_name,
        )

    # ---- helpers ---------------------------------------------------------

    def _wait_for_exit(self, timeout_seconds: int) -> None:
        deadline = time.monotonic() + timeout_seconds
        poll_interval = 1.0
        while time.monotonic() < deadline:
            try:
                logs = self.agent.get_execution_logs()
            except (AgentUnreachable, AgentError):
                time.sleep(poll_interval)
                continue
            status = (logs.get("status") or "").lower()
            if status and status != "running":
                return
            time.sleep(poll_interval)

    @classmethod
    def _classify_kill(
        cls,
        exec_logs: dict,
        *,
        filename: Optional[str] = None,
        alerts: Optional[list] = None,
    ) -> bool:
        raw_status = (exec_logs.get("status") or "").lower()
        if raw_status == "killed":
            return False
        exit_code = exec_logs.get("exit_code")
        if exit_code in (0, None):
            return False
        return bool(alerts)

    # ---- result builders -------------------------------------------------

    def _success_result(
        self,
        agent_info: dict,
        exec_logs: dict,
        pid: int,
        run_start: datetime,
        run_end: datetime,
        hostname: str,
        alerts: list,
        file_name: Optional[str] = None,
    ) -> dict:
        alert_dicts = self._to_alert_dicts(alerts)
        high_severity_count = sum(
            1 for a in alert_dicts if a.get("severity") in HIGH_SEVERITY
        )
        killed_by_edr = self._classify_kill(
            exec_logs, filename=file_name, alerts=alert_dicts,
        )
        raw_exec_status = exec_logs.get("status")
        exec_status_label = "killed_by_edr" if killed_by_edr else raw_exec_status

        return {
            "status": "completed",
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "kind": self.profile.kind,
            "agent_info": agent_info,
            "hostname": hostname,
            "execution": {
                "pid": pid,
                "stdout": exec_logs.get("stdout", ""),
                "stderr": exec_logs.get("stderr", ""),
                "exit_code": exec_logs.get("exit_code"),
                "exec_status": exec_status_label,
                "agent_exec_status": raw_exec_status,
                "killed_by_edr": killed_by_edr,
            },
            "alerts": alert_dicts,
            "summary": {
                "total_alerts": len(alert_dicts),
                "high_severity_alerts": high_severity_count,
                "killed_by_edr": killed_by_edr,
                "blocked_by_av": False,
                "run_start": run_start.isoformat(),
                "run_end": run_end.isoformat(),
                "wait_seconds_for_alerts": self.profile.wait_seconds_for_alerts,
            },
        }

    def _virus_blocked_result(
        self,
        exec_resp: dict,
        agent_info: dict,
        run_start: datetime,
        run_end: datetime,
        alerts: list,
        hostname: str,
    ) -> dict:
        alert_dicts = self._to_alert_dicts(alerts)
        return {
            "status": "blocked_by_av",
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "kind": self.profile.kind,
            "agent_info": agent_info,
            "hostname": hostname,
            "execution": {
                "pid": None,
                "stdout": "",
                "stderr": "",
                "exit_code": None,
                "exec_status": "virus",
                "message": exec_resp.get("message"),
            },
            "alerts": alert_dicts,
            "summary": {
                "total_alerts": len(alert_dicts),
                "high_severity_alerts": sum(
                    1 for a in alert_dicts if a.get("severity") in HIGH_SEVERITY
                ),
                "run_start": run_start.isoformat(),
                "run_end": run_end.isoformat(),
                "wait_seconds_for_alerts": self.profile.av_block_wait_seconds,
                "blocked_by_av": True,
            },
        }

    def _partial_result(
        self,
        sub_status: str,
        error: str,
        agent_info: dict,
        exec_logs: dict,
        pid: Optional[int],
        run_start: datetime,
        run_end: datetime,
        hostname: str,
        alerts: list,
    ) -> dict:
        return {
            "status": "partial",
            "sub_status": sub_status,
            "error": error,
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "kind": self.profile.kind,
            "agent_info": agent_info,
            "hostname": hostname,
            "execution": {
                "pid": pid,
                "stdout": exec_logs.get("stdout", ""),
                "stderr": exec_logs.get("stderr", ""),
                "exit_code": exec_logs.get("exit_code"),
                "exec_status": exec_logs.get("status"),
            },
            "alerts": self._to_alert_dicts(alerts),
            "summary": {
                "total_alerts": 0,
                "high_severity_alerts": 0,
                "run_start": run_start.isoformat(),
                "run_end": run_end.isoformat(),
            },
        }

    def _unreachable_result(self, exc: Exception) -> dict:
        return {
            "status": "agent_unreachable",
            "error": str(exc),
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "kind": self.profile.kind,
            "agent_url": self.profile.agent_url,
        }

    @staticmethod
    def _to_alert_dicts(alerts: list) -> list:
        out = []
        for a in alerts:
            if isinstance(a, dict):
                out.append(a)
            elif hasattr(a, "to_dict"):
                out.append(a.to_dict())
            else:
                raise TypeError(f"unexpected alert type: {type(a)}")
        return out
