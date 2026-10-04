"""Profile registry — single entry point for EDR-profile dispatch.

The Flask blueprints layer calls into this module rather than reaching into
profile.py or individual analyzers directly. Three responsibilities:

  1. Load profiles at import time so the UI can list them.
  2. Dispatch a payload to a named profile and return the analyzer's results
     (full synchronous run — used by tests and CLI).
  3. Dispatch in split-phase mode: Phase 1 returns immediately, Phase 2
     (alert correlation) runs in a background thread and invokes a
     completion callback with the final result.

Backend selection is fully pluggable: ``init()`` calls
``discover_backends()`` which imports every module under
``app/analyzers/edr/backends/`` (and any ``litterbox.edr_backends``
entry-points). Each backend self-registers its ``kind`` and the registry
matches profiles to backends by that discriminator — no if/else dispatch.
"""

import logging
import threading
from typing import Callable, Dict, List, Optional

from .backend import discover_backends, get_backend, registered_kinds
from .base_runner import BaseEdrRunner
from .profile import EdrProfile, load_profiles


logger = logging.getLogger(__name__)


_PROFILES: Dict[str, EdrProfile] = {}
_LOADED = False


def _make_runner(profile: EdrProfile, config: dict) -> BaseEdrRunner:
    """Construct a BaseEdrRunner wired to the correct backend for this
    profile's ``kind``. Raises KeyError if no backend is registered for
    the kind (should not happen — profile validation rejects unknown kinds).
    """
    backend_cls = get_backend(profile.kind)
    if backend_cls is None:
        raise KeyError(
            f"no EDR backend registered for kind {profile.kind!r} "
            f"(registered: {sorted(registered_kinds())})"
        )
    backend = backend_cls(config, profile)
    return BaseEdrRunner(config, profile, backend)


def init(config: dict, profiles_dir: Optional[str] = None) -> None:
    """Load profiles from disk. Called once at app startup. Idempotent —
    re-calling reloads the registry, which is useful for tests but
    intentionally not exposed via HTTP (profile YAML edits require a
    restart, same as config.yaml).
    """
    global _LOADED, _PROFILES
    discover_backends()
    profiles = load_profiles(profiles_dir) if profiles_dir else load_profiles()
    _PROFILES = {p.name: p for p in profiles}
    _LOADED = True
    logger.info(
        "EDR registry initialized with %d profile(s): %s",
        len(_PROFILES),
        list(_PROFILES.keys()),
    )


def list_profiles() -> List[dict]:
    """Public-facing profile list for the UI. Intentionally omits secrets
    (apikey, ingest_token) — only the operator-facing identity + agent URL
    is returned. ``kind`` and ``label`` are included so the UI can render
    kind-aware affordances and human-readable backend names.
    """
    backends = registered_kinds()
    result = []
    for p in _PROFILES.values():
        bcls = backends.get(p.kind)
        result.append({
            "name": p.name,
            "display_name": p.display_name,
            "agent_url": p.agent_url,
            "elastic_url": p.elastic_url,
            "kind": p.kind,
            "kind_label": getattr(bcls, "label", p.kind),
            "has_correlation": getattr(bcls, "has_correlation", True),
            "live_edr": p.live_edr,
        })
    return result


def get_profile(name: str) -> Optional[EdrProfile]:
    return _PROFILES.get(name)


def dispatch(profile_name: str, payload_path: str, config: dict) -> dict:
    """Synchronous full pipeline. Blocks until both Phase 1 (exec) and
    Phase 2 (correlation) finish. Used by tests/CLI."""
    profile = _PROFILES.get(profile_name)
    if profile is None:
        raise KeyError(f"unknown EDR profile: {profile_name!r}")

    runner = _make_runner(profile, config)
    runner.analyze(payload_path)
    try:
        return runner.get_results()
    finally:
        runner.cleanup()


def dispatch_split(
    profile_name: str,
    payload_path: str,
    config: dict,
    on_phase_2_done: Callable[[dict], None],
    executable_args: Optional[str] = None,
    exec_command: Optional[str] = None,
    archive_password: Optional[str] = None,
) -> dict:
    """Split-phase dispatch.

    Phase 1 (lock + exec + log fetch) runs synchronously and the result is
    returned immediately. If the backend has correlation (``has_correlation
    = True``) and Phase 1 was non-terminal, Phase 2 is spawned in a
    background thread; when it completes, ``on_phase_2_done`` is called
    with the final findings dict.

    For exec-only backends (``has_correlation = False``), Phase 1 is the
    final result — no background thread is spawned, and the callback is
    never invoked.

    Phase 2 errors are swallowed and surfaced to the callback as a
    ``status: 'error'`` dict — the thread never raises into nothing.
    """
    profile = _PROFILES.get(profile_name)
    if profile is None:
        raise KeyError(f"unknown EDR profile: {profile_name!r}")

    runner = _make_runner(profile, config)
    phase_1, continuation = runner.run_exec(
        payload_path, executable_args,
        exec_command=exec_command, archive_password=archive_password,
    )

    if continuation is None:
        runner.cleanup()
        return phase_1

    def _phase_2_runner():
        try:
            phase_2 = runner.run_correlation(continuation)
        except Exception as exc:
            logger.exception("EDR Phase 2 thread crashed")
            phase_2 = {
                **phase_1,
                "status": "error",
                "error": f"Phase 2 thread crashed: {exc}",
            }
        finally:
            runner.cleanup()
        try:
            on_phase_2_done(phase_2)
        except Exception:
            logger.exception("on_phase_2_done callback raised")

    thread = threading.Thread(
        target=_phase_2_runner,
        name=f"edr-phase2-{profile_name}",
        daemon=True,
    )
    thread.start()
    return phase_1


def is_loaded() -> bool:
    return _LOADED
