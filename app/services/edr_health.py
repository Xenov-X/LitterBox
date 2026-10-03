"""Cached EDR-profile reachability probe.

The dashboard renders one card per profile and shows agent + backend
reachability. Probing every profile on every page load makes the
dashboard slow — especially when one of the targets is offline and
we wait the full timeout. This module fixes that with two layers:

  1. A short TTL cache keyed by registered-profiles set. Repeat reads
     within the TTL window return the cached snapshot instantly.

  2. A background daemon thread that pre-warms the cache every
     ``REFRESH_INTERVAL`` seconds, so even the first dashboard load
     after app boot lands on a warm cache (after ~one initial probe
     cycle).

Backend-specific health probes are delegated to each backend's
``health_probe()`` method — no kind-specific if/else branching here.
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional


logger = logging.getLogger(__name__)


AGENT_TIMEOUT_S = 2.0
CACHE_TTL_S = 30.0
REFRESH_INTERVAL_S = 15.0


_lock = threading.Lock()
_cached: Optional[dict] = None
_cached_at: float = 0.0
_poller_started = False


def get_status_snapshot(profiles: List, *, force_refresh: bool = False) -> dict:
    global _cached, _cached_at

    if not profiles:
        return {"agents": [], "cache_age_seconds": 0}

    profile_key = _profile_key(profiles)

    with _lock:
        cached = _cached
        cached_at = _cached_at
        cache_valid = (
            cached is not None
            and not force_refresh
            and (time.monotonic() - cached_at) < CACHE_TTL_S
            and cached.get("_profile_key") == profile_key
        )

    if cache_valid:
        age = time.monotonic() - cached_at
        return _public_snapshot(cached, age)

    snapshot = _probe_all(profiles)
    snapshot["_profile_key"] = profile_key
    with _lock:
        _cached = snapshot
        _cached_at = time.monotonic()
    return _public_snapshot(snapshot, 0.0)


def start_poller(deps) -> None:
    global _poller_started
    with _lock:
        if _poller_started:
            return
        _poller_started = True

    def _loop():
        time.sleep(0.5)
        while True:
            try:
                profiles = list(deps.edr_registry._PROFILES.values())
                if profiles:
                    get_status_snapshot(profiles, force_refresh=True)
            except Exception:
                logger.exception("EDR health poller tick failed")
            time.sleep(REFRESH_INTERVAL_S)

    t = threading.Thread(target=_loop, name="edr-health-poller", daemon=True)
    t.start()
    logger.info("EDR health poller started (interval=%ss)", REFRESH_INTERVAL_S)


# ---- internals ---------------------------------------------------------


def _profile_key(profiles: List) -> tuple:
    return tuple(sorted((p.name, p.kind, p.agent_url) for p in profiles))


def _public_snapshot(snapshot: dict, age: float) -> dict:
    out = {k: v for k, v in snapshot.items() if not k.startswith("_")}
    out["cache_age_seconds"] = round(age, 1)
    return out


def _probe_all(profiles: List) -> dict:
    with ThreadPoolExecutor(max_workers=min(8, len(profiles))) as pool:
        results = list(pool.map(_probe_one, profiles))
    return {"agents": results}


def _probe_one(p) -> dict:
    from ..analyzers.edr.agent_client import AgentClient, AgentError, AgentUnreachable
    from ..analyzers.edr.backend import get_backend

    agent = AgentClient(p.agent_url, timeout=AGENT_TIMEOUT_S)
    agent_info, agent_err, lock = None, None, None
    try:
        agent_info = agent.get_info()
        try:
            lock = agent.lock_status()
        except (AgentUnreachable, AgentError):
            pass
    except AgentUnreachable as e:
        agent_err = f"unreachable: {e}"
    except AgentError as e:
        agent_err = f"error: {e}"

    backend_cls = get_backend(p.kind)
    backend_health = {"reachable": None, "error": None}
    type_label = p.kind
    if backend_cls is not None:
        type_label = backend_cls.label or p.kind
        try:
            backend_health = backend_cls.health_probe(p)
        except Exception as e:
            logger.debug("backend health_probe failed for %s: %s", p.name, e)
            backend_health = {"reachable": False, "error": str(e)}

    return {
        "name": p.name,
        "display_name": p.display_name,
        "type": type_label,
        "kind": p.kind,
        "has_correlation": getattr(backend_cls, "has_correlation", True) if backend_cls else True,
        "agent_url": p.agent_url,
        "elastic_url": p.elastic_url,
        "agent": {
            "reachable": agent_info is not None,
            "error": agent_err,
            "hostname": (agent_info or {}).get("hostname"),
            "os_version": (agent_info or {}).get("os_version"),
            "agent_version": (agent_info or {}).get("agent_version"),
            "telemetry_sources": (agent_info or {}).get("telemetry_sources") or [],
        },
        "lock": lock,
        "backend": backend_health,
    }
