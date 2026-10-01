"""Pluggable EDR backend protocol and registry.

Every EDR backend is a class that satisfies the ``EdrBackend`` protocol
and self-registers by calling ``register_backend()`` at module level.
Discovery happens automatically: ``discover_backends()`` imports every
module under ``app/analyzers/edr/backends/``, which triggers each
module's ``register_backend()`` call.

Third-party backends can register via Python entry-points in the
``litterbox.edr_backends`` group — ``discover_backends()`` loads those
after the built-in scan.

Adding a new built-in backend
-----------------------------
1. Create ``app/analyzers/edr/backends/<name>.py``.
2. Define a class implementing the ``EdrBackend`` interface.
3. Call ``register_backend("<kind>", YourClass)`` at module level.
4. Add a ``Config/edr_profiles/<name>.yml.example`` with the kind + fields.

That's it — no registry.py edits, no profile.py edits, no if/else branches.
"""

import importlib
import logging
import pkgutil
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple, Type

from .profile import EdrProfile


logger = logging.getLogger(__name__)


_BACKENDS: Dict[str, Type["EdrBackend"]] = {}


class EdrBackend:
    """Interface every EDR backend must satisfy.

    The base runner drives the shared exec spine (lock, upload, wait, kill,
    log-fetch) and then hands off to the backend for alert correlation and
    health probing. Backends that skip correlation entirely (exec-only) can
    leave ``correlate`` as a no-op that returns an empty list.

    Class-level attributes
    ----------------------
    kind : str
        Discriminator value that matches the ``kind`` field in profile YAML.
    label : str
        Human-readable name shown in the UI (e.g. "Elastic Defend").
    required_profile_fields : tuple of str
        Profile YAML keys required beyond the common set (name, display_name,
        agent_url). Validated at profile-load time.
    optional_profile_fields : tuple of str
        Profile YAML keys that are accepted but not required.
    has_correlation : bool
        True if this backend queries an external detection source.
        False for exec-only runners: Phase 2 is skipped, and the UI
        shows ``coverage: "not_configured"`` instead of empty alerts.
    """

    kind: str = ""
    label: str = ""
    required_profile_fields: Tuple[str, ...] = ()
    optional_profile_fields: Tuple[str, ...] = ()
    has_correlation: bool = True

    def __init__(self, config: dict, profile: EdrProfile):
        self.config = config
        self.profile = profile

    def correlate(
        self,
        hostname: str,
        run_start: datetime,
        run_end_factory: Callable[[], datetime],
        file_name: Optional[str],
        max_wait_seconds: int,
        outcome: dict,
    ) -> dict:
        """Run Phase-2 alert correlation.

        Must return a dict with:
            alerts: list[dict]  — normalized alert dicts (title/severity/...)
            run_end: str        — ISO timestamp
            error: dict|None    — {sub_status, message} or None

        ``run_end_factory`` is a zero-arg callable returning ``datetime.now(utc)``
        — backends call it to stamp the end of their polling window rather
        than importing datetime themselves.

        ``outcome`` is the exec-phase outcome dict (kind, exec_logs, pid, ...).

        Backends with ``has_correlation = False`` should not be called here;
        the base runner skips Phase 2 for them. But for safety a no-op
        default is provided.
        """
        return {
            "alerts": [],
            "run_end": run_end_factory().isoformat(),
            "error": None,
        }

    @classmethod
    def health_probe(cls, profile: EdrProfile) -> dict:
        """Return backend-specific health info for the health poller.

        The base health-probe structure (agent reachability, lock status)
        is handled by the generic poller. This method adds backend-specific
        fields. Return a dict that will be merged under the ``"backend"``
        key in the health response.

        Default: no backend health to report.
        """
        return {
            "reachable": None,
            "error": None,
        }

    @classmethod
    def validate_profile(cls, data: dict) -> None:
        """Backend-specific profile validation, called after common checks.

        Raise ``EdrProfileError`` (imported from ``.profile``) for
        placeholder sentinels, format issues, or any backend-specific
        constraint. Default: no extra validation.
        """

    def cleanup(self):
        """Release any resources held by this backend instance."""
        pass


def register_backend(kind: str, cls: Type[EdrBackend]) -> None:
    """Register a backend class for a given kind discriminator.

    Called at module level by each backend module. Idempotent for the same
    (kind, class) pair (safe across re-imports and entry-point overlap).
    Raises ValueError if a *different* class tries to claim an existing kind.
    """
    existing = _BACKENDS.get(kind)
    if existing is not None:
        if existing is cls:
            return
        raise ValueError(
            f"EDR backend kind {kind!r} is already registered "
            f"by {existing.__name__}; cannot register {cls.__name__}"
        )
    _BACKENDS[kind] = cls
    logger.debug("registered EDR backend: kind=%s cls=%s", kind, cls.__name__)


def get_backend(kind: str) -> Optional[Type[EdrBackend]]:
    """Look up a registered backend class by kind."""
    return _BACKENDS.get(kind)


def registered_kinds() -> Dict[str, Type[EdrBackend]]:
    """Snapshot of all registered {kind: class} pairs."""
    return dict(_BACKENDS)


def discover_backends() -> None:
    """Import all backend modules so they self-register.

    1. Scans ``app/analyzers/edr/backends/`` for Python modules.
    2. Loads entry-points in the ``litterbox.edr_backends`` group (for
       third-party plugins installed as packages).

    Idempotent — re-importing an already-loaded module is a no-op, and
    ``register_backend`` is a no-op for the same (kind, class) pair.
    """
    # Built-in backends.
    try:
        from . import backends as _backends_pkg
        for importer, modname, ispkg in pkgutil.iter_modules(_backends_pkg.__path__):
            fqn = f"{_backends_pkg.__name__}.{modname}"
            try:
                importlib.import_module(fqn)
            except Exception:
                logger.exception("failed to import EDR backend module %s", fqn)
    except ImportError:
        logger.debug("no app.analyzers.edr.backends package found")

    # Third-party entry-points.
    try:
        from importlib.metadata import entry_points
        eps = entry_points()
        group = eps.get("litterbox.edr_backends", [])
        for ep in group:
            try:
                ep.load()
            except Exception:
                logger.exception("failed to load entry-point EDR backend %s", ep.name)
    except Exception:
        pass

    logger.info(
        "EDR backend discovery complete: %d kind(s) registered: %s",
        len(_BACKENDS),
        sorted(_BACKENDS.keys()),
    )
