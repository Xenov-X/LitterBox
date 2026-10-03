"""EDR profile schema + loader.

A profile is one YAML file under ``Config/edr_profiles/``. It binds a Whiskers
agent (on the EDR VM) to a backend (e.g. an Elastic stack) for alert
queries. The loader scans the directory at boot and returns a list of
validated profiles to register with the analyzer manager.

Real profile files are gitignored — the repo only ships ``*.example.yml``.

Field validation is dynamic: each registered backend declares its required
and optional profile fields, plus a ``validate_profile()`` classmethod for
backend-specific checks. The common fields (name, display_name, agent_url)
are always required. The registry's ``init()`` calls ``discover_backends()``
before ``load_profiles()``, so backends are available at validation time.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

import yaml


logger = logging.getLogger(__name__)


PROFILES_DIR = os.path.join("Config", "edr_profiles")


class EdrProfileError(ValueError):
    """Profile YAML failed validation. Message names the field at fault."""


def _get_valid_kinds():
    """Return the set of registered backend kinds."""
    try:
        from .backend import registered_kinds
        return set(registered_kinds().keys())
    except ImportError:
        return None


def _get_backend_cls(kind: str):
    """Return the backend class for a kind, or None if not registered."""
    try:
        from .backend import get_backend
        return get_backend(kind)
    except ImportError:
        return None


def _get_backend_fields(kind: str):
    """Return (required_fields, optional_fields) for a backend kind, or
    ((), ()) if the backend isn't registered yet."""
    cls = _get_backend_cls(kind)
    if cls is None:
        return (), ()
    return cls.required_profile_fields, cls.optional_profile_fields


@dataclass
class EdrProfile:
    name: str
    display_name: str
    agent_url: str
    live_edr: bool = False
    kind: str = "elastic"

    elastic_url: Optional[str] = None
    elastic_apikey: Optional[str] = None
    elastic_verify_tls: bool = False

    wait_seconds_for_alerts: int = 90
    av_block_wait_seconds: int = 60
    exec_timeout_seconds: int = 60
    drop_path: Optional[str] = None
    source_path: Optional[str] = field(default=None, repr=False)

    @classmethod
    def from_dict(cls, data: dict, source_path: Optional[str] = None) -> "EdrProfile":
        if not isinstance(data, dict):
            raise EdrProfileError(
                f"profile must be a YAML mapping, got {type(data).__name__}"
            )

        kind = (data.get("kind") or "elastic").strip().lower()

        valid_kinds = _get_valid_kinds()
        if valid_kinds is not None and kind not in valid_kinds:
            raise EdrProfileError(
                f"unknown profile kind {kind!r} — must be one of {sorted(valid_kinds)}"
            )

        common_required = ("name", "display_name", "agent_url")
        backend_required, _ = _get_backend_fields(kind)
        required = common_required + tuple(backend_required)
        missing = [k for k in required if not data.get(k)]
        if "live_edr" not in data:
            missing.append("live_edr")
        if missing:
            raise EdrProfileError(f"missing required field(s): {', '.join(missing)}")

        backend_cls = _get_backend_cls(kind)
        if backend_cls is not None:
            backend_cls.validate_profile(data)

        return cls(
            name=data["name"],
            display_name=data["display_name"],
            agent_url=data["agent_url"].rstrip("/"),
            live_edr=bool(data["live_edr"]),
            kind=kind,
            elastic_url=(data.get("elastic_url") or "").rstrip("/") or None,
            elastic_apikey=data.get("elastic_apikey"),
            elastic_verify_tls=bool(data.get("elastic_verify_tls", False)),
            wait_seconds_for_alerts=int(data.get("wait_seconds_for_alerts", 90)),
            av_block_wait_seconds=int(data.get("av_block_wait_seconds", 60)),
            exec_timeout_seconds=int(data.get("exec_timeout_seconds", 60)),
            drop_path=data.get("drop_path"),
            source_path=source_path,
        )


def load_profiles(profiles_dir: str = PROFILES_DIR) -> List[EdrProfile]:
    """Scan ``profiles_dir`` for *.yml (excluding *.example.yml) and return a
    list of validated profiles. A malformed file is logged and skipped — one
    bad profile must not prevent the others from loading.
    """
    if not os.path.isdir(profiles_dir):
        logger.debug("EDR profiles dir %s does not exist; no profiles loaded", profiles_dir)
        return []

    profiles: List[EdrProfile] = []
    seen_names = set()

    for entry in sorted(os.listdir(profiles_dir)):
        if not entry.endswith(".yml") or entry.endswith(".example.yml"):
            continue
        path = os.path.join(profiles_dir, entry)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            profile = EdrProfile.from_dict(data, source_path=path)
        except (EdrProfileError, yaml.YAMLError, OSError) as exc:
            logger.error("skipping EDR profile %s: %s", path, exc)
            continue

        if profile.name in seen_names:
            logger.error(
                "skipping EDR profile %s: duplicate name %r (already registered)",
                path,
                profile.name,
            )
            continue
        seen_names.add(profile.name)
        profiles.append(profile)
        logger.info("loaded EDR profile %r from %s", profile.name, path)

    return profiles
