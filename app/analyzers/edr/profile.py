"""EDR profile schema + loader.

A profile is one YAML file under ``Config/edr_profiles/``. It binds a Whiskers
agent (on the EDR VM) to a backend (e.g. an Elastic stack) for alert
queries. The loader scans the directory at boot and returns a list of
validated profiles to register with the analyzer manager.

Real profile files are gitignored — the repo only ships ``*.yml.example``.

Field validation is dynamic: each registered backend declares its required
and optional profile fields, plus a ``validate_profile()`` classmethod for
backend-specific checks. The common fields (name, display_name, agent_url)
are always required. The registry's ``init()`` calls ``discover_backends()``
before ``load_profiles()``, so backends are available at validation time.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

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



# Profile names appear in URLs and in result filenames
# (edr_<name>_results.json), so keep them to a safe character set.
_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')


def _positive_int(data: dict, key: str, default: int, *, allow_zero: bool = False) -> int:
    value = data.get(key, default)
    if value is None:
        value = default
    if isinstance(value, bool):
        raise EdrProfileError(f"{key} must be an integer number of seconds, got {value!r}")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise EdrProfileError(f"{key} must be an integer number of seconds, got {value!r}") from None
    if number < 0 or (number == 0 and not allow_zero):
        raise EdrProfileError(f"{key} must be {'>= 0' if allow_zero else '> 0'}, got {number}")
    return number


def _optional_str(data: dict, key: str) -> Optional[str]:
    value = data.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise EdrProfileError(f"{key} must be a string, got {type(value).__name__}")
    return value


def _http_url(value: str, key: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise EdrProfileError(f"{key} must be an http(s) URL, got {value!r}")
    return value.rstrip("/")


@dataclass
class EdrProfile:
    name: str
    display_name: str
    agent_url: str
    # Fail closed: a profile that doesn't say otherwise may reach live
    # vendor infrastructure, so samples need explicit live-EDR consent.
    live_edr: bool = True
    kind: str = "elastic"

    elastic_url: Optional[str] = None
    elastic_apikey: Optional[str] = None
    elastic_verify_tls: bool = False
    # Path to a CA bundle for the Elastic endpoint (implies TLS verification).
    elastic_ca_cert: Optional[str] = None
    # Comma-separated index patterns to query for alerts (optional override).
    elastic_index_pattern: Optional[str] = None
    # Shared secret sent to Whiskers as `Authorization: Bearer <token>`.
    agent_token: Optional[str] = None

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

        raw_kind = data.get("kind") or "elastic"
        if not isinstance(raw_kind, str):
            raise EdrProfileError(f"kind must be a string, got {raw_kind!r}")
        kind = raw_kind.strip().lower()

        backend_cls = _get_backend_cls(kind)

        valid_kinds = _get_valid_kinds()
        if valid_kinds is not None and kind not in valid_kinds:
            raise EdrProfileError(
                f"unknown profile kind {kind!r} — must be one of {sorted(valid_kinds)}"
            )

        common_required = ("name", "display_name", "agent_url")
        backend_required = backend_cls.required_profile_fields if backend_cls else ()
        required = common_required + tuple(backend_required)
        missing = [k for k in required if not data.get(k)]
        if missing:
            raise EdrProfileError(f"missing required field(s): {', '.join(missing)}")

        name = data["name"]
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise EdrProfileError(
                f"name must be 1-64 chars of letters, digits, '_', '.', '-', got {name!r}"
            )
        display_name = data["display_name"]
        if not isinstance(display_name, str):
            raise EdrProfileError("display_name must be a string")
        agent_url = data["agent_url"]
        if not isinstance(agent_url, str):
            raise EdrProfileError("agent_url must be a string")

        # live_edr gates TTP exposure to vendor clouds. A missing key is
        # treated as live (fail closed); anything but a real boolean is an
        # error rather than silently truthy/falsy.
        if "live_edr" not in data:
            logger.warning(
                "EDR profile %r has no live_edr key; treating it as live_edr: true "
                "(samples need 'Allow live EDR'). Set live_edr explicitly to silence this.",
                name,
            )
            live_edr = True
        elif isinstance(data["live_edr"], bool):
            live_edr = data["live_edr"]
        else:
            raise EdrProfileError(f"live_edr must be true or false, got {data['live_edr']!r}")

        verify_tls = data.get("elastic_verify_tls", False)
        if not isinstance(verify_tls, bool):
            raise EdrProfileError(f"elastic_verify_tls must be true or false, got {verify_tls!r}")

        if backend_cls is not None:
            backend_cls.validate_profile(data)

        elastic_url = _optional_str(data, "elastic_url")

        return cls(
            name=name,
            display_name=display_name,
            agent_url=_http_url(agent_url, "agent_url"),
            live_edr=live_edr,
            kind=kind,
            elastic_url=_http_url(elastic_url, "elastic_url") if elastic_url else None,
            elastic_apikey=_optional_str(data, "elastic_apikey"),
            elastic_verify_tls=verify_tls,
            elastic_ca_cert=_optional_str(data, "elastic_ca_cert"),
            elastic_index_pattern=_optional_str(data, "elastic_index_pattern"),
            agent_token=_optional_str(data, "agent_token"),
            wait_seconds_for_alerts=_positive_int(data, "wait_seconds_for_alerts", 90, allow_zero=True),
            av_block_wait_seconds=_positive_int(data, "av_block_wait_seconds", 60, allow_zero=True),
            exec_timeout_seconds=_positive_int(data, "exec_timeout_seconds", 60),
            drop_path=_optional_str(data, "drop_path"),
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
        except (EdrProfileError, yaml.YAMLError, OSError, ValueError, TypeError, AttributeError) as exc:
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
