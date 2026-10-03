# app/services/security.py
"""Request guards for an unauthenticated app that can execute samples.

- URL converters restrict `<target>` to an MD5 / PID and `<profile>` to a
  profile-name character set, so path segments can't carry anything
  that reaches templates, globs or file names.
- A Host allowlist stops DNS-rebinding pages from talking to a
  loopback-bound LitterBox as a same-origin client.
- State-changing requests from another site (CSRF, including `no-cors`
  multipart uploads that skip CORS preflight) are rejected based on the
  `Origin` / `Sec-Fetch-Site` headers browsers attach. Non-browser
  clients such as GrumpyCats send neither header and are unaffected.
"""
import logging
from urllib.parse import urlparse

from flask import jsonify, request
from werkzeug.routing import BaseConverter

logger = logging.getLogger(__name__)

SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})
_LOOPBACK_NAMES = frozenset({'localhost', '127.0.0.1', '::1'})
_WILDCARD_BINDS = frozenset({'', '0.0.0.0', '::', '*'})


class TargetConverter(BaseConverter):
    """A sample's MD5 or a process ID."""
    regex = r'[0-9a-fA-F]{32}|[0-9]{1,10}'


class ProfileConverter(BaseConverter):
    """An EDR profile name (see edr.profile._NAME_RE)."""
    regex = r'[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}'


def register_converters(app):
    app.url_map.converters['target'] = TargetConverter
    app.url_map.converters['profile'] = ProfileConverter


def _hostname(host):
    """Hostname part of a Host header / netloc, lower-cased, no port."""
    host = (host or '').strip().lower()
    if host.startswith('['):
        return host[1:host.find(']')] if ']' in host else host[1:]
    if host.count(':') == 1:
        return host.split(':', 1)[0]
    return host


def allowed_hosts(config):
    """Hostnames this instance answers to, or None to accept any Host.

    Loopback names are always allowed, plus the configured bind address
    and `application.allowed_hosts`. Binding to a wildcard address
    without an explicit allowlist accepts any Host (the cross-site check
    still applies).
    """
    app_cfg = (config or {}).get('application', {}) or {}
    extra = app_cfg.get('allowed_hosts') or []
    if isinstance(extra, str):
        extra = [extra]
    extra = {_hostname(h) for h in extra if h}
    if '*' in extra:
        return None
    bind = _hostname(str(app_cfg.get('host', '127.0.0.1')))
    if bind in _WILDCARD_BINDS and not extra:
        return None
    hosts = set(_LOOPBACK_NAMES) | extra
    if bind not in _WILDCARD_BINDS:
        hosts.add(bind)
    return hosts


def _reject(status, message):
    response = jsonify({'error': message})
    response.status_code = status
    return response


def init_request_guards(app):
    @app.before_request
    def _guard_request():
        hosts = allowed_hosts(app.config)
        if hosts is not None and _hostname(request.host) not in hosts:
            logger.warning("Rejected request with Host %r (not in allowed hosts)", request.host)
            return _reject(400, f'Host {request.host!r} is not allowed; add it to application.allowed_hosts')

        if request.method in SAFE_METHODS:
            return None

        origin = request.headers.get('Origin')
        if origin is not None:
            if origin == 'null' or urlparse(origin).netloc.lower() != request.host.lower():
                logger.warning("Rejected cross-site %s %s from Origin %r", request.method, request.path, origin)
                return _reject(403, 'Cross-site request rejected')
            return None

        fetch_site = request.headers.get('Sec-Fetch-Site')
        if fetch_site and fetch_site not in ('same-origin', 'none'):
            logger.warning("Rejected %s %s with Sec-Fetch-Site %r", request.method, request.path, fetch_site)
            return _reject(403, 'Cross-site request rejected')
        return None
