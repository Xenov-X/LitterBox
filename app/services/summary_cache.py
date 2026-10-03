# app/services/summary_cache.py
"""On-disk cache for per-sample summary dicts.

The /files dashboard calls `process_file_summary` for every result
directory. Each call previously did 4-6 sequential JSON reads + a
fresh `risk_analyzer.calculate_risk` walk over potentially multi-MB
analyzer outputs. The result is deterministic for a given set of
on-disk JSONs — perfect for caching.

This module persists a tiny `_summary_cache.json` next to the analyzer
outputs. Each cached entry stamps the mtimes of every source JSON it
depends on (file_info / static / dynamic / byovd / edr_*); a read
reconstructs the source mtimes and compares against the stamp. Any
drift forces a recompute, so the cache stays correct without any
manual invalidation at write sites.

Cache miss (~stale mtimes / no file): caller falls back to the slow
recompute path and stores the fresh result on the way out.
"""

import json
import logging
import os
from typing import Dict, Optional

from ..utils.json_helpers import write_json_atomic


logger = logging.getLogger(__name__)


# Source files whose mtimes determine cache validity. Anything past
# this list (e.g. report HTML, ad-hoc operator notes) is intentionally
# outside the dependency set — adding a report doesn't invalidate the
# summary, since the report is derived from the same JSONs.
_FIXED_SOURCES = (
    'file_info.json',
    'static_analysis_results.json',
    'dynamic_analysis_results.json',
    'byovd_results.json',
)
_EDR_PREFIX = 'edr_'
_EDR_SUFFIX = '_results.json'

CACHE_FILE = '_summary_cache.json'

# Bump whenever the summary shape or the risk scoring changes, so entries
# computed by older code are recomputed instead of served forever.
CACHE_VERSION = 2


def snapshot(item_path: str) -> Dict[str, int]:
    """Source mtimes to validate against. Take this BEFORE reading the
    sources and pass the same snapshot to get_cached() and store():
    stamping mtimes taken after the reads could label a summary built
    from older data as current."""
    return _source_mtimes(item_path)


def get_cached(item_path: str, sources: Optional[Dict[str, int]] = None) -> Optional[dict]:
    """Return a cached summary for `item_path` if it was built by this
    cache version from sources with exactly these mtimes. None on miss /
    staleness / corrupted cache."""
    cache_path = os.path.join(item_path, CACHE_FILE)
    if not os.path.exists(cache_path):
        return None
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            cached = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug(f"Summary cache read failed for {item_path}: {exc}")
        return None

    if cached.get('_version') != CACHE_VERSION:
        return None
    if sources is None:
        sources = _source_mtimes(item_path)
    if (cached.get('_sources') or {}) != sources:
        return None

    return cached.get('summary')


def store(item_path: str, summary: dict, sources: Optional[Dict[str, int]] = None) -> None:
    """Persist `summary` for `item_path`, stamped with `sources` (the
    snapshot taken before the summary's inputs were read). Failures are
    logged but not raised — the cache is purely a perf optimization."""
    cache_path = os.path.join(item_path, CACHE_FILE)
    payload = {
        '_version': CACHE_VERSION,
        '_sources': sources if sources is not None else _source_mtimes(item_path),
        'summary': summary,
    }
    try:
        write_json_atomic(cache_path, payload)
    except OSError as exc:
        logger.debug(f"Summary cache write failed for {item_path}: {exc}")


def invalidate(item_path: str) -> None:
    """Remove the cached entry for `item_path`. Idempotent — missing
    cache is fine. The mtime check normally makes manual invalidation
    unnecessary; this is mostly here for cleanup / cleanup endpoints."""
    cache_path = os.path.join(item_path, CACHE_FILE)
    try:
        os.remove(cache_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.debug(f"Summary cache invalidate failed for {item_path}: {exc}")


# ---- internals ---------------------------------------------------------


def _source_mtimes(item_path: str) -> Dict[str, int]:
    """Snapshot the mtimes (in nanoseconds) of every source JSON we
    depend on. Discovers per-profile EDR result files dynamically so
    a freshly-added profile invalidates the cache automatically."""
    out: Dict[str, int] = {}
    try:
        entries = os.listdir(item_path)
    except (FileNotFoundError, OSError):
        return out
    for name in entries:
        if name in _FIXED_SOURCES or (
            name.startswith(_EDR_PREFIX) and name.endswith(_EDR_SUFFIX)
        ):
            try:
                out[name] = os.stat(os.path.join(item_path, name)).st_mtime_ns
            except OSError:
                pass
    return out
