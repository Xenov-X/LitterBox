"""Shared alert-polling loop with settle-window logic.

Both the Elastic and Fibratus backends (and any future correlating backend)
use the same two-stage polling algorithm: wait for the first hit, then
settle for a burst window to catch late-arriving alerts. This module
provides the single implementation so backends only supply a fetch callback.
"""

import logging
import time
from typing import Callable

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 2.0
SETTLE_SECONDS = 8.0


def poll_with_settle(
    fetch_fn: Callable,
    run_end_factory: Callable,
    max_wait_seconds: int,
    poll_interval: float = POLL_INTERVAL_SECONDS,
    settle_seconds: float = SETTLE_SECONDS,
) -> dict:
    """Poll ``fetch_fn`` with a settle window for bursty alert sources.

    ``fetch_fn(run_end)`` is called each tick and must return a dict:

        {"alerts": [...]}             — successful fetch (may be empty)
        {"error": {...}}              — transient error, keep polling
        {"done": True, "alerts": ...} — short-circuit, return immediately

    When ``"alerts"`` is absent (error-only dict), previous alerts are
    preserved so the settle window isn't disrupted by transient failures.

    Returns ``{"alerts": list, "run_end": datetime, "error": dict|None}``.
    """
    deadline = time.monotonic() + max_wait_seconds
    latest_alerts: list = []
    run_end = run_end_factory()
    last_error = None
    settle_deadline = None
    last_seen_count = 0

    while time.monotonic() < deadline:
        run_end = run_end_factory()
        tick = fetch_fn(run_end)

        if tick.get("done"):
            tick.setdefault("run_end", run_end)
            return tick

        tick_alerts = tick.get("alerts")
        tick_error = tick.get("error")

        if tick_error:
            last_error = tick_error
        else:
            last_error = None

        if tick_alerts is not None:
            latest_alerts = tick_alerts

        if latest_alerts:
            if settle_deadline is None:
                settle_deadline = time.monotonic() + settle_seconds
                logger.info(
                    "First alert(s) landed (count=%d); settling for %.0fs",
                    len(latest_alerts), settle_seconds,
                )
            elif len(latest_alerts) > last_seen_count:
                settle_deadline = time.monotonic() + settle_seconds
            last_seen_count = len(latest_alerts)
            if time.monotonic() >= settle_deadline:
                return {"alerts": latest_alerts, "run_end": run_end, "error": None}
        time.sleep(poll_interval)

    return {"alerts": latest_alerts, "run_end": run_end, "error": last_error}
