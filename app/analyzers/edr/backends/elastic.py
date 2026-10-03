"""Elastic Defend backend — correlates via an Elastic Detection-Engine cluster.

Self-registers as kind="elastic". The exec spine lives in BaseEdrRunner;
this module only owns:
  - Elastic alert polling (Phase 2)
  - Elastic cluster health probe
  - Required profile fields (elastic_url, elastic_apikey)
"""

import logging
from datetime import datetime
from typing import Callable, Optional

from ..backend import EdrBackend, register_backend
from ..elastic_client import (
    ElasticClient,
    ElasticError,
    ElasticUnreachable,
)
from ..polling import poll_with_settle
from ..profile import EdrProfile, EdrProfileError


logger = logging.getLogger(__name__)


class ElasticBackend(EdrBackend):
    kind = "elastic"
    label = "Elastic Defend"
    required_profile_fields = ("elastic_url", "elastic_apikey")
    optional_profile_fields = ("elastic_verify_tls",)
    has_correlation = True

    def __init__(self, config: dict, profile: EdrProfile):
        super().__init__(config, profile)
        self.elastic = ElasticClient(
            profile.elastic_url,
            profile.elastic_apikey,
            verify_tls=profile.elastic_verify_tls,
        )

    def correlate(
        self,
        hostname: str,
        run_start: datetime,
        run_end_factory: Callable[[], datetime],
        file_name: Optional[str],
        max_wait_seconds: int,
        outcome: dict,
    ) -> dict:
        kind = outcome["kind"]
        label = "AV-prevention alert" if kind == "virus" else "detection alerts"
        logger.info(
            "Polling Elastic for %s on %s (file=%s, max %ds)",
            label, hostname, file_name or "*", max_wait_seconds,
        )

        def _fetch(run_end):
            try:
                alerts = self.elastic.fetch_alerts(
                    hostname, run_start, run_end, file_name=file_name,
                )
                return {"alerts": [a.to_dict() for a in alerts]}
            except ElasticUnreachable as exc:
                return {"error": {"sub_status": "elastic_unreachable", "message": str(exc)}}
            except ElasticError as exc:
                return {"error": {"sub_status": "elastic_error", "message": str(exc)}}

        return poll_with_settle(_fetch, run_end_factory, max_wait_seconds)

    @classmethod
    def health_probe(cls, profile: EdrProfile) -> dict:
        elastic = ElasticClient(
            profile.elastic_url, profile.elastic_apikey,
            verify_tls=profile.elastic_verify_tls, timeout=2.0,
        )
        try:
            info = elastic.ping()
            return {
                "reachable": True,
                "error": None,
                "cluster_name": info.get("cluster_name"),
                "version": (info.get("version") or {}).get("number"),
            }
        except ElasticUnreachable as e:
            return {"reachable": False, "error": f"unreachable: {e}"}
        except ElasticError as e:
            return {"reachable": False, "error": f"error: {e}"}

    @classmethod
    def validate_profile(cls, data: dict) -> None:
        apikey = data.get("elastic_apikey")
        if not isinstance(apikey, str):
            raise EdrProfileError("elastic_apikey must be a string (quote it in YAML)")
        if apikey.startswith("REPLACE_ME"):
            raise EdrProfileError(
                "elastic_apikey is still the example placeholder — fill it in"
            )


register_backend("elastic", ElasticBackend)
