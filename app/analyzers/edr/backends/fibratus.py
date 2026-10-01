"""Fibratus backend — correlates via Whiskers event-log polling.

Self-registers as kind="fibratus". Polls the Whiskers agent's
GET /api/alerts/fibratus/since endpoint for event-log records written by
Fibratus's ``alertsenders.eventlog`` sender, normalizes them into the
same alert dict shape the UI renderer expects.
"""

import json as _json
import logging
from datetime import datetime
from typing import Callable, Dict, List, Optional

from ..agent_client import AgentClient, AgentError, AgentUnreachable
from ..backend import EdrBackend, register_backend
from ..polling import poll_with_settle
from ..profile import EdrProfile


logger = logging.getLogger(__name__)


class FibratusBackend(EdrBackend):
    kind = "fibratus"
    label = "Fibratus"
    required_profile_fields = ()
    optional_profile_fields = ()
    has_correlation = True

    def __init__(self, config: dict, profile: EdrProfile):
        super().__init__(config, profile)
        self.agent = AgentClient(profile.agent_url)

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
        label = "Fibratus AV-block alert" if kind == "virus" else "Fibratus alerts"
        logger.info(
            "Polling Whiskers Fibratus event log for %s on %s (file=%s, max %ds)",
            label, hostname, file_name or "*", max_wait_seconds,
        )

        def _fetch(run_end):
            try:
                resp = self.agent.get_fibratus_alerts(
                    run_start.isoformat(), run_end.isoformat(),
                )
            except (AgentUnreachable, AgentError) as exc:
                return {"error": {"sub_status": "agent_error", "message": str(exc)}}

            if not resp.get("supported", True):
                return {
                    "done": True,
                    "alerts": [],
                    "error": {
                        "sub_status": "not_supported",
                        "message": "Whiskers reports Fibratus is not installed on this VM",
                    },
                }

            raw_events = resp.get("events") or []
            return {"alerts": _normalize_and_filter(raw_events, file_name)}

        return poll_with_settle(_fetch, run_end_factory, max_wait_seconds)

    @classmethod
    def health_probe(cls, profile: EdrProfile) -> dict:
        return {"reachable": None, "error": None}


register_backend("fibratus", FibratusBackend)


# ---- alert normalization (module-level, shared with legacy analyzer) ------


def _normalize_and_filter(
    raw_events: list, file_name: Optional[str],
) -> List[dict]:
    out: List[dict] = []
    for ev in raw_events:
        if not isinstance(ev, dict):
            continue
        data_str = ev.get("data")
        if not isinstance(data_str, str):
            continue
        try:
            payload = _json.loads(data_str)
        except ValueError:
            logger.debug("Fibratus alert with non-JSON Data field; skipping")
            continue
        if not isinstance(payload, dict):
            continue
        if file_name and not _payload_mentions_filename(payload, file_name):
            continue
        entry = {
            "received_at": ev.get("time_created") or "",
            "payload": payload,
        }
        out.append(_normalize_alert(entry))
    return out


def _normalize_alert(entry: dict) -> dict:
    payload = entry.get("payload") or {}
    title = payload.get("title") or "Fibratus alert"
    severity = (payload.get("severity") or "").lower() or "unknown"
    rule_id = payload.get("id")
    reason = payload.get("text")
    rule_description = payload.get("description")

    events = payload.get("events") if isinstance(payload.get("events"), list) else []
    first_event = events[0] if events else {}
    detected_at = (
        first_event.get("timestamp") if isinstance(first_event, dict) else None
    ) or entry.get("received_at")

    proc_dict = first_event.get("proc") if isinstance(first_event, dict) else None
    process = _fibratus_proc_to_process(proc_dict)
    parent = _fibratus_proc_to_parent(proc_dict)

    labels = payload.get("labels") if isinstance(payload.get("labels"), dict) else {}
    mitre = _fibratus_labels_to_mitre(labels)

    rule_tags = payload.get("tags") if isinstance(payload.get("tags"), list) else []
    category = first_event.get("category") if isinstance(first_event, dict) else None
    if category and category not in rule_tags:
        rule_tags = list(rule_tags) + [category]

    details = {
        "reason": reason,
        "rule_description": rule_description,
        "rule_id": rule_id,
        "rule_tags": rule_tags,
        "process": process,
        "parent": parent,
        "mitre": mitre,
        "fibratus_events": events,
    }

    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "rule_uuid": rule_id,
        "detected_at": detected_at,
        "details": details,
        "raw": payload,
    }


def _fibratus_proc_to_process(proc) -> Optional[dict]:
    if not isinstance(proc, dict):
        return None
    return {
        "name": proc.get("name"),
        "pid": proc.get("pid"),
        "executable": proc.get("exe"),
        "command_line": proc.get("cmdline"),
        "working_directory": proc.get("cwd"),
        "integrity_level": proc.get("integrity_level"),
        "entity_id": None,
    }


def _fibratus_proc_to_parent(proc) -> Optional[dict]:
    if not isinstance(proc, dict):
        return None
    if not (proc.get("parent_name") or proc.get("parent_cmdline")):
        return None
    return {
        "name": proc.get("parent_name"),
        "pid": proc.get("ppid"),
        "executable": None,
        "command_line": proc.get("parent_cmdline"),
    }


def _fibratus_labels_to_mitre(labels: dict) -> list:
    if not isinstance(labels, dict):
        return []
    flat = {k.lower(): v for k, v in labels.items() if isinstance(v, str)}

    def _pick(*candidates):
        for c in candidates:
            v = flat.get(c)
            if v:
                return v
        return None

    tactic_id = _pick("tactic.id", "mitre.tactic.id", "mitre.tactics.id")
    tactic_name = _pick("tactic.name", "mitre.tactic.name", "mitre.tactics.name")
    tactic_ref = _pick("tactic.ref", "tactic.reference")
    technique_id = _pick("technique.id", "mitre.technique.id", "mitre.techniques.id")
    technique_name = _pick("technique.name", "mitre.technique.name", "mitre.techniques.name")
    technique_ref = _pick("technique.ref", "technique.reference")
    sub_id = _pick("subtechnique.id", "mitre.subtechnique.id", "mitre.subtechniques.id")
    sub_name = _pick("subtechnique.name", "mitre.subtechnique.name", "mitre.subtechniques.name")
    sub_ref = _pick("subtechnique.ref", "subtechnique.reference")

    if not (tactic_id or tactic_name or technique_id or technique_name):
        return []

    chip = {
        "tactic_id": tactic_id,
        "tactic_name": tactic_name,
        "tactic_reference": (
            tactic_ref
            or (f"https://attack.mitre.org/tactics/{tactic_id}/" if tactic_id else None)
        ),
        "technique_id": technique_id,
        "technique_name": technique_name,
        "technique_reference": (
            technique_ref
            or (f"https://attack.mitre.org/techniques/{technique_id}/" if technique_id else None)
        ),
    }
    if sub_id or sub_name:
        chip["subtechnique_id"] = sub_id
        chip["subtechnique_name"] = sub_name
        chip["subtechnique_reference"] = sub_ref or (
            (lambda: (
                f"https://attack.mitre.org/techniques/{sub_id.split('.', 1)[0]}/{sub_id.split('.', 1)[1]}/"
            ))() if sub_id and "." in sub_id else None
        )
    return [chip]


def _payload_mentions_filename(payload, file_name: str) -> bool:
    if not isinstance(payload, dict):
        return False
    needle = file_name.lower()

    def _scan(obj, depth: int = 0) -> bool:
        if depth > 6:
            return False
        if isinstance(obj, str):
            return needle in obj.lower()
        if isinstance(obj, dict):
            return any(_scan(v, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return any(_scan(v, depth + 1) for v in obj)
        return False

    process_blobs = []
    for key in ("events", "proc", "ps", "pps", "process"):
        v = payload.get(key)
        if v is not None:
            process_blobs.append(v)
    if process_blobs:
        return any(_scan(b) for b in process_blobs)
    return _scan(payload)
