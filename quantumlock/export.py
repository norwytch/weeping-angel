"""Export findings to standard SIEM schemas: ECS and OCSF.

The detector speaks `Finding`; SIEMs and autonomous-response platforms speak a
schema. This renders a `Finding` as either:

* **ECS** (Elastic Common Schema) -- an alert document with ECS `rule.*`,
  `file.*`, and `threat.*` (ATT&CK) fields, ready to ingest into Elasticsearch.
* **OCSF** (Open Cybersecurity Schema Framework) -- a Detection Finding
  (class_uid 2004) with the ATT&CK mapping under `attacks`, the format a growing
  set of platforms consume natively.

Both carry the rule, severity, the file, and the MITRE ATT&CK tactic/technique,
so a finding drops straight into a detection pipeline. `to_jsonl` renders a
batch as newline-delimited JSON for bulk ingestion.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .detector import Finding

# ATT&CK names for the ids the detector tags (T1070.006 / TA0005).
_TECHNIQUE_NAME = "Indicator Removal: Timestomp"
_TACTIC_NAME = "Defense Evasion"

# ECS detection severity (Elastic's 0-100 convention).
_ECS_SEVERITY = {"high": 73, "medium": 47, "low": 21}
# OCSF severity_id: 2 Low, 3 Medium, 4 High.
_OCSF_SEVERITY_ID = {"low": 2, "medium": 3, "high": 4}

_PRODUCT = {"name": "Weeping Angel", "vendor_name": "quantumlock"}


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def ecs_event(
    finding: Finding, timestamp: float | None = None, host: str | None = None
) -> dict:
    """Render a Finding as an ECS alert document."""
    doc: dict = {
        "event": {
            "kind": "alert",
            "category": ["file"],
            "type": ["change"],
            "action": "timestomp-detected",
            "dataset": "quantumlock.detector",
            "module": "quantumlock",
            "provider": "weeping-angel",
            "severity": _ECS_SEVERITY.get(finding.severity, 0),
        },
        "rule": {
            "id": finding.rule,
            "name": finding.rule,
            "description": finding.explanation,
        },
        "file": {"name": _basename(finding.file_id), "path": finding.file_id},
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": finding.tactic, "name": _TACTIC_NAME},
            "technique": {"id": finding.technique, "name": _TECHNIQUE_NAME},
        },
        "message": finding.explanation,
        "tags": ["timestomp", "dfir", "anti-forensics"],
    }
    iso = _iso(timestamp)
    if iso is not None:
        doc["@timestamp"] = iso
    if host is not None:
        doc["host"] = {"name": host}
    return doc


def ocsf_finding(
    finding: Finding, timestamp: float | None = None, host: str | None = None
) -> dict:
    """Render a Finding as an OCSF Detection Finding (class_uid 2004)."""
    doc: dict = {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "severity_id": _OCSF_SEVERITY_ID.get(finding.severity, 0),
        "severity": finding.severity.capitalize(),
        "status_id": 1,
        "status": "New",
        "message": finding.explanation,
        "metadata": {"version": "1.3.0", "product": _PRODUCT},
        "finding_info": {
            "uid": finding.rule,
            "title": finding.rule,
            "desc": finding.explanation,
        },
        "attacks": [
            {
                "tactic": {"uid": finding.tactic, "name": _TACTIC_NAME},
                "technique": {"uid": finding.technique, "name": _TECHNIQUE_NAME},
            }
        ],
        "evidences": [{"file": {"name": _basename(finding.file_id), "path": finding.file_id}}],
    }
    if timestamp is not None:
        doc["time"] = int(timestamp * 1000)  # OCSF time is epoch milliseconds
    if host is not None:
        doc["device"] = {"hostname": host}
    return doc


_RENDERERS = {"ecs": ecs_event, "ocsf": ocsf_finding}


def to_jsonl(
    findings, schema: str = "ecs", timestamp: float | None = None, host: str | None = None
) -> str:
    """Render a batch of findings as newline-delimited JSON for bulk ingestion."""
    import json

    if schema not in _RENDERERS:
        raise ValueError(f"unknown schema {schema!r}; use 'ecs' or 'ocsf'")
    render = _RENDERERS[schema]
    return "\n".join(
        json.dumps(render(f, timestamp=timestamp, host=host), sort_keys=True) for f in findings
    )
