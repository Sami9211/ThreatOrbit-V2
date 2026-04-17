import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from log_api.models import AnalysisResult, AnomalyFinding


def findings_to_stix_bundle(result: AnalysisResult) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'ThreatOrbit Log API')}"

    objects: List[Dict[str, Any]] = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "ThreatOrbit Log API",
        "identity_class": "organization"
    }]

    report_refs = []

    for f in result.findings:
        indicator_id = f"indicator--{uuid.uuid4()}"
        pattern = _to_stix_pattern(f)
        if not pattern:
            continue

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"{f.finding_type} ({f.detector})",
            "description": f.description,
            "indicator_types": ["anomalous-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": max(0, min(100, f.severity_score)),
            "labels": [f.severity.value.lower(), f.detector.lower().replace(" ", "_")],
            "created_by_ref": identity_id
        }
        objects.append(indicator)
        report_refs.append(indicator_id)

    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": f"Log anomaly report ({result.log_format})",
        "description": f"Automated anomaly analysis with {len(result.findings)} findings.",
        "published": now,
        "report_types": ["threat-report"],
        "object_refs": report_refs,
        "created_by_ref": identity_id
    }
    objects.append(report)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects
    }


def _to_stix_pattern(f: AnomalyFinding) -> str | None:
    if f.source_ip:
        return f"[ipv4-addr:value = '{f.source_ip}']"
    return None
