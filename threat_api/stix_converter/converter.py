import uuid
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from models import EnrichedIOC
from config import STIX_IDENTITY_NAME, STIX_IDENTITY_CLASS


def convert_to_stix_bundle(iocs: List[EnrichedIOC]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, STIX_IDENTITY_NAME)}"
    objects: List[Dict[str, Any]] = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": STIX_IDENTITY_NAME,
        "identity_class": STIX_IDENTITY_CLASS,
    }]

    for i in iocs:
        ind_id = f"indicator--{uuid.uuid4()}"
        pattern = _pattern_for_ioc(i)
        if not pattern:
            continue

        labels = ["threatorbit"]
        labels.extend(i.tags or [])
        labels = list(dict.fromkeys(labels))[:20]

        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"{i.ioc_type.upper()} {i.value}",
            "description": i.description or f"IOC from {i.source}",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": max(0, min(100, i.confidence)),
            "labels": labels,
            "created_by_ref": identity_id
        })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects
    }
    return bundle


def save_bundle_to_file(bundle: Dict[str, Any], path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)


def _pattern_for_ioc(ioc: EnrichedIOC) -> str | None:
    if ioc.ioc_type == "ip":
        return f"[ipv4-addr:value = '{ioc.value}']"
    if ioc.ioc_type == "domain":
        return f"[domain-name:value = '{ioc.value}']"
    if ioc.ioc_type == "url":
        return f"[url:value = '{ioc.value}']"
    if ioc.ioc_type == "hash":
        return f"[file:hashes.'SHA-256' = '{ioc.value}']"
    return None