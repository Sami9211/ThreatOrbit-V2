import json
import os
from typing import Dict, Any, List
from threat_api.models import IOC
from threat_api.config import TRUST_CONFIG_PATH

CONFIG_PATH = TRUST_CONFIG_PATH


def load_trust_config(path: str = CONFIG_PATH) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {
            "default_weight": 1.0,
            "default_base_confidence": 50,
            "sources": {},
            "feed_overrides": {}
        }
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def apply_trust_scoring(iocs: List[IOC], config: Dict[str, Any]) -> List[IOC]:
    default_weight = float(config.get("default_weight", 1.0))
    default_base_conf = int(config.get("default_base_confidence", 50))
    source_cfg = config.get("sources", {})
    feed_overrides = config.get("feed_overrides", {})

    for ioc in iocs:
        source_name = _canonical_source_name(ioc.source)
        source_meta = source_cfg.get(source_name, {})
        weight = float(source_meta.get("weight", default_weight))
        base_conf = int(source_meta.get("base_confidence", default_base_conf))

        feed_url = _extract_feed_url_from_source(ioc.source)
        if feed_url and feed_url in feed_overrides:
            ov = feed_overrides[feed_url]
            weight = float(ov.get("weight", weight))
            base_conf = int(ov.get("base_confidence", base_conf))

        conf = max(ioc.confidence or 0, base_conf)
        conf = int(round(conf * weight))
        ioc.confidence = max(0, min(100, conf))

        tags = ioc.tags or []
        tags.append(f"trust_weight:{weight}")
        ioc.tags = list(dict.fromkeys(tags))[:20]

    return iocs


def _canonical_source_name(source: str) -> str:
    s = (source or "").lower()
    if "alienvault" in s or "otx" in s:
        return "AlienVault OTX"
    if "abuse.ch" in s:
        return "abuse.ch"
    if s.startswith("rss"):
        return "RSS"
    if "darkweb" in s:
        return "DarkWeb OSINT"
    if "social" in s:
        return "Social OSINT"
    return source


def _extract_feed_url_from_source(source: str) -> str | None:
    if ":" not in (source or ""):
        return None
    maybe = source.split(":", 1)[1].strip()
    if maybe.startswith("http://") or maybe.startswith("https://"):
        return maybe
    return None
