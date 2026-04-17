from datetime import datetime, timezone
from typing import List
import requests

from config import OTX_API_KEY, OTX_DAYS_BACK
from models import IOC, FetchResult


def fetch_otx_iocs() -> FetchResult:
    iocs: List[IOC] = []
    errors: List[str] = []

    if not OTX_API_KEY or "YOUR_OTX_API_KEY_HERE" in OTX_API_KEY:
        return FetchResult(
            source="AlienVault OTX",
            ioc_count=0,
            iocs=[],
            fetched_at=datetime.now(timezone.utc),
            errors=["OTX API key missing, skipping OTX fetch."]
        )

    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return FetchResult(
            source="AlienVault OTX",
            ioc_count=0,
            iocs=[],
            fetched_at=datetime.now(timezone.utc),
            errors=[f"OTX fetch failed: {e}"]
        )

    pulses = data.get("results", [])
    for p in pulses:
        pulse_name = p.get("name", "OTX Pulse")
        indicators = p.get("indicators", [])

        for ind in indicators:
            itype = ind.get("type", "")
            value = (ind.get("indicator") or "").strip()
            if not value:
                continue

            mapped = _map_otx_type(itype)
            if not mapped:
                continue

            iocs.append(IOC(
                ioc_type=mapped,
                value=value,
                source="AlienVault OTX",
                threat_type="malicious-activity",
                tags=["otx", "community-intel"],
                first_seen=_parse_otx_time(ind.get("created")),
                description=f"{pulse_name[:180]}",
                confidence=70
            ))

    return FetchResult(
        source="AlienVault OTX",
        ioc_count=len(iocs),
        iocs=iocs,
        fetched_at=datetime.now(timezone.utc),
        errors=errors
    )


def _map_otx_type(otx_type: str) -> str | None:
    t = (otx_type or "").lower()
    if t in ["ipv4", "ipv6"]:
        return "ip"
    if "domain" in t or t == "hostname":
        return "domain"
    if "url" in t:
        return "url"
    if "filehash-sha256" in t or t == "sha256":
        return "hash"
    return None


def _parse_otx_time(s: str):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None