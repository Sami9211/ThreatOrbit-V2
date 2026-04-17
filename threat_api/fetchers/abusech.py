from datetime import datetime, timezone
from typing import List
import requests

from config import ABUSECH_URLHAUS_URL, ABUSECH_FEODO_URL
from models import IOC, FetchResult


def fetch_abusech_iocs() -> FetchResult:
    iocs: List[IOC] = []
    errors: List[str] = []

    # URLHaus (URLs)
    try:
        r = requests.post(ABUSECH_URLHAUS_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
        for row in data.get("urls", [])[:500]:
            url = (row.get("url") or "").strip()
            if not url:
                continue
            iocs.append(IOC(
                ioc_type="url",
                value=url,
                source="abuse.ch URLHaus",
                threat_type="malicious-activity",
                tags=["abusech", "urlhaus"],
                first_seen=_parse_time(row.get("date_added")),
                description=f"URL status={row.get('url_status', 'unknown')}",
                confidence=80
            ))
    except Exception as e:
        errors.append(f"URLHaus fetch failed: {e}")

    # Feodo IP blocklist
    try:
        r = requests.get(ABUSECH_FEODO_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
        for row in data[:1000]:
            ip = (row.get("ip_address") or "").strip()
            if not ip:
                continue
            iocs.append(IOC(
                ioc_type="ip",
                value=ip,
                source="abuse.ch Feodo",
                threat_type="malicious-activity",
                tags=["abusech", "feodo"],
                first_seen=_parse_time(row.get("first_seen_utc")),
                description=f"Feodo malware family={row.get('malware', 'unknown')}",
                confidence=85
            ))
    except Exception as e:
        errors.append(f"Feodo fetch failed: {e}")

    return FetchResult(
        source="abuse.ch",
        ioc_count=len(iocs),
        iocs=iocs,
        fetched_at=datetime.now(timezone.utc),
        errors=errors
    )


def _parse_time(s: str):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None