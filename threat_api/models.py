from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class IOC(BaseModel):
    ioc_type: str
    value: str
    source: str
    threat_type: Optional[str] = "malicious-activity"
    malware_family: Optional[str] = None
    tags: List[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: Optional[str] = None
    confidence: int = 50
    extra: Dict[str, Any] = {}


class EnrichedIOC(IOC):
    vt_malicious_count: Optional[int] = None
    vt_total_engines: Optional[int] = None
    vt_permalink: Optional[str] = None
    vt_last_analysis: Optional[datetime] = None
    enrichment_status: str = "pending"
    enrichment_error: Optional[str] = None


class FetchResult(BaseModel):
    source: str
    ioc_count: int
    iocs: List[IOC]
    fetched_at: datetime
    errors: List[str] = []


class LibraryStats(BaseModel):
    total_iocs: int
    by_type: dict
    by_source: dict
    last_updated: Optional[datetime]
