from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class LogFormat(str, Enum):
    SYSLOG = "syslog"
    APACHE = "apache"
    WINDOWS_EVENT = "windows_event"
    GENERIC = "generic"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ParsedLogEntry(BaseModel):
    raw: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    event_id: Optional[str] = None
    log_level: Optional[str] = None
    message: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    bytes_sent: Optional[int] = None
    user_agent: Optional[str] = None
    extra: Dict[str, Any] = {}
    log_format: Optional[str] = None


class MitreTag(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    url: str


class AnomalyFinding(BaseModel):
    detector: str
    finding_type: str
    description: str
    severity_score: int = Field(ge=0, le=100)
    severity: Severity = Severity.LOW
    source_ip: Optional[str] = None
    username: Optional[str] = None
    timestamp: Optional[datetime] = None
    evidence: List[str] = []
    mitre_tags: List[MitreTag] = []
    count: int = 1
    extra: Dict[str, Any] = {}


class AnalysisResult(BaseModel):
    log_format: str
    total_lines: int
    parsed_lines: int
    parse_errors: int
    analysis_duration_seconds: float
    findings: List[AnomalyFinding]
    summary: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    analysed_at: datetime
    detectors_used: List[str]
