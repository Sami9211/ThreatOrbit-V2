import re
from collections import defaultdict
from typing import List, Dict
from models import ParsedLogEntry, AnomalyFinding, MitreTag, Severity
from config import SEVERITY_CRITICAL_THRESHOLD, SEVERITY_HIGH_THRESHOLD, SEVERITY_MEDIUM_THRESHOLD

SIGNATURES = [
    {
        "name": "sql_injection",
        "fields": ["http_path", "message", "raw"],
        "pattern": re.compile(r"(?i)(?:union|select|drop\s+table|or\s+'1'='1|information_schema|xp_cmdshell)"),
        "description": "SQL Injection attempt detected in request",
        "score": 75,
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    },
    {
        "name": "xss_attempt",
        "fields": ["http_path", "message", "raw"],
        "pattern": re.compile(r"(?i)(?:<script|javascript:|onerror=|alert\()"),
        "description": "Cross-Site Scripting (XSS) attempt detected",
        "score": 55,
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    },
    {
        "name": "path_traversal",
        "fields": ["http_path", "message", "raw"],
        "pattern": re.compile(r"(?i)(?:\.\./|%2e%2e|/etc/passwd|/etc/shadow)"),
        "description": "Path traversal / directory traversal attempt",
        "score": 65,
        "mitre": [{"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"}],
    },
    {
        "name": "scanner_useragent",
        "fields": ["user_agent", "raw"],
        "pattern": re.compile(r"(?i)(?:nikto|sqlmap|nmap|masscan|curl/[0-9]|python-requests/)"),
        "description": "Known scanner or attack tool user-agent detected",
        "score": 60,
        "mitre": [{"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}],
    },
    {
        "name": "log4shell",
        "fields": ["http_path", "message", "user_agent", "raw"],
        "pattern": re.compile(r"(?i)\$\{jndi:"),
        "description": "Log4Shell (CVE-2021-44228) exploitation attempt",
        "score": 95,
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    },
]


def run_pattern_detector(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    hits: Dict[str, Dict[str, List[ParsedLogEntry]]] = defaultdict(lambda: defaultdict(list))

    for entry in entries:
        for sig in SIGNATURES:
            for field in sig["fields"]:
                val = _get_field(entry, field)
                if val and sig["pattern"].search(val):
                    key = entry.source_ip or entry.username or "unknown"
                    hits[sig["name"]][key].append(entry)
                    break

    findings: List[AnomalyFinding] = []

    for sig_name, groups in hits.items():
        sig = next(s for s in SIGNATURES if s["name"] == sig_name)
        for _, matched_entries in groups.items():
            count = len(matched_entries)
            score = min(100, sig["score"] + (10 if count > 5 else 0) + (15 if count > 20 else 0))
            ts = matched_entries[0].timestamp if matched_entries else None

            mitre_tags = [
                MitreTag(
                    technique_id=t["id"],
                    technique_name=t["name"],
                    tactic=t["tactic"],
                    url=f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/",
                )
                for t in sig["mitre"]
            ]

            findings.append(AnomalyFinding(
                detector="Pattern Detector",
                finding_type=sig_name,
                description=f"{sig['description']} ({count} event{'s' if count > 1 else ''})",
                severity_score=score,
                severity=_score_to_severity(score),
                source_ip=matched_entries[0].source_ip,
                username=matched_entries[0].username,
                timestamp=ts,
                evidence=[e.raw[:200] for e in matched_entries[:5]],
                mitre_tags=mitre_tags,
                count=count,
            ))

    return findings


def _get_field(entry: ParsedLogEntry, field: str) -> str | None:
    return getattr(entry, field, None)


def _score_to_severity(score: int) -> Severity:
    if score >= SEVERITY_CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score >= SEVERITY_HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= SEVERITY_MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    return Severity.LOW