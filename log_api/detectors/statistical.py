import math
from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Tuple
from models import ParsedLogEntry, AnomalyFinding, MitreTag, Severity
from config import (
    ZSCORE_THRESHOLD, RATE_SPIKE_RPM_THRESHOLD, ERROR_RATE_THRESHOLD_PCT,
    SEVERITY_CRITICAL_THRESHOLD, SEVERITY_HIGH_THRESHOLD, SEVERITY_MEDIUM_THRESHOLD
)


def run_statistical_detector(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []
    findings.extend(_detect_request_rate_spike(entries))
    findings.extend(_detect_error_rate_spike(entries))
    findings.extend(_detect_bytes_anomaly(entries))
    findings.extend(_detect_path_enumeration_rate(entries))
    return findings


def _detect_request_rate_spike(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []
    rpm_by_ip: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    ev_by_ip: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if not e.source_ip or not e.timestamp:
            continue
        bucket = e.timestamp.strftime("%Y-%m-%d %H:%M")
        rpm_by_ip[e.source_ip][bucket] += 1
        ev_by_ip[e.source_ip].append(e)

    ip_max = {ip: max(b.values()) for ip, b in rpm_by_ip.items()} if rpm_by_ip else {}
    if not ip_max:
        return findings

    all_rpms = list(ip_max.values())
    mean, std = _mean_std(all_rpms)

    for ip, max_rpm in ip_max.items():
        z = (max_rpm - mean) / std if std > 0 else 0
        if not (max_rpm >= RATE_SPIKE_RPM_THRESHOLD or z >= ZSCORE_THRESHOLD):
            continue

        score = min(100, 40 + int(z * 10))
        ev = ev_by_ip[ip]
        findings.append(AnomalyFinding(
            detector="Statistical Detector",
            finding_type="request_rate_spike",
            description=f"IP {ip} sent {max_rpm} requests/minute (Z-score: {z:.1f}).",
            severity_score=score,
            severity=_score_to_severity(score),
            source_ip=ip,
            timestamp=ev[0].timestamp if ev else None,
            evidence=[e.raw[:200] for e in ev[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                url="https://attack.mitre.org/techniques/T1110/",
            )],
            count=sum(rpm_by_ip[ip].values()),
            extra={"max_rpm": max_rpm, "z_score": round(z, 2)},
        ))

    return findings


def _detect_error_rate_spike(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []
    windows: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "errors": 0})
    window_entries: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if e.http_status is None or not e.timestamp:
            continue
        minute = e.timestamp.replace(second=0, microsecond=0)
        bucket_minute = minute - timedelta(minutes=minute.minute % 5)
        bucket = bucket_minute.strftime("%Y-%m-%d %H:%M")
        windows[bucket]["total"] += 1
        if e.http_status >= 400:
            windows[bucket]["errors"] += 1
        window_entries[bucket].append(e)

    for bucket, counts in windows.items():
        total = counts["total"]
        if total < 10:
            continue
        error_pct = (counts["errors"] / total) * 100
        if error_pct < ERROR_RATE_THRESHOLD_PCT:
            continue

        score = min(100, int(error_pct))
        ev = window_entries[bucket]
        findings.append(AnomalyFinding(
            detector="Statistical Detector",
            finding_type="error_rate_spike",
            description=f"{error_pct:.0f}% error rate in window {bucket} ({counts['errors']}/{total}).",
            severity_score=score,
            severity=_score_to_severity(score),
            timestamp=ev[0].timestamp if ev else None,
            evidence=[e.raw[:200] for e in ev[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1595",
                technique_name="Active Scanning",
                tactic="Reconnaissance",
                url="https://attack.mitre.org/techniques/T1595/",
            )],
            count=total,
            extra={"error_pct": round(error_pct, 1), "window": bucket},
        ))

    return findings


def _detect_bytes_anomaly(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []
    byte_entries = [(e, e.bytes_sent) for e in entries if e.bytes_sent is not None and e.bytes_sent > 0]
    if len(byte_entries) < 20:
        return findings

    vals = [b for _, b in byte_entries]
    mean, std = _mean_std(vals)
    if std == 0:
        return findings

    for e, b in byte_entries:
        z = (b - mean) / std
        if z < ZSCORE_THRESHOLD:
            continue
        score = min(100, 45 + int(z * 8))
        findings.append(AnomalyFinding(
            detector="Statistical Detector",
            finding_type="large_response_bytes",
            description=f"Unusually large response: {b:,} bytes (Z-score: {z:.1f}).",
            severity_score=score,
            severity=_score_to_severity(score),
            source_ip=e.source_ip,
            timestamp=e.timestamp,
            evidence=[e.raw[:200]],
            mitre_tags=[MitreTag(
                technique_id="T1030",
                technique_name="Data Transfer Size Limits",
                tactic="Exfiltration",
                url="https://attack.mitre.org/techniques/T1030/",
            )],
            count=1,
        ))

    return findings


def _detect_path_enumeration_rate(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    findings: List[AnomalyFinding] = []
    paths_by_ip: Dict[str, set] = defaultdict(set)
    ev_by_ip: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        if e.source_ip and e.http_path:
            paths_by_ip[e.source_ip].add(e.http_path)
            ev_by_ip[e.source_ip].append(e)

    if not paths_by_ip:
        return findings

    counts = [len(v) for v in paths_by_ip.values()]
    mean, std = _mean_std(counts)

    for ip, paths in paths_by_ip.items():
        count = len(paths)
        z = (count - mean) / std if std > 0 else 0
        if z < ZSCORE_THRESHOLD or count < 20:
            continue

        score = min(100, 40 + int(z * 8))
        ev = ev_by_ip[ip]
        findings.append(AnomalyFinding(
            detector="Statistical Detector",
            finding_type="path_enumeration",
            description=f"IP {ip} accessed {count} unique paths (Z-score: {z:.1f}).",
            severity_score=score,
            severity=_score_to_severity(score),
            source_ip=ip,
            timestamp=ev[0].timestamp if ev else None,
            evidence=[e.raw[:200] for e in ev[:5]],
            mitre_tags=[MitreTag(
                technique_id="T1595.003",
                technique_name="Wordlist Scanning",
                tactic="Reconnaissance",
                url="https://attack.mitre.org/techniques/T1595/003/",
            )],
            count=count,
        ))

    return findings


def _mean_std(values: List[float]) -> Tuple[float, float]:
    if not values:
        return 0.0, 0.0
    n = len(values)
    mean = sum(values) / n
    var = sum((x - mean) ** 2 for x in values) / n
    return mean, math.sqrt(var)


def _score_to_severity(score: int) -> Severity:
    if score >= SEVERITY_CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score >= SEVERITY_HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= SEVERITY_MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    return Severity.LOW