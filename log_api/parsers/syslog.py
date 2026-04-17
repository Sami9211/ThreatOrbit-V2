import re
from datetime import datetime, timezone
from typing import List, Tuple
from models import ParsedLogEntry

SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>\w[\w\-\.]*?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)$'
)

SYSLOG5424_RE = re.compile(
    r'^<\d+>(?:\d+\s+)?'
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+'
    r'(?P<hostname>\S+)\s+(?P<process>\S+)\s+(?P<pid>\S+)\s+\S+\s+\S+\s+'
    r'(?P<message>.+)$'
)

PATTERNS = {
    "failed_ssh": re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)'),
    "accepted_ssh": re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)'),
    "invalid_user": re.compile(r'Invalid user (\S+) from ([\d.]+)'),
    "sudo": re.compile(r'sudo:\s+(\S+)\s+:.*COMMAND=(.+)'),
    "ip_extract": re.compile(r'(?:from|src|source)\s+([\d.a-fA-F:]+)'),
}

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_syslog(lines: List[str]) -> Tuple[List[ParsedLogEntry], int]:
    entries: List[ParsedLogEntry] = []
    errors = 0
    current_year = datetime.now().year

    for raw in lines:
        raw = raw.rstrip()
        if not raw or raw.startswith("#"):
            continue

        entry = _try_parse_rfc3164(raw, current_year) or _try_parse_rfc5424(raw)
        if not entry:
            errors += 1
            entries.append(ParsedLogEntry(raw=raw, log_format="syslog", message=raw))
            continue

        entries.append(entry)

    return entries, errors


def _try_parse_rfc3164(raw: str, year: int) -> ParsedLogEntry | None:
    m = SYSLOG_RE.match(raw)
    if not m:
        return None

    ts = _build_timestamp(m.group("month"), m.group("day"), m.group("time"), year)
    msg = m.group("message")
    entry = ParsedLogEntry(
        raw=raw,
        log_format="syslog",
        timestamp=ts,
        hostname=m.group("hostname"),
        process=m.group("process"),
        pid=int(m.group("pid")) if m.group("pid") else None,
        message=msg,
        log_level=_infer_level(msg),
    )
    _enrich_from_message(entry, msg)
    return entry


def _try_parse_rfc5424(raw: str) -> ParsedLogEntry | None:
    m = SYSLOG5424_RE.match(raw)
    if not m:
        return None

    ts_str = m.group("timestamp").replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(ts_str)
    except ValueError:
        ts = None

    pid_str = m.group("pid")
    pid = int(pid_str) if pid_str and pid_str.isdigit() else None

    msg = m.group("message")
    entry = ParsedLogEntry(
        raw=raw,
        log_format="syslog",
        timestamp=ts,
        hostname=m.group("hostname"),
        process=m.group("process"),
        pid=pid,
        message=msg,
        log_level=_infer_level(msg),
    )
    _enrich_from_message(entry, msg)
    return entry


def _enrich_from_message(entry: ParsedLogEntry, msg: str):
    for name, pat in PATTERNS.items():
        match = pat.search(msg)
        if not match:
            continue

        if name in ("failed_ssh", "accepted_ssh", "invalid_user"):
            entry.username = match.group(1)
            entry.source_ip = match.group(2)
            entry.extra[name] = True
        elif name == "sudo":
            entry.username = match.group(1)
            entry.extra["sudo_command"] = match.group(2).strip()
        elif name == "ip_extract" and not entry.source_ip:
            entry.source_ip = match.group(1)


def _infer_level(msg: str) -> str:
    m = msg.lower()
    if any(w in m for w in ("error", "failed", "failure", "denied", "invalid")):
        return "ERROR"
    if any(w in m for w in ("warn", "warning")):
        return "WARNING"
    return "INFO"


def _build_timestamp(month: str, day: str, time_str: str, year: int) -> datetime | None:
    try:
        mo = MONTH_MAP.get(month, 1)
        h, mi, s = map(int, time_str.split(":"))
        return datetime(year, mo, int(day), h, mi, s, tzinfo=timezone.utc)
    except Exception:
        return None