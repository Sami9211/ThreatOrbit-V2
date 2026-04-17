from datetime import datetime, timezone


class ThreatMetrics:
    def __init__(self):
        self.fetch_runs_total = 0
        self.fetch_failures_total = 0
        self.iocs_last_run = 0
        self.iocs_total_ingested = 0
        self.last_fetch_at = None

    def mark_success(self, ioc_count: int):
        self.fetch_runs_total += 1
        self.iocs_last_run = ioc_count
        self.iocs_total_ingested += ioc_count
        self.last_fetch_at = datetime.now(timezone.utc).isoformat()

    def mark_failure(self):
        self.fetch_runs_total += 1
        self.fetch_failures_total += 1
        self.last_fetch_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "fetch_runs_total": self.fetch_runs_total,
            "fetch_failures_total": self.fetch_failures_total,
            "iocs_last_run": self.iocs_last_run,
            "iocs_total_ingested": self.iocs_total_ingested,
            "last_fetch_at": self.last_fetch_at,
        }
