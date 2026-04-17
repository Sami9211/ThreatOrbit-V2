from datetime import datetime, timezone


class LogMetrics:
    def __init__(self):
        self.analysis_runs_total = 0
        self.analysis_failures_total = 0
        self.last_analysis_at = None
        self.last_findings_count = 0

    def mark_success(self, findings_count: int):
        self.analysis_runs_total += 1
        self.last_findings_count = findings_count
        self.last_analysis_at = datetime.now(timezone.utc).isoformat()

    def mark_failure(self):
        self.analysis_runs_total += 1
        self.analysis_failures_total += 1
        self.last_analysis_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "analysis_runs_total": self.analysis_runs_total,
            "analysis_failures_total": self.analysis_failures_total,
            "last_analysis_at": self.last_analysis_at,
            "last_findings_count": self.last_findings_count
        }
