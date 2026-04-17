from datetime import datetime, timezone, timedelta
from db import get_conn


def cleanup_old_iocs(days: int = 30):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with get_conn() as conn:
        conn.execute("DELETE FROM iocs WHERE created_at < ?", (cutoff,))
        conn.commit()