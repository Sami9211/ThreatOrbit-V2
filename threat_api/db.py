import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

from threat_api.config import DB_PATH
from threat_api.models import EnrichedIOC

_DB_PATH = Path(DB_PATH)


def init_db():
    with sqlite3.connect(_DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT NOT NULL,
            threat_type TEXT,
            confidence INTEGER,
            enrichment_status TEXT,
            vt_malicious_count INTEGER,
            created_at TEXT
        )
        """)
        cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_unique
        ON iocs (ioc_type, value, source)
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            status TEXT,
            created_at TEXT,
            updated_at TEXT,
            details TEXT
        )
        """)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(_DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def upsert_iocs(iocs: Iterable[EnrichedIOC]):
    with get_conn() as conn:
        cur = conn.cursor()
        for i in iocs:
            cur.execute("""
            INSERT INTO iocs (
                ioc_type, value, source, threat_type, confidence,
                enrichment_status, vt_malicious_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ioc_type, value, source) DO UPDATE SET
                threat_type=excluded.threat_type,
                confidence=excluded.confidence,
                enrichment_status=excluded.enrichment_status,
                vt_malicious_count=excluded.vt_malicious_count,
                created_at=excluded.created_at
            """, (
                i.ioc_type,
                i.value,
                i.source,
                i.threat_type,
                i.confidence,
                i.enrichment_status,
                i.vt_malicious_count,
                i.last_seen.isoformat() if i.last_seen else None
            ))
        conn.commit()
