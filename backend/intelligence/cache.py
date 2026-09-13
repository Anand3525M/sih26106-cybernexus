import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from backend.config import settings

def get_cache_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(settings.DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS origin_cache (
            cache_key TEXT PRIMARY KEY,
            data_json TEXT NOT NULL,
            created_at_utc TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

def get_cached_intel(cache_key: str) -> Optional[Dict[str, Any]]:
    try:
        conn = get_cache_db()
        cur = conn.cursor()
        cur.execute("SELECT data_json FROM origin_cache WHERE cache_key = ?", (cache_key,))
        row = cur.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception:
        pass
    return None

def store_cached_intel(cache_key: str, data: Dict[str, Any]) -> None:
    try:
        conn = get_cache_db()
        cur = conn.cursor()
        now_utc = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            INSERT INTO origin_cache (cache_key, data_json, created_at_utc)
            VALUES (?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                data_json = excluded.data_json,
                created_at_utc = excluded.created_at_utc
        """, (cache_key, json.dumps(data), now_utc))
        conn.commit()
        conn.close()
    except Exception:
        pass
