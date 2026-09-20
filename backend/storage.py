"""
ScamShield AI - SQLite Persistent Scan History Storage
"""

import sqlite3
import json
import time
from .config import Config

class Storage:
    @staticmethod
    def get_connection():
        conn = sqlite3.connect(Config.DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def init_db():
        """Initializes the SQLite database tables"""
        with Storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    engine TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    full_json TEXT NOT NULL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)")
            conn.commit()

    @staticmethod
    def save_scan(data: dict) -> str:
        scan_id = data.get("id") or f"scan_{int(time.time() * 1000)}"
        target_type = data.get("targetType", "UNKNOWN")
        target = data.get("target", "")
        risk_score = int(data.get("riskScore", 0))
        verdict = data.get("verdict", "UNKNOWN")
        engine = data.get("engine", "Server Engine")
        created_at = data.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        full_json = json.dumps(data)

        with Storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO scans (id, target_type, target, risk_score, verdict, engine, created_at, full_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, target_type, target, risk_score, verdict, engine, created_at, full_json))
            conn.commit()

        return scan_id

    @staticmethod
    def get_history(limit: int = 50) -> list:
        with Storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, target_type, target, risk_score, verdict, engine, created_at, full_json
                FROM scans
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                try:
                    full_res = json.loads(row["full_json"])
                except Exception:
                    full_res = {}
                results.append({
                    "id": row["id"],
                    "targetType": row["target_type"],
                    "target": row["target"],
                    "riskScore": row["risk_score"],
                    "verdict": row["verdict"],
                    "engine": row["engine"],
                    "timestamp": row["created_at"],
                    "fullResult": full_res
                })
            return results

    @staticmethod
    def clear_history():
        with Storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans")
            conn.commit()
