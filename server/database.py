"""
Database layer - SQLite for development, PostgreSQL for production
"""

import asyncio
import json
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("soc-database")

DATABASE_URL = os.getenv("DATABASE_URL", "soc_platform.db")
USE_POSTGRES = DATABASE_URL.startswith("postgresql")

try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False


class Database:
    def __init__(self):
        self.db_url = DATABASE_URL
        self._conn = None
        self._lock = asyncio.Lock()

    async def initialize(self):
        if USE_POSTGRES and HAS_ASYNCPG:
            self._conn = await asyncpg.connect(self.db_url)
            logger.info("Connected to PostgreSQL")
        else:
            # Use sqlite3 via thread executor for async compat
            self._sqlite_path = self.db_url if not USE_POSTGRES else "soc_platform.db"
            await self._init_sqlite()
            logger.info(f"Connected to SQLite: {self._sqlite_path}")

    async def _init_sqlite(self):
        def _create_tables():
            conn = sqlite3.connect(self._sqlite_path)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            c.executescript("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    endpoint_id TEXT PRIMARY KEY,
                    hostname TEXT,
                    ip_address TEXT,
                    os_version TEXT,
                    agent_version TEXT,
                    cpu_usage REAL DEFAULT 0,
                    memory_usage REAL DEFAULT 0,
                    disk_usage REAL DEFAULT 0,
                    active_processes INTEGER DEFAULT 0,
                    threat_level TEXT DEFAULT 'normal',
                    status TEXT DEFAULT 'active',
                    last_seen TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    endpoint_id TEXT,
                    hostname TEXT,
                    alert_type TEXT,
                    severity TEXT,
                    title TEXT,
                    description TEXT,
                    process_name TEXT,
                    process_pid INTEGER,
                    file_path TEXT,
                    network_ip TEXT,
                    mitre_tactic TEXT,
                    mitre_technique TEXT,
                    raw_data TEXT,
                    acknowledged INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS siem_logs (
                    log_id TEXT PRIMARY KEY,
                    endpoint_id TEXT,
                    log_type TEXT,
                    content TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS correlations (
                    corr_id TEXT PRIMARY KEY,
                    rule_name TEXT,
                    description TEXT,
                    alert_ids TEXT,
                    severity TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS threat_intel (
                    intel_id TEXT PRIMARY KEY,
                    intel_type TEXT,
                    value TEXT UNIQUE,
                    description TEXT,
                    source TEXT,
                    severity TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS commands (
                    command_id TEXT PRIMARY KEY,
                    endpoint_id TEXT,
                    command TEXT,
                    parameters TEXT,
                    status TEXT DEFAULT 'pending',
                    result TEXT,
                    delivered_at TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_commands_ep_status
                    ON commands(endpoint_id, status);

                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    policy_name TEXT,
                    rules TEXT,
                    endpoints TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS telemetry (
                    telemetry_id TEXT PRIMARY KEY,
                    endpoint_id TEXT,
                    events TEXT,
                    timestamp TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS geo_data (
                    geo_id TEXT PRIMARY KEY,
                    ip_address TEXT UNIQUE,
                    country TEXT,
                    city TEXT,
                    isp TEXT,
                    latitude REAL,
                    longitude REAL,
                    hit_count INTEGER DEFAULT 1,
                    last_seen TEXT DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_endpoint ON alerts(endpoint_id);
                CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
                CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
                -- Composite indexes for common dashboard queries
                CREATE INDEX IF NOT EXISTS idx_alerts_ep_time
                    ON alerts(endpoint_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_ep_severity
                    ON alerts(endpoint_id, severity, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_commands_ep_time
                    ON commands(endpoint_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_commands_ep_status_time
                    ON commands(endpoint_id, status, created_at DESC);
            """)
            conn.commit()
            conn.close()
            logger.info("SQLite tables initialized")

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _create_tables)

    def _get_conn(self):
        conn = sqlite3.connect(self._sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn

    async def _execute(self, query: str, params: tuple = ()):
        def _run():
            conn = self._get_conn()
            try:
                c = conn.cursor()
                c.execute(query, params)
                conn.commit()
                return c.lastrowid
            finally:
                conn.close()
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _run)

    async def _fetchall(self, query: str, params: tuple = ()) -> List[Dict]:
        def _run():
            conn = self._get_conn()
            try:
                c = conn.cursor()
                c.execute(query, params)
                rows = c.fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _run)

    async def _fetchone(self, query: str, params: tuple = ()) -> Optional[Dict]:
        def _run():
            conn = self._get_conn()
            try:
                c = conn.cursor()
                c.execute(query, params)
                row = c.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _run)

    # ─── Endpoints ──────────────────────────────────────────────────────────────
    async def upsert_endpoint(self, data: dict):
        now = datetime.utcnow().isoformat()
        await self._execute("""
            INSERT INTO endpoints (endpoint_id, hostname, ip_address, os_version, agent_version,
                cpu_usage, memory_usage, disk_usage, active_processes, threat_level, status, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
            ON CONFLICT(endpoint_id) DO UPDATE SET
                hostname=excluded.hostname, ip_address=excluded.ip_address,
                cpu_usage=excluded.cpu_usage, memory_usage=excluded.memory_usage,
                disk_usage=excluded.disk_usage, active_processes=excluded.active_processes,
                threat_level=excluded.threat_level, status='active', last_seen=excluded.last_seen
        """, (
            data["endpoint_id"], data["hostname"], data["ip_address"],
            data["os_version"], data["agent_version"], data["cpu_usage"],
            data["memory_usage"], data["disk_usage"], data["active_processes"],
            data["threat_level"], now
        ))

    async def get_all_endpoints(self) -> List[Dict]:
        # Mark stale endpoints as inactive
        cutoff = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        await self._execute("UPDATE endpoints SET status='inactive' WHERE last_seen < ?", (cutoff,))
        return await self._fetchall("SELECT * FROM endpoints ORDER BY last_seen DESC")

    async def get_endpoint(self, endpoint_id: str) -> Optional[Dict]:
        return await self._fetchone("SELECT * FROM endpoints WHERE endpoint_id = ?", (endpoint_id,))

    # ─── Alerts ─────────────────────────────────────────────────────────────────
    async def create_alert(self, alert_data: dict) -> str:
        alert_id = secrets.token_hex(12)
        await self._execute("""
            INSERT INTO alerts (alert_id, endpoint_id, hostname, alert_type, severity, title,
                description, process_name, process_pid, file_path, network_ip,
                mitre_tactic, mitre_technique, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            alert_data.get("endpoint_id"),
            alert_data.get("hostname"),
            alert_data.get("alert_type"),
            alert_data.get("severity", "medium"),
            alert_data.get("title"),
            alert_data.get("description"),
            alert_data.get("process_name"),
            alert_data.get("process_pid"),
            alert_data.get("file_path"),
            alert_data.get("network_ip"),
            alert_data.get("mitre_tactic"),
            alert_data.get("mitre_technique"),
            json.dumps(alert_data.get("raw_data") or {})
        ))
        return alert_id

    async def get_alerts(self, severity=None, endpoint_id=None, limit=100, offset=0) -> List[Dict]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if endpoint_id:
            query += " AND endpoint_id = ?"
            params.append(endpoint_id)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = await self._fetchall(query, tuple(params))
        for row in rows:
            if row.get("raw_data"):
                try:
                    row["raw_data"] = json.loads(row["raw_data"])
                except Exception:
                    pass
        return rows

    async def get_alert_stats(self) -> Dict:
        stats = {}
        for sev in ["low", "medium", "high", "critical", "emergency"]:
            row = await self._fetchone("SELECT COUNT(*) as cnt FROM alerts WHERE severity = ?", (sev,))
            stats[sev] = row["cnt"] if row else 0
        row = await self._fetchone("SELECT COUNT(*) as cnt FROM alerts WHERE acknowledged = 0", ())
        stats["unacknowledged"] = row["cnt"] if row else 0
        row = await self._fetchone(
            "SELECT COUNT(*) as cnt FROM alerts WHERE created_at > datetime('now', '-24 hours')", ()
        )
        stats["last_24h"] = row["cnt"] if row else 0
        return stats

    async def acknowledge_alert(self, alert_id: str):
        await self._execute("UPDATE alerts SET acknowledged = 1 WHERE alert_id = ?", (alert_id,))

    async def get_alert_timeline(self, hours: int = 24) -> List[Dict]:
        return await self._fetchall("""
            SELECT strftime('%Y-%m-%dT%H:00:00', created_at) as hour,
                   severity, COUNT(*) as count
            FROM alerts
            WHERE created_at > datetime('now', ?)
            GROUP BY hour, severity
            ORDER BY hour ASC
        """, (f"-{hours} hours",))

    async def get_mitre_coverage(self) -> List[Dict]:
        return await self._fetchall("""
            SELECT mitre_tactic, mitre_technique, COUNT(*) as count
            FROM alerts
            WHERE mitre_technique IS NOT NULL
            GROUP BY mitre_tactic, mitre_technique
        """)

    # ─── Threat Intel ───────────────────────────────────────────────────────────
    async def add_threat_intel(self, intel_type: str, value: str, description: str, source: str, severity: str = "high"):
        intel_id = secrets.token_hex(8)
        try:
            await self._execute("""
                INSERT OR IGNORE INTO threat_intel (intel_id, intel_type, value, description, source, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (intel_id, intel_type, value, description, source, severity))
        except Exception:
            pass

    async def check_threat_intel(self, intel_type: str, value: str) -> Optional[Dict]:
        return await self._fetchone(
            "SELECT * FROM threat_intel WHERE intel_type = ? AND value = ?", (intel_type, value)
        )

    async def get_threat_intel_count(self) -> Dict:
        rows = await self._fetchall("SELECT intel_type, COUNT(*) as cnt FROM threat_intel GROUP BY intel_type")
        return {r["intel_type"]: r["cnt"] for r in rows}

    # ─── Commands ───────────────────────────────────────────────────────────────
    async def store_command(self, command_id: str, data: dict):
        # Use SQLite-compatible timestamp format (space separator, not T)
        # so that datetime('now', '-60 seconds') comparison works correctly.
        sqlite_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        await self._execute("""
            INSERT OR IGNORE INTO commands
                (command_id, endpoint_id, command, parameters, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
        """, (
            command_id,
            data["endpoint_id"],
            data["command"],
            json.dumps(data.get("parameters") or {}),
            sqlite_now,
        ))

    async def get_pending_commands(self, endpoint_id: str) -> List[Dict]:
        """Only return 'pending' commands created within the last 60 seconds."""
        rows = await self._fetchall(
            """SELECT * FROM commands
               WHERE endpoint_id = ? AND status = 'pending'
               AND created_at >= datetime('now', '-60 seconds')
               ORDER BY created_at ASC""",
            (endpoint_id,)
        )
        for row in rows:
            if row.get("parameters"):
                try:
                    row["parameters"] = json.loads(row["parameters"])
                except Exception:
                    pass
        return rows

    async def expire_old_commands(self, endpoint_id: str = None):
        """Mark commands older than 60s as expired so they're never re-delivered."""
        if endpoint_id:
            await self._execute(
                """UPDATE commands SET status='expired'
                   WHERE status='pending' AND endpoint_id = ?
                   AND created_at < datetime('now', '-60 seconds')""",
                (endpoint_id,))
        else:
            await self._execute(
                """UPDATE commands SET status='expired'
                   WHERE status='pending'
                   AND created_at < datetime('now', '-60 seconds')""")

    async def update_command_result(self, command_id: str, result: dict):
        status = result.get("status", "completed")
        # Normalise — only use DB-valid statuses
        if status not in ("completed", "delivered", "expired", "error", "failed", "executed", "not_found", "admin_required", "unknown"):
            status = "completed"
        await self._execute(
            "UPDATE commands SET status=?, result=? WHERE command_id=?",
            (status, json.dumps(result), command_id)
        )

    # ─── Policies ───────────────────────────────────────────────────────────────
    async def create_policy(self, data: dict) -> str:
        policy_id = secrets.token_hex(8)
        await self._execute("""
            INSERT INTO policies (policy_id, policy_name, rules, endpoints)
            VALUES (?, ?, ?, ?)
        """, (policy_id, data["policy_name"], json.dumps(data["rules"]), json.dumps(data["endpoints"])))
        return policy_id

    async def get_all_policies(self) -> List[Dict]:
        rows = await self._fetchall("SELECT * FROM policies ORDER BY created_at DESC")
        for row in rows:
            for field in ["rules", "endpoints"]:
                if row.get(field):
                    try:
                        row[field] = json.loads(row[field])
                    except Exception:
                        pass
        return rows

    async def get_policy_for_endpoint(self, endpoint_id: str) -> Optional[Dict]:
        rows = await self.get_all_policies()
        for policy in rows:
            if endpoint_id in (policy.get("endpoints") or []) or not policy.get("endpoints"):
                return policy
        return None

    # ─── Correlations ───────────────────────────────────────────────────────────
    async def store_correlation(self, rule_name: str, description: str, alert_ids: List[str], severity: str):
        corr_id = secrets.token_hex(8)
        await self._execute("""
            INSERT INTO correlations (corr_id, rule_name, description, alert_ids, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (corr_id, rule_name, description, json.dumps(alert_ids), severity))
        return corr_id

    async def get_correlations(self, limit: int = 50) -> List[Dict]:
        rows = await self._fetchall("SELECT * FROM correlations ORDER BY created_at DESC LIMIT ?", (limit,))
        for row in rows:
            if row.get("alert_ids"):
                try:
                    row["alert_ids"] = json.loads(row["alert_ids"])
                except Exception:
                    pass
        return rows

    # ─── Geo Data ───────────────────────────────────────────────────────────────
    async def store_geo_data(self, ip: str, country: str, city: str, isp: str, lat: float, lon: float):
        geo_id = secrets.token_hex(8)
        await self._execute("""
            INSERT INTO geo_data (geo_id, ip_address, country, city, isp, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                hit_count = hit_count + 1, last_seen = datetime('now')
        """, (geo_id, ip, country, city, isp, lat, lon))

    async def get_attack_geo_data(self) -> List[Dict]:
        return await self._fetchall("SELECT * FROM geo_data ORDER BY hit_count DESC LIMIT 100")

    # ─── Telemetry ──────────────────────────────────────────────────────────────
    async def store_telemetry(self, data: dict):
        tel_id = secrets.token_hex(8)
        await self._execute("""
            INSERT INTO telemetry (telemetry_id, endpoint_id, events, timestamp)
            VALUES (?, ?, ?, ?)
        """, (tel_id, data["endpoint_id"], json.dumps(data["events"]), data["timestamp"]))

    # ─── Cleanup ────────────────────────────────────────────────────────────────
    async def cleanup_old_records(self, days: int = 30):
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        for table in ["alerts", "siem_logs", "telemetry", "correlations"]:
            try:
                await self._execute(f"DELETE FROM {table} WHERE created_at < ?", (cutoff,))
            except Exception:
                pass
        logger.info(f"Cleaned up records older than {days} days")

    async def close(self):
        if self._conn:
            await self._conn.close()