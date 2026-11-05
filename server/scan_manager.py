"""
scan_manager.py — Malabar Sentinel
====================================
Server-side scan management: issue scan commands, track progress,
store results, manage endpoint_timeline and scan_reports tables.

Blocking/unblocking of threat IPs is delegated entirely to the existing
network_blocking module via the standard command-queue pathway
(block_ip / unblock_ip / block_url / unblock_url commands).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Optional

logger = logging.getLogger("scan-manager")

# ─────────────────────────────────────────────────────────────────────────────
# TABLE SCHEMAS  (appended to database.py's _init_db via init_scan_tables)
# ─────────────────────────────────────────────────────────────────────────────

SCAN_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS scan_reports (
    id           TEXT PRIMARY KEY,
    endpoint_id  TEXT NOT NULL,
    scan_type    TEXT NOT NULL,          -- quick | full | custom
    status       TEXT DEFAULT 'pending', -- pending | running | completed | stopped | error
    folder_path  TEXT,                   -- for custom scans
    started_at   TEXT,
    completed_at TEXT,
    files_scanned INTEGER DEFAULT 0,
    threats_found INTEGER DEFAULT 0,
    duration      INTEGER DEFAULT 0,     -- seconds
    created_at    TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scan_ep  ON scan_reports(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_scan_ts  ON scan_reports(started_at);
CREATE INDEX IF NOT EXISTS idx_scan_ep_status ON scan_reports(endpoint_id, status, started_at DESC);

CREATE TABLE IF NOT EXISTS threat_details (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scan_reports(id) ON DELETE CASCADE,
    endpoint_id  TEXT NOT NULL,
    file_path    TEXT,
    threat_name  TEXT,
    severity     TEXT DEFAULT 'medium',  -- low | medium | high | critical
    action_taken TEXT DEFAULT 'logged',  -- logged | quarantined | blocked | sandbox
    detected_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_threat_scan ON threat_details(scan_id);
CREATE INDEX IF NOT EXISTS idx_threat_ep   ON threat_details(endpoint_id);

CREATE TABLE IF NOT EXISTS endpoint_timeline (
    id            TEXT PRIMARY KEY,
    endpoint_id   TEXT NOT NULL,
    event_type    TEXT NOT NULL,   -- scan | threat | quarantine | sandbox | usb | system | response
    event_message TEXT,
    severity      TEXT DEFAULT 'info',   -- info | low | medium | high | critical
    created_at    TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tl_ep  ON endpoint_timeline(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_tl_ts  ON endpoint_timeline(created_at);
CREATE INDEX IF NOT EXISTS idx_tl_ep_type ON endpoint_timeline(endpoint_id, event_type, created_at DESC);
"""


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

async def init_scan_tables(db) -> None:
    """Create scan / timeline tables if they don't exist. Call once at startup."""
    async with db._lock:
        try:
            await db._conn.executescript(SCAN_TABLES_SQL)
            await db._conn.commit()
            logger.info("[scan_tables] tables ensured")
        except Exception as e:
            logger.error("[scan_tables] init error: %s", e)


async def create_scan(db, endpoint_id: str, scan_type: str,
                      folder_path: Optional[str] = None) -> str:
    """Insert a new scan_report row and return its id."""
    scan_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    async with db._lock:
        await db._conn.execute(
            """INSERT INTO scan_reports
               (id, endpoint_id, scan_type, status, folder_path, started_at)
               VALUES (?,?,?,?,?,?)""",
            (scan_id, endpoint_id, scan_type, "running", folder_path, now),
        )
        await db._conn.commit()
    logger.info("[scan] created id=%s ep=%s type=%s", scan_id, endpoint_id, scan_type)
    return scan_id


async def update_scan(db, scan_id: str, **kwargs) -> None:
    """Update any columns on a scan_report row."""
    if not kwargs:
        return
    cols = ", ".join(f"{k}=?" for k in kwargs)
    vals = list(kwargs.values()) + [scan_id]
    async with db._lock:
        await db._conn.execute(
            f"UPDATE scan_reports SET {cols} WHERE id=?", vals
        )
        await db._conn.commit()


async def get_scan(db, scan_id: str) -> Optional[dict]:
    row = await db._fetchone("SELECT * FROM scan_reports WHERE id=?", (scan_id,))
    return dict(row) if row else None


async def get_scans_for_endpoint(db, endpoint_id: str, limit: int = 20) -> list:
    rows = await db._fetchall(
        "SELECT * FROM scan_reports WHERE endpoint_id=? ORDER BY started_at DESC LIMIT ?",
        (endpoint_id, limit),
    )
    return [dict(r) for r in rows]


async def get_active_scan(db, endpoint_id: str) -> Optional[dict]:
    row = await db._fetchone(
        "SELECT * FROM scan_reports WHERE endpoint_id=? AND status='running' LIMIT 1",
        (endpoint_id,),
    )
    return dict(row) if row else None


async def add_threat(db, scan_id: str, endpoint_id: str, file_path: str,
                     threat_name: str, severity: str = "medium",
                     action_taken: str = "logged") -> str:
    """Insert a threat_detail row and return its id."""
    tid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    async with db._lock:
        await db._conn.execute(
            """INSERT INTO threat_details
               (id, scan_id, endpoint_id, file_path, threat_name,
                severity, action_taken, detected_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (tid, scan_id, endpoint_id, file_path, threat_name,
             severity, action_taken, now),
        )
        await db._conn.commit()
    return tid


async def get_threats_for_scan(db, scan_id: str) -> list:
    rows = await db._fetchall(
        "SELECT * FROM threat_details WHERE scan_id=? ORDER BY detected_at",
        (scan_id,),
    )
    return [dict(r) for r in rows]


async def get_threats_for_endpoint(db, endpoint_id: str, limit: int = 100) -> list:
    rows = await db._fetchall(
        "SELECT * FROM threat_details WHERE endpoint_id=? ORDER BY detected_at DESC LIMIT ?",
        (endpoint_id, limit),
    )
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# TIMELINE
# ─────────────────────────────────────────────────────────────────────────────

_EVENT_ICONS = {
    "scan":       "🔍",
    "threat":     "⚠️",
    "quarantine": "🔒",
    "sandbox":    "🧪",
    "usb":        "📦",
    "system":     "🟢",
    "response":   "🛑",
    "malware":    "🚨",
    "block":      "🛡",
}


async def log_event(db, endpoint_id: str, event_type: str,
                    message: str, severity: str = "info") -> str:
    """
    Append a forensic timeline entry for *endpoint_id*.

    event_type: scan | threat | quarantine | sandbox | usb | system | response | block
    severity:   info | low | medium | high | critical
    """
    eid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    async with db._lock:
        await db._conn.execute(
            """INSERT INTO endpoint_timeline
               (id, endpoint_id, event_type, event_message, severity, created_at)
               VALUES (?,?,?,?,?,?)""",
            (eid, endpoint_id, event_type, message, severity, now),
        )
        await db._conn.commit()
    logger.debug("[timeline] ep=%s type=%s sev=%s msg=%s",
                 endpoint_id, event_type, severity, message[:80])
    return eid


async def get_timeline(db, endpoint_id: str,
                       event_type_filter: Optional[str] = None,
                       limit: int = 200) -> list:
    """
    Fetch timeline entries for an endpoint, newest-first.
    Pass event_type_filter to restrict to one category.
    """
    if event_type_filter and event_type_filter != "all":
        rows = await db._fetchall(
            """SELECT * FROM endpoint_timeline
               WHERE endpoint_id=? AND event_type=?
               ORDER BY created_at DESC LIMIT ?""",
            (endpoint_id, event_type_filter, limit),
        )
    else:
        rows = await db._fetchall(
            """SELECT * FROM endpoint_timeline
               WHERE endpoint_id=?
               ORDER BY created_at DESC LIMIT ?""",
            (endpoint_id, limit),
        )
    events = []
    for r in rows:
        d = dict(r)
        d["icon"] = _EVENT_ICONS.get(d.get("event_type", ""), "📌")
        events.append(d)
    return events


# ─────────────────────────────────────────────────────────────────────────────
# AGGREGATE STATS  (used by PDF report and dashboard summary card)
# ─────────────────────────────────────────────────────────────────────────────

async def get_endpoint_scan_stats(db, endpoint_id: str) -> dict:
    """Return counts used in the PDF header / dashboard KPI block."""
    total_scans = await db._fetchone(
        "SELECT COUNT(*) as c FROM scan_reports WHERE endpoint_id=?", (endpoint_id,)
    )
    threats_found = await db._fetchone(
        "SELECT COALESCE(SUM(threats_found),0) as c FROM scan_reports WHERE endpoint_id=?",
        (endpoint_id,),
    )
    sandbox_events = await db._fetchone(
        "SELECT COUNT(*) as c FROM endpoint_timeline WHERE endpoint_id=? AND event_type='sandbox'",
        (endpoint_id,),
    )
    isolation_events = await db._fetchone(
        "SELECT COUNT(*) as c FROM endpoint_timeline WHERE endpoint_id=? AND event_type='response'",
        (endpoint_id,),
    )
    last_scan = await db._fetchone(
        "SELECT completed_at FROM scan_reports WHERE endpoint_id=? AND status='completed' ORDER BY completed_at DESC LIMIT 1",
        (endpoint_id,),
    )
    return {
        "total_scans":       (total_scans["c"] if total_scans else 0),
        "threats_found":     (threats_found["c"] if threats_found else 0),
        "sandbox_analyses":  (sandbox_events["c"] if sandbox_events else 0),
        "isolation_events":  (isolation_events["c"] if isolation_events else 0),
        "last_scan":         (last_scan["completed_at"] if last_scan else None),
    }


async def get_endpoint_security_status(db, endpoint_id: str) -> str:
    """
    Return overall status: SECURE | WARNING | CRITICAL
    Used as the final verdict in PDF reports.
    """
    stats = await get_endpoint_scan_stats(db, endpoint_id)
    active = await get_active_scan(db, endpoint_id)
    critical_threats = await db._fetchone(
        """SELECT COUNT(*) as c FROM threat_details
           WHERE endpoint_id=? AND severity IN ('high','critical')
             AND action_taken NOT IN ('quarantined','blocked')""",
        (endpoint_id,),
    )
    crit = critical_threats["c"] if critical_threats else 0
    if crit > 0:
        return "CRITICAL"
    if stats["threats_found"] > 0 or active:
        return "WARNING"
    return "SECURE"
