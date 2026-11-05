"""
Malabar Sentinel — Enterprise SOC + EDR Platform  v2.0
FastAPI server: alerts, endpoints, remote-response commands, WebSocket push.

KEY FIX (v2): Every command result is stored server-side.
Dashboard polls  GET /api/commands/{id}/status  as fallback so it NEVER stays
"waiting for agent" even if the WebSocket drops between issue and result.
"""

import asyncio
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import httpx

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env')
    load_dotenv(dotenv_path=env_path)
except ImportError:
    pass

from database import Database
from models import Alert, Endpoint, ThreatEvent, Policy, SIEMLog
from alert_handler import AlertHandler
from policy_engine import PolicyEngine
from mitre_mapper import MITREMapper
from threat_intelligence import ThreatIntelligence
from siem_correlator import SIEMCorrelator
from ml_detection import MLDetectionEngine
from ai_prediction import AIPredictionEngine
from websocket_manager import WebSocketManager
from scan_routes  import router as scan_router, attach_scan_routes
from scan_manager import init_scan_tables, log_event as tl_log_event
from command_queue import (
    enqueue       as cq_enqueue,
    dequeue       as cq_dequeue,
    record_result as cq_result,
    get_result    as cq_get_result,
    stats         as cq_stats,
)

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("soc-server")

# ── Global singletons ─────────────────────────────────────────────────────────
db              = Database()
ws_manager      = WebSocketManager()
alert_handler   = AlertHandler(db, ws_manager)
policy_engine   = PolicyEngine(db)
mitre_mapper    = MITREMapper()
threat_intel    = ThreatIntelligence(db)
siem_correlator = SIEMCorrelator(db, alert_handler)
ml_engine       = MLDetectionEngine()
ai_predictor    = AIPredictionEngine(db)

# ── In-memory command status store ────────────────────────────────────────────
# command_id → {command, endpoint_id, status, detail, created_at, updated_at}
# This is the source-of-truth for the /api/commands/{id}/status polling endpoint.
_cmd_store: Dict[str, dict] = {}
# endpoint_id → list of process dicts sent by agent heartbeat
_process_cache: Dict[str, list] = {}

def _cmd_upsert(command_id: str, **fields):
    """Create or update a command record in the in-memory store."""
    now = datetime.utcnow().isoformat()
    if command_id not in _cmd_store:
        _cmd_store[command_id] = {"command_id": command_id, "created_at": now}
    _cmd_store[command_id].update(fields)
    _cmd_store[command_id]["updated_at"] = now
    # Rolling window — keep newest 2 000 records
    if len(_cmd_store) > 2000:
        oldest = sorted(_cmd_store, key=lambda k: _cmd_store[k].get("created_at",""))[:500]
        for k in oldest:
            del _cmd_store[k]

# ── Rate limiting ─────────────────────────────────────────────────────────────
_rate_buckets: Dict[str, List[float]] = {}
RATE_LIMIT = 300  # requests/minute/IP

def check_rate_limit(ip: str) -> bool:
    now = time.time()
    _rate_buckets.setdefault(ip, [])
    _rate_buckets[ip] = [t for t in _rate_buckets[ip] if now - t < 60]
    if len(_rate_buckets[ip]) >= RATE_LIMIT:
        return False
    _rate_buckets[ip].append(now)
    return True

# ── Auth ──────────────────────────────────────────────────────────────────────
security     = HTTPBearer()
_admin_key   = os.getenv("SOC_ADMIN_KEY",  os.getenv("SOC_MASTER_KEY", ""))
_agent_key   = os.getenv("AGENT_KEY", "")

if not _admin_key:
    logger.warning("SOC_ADMIN_KEY not set — using insecure default; set it in .env")
    _admin_key = "SOC-MASTER-KEY-2024"
if not _agent_key:
    logger.warning("AGENT_KEY not set — using insecure default; set it in .env")
    _agent_key = "AGENT-KEY-ENDPOINT-001"

RATE_LIMIT = int(os.getenv("SOC_RATE_LIMIT_PER_MINUTE", "300"))

def _ct_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return secrets.compare_digest(a.encode(), b.encode())

def verify_api_key(creds: HTTPAuthorizationCredentials = Depends(security)):
    """Accept admin key or agent key; constant-time comparison."""
    token = creds.credentials
    ok = _ct_compare(token, _admin_key) or _ct_compare(token, _agent_key)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return token

def verify_admin_key(creds: HTTPAuthorizationCredentials = Depends(security)):
    """Only accept admin (dashboard) key — not agent key."""
    token = creds.credentials
    if not _ct_compare(token, _admin_key):
        raise HTTPException(status_code=401, detail="Admin key required")
    return token

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.initialize()
    await init_scan_tables(db)                              # scan / timeline tables
    attach_scan_routes(db, _issue_command, verify_api_key)  # wire scan API
    asyncio.create_task(_housekeeping())
    logger.info("Malabar Sentinel v2.0 ready")
    yield

async def _housekeeping():
    while True:
        try:
            await db.expire_old_commands()
        except Exception:
            pass
        await asyncio.sleep(30)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Malabar Sentinel SOC Platform",
    description="Enterprise EDR — Kerala Police Cybercrime Division",
    version="2.0.0",
    lifespan=lifespan,
)
_raw_origins = os.getenv("SOC_ALLOWED_ORIGINS", "")
_allowed_origins: List[str] = (
    [o.strip() for o in _raw_origins.split(",") if o.strip()]
    if _raw_origins
    else ["http://localhost:9001", "http://127.0.0.1:9001"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.include_router(scan_router)   # antivirus scan + timeline + PDF endpoints

# ── Pydantic Models ───────────────────────────────────────────────────────────
class AlertSubmit(BaseModel):
    endpoint_id:      str
    alert_type:       str
    severity:         str
    title:            str
    description:      str
    process_name:     Optional[str]  = None
    file_path:        Optional[str]  = None
    network_ip:       Optional[str]  = None
    mitre_tactic:     Optional[str]  = None
    mitre_technique:  Optional[str]  = None
    raw_data:         Optional[dict] = None

class HeartbeatData(BaseModel):
    endpoint_id:      str
    hostname:         str
    ip_address:       str
    os_version:       str
    agent_version:    str
    cpu_usage:        float
    memory_usage:     float
    disk_usage:       float
    active_processes: int
    threat_level:     str = "normal"
    process_list:     Optional[list] = None  # agent sends real process list here
    usb_devices:      Optional[list] = None  # agent sends live USB/device snapshot
    is_admin:         Optional[bool] = None

class RemoteCommandRequest(BaseModel):
    endpoint_id: str
    command:     str
    parameters:  Optional[dict] = None

class _SendCmdBody(BaseModel):
    endpoint_id: str
    command:     str
    parameters:  Optional[dict] = None

class PolicyUpdate(BaseModel):
    policy_name: str
    rules:       dict
    endpoints:   List[str] = []

class TelemetryData(BaseModel):
    endpoint_id: str
    events:      List[dict]
    timestamp:   str

class AgentRegister(BaseModel):
    endpoint_id:   str
    hostname:      str
    ip_address:    str
    os_version:    str = "Unknown"
    agent_version: str = "1.0.0"

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":    "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version":   "2.0.0",
        "ws":        ws_manager.get_stats(),
        "cmd_queue": cq_stats(),
    }

# ── Alerts ────────────────────────────────────────────────────────────────────
@app.post("/api/alerts", tags=["Alerts"])
async def submit_alert(data: AlertSubmit, request: Request,
                       api_key: str = Depends(verify_api_key)):
    if not check_rate_limit(request.client.host):
        raise HTTPException(429, "Rate limit exceeded")

    if not data.mitre_technique:
        m = mitre_mapper.map_alert(data.alert_type, data.description)
        data.mitre_tactic, data.mitre_technique = m.get("tactic"), m.get("technique")

    ti = None
    if data.network_ip:
        ti = await threat_intel.check_ip(data.network_ip)
    if data.file_path and not ti:
        ti = await threat_intel.check_file_hash(
            data.raw_data.get("sha256") if data.raw_data else None)
    if ti:
        data.severity     = "critical"
        data.description += f" | THREAT INTEL: {ti}"

    ml = ml_engine.score_alert(data.dict())
    if ml > 0.85 and data.severity in ["low","medium"]:
        data.severity     = "high"
        data.description += f" | ML Score: {ml:.2f}"

    alert_id = await alert_handler.process_alert(data.dict())
    await siem_correlator.add_event(data.dict())
    return {"status": "accepted", "alert_id": alert_id, "ml_score": ml}

@app.get("/api/alerts", tags=["Alerts"])
async def get_alerts(severity: Optional[str]=None, endpoint_id: Optional[str]=None,
                     limit: int=100, offset: int=0, api_key: str=Depends(verify_api_key)):
    alerts = await db.get_alerts(severity=severity, endpoint_id=endpoint_id,
                                  limit=limit, offset=offset)
    return {"alerts": alerts, "total": len(alerts)}

@app.get("/api/alerts/stats", tags=["Alerts"])
async def get_alert_stats(api_key: str = Depends(verify_api_key)):
    return await db.get_alert_stats()

@app.put("/api/alerts/{alert_id}/acknowledge", tags=["Alerts"])
async def acknowledge_alert(alert_id: str, api_key: str=Depends(verify_api_key)):
    await db.acknowledge_alert(alert_id)
    return {"status": "acknowledged"}

# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.post("/api/endpoints/heartbeat", tags=["Endpoints"])
async def endpoint_heartbeat(data: HeartbeatData, api_key: str=Depends(verify_api_key)):
    hb_dict = data.dict()
    # Cache process list separately — don't store in endpoint DB record
    if data.process_list:
        _process_cache[data.endpoint_id] = {
            "processes": data.process_list,
            "updated_at": datetime.utcnow().isoformat(),
        }
    # Cache live USB/device list if agent sends it
    if data.usb_devices is not None:
        cache = {}
        for dev in data.usb_devices:
            key = dev.get("device_id") or dev.get("drive") or ""
            if key:
                cache[key] = dev
        _usb_cache[data.endpoint_id] = {
            "devices": cache,
            "updated_at": datetime.utcnow().isoformat(),
        }
    # Remove agent-only fields before upserting to DB (not endpoint table columns)
    ep_data = {k: v for k, v in hb_dict.items()
               if k not in ('process_list', 'usb_devices', 'is_admin')}
    await db.upsert_endpoint(ep_data)
    await ws_manager.broadcast({"type": "endpoint_update", "data": ep_data})
    policy = await policy_engine.get_policy_for_endpoint(data.endpoint_id)
    return {"status": "ok", "policy": policy}

@app.get("/api/endpoints", tags=["Endpoints"])
async def get_endpoints(api_key: str=Depends(verify_api_key)):
    return {"endpoints": await db.get_all_endpoints()}

@app.get("/api/endpoints/{endpoint_id}", tags=["Endpoints"])
async def get_endpoint(endpoint_id: str, api_key: str=Depends(verify_api_key)):
    ep = await db.get_endpoint(endpoint_id)
    if not ep:
        raise HTTPException(404, "Endpoint not found")
    return ep

@app.get("/api/endpoints/{endpoint_id}/processes", tags=["Endpoints"])
async def get_processes(endpoint_id: str, api_key: str=Depends(verify_api_key)):
    """
    Returns the real process list from the monitored endpoint.
    The agent sends its process list via heartbeat; we cache and serve it here.
    This endpoint does NOT run psutil on the server — that would show the
    server's own processes, not the monitored machine's.
    """
    STALE_SECONDS = 120  # label data older than 2 min as stale
    entry = _process_cache.get(endpoint_id)
    if not entry:
        return {
            "processes": [],
            "source": "none",
            "count": 0,
            "note": "No process data yet — ensure agent is connected and monitoring",
            "stale": False,
        }
    procs = entry.get("processes", [])
    updated_at = entry.get("updated_at", "")
    stale = False
    try:
        age = (datetime.utcnow() - datetime.fromisoformat(updated_at)).total_seconds()
        stale = age > STALE_SECONDS
    except Exception:
        pass
    return {
        "processes": procs,
        "source": "agent",
        "count": len(procs),
        "updated_at": updated_at,
        "stale": stale,
        "note": "Data may be stale — agent has not reported recently" if stale else "",
    }

# In-memory cache: endpoint_id → list of currently connected USB/portable devices
# Agent pushes live snapshot via heartbeat; alerts also update this list
_usb_cache: Dict[str, dict] = {}   # endpoint_id → {device_key: device_dict}

@app.get("/api/endpoints/{endpoint_id}/usb-devices", tags=["Endpoints"])
async def get_usb_devices(endpoint_id: str, api_key: str=Depends(verify_api_key)):
    """
    Returns ONLY currently connected USB devices.

    Source: live cache (_usb_cache) populated by agent heartbeat every 10s.
    The agent calls _get_live_usb_snapshot() which runs the full USB monitor
    detection (WPD class, PnP entities, removable drives) on the endpoint.

    We intentionally do NOT use alert history here — historical usb_insertion
    alerts would show devices that were connected days/weeks ago and have since
    been removed, making the list inaccurate.

    Returns empty list (not an error) when agent hasn't connected yet.
    """
    try:
        entry = _usb_cache.get(endpoint_id, {})
        live_devices = list(entry.get("devices", {}).values())
        updated_at = entry.get("updated_at", "")
        stale = False
        STALE_SECONDS = 120
        if updated_at:
            try:
                age = (datetime.utcnow() - datetime.fromisoformat(updated_at)).total_seconds()
                stale = age > STALE_SECONDS
            except Exception:
                pass
        return {
            "devices": live_devices,
            "count": len(live_devices),
            "updated_at": updated_at,
            "stale": stale,
            "source": "live" if live_devices else "none",
            "note": (
                "Data may be stale — agent has not reported recently" if stale
                else ("" if live_devices else "No devices detected. Ensure agent is connected and monitoring is active.")
            ),
        }
    except Exception as e:
        logger.error("get_usb_devices error: %s", e)
        return {"devices": [], "error": str(e)}

# ── Commands — CORE HELPER ─────────────────────────────────────────────────────
async def _issue_command(endpoint_id: str, command: str, parameters: dict) -> dict:
    """
    Single place that enqueues a command, stores it, pushes via WS.
    Returns a dict that includes poll_url so the dashboard can poll for status.
    """
    command_id = await cq_enqueue(endpoint_id, command, parameters)
    now        = datetime.utcnow().isoformat()

    _cmd_upsert(command_id,
                endpoint_id=endpoint_id,
                command=command,
                parameters=parameters,
                status="pending",
                created_at=now)

    try:
        await db.store_command(command_id, {
            "endpoint_id": endpoint_id, "command": command,
            "parameters":  parameters,  "command_id": command_id,
            "created_at":  now,
        })
    except Exception as e:
        logger.warning("DB store_command: %s", e)

    ws_ok = await ws_manager.send_to_endpoint(endpoint_id, {
        "type": "command", "command_id": command_id,
        "command": command, "parameters": parameters,
    })
    await ws_manager.broadcast({
        "type": "command_sent", "command_id": command_id,
        "endpoint_id": endpoint_id, "command": command,
        "ws_delivered": ws_ok, "timestamp": now,
    })
    logger.info("CMD issued: [%s] → %s id=%s ws=%s",
                command, endpoint_id, command_id[:12], ws_ok)
    return {
        "status":      "queued",
        "command_id":  command_id,
        "endpoint_id": endpoint_id,
        "command":     command,
        "ws_delivered": ws_ok,
        "poll_url":    f"/api/commands/{command_id}/status",
    }

# ── Commands — DASHBOARD POST (no auth) ───────────────────────────────────────
@app.post("/send-command", tags=["Commands"])
async def send_command_dashboard(body: _SendCmdBody):
    """Dashboard sends command here — no auth required (local)."""
    return await _issue_command(body.endpoint_id, body.command, body.parameters or {})

# ── Commands — API POST (with auth) ───────────────────────────────────────────
@app.post("/api/commands", tags=["Commands"])
async def send_command_api(cmd: RemoteCommandRequest, api_key: str=Depends(verify_api_key)):
    return await _issue_command(cmd.endpoint_id, cmd.command, cmd.parameters or {})

# ── Commands — STATUS POLLING (THE KEY FIX) ───────────────────────────────────
@app.get("/api/commands/{command_id}/status", tags=["Commands"])
async def get_command_status(command_id: str,
                              api_key: str = Depends(verify_api_key)):
    """
    Dashboard polls this every 2s to get result without depending on WebSocket.
    Returns: pending | delivered | executed | failed | expired
    DB is the source of truth; _cmd_store is a short-lived write-through cache.
    """
    # 1. Try DB first (authoritative)
    try:
        db_rec = await db.get_command_result(command_id)
        if db_rec:
            # Hydrate cache for subsequent fast reads
            _cmd_upsert(command_id, **{k: v for k, v in db_rec.items()
                                        if k != "command_id"})
            return {**db_rec, "poll_url": f"/api/commands/{command_id}/status"}
    except Exception:
        pass

    # 2. In-memory cache (recent, not yet flushed to DB)
    rec = _cmd_store.get(command_id)
    if rec:
        return {**rec, "poll_url": f"/api/commands/{command_id}/status"}

    # 3. In-memory result queue
    result = await cq_get_result(command_id)
    if result:
        return {**result, "poll_url": f"/api/commands/{command_id}/status"}

    raise HTTPException(404, "Command not found")

# ── Commands — HISTORY ────────────────────────────────────────────────────────
@app.get("/api/commands/history", tags=["Commands"])
async def command_history(endpoint_id: Optional[str]=None, limit: int=100):
    recs = list(_cmd_store.values())
    if endpoint_id:
        recs = [r for r in recs if r.get("endpoint_id") == endpoint_id]
    recs.sort(key=lambda r: r.get("created_at",""), reverse=True)
    return {"commands": recs[:limit]}

# ── Commands — AGENT POLL ─────────────────────────────────────────────────────
@app.get("/get-commands/{endpoint_id}", tags=["Commands"])
async def get_commands_agent(endpoint_id: str,
                              api_key: str = Depends(verify_api_key)):
    """Agent polls every 1–2 s."""
    cmds = await cq_dequeue(endpoint_id)
    seen = {c["command_id"] for c in cmds}

    # DB fallback (offline reconnect, ≤60 s window)
    try:
        for dc in await db.get_pending_commands(endpoint_id):
            cid = dc.get("command_id","")
            if not cid or cid in seen:
                continue
            import datetime as _dt
            try:
                age = (_dt.datetime.utcnow() -
                       _dt.datetime.fromisoformat(dc.get("created_at",""))).total_seconds()
                if age > 60:
                    await db.update_command_result(cid, {"status": "expired"})
                    _cmd_upsert(cid, status="expired")
                    continue
            except Exception:
                pass
            cmds.append(dc)
            seen.add(cid)
    except Exception:
        pass

    now = datetime.utcnow().isoformat()
    for cmd in cmds:
        cid = cmd.get("command_id","")
        if cid:
            _cmd_upsert(cid, status="delivered", delivered_at=now)
            try:
                await db.update_command_result(cid, {"status": "delivered", "delivered_at": now})
            except Exception:
                pass

    if cmds:
        logger.info("Delivering %d cmd(s) → %s", len(cmds), endpoint_id)
    return {"commands": cmds, "count": len(cmds)}

# ── Commands — AGENT RESULT ───────────────────────────────────────────────────
@app.post("/command-response", tags=["Commands"])
async def command_response(data: dict,
                            api_key: str = Depends(verify_api_key)):
    """Agent posts execution result here."""
    cid    = data.get("command_id","")
    status = data.get("status","executed")
    detail = data.get("detail","")

    await cq_result(cid, data)
    _cmd_upsert(cid,
                status=status, detail=detail,
                command=data.get("command",""),
                endpoint_id=data.get("endpoint_id",""),
                hostname=data.get("hostname",""),
                completed_at=datetime.utcnow().isoformat())
    try:
        await db.update_command_result(cid, data)
    except Exception:
        pass

    msg = {
        "type":        "command_result",
        "command_id":  cid,
        "status":      status,
        "detail":      detail,
        "command":     data.get("command",""),
        "endpoint_id": data.get("endpoint_id",""),
        "hostname":    data.get("hostname",""),
        "timestamp":   datetime.utcnow().isoformat(),
    }
    await ws_manager.broadcast(msg)
    logger.info("CMD result [%s] %s — %s", status, data.get("command",""), detail[:80])

    # ── Write timeline entry for block/unblock commands ───────────────────────
    # These are executed by network_blocking.IPBlocker / URLBlocker on the agent.
    # We mirror them as 'block' timeline events on the server so the forensic
    # timeline and PDF report capture every block action automatically.
    cmd    = data.get("command", "")
    ep_id  = data.get("endpoint_id", "")
    if cmd in ("block_ip", "unblock_ip", "block_url", "unblock_url") and ep_id:
        try:
            params = data.get("parameters") or {}
            target = params.get("ip") or params.get("url") or detail[:60]
            sev    = "high" if cmd in ("block_ip", "block_url") else "low"
            asyncio.create_task(
                tl_log_event(db, ep_id, "block",
                             f"{cmd.replace('_',' ').title()}: {target}",
                             severity=sev)
            )
        except Exception:
            pass

    return {"status": "recorded"}

@app.post("/api/commands/{command_id}/result", tags=["Commands"])
async def command_result_api(command_id: str, result: dict,
                              api_key: str=Depends(verify_api_key)):
    result["command_id"] = command_id
    return await command_response(result)

@app.get("/api/commands/{endpoint_id}/pending", tags=["Commands"])
async def pending_commands(endpoint_id: str, api_key: str=Depends(verify_api_key)):
    return {"commands": await db.get_pending_commands(endpoint_id)}

@app.get("/queue-stats", tags=["Commands"])
async def queue_stats():
    return {**cq_stats(), "tracked": len(_cmd_store)}

# ── Agent registration ────────────────────────────────────────────────────────
@app.post("/register", tags=["Agent"])
async def register_agent(data: AgentRegister, request: Request):
    await db.upsert_endpoint({
        "endpoint_id":      data.endpoint_id,
        "hostname":         data.hostname,
        "ip_address":       data.ip_address,
        "os_version":       data.os_version,
        "agent_version":    data.agent_version,
        "status":           "active",
        "last_seen":        datetime.utcnow().isoformat(),
        # Fields required by upsert_endpoint — seeded with safe defaults
        # and updated by heartbeat once monitoring starts
        "cpu_usage":        0,
        "memory_usage":     0,
        "disk_usage":       0,
        "active_processes": 0,
        "threat_level":     "normal",
    })
    logger.info("Agent registered: %s (%s)", data.hostname, data.endpoint_id)
    await ws_manager.broadcast({"type": "agent_registered", "data": data.dict()})
    return {"status": "registered", "api_key": _master_key}

@app.post("/unregister", tags=["Agent"])
async def unregister_agent(data: dict):
    eid = data.get("endpoint_id","")
    try:
        await db._execute(
            "UPDATE endpoints SET status='inactive' WHERE endpoint_id=?", (eid,))
    except Exception:
        pass
    await ws_manager.broadcast({"type": "agent_disconnected", "endpoint_id": eid})
    return {"status": "unregistered"}

# ── Telemetry ─────────────────────────────────────────────────────────────────
@app.post("/api/telemetry", tags=["Telemetry"])
async def ingest_telemetry(data: TelemetryData, api_key: str=Depends(verify_api_key)):
    await db.store_telemetry(data.dict())
    for ev in data.events:
        if ml_engine.score_event(ev) > 0.9:
            await alert_handler.process_alert({
                "endpoint_id": data.endpoint_id,
                "alert_type":  "ml_anomaly", "severity": "high",
                "title":       "ML Anomaly Detected",
                "description": f"Unusual activity: {ev.get('type','unknown')}",
                "raw_data":    ev,
            })
    return {"status": "ingested", "count": len(data.events)}

# ── SIEM ──────────────────────────────────────────────────────────────────────
@app.get("/api/siem/correlations", tags=["SIEM"])
async def siem_correlations(limit: int=50, api_key: str=Depends(verify_api_key)):
    return {"correlations": await db.get_correlations(limit=limit)}

@app.get("/api/siem/timeline", tags=["SIEM"])
async def siem_timeline(hours: int=24, api_key: str=Depends(verify_api_key)):
    return {"timeline": await db.get_alert_timeline(hours=hours)}

# ── Threat Intel ──────────────────────────────────────────────────────────────
@app.get("/api/threat-intel", tags=["Threat Intelligence"])
async def threat_intel_summary(api_key: str=Depends(verify_api_key)):
    return await threat_intel.get_summary()

@app.post("/api/threat-intel/check-ip", tags=["Threat Intelligence"])
async def check_ip(data: dict, api_key: str=Depends(verify_api_key)):
    return {"match": await threat_intel.check_ip(data.get("ip"))}

# ── ML / AI ───────────────────────────────────────────────────────────────────
@app.get("/api/ml/predictions", tags=["AI/ML"])
async def ml_predictions(api_key: str=Depends(verify_api_key)):
    return {"predictions": await ai_predictor.get_latest_predictions()}

@app.get("/api/ml/model-stats", tags=["AI/ML"])
async def ml_stats(api_key: str=Depends(verify_api_key)):
    return ml_engine.get_stats()

# ── MITRE ─────────────────────────────────────────────────────────────────────
@app.get("/api/mitre/matrix", tags=["MITRE ATT&CK"])
async def mitre_matrix(api_key: str=Depends(verify_api_key)):
    return {"matrix": await db.get_mitre_coverage(),
            "techniques": mitre_mapper.get_all_techniques()}

# ── Policies ──────────────────────────────────────────────────────────────────
@app.get("/api/policies", tags=["Policies"])
async def get_policies(api_key: str=Depends(verify_api_key)):
    return {"policies": await db.get_all_policies()}

@app.post("/api/policies", tags=["Policies"])
async def create_policy(policy: PolicyUpdate, api_key: str=Depends(verify_api_key)):
    pid = await db.create_policy(policy.dict())
    await policy_engine.deploy_policy(pid, policy.endpoints)
    return {"status": "created", "policy_id": pid}

# ── Geo ───────────────────────────────────────────────────────────────────────
@app.get("/api/geo/attack-origins", tags=["Geo"])
async def geo_origins(api_key: str=Depends(verify_api_key)):
    return {"origins": await db.get_attack_geo_data()}


# ── IP Lookup Proxy (server-side, avoids CORS) ────────────────────────────────
@app.get("/api/ip-lookup/{ip}", tags=["Geo"])
async def ip_lookup(ip: str, api_key: str = Depends(verify_api_key)):
    """Server-side IP geolocation proxy. Primary: ip-api.com, fallback: ipwho.is"""
    ip = ip.strip()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,query,proxy,hosting,mobile,reverse,timezone"}
            )
            data = r.json()
            if data.get("status") == "success":
                return {"success": True, "source": "ip-api", "data": data}
    except Exception as e:
        logger.warning("ip-api lookup failed for %s: %s", ip, e)
    # Fallback: ipwho.is
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r2 = await client.get(f"https://ipwho.is/{ip}")
            raw = r2.json()
            if raw.get("success") is not False and raw.get("ip"):
                conn = raw.get("connection") or {}
                sec  = raw.get("security") or {}
                tz   = raw.get("timezone") or {}
                return {"success": True, "source": "ipwho", "data": {
                    "status": "success", "query": raw.get("ip", ip),
                    "country": raw.get("country", ""), "countryCode": raw.get("country_code", ""),
                    "regionName": raw.get("region", ""), "city": raw.get("city", ""),
                    "zip": raw.get("postal", ""), "lat": raw.get("latitude", 0), "lon": raw.get("longitude", 0),
                    "isp": conn.get("isp", ""), "org": conn.get("org", ""),
                    "as": f"AS{conn.get('asn','')} {conn.get('org','')}", 
                    "proxy": bool(sec.get("proxy") or sec.get("vpn") or sec.get("tor")),
                    "hosting": bool(sec.get("hosting")), "mobile": False,
                    "reverse": tz.get("id", ""), "timezone": tz.get("id", ""),
                }}
    except Exception as e2:
        logger.warning("ipwho fallback failed for %s: %s", ip, e2)
    return {"success": False, "error": f"Could not resolve IP: {ip}"}


# ── Per-Endpoint AI/ML Analysis ───────────────────────────────────────────────
@app.get("/api/endpoints/{endpoint_id}/ai-analysis", tags=["AI/ML"])
async def endpoint_ai_analysis(endpoint_id: str, api_key: str = Depends(verify_api_key)):
    alerts   = await db.get_alerts(endpoint_id=endpoint_id, limit=100)
    all_preds = await ai_predictor.get_latest_predictions()
    ep_preds  = [p for p in all_preds if endpoint_id in (p.get("affected_endpoints") or [])]
    if not ep_preds:
        ep_preds = all_preds[:3]
    recent_critical = [a for a in alerts if a.get("severity") in ("critical", "emergency", "high")]
    score = min(0.99, 0.25 + len(recent_critical) * 0.07)
    ml_alerts   = [a for a in alerts if a.get("alert_type") == "ml_anomaly"]
    techniques  = list({a.get("mitre_technique") for a in alerts if a.get("mitre_technique")})
    return {
        "endpoint_id":     endpoint_id,
        "anomaly_score":   round(score, 2),
        "risk_level":      "critical" if score > 0.85 else "high" if score > 0.65 else "medium" if score > 0.35 else "low",
        "predictions":     ep_preds,
        "ml_alerts":       ml_alerts[:10],
        "mitre_hits":      techniques,
        "total_alerts":    len(alerts),
        "critical_alerts": len([a for a in alerts if a.get("severity") in ("critical", "emergency")]),
        "models_active":   ["Isolation Forest", "Random Forest", "Behavioral Baseline"],
        "analyzed_at":     datetime.utcnow().isoformat(),
    }


# ── Per-Endpoint SIEM Events ──────────────────────────────────────────────────
@app.get("/api/endpoints/{endpoint_id}/siem-events", tags=["SIEM"])
async def endpoint_siem_events(endpoint_id: str, api_key: str = Depends(verify_api_key)):
    alerts   = await db.get_alerts(endpoint_id=endpoint_id, limit=100)
    all_corrs = await db.get_correlations(limit=100)
    ep_corrs  = [c for c in all_corrs if c.get("endpoint_id") == endpoint_id]
    RULE_MAP  = {
        "brute_force":          ("Brute Force Attack",      "critical"),
        "ransomware":           ("Ransomware Campaign",     "emergency"),
        "credential_dump":      ("Credential Dump",         "critical"),
        "usb_exfiltration":     ("Insider Threat / USB",   "high"),
        "process_injection":    ("Process Injection",       "high"),
        "privilege_escalation": ("Privilege Escalation",   "high"),
        "malicious_ip":         ("C2 / Malicious IP",      "high"),
        "ml_anomaly":           ("ML Anomaly Detected",    "medium"),
        "dll_injection":        ("DLL Injection",           "high"),
        "sensitive_file":       ("Sensitive File Access",  "medium"),
    }
    triggered, seen = [], set()
    for a in alerts:
        atype = a.get("alert_type", "")
        if atype in RULE_MAP and atype not in seen:
            seen.add(atype)
            rname, rsev = RULE_MAP[atype]
            triggered.append({"rule_name": rname, "severity": rsev,
                               "triggered_at": a.get("created_at", ""),
                               "description": a.get("description") or a.get("title") or rname})
    return {
        "endpoint_id":     endpoint_id,
        "correlations":    ep_corrs[:20],
        "triggered_rules": triggered,
        "event_log":       alerts[:30],
        "total_events":    len(alerts),
        "rules_triggered": len(triggered),
        "analyzed_at":     datetime.utcnow().isoformat(),
    }


# ── Per-Endpoint Threat Intelligence ─────────────────────────────────────────
@app.get("/api/endpoints/{endpoint_id}/threat-intel", tags=["Threat Intelligence"])
async def endpoint_threat_intel(endpoint_id: str, api_key: str = Depends(verify_api_key)):
    alerts = await db.get_alerts(endpoint_id=endpoint_id, limit=100)
    malicious_ips = list({a.get("network_ip") for a in alerts
                          if a.get("alert_type") == "malicious_ip" and a.get("network_ip")})
    suspicious_ips = list({a.get("network_ip") for a in alerts
                           if a.get("network_ip") and a.get("alert_type") != "malicious_ip"})
    iocs = []
    for a in alerts:
        if a.get("alert_type") in ("malicious_ip", "block_ip") and a.get("network_ip"):
            iocs.append({"type": "ip", "value": a["network_ip"],
                         "severity": a.get("severity", "medium"), "seen_at": a.get("created_at", "")})
        if a.get("file_path") and a.get("alert_type") in ("ransomware", "malware_hash", "quarantine"):
            iocs.append({"type": "file", "value": a["file_path"],
                         "severity": a.get("severity", "medium"), "seen_at": a.get("created_at", "")})
    global_ti = await threat_intel.get_summary()
    return {
        "endpoint_id":    endpoint_id,
        "malicious_ips":  malicious_ips[:20],
        "suspicious_ips": suspicious_ips[:20],
        "iocs":           iocs[:30],
        "global_feeds":   global_ti,
        "alert_count":    len(alerts),
        "analyzed_at":    datetime.utcnow().isoformat(),
    }

# ── Dashboard overview ────────────────────────────────────────────────────────
@app.get("/api/dashboard/overview", tags=["Dashboard"])
async def dashboard_overview(api_key: str=Depends(verify_api_key)):
    eps    = await db.get_all_endpoints()
    stats  = await db.get_alert_stats()
    preds  = await ai_predictor.get_latest_predictions()
    ti     = await threat_intel.get_summary()
    return {
        "active_endpoints":   len([e for e in eps if e.get("status")=="active"]),
        "total_endpoints":    len(eps),
        "critical_endpoints": len([e for e in eps if e.get("threat_level") in ["high","critical"]]),
        "alert_stats":        stats,
        "threat_intel":       ti,
        "top_predictions":    preds[:3] if preds else [],
        "timestamp":          datetime.utcnow().isoformat(),
    }

# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    await ws_manager.connect_dashboard(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await ws_manager.handle_dashboard_message(data, websocket)
    except WebSocketDisconnect:
        ws_manager.disconnect_dashboard(websocket)

@app.websocket("/ws/agent/{endpoint_id}")
async def ws_agent(websocket: WebSocket, endpoint_id: str):
    if websocket.query_params.get("api_key","") not in VALID_API_KEYS:
        await websocket.close(code=4001)
        return
    await ws_manager.connect_agent(endpoint_id, websocket)
    try:
        for cmd in await cq_dequeue(endpoint_id):
            try:
                await websocket.send_json({
                    "type": "command", "command_id": cmd["command_id"],
                    "command": cmd["command"], "parameters": cmd.get("parameters",{}),
                })
                _cmd_upsert(cmd["command_id"], status="delivered")
            except Exception:
                pass
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "command_result":
                cid = data.get("command_id","")
                if cid:
                    _cmd_upsert(cid,
                                status=data.get("status","executed"),
                                detail=data.get("detail",""),
                                command=data.get("command",""),
                                completed_at=datetime.utcnow().isoformat())
                    await cq_result(cid, data)
            await ws_manager.handle_agent_message(
                endpoint_id, data, alert_handler=alert_handler, db=db)
    except WebSocketDisconnect:
        ws_manager.disconnect_agent(endpoint_id)
    except Exception as e:
        ws_manager.disconnect_agent(endpoint_id)
        logger.error("Agent WS (%s): %s", endpoint_id, e)

@app.websocket("/ws")
async def ws_alias(websocket: WebSocket):
    await ws_dashboard(websocket)

# ── Entry point ───────────────────────────────────────────────────────────────
def _free_port(start=9001, end=9020):
    import socket
    for p in range(start, end):
        with socket.socket() as s:
            try:
                s.bind(("0.0.0.0", p)); return p
            except OSError:
                pass
    return start

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    port = args.port or _free_port()
    print(f"\n{'='*60}")
    print(f"  Malabar Sentinel SOC v2.0")
    print(f"  http://{args.host}:{port}  |  docs: /docs")
    print(f"{'='*60}\n")
    uvicorn.run("main:app", host=args.host, port=port,
                log_level="info", access_log=False)
