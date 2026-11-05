"""
scan_routes.py — Malabar Sentinel
====================================
FastAPI route handlers for:
  - Remote antivirus scan control  (start / stop)
  - Scan progress polling
  - Scan reports & threat details
  - Endpoint security timeline (with filtering)
  - PDF forensic report download
  - Sandbox integration hook (writes timeline + triggers block via existing
    network_blocking pathway — no new blocking logic added here)

INTEGRATION NOTE — IP/URL blocking
-----------------------------------
This module does NOT re-implement any firewall or hosts-file logic.
When a threat is detected and an analyst wants to block the associated IP
or URL, the dashboard calls the existing  issueCommand(epId,'block_ip',…)
/ issueCommand(epId,'block_url',…)  flow, which routes through the
command-queue  →  agent_core.py  →  network_blocking.IPBlocker /
URLBlocker  chain — exactly as the Blocklist Manager does today.

The only new thing here is writing timeline entries of type 'block' when
those commands are issued (hooked from /command-response).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger("scan-routes")

router = APIRouter(prefix="/api/scan", tags=["Scanning"])

# ── These are set by attach_scan_routes() called from main.py ────────────────
_db              = None
_issue_command   = None   # async (_issue_command from main.py)
_verify_api_key  = None


def attach_scan_routes(db, issue_command_fn, verify_api_key_fn):
    """
    Called once at startup from main.py to inject dependencies.

    db               — Database instance
    issue_command_fn — the existing _issue_command(endpoint_id, cmd, params)
    verify_api_key_fn— the existing Depends-compatible auth function
    """
    global _db, _issue_command, _verify_api_key
    _db             = db
    _issue_command  = issue_command_fn
    _verify_api_key = verify_api_key_fn
    logger.info("[scan_routes] attached to app")


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE MODELS
# ─────────────────────────────────────────────────────────────────────────────

class StartScanRequest(BaseModel):
    endpoint_id:  str
    scan_type:    str          # quick | full | custom
    folder_path:  Optional[str] = None


class StopScanRequest(BaseModel):
    endpoint_id: str


class TimelineEventRequest(BaseModel):
    endpoint_id:  str
    event_type:   str
    event_message: str
    severity:     str = "info"


# ─────────────────────────────────────────────────────────────────────────────
# SCAN CONTROL
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/start")
async def start_scan(req: StartScanRequest, api_key: str = Depends(_verify_api_key)):
    """
    Trigger a remote antivirus scan on an endpoint.

    Flow:
      1. Create scan_report row (status = running).
      2. Log timeline entry.
      3. Issue 'start_scan' command via existing command-queue.
      4. Return scan_id so the dashboard can poll progress.
    """
    from scan_manager import create_scan, log_event

    if req.scan_type not in ("quick", "full", "custom"):
        raise HTTPException(400, "scan_type must be quick | full | custom")
    if req.scan_type == "custom" and not req.folder_path:
        raise HTTPException(400, "folder_path required for custom scan")

    scan_id = await create_scan(_db, req.endpoint_id, req.scan_type, req.folder_path)

    await log_event(
        _db, req.endpoint_id, "scan",
        f"{req.scan_type.capitalize()} Scan Started (id={scan_id[:8]})",
        severity="info",
    )

    params = {
        "scan_id":     scan_id,
        "scan_type":   req.scan_type,
        "folder_path": req.folder_path or "",
    }
    cmd_result = await _issue_command(req.endpoint_id, "start_scan", params)
    return {"scan_id": scan_id, "command": cmd_result}


@router.post("/stop")
async def stop_scan(req: StopScanRequest, api_key: str = Depends(_verify_api_key)):
    """Cancel the currently running scan on an endpoint."""
    from scan_manager import get_active_scan, update_scan, log_event

    active = await get_active_scan(_db, req.endpoint_id)
    if not active:
        return {"status": "no_active_scan"}

    await update_scan(_db, active["id"], status="stopped",
                      completed_at=datetime.utcnow().isoformat())
    await log_event(_db, req.endpoint_id, "scan",
                    "Scan Stopped by administrator", severity="info")

    cmd_result = await _issue_command(req.endpoint_id, "stop_scan", {})
    return {"status": "stop_issued", "command": cmd_result}


# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS & REPORTS
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/progress/{endpoint_id}")
async def get_scan_progress(endpoint_id: str, api_key: str = Depends(_verify_api_key)):
    """
    Return current scan progress for live dashboard bar.
    The actual numbers are pushed back by the agent via /api/scan/report/update.
    This endpoint returns whatever is currently stored.
    """
    from scan_manager import get_active_scan
    scan = await get_active_scan(_db, endpoint_id)
    if not scan:
        return {"running": False}
    return {
        "running":       True,
        "scan_id":       scan["id"],
        "scan_type":     scan["scan_type"],
        "files_scanned": scan["files_scanned"],
        "threats_found": scan["threats_found"],
        "started_at":    scan["started_at"],
        "status":        scan["status"],
    }


@router.post("/report/update")
async def update_scan_progress(data: dict, api_key: str = Depends(_verify_api_key)):
    """
    Called by the agent to push progress updates mid-scan.
    Payload: {scan_id, files_scanned, threats_found, status?, completed_at?}
    """
    from scan_manager import update_scan, add_threat, log_event

    scan_id = data.get("scan_id")
    if not scan_id:
        raise HTTPException(400, "scan_id required")

    kwargs = {}
    for field in ("files_scanned", "threats_found", "status", "completed_at", "duration"):
        if field in data:
            kwargs[field] = data[field]
    if kwargs:
        await update_scan(_db, scan_id, **kwargs)

    # ── Ingest newly detected threats ────────────────────────────────────────
    for threat in data.get("new_threats", []):
        endpoint_id = data.get("endpoint_id", "")
        tid = await add_threat(
            _db, scan_id, endpoint_id,
            file_path=threat.get("file_path", ""),
            threat_name=threat.get("threat_name", "Unknown"),
            severity=threat.get("severity", "medium"),
            action_taken=threat.get("action_taken", "logged"),
        )
        await log_event(
            _db, endpoint_id, "threat",
            f"Threat Detected: {threat.get('threat_name','?')} "
            f"→ {threat.get('file_path','?')}",
            severity=threat.get("severity", "medium"),
        )

        # If the action was quarantine, log that too
        if threat.get("action_taken") == "quarantined":
            await log_event(
                _db, endpoint_id, "quarantine",
                f"File Quarantined: {threat.get('file_path','?')}",
                severity="high",
            )

    # ── Scan completed ────────────────────────────────────────────────────────
    if data.get("status") in ("completed", "stopped"):
        ep_id = data.get("endpoint_id", "")
        msg = (f"Scan Completed — "
               f"{data.get('files_scanned',0)} files, "
               f"{data.get('threats_found',0)} threats")
        await log_event(_db, ep_id, "scan", msg, severity="info")

    return {"status": "ok"}


@router.get("/report/{endpoint_id}")
async def get_scan_report(endpoint_id: str,
                          scan_id: Optional[str] = Query(None),
                          api_key: str = Depends(_verify_api_key)):
    """
    Return the latest (or specified) scan report + its threat details.
    """
    from scan_manager import get_scans_for_endpoint, get_threats_for_scan, get_active_scan

    if scan_id:
        from scan_manager import get_scan
        scan = await get_scan(_db, scan_id)
    else:
        active = await get_active_scan(_db, endpoint_id)
        if active:
            scan = active
        else:
            scans = await get_scans_for_endpoint(_db, endpoint_id, limit=1)
            scan = scans[0] if scans else None

    if not scan:
        return {"scan": None, "threats": []}

    threats = await get_threats_for_scan(_db, scan["id"])
    return {"scan": scan, "threats": threats}


@router.get("/history/{endpoint_id}")
async def get_scan_history(endpoint_id: str, limit: int = 20, api_key: str = Depends(_verify_api_key)):
    """Return paginated historical scan list for the endpoint page table."""
    from scan_manager import get_scans_for_endpoint
    scans = await get_scans_for_endpoint(_db, endpoint_id, limit)
    return {"scans": scans, "count": len(scans)}


# ─────────────────────────────────────────────────────────────────────────────
# TIMELINE
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/timeline/{endpoint_id}")
async def get_endpoint_timeline(
    endpoint_id: str,
    filter: Optional[str] = Query(None, description="all|scan|threat|quarantine|sandbox|usb|system|response|block"),
    limit: int = 200,
    api_key: str = Depends(_verify_api_key),
):
    """Fetch the forensic event timeline for an endpoint."""
    from scan_manager import get_timeline
    events = await get_timeline(_db, endpoint_id,
                                event_type_filter=filter, limit=limit)
    return {"endpoint_id": endpoint_id, "events": events, "count": len(events)}


@router.post("/timeline/event")
async def post_timeline_event(req: TimelineEventRequest, api_key: str = Depends(_verify_api_key)):
    """
    External hook: write a custom timeline entry.
    Used by sandbox webhook, USB monitor hook, etc.
    """
    from scan_manager import log_event
    eid = await log_event(_db, req.endpoint_id, req.event_type,
                          req.event_message, req.severity)
    return {"id": eid}


# ─────────────────────────────────────────────────────────────────────────────
# PDF FORENSIC REPORT DOWNLOAD
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/download/timeline/{endpoint_id}")
async def download_timeline_pdf(endpoint_id: str, api_key: str = Depends(_verify_api_key)):
    """
    Generate and stream a PDF forensic report for the endpoint.

    Filename: Endpoint_Timeline_<endpoint_id>.pdf
    """
    from scan_manager import (
        get_timeline, get_threats_for_endpoint,
        get_endpoint_scan_stats, get_endpoint_security_status,
    )
    from forensic_pdf import generate_timeline_pdf

    # ── Gather data ──────────────────────────────────────────────────────────
    # Endpoint info from the endpoints table
    ep_row = await _db._fetchone(
        "SELECT * FROM endpoints WHERE endpoint_id=?", (endpoint_id,)
    )
    endpoint_info = {
        "endpoint_id":  endpoint_id,
        "hostname":     ep_row["hostname"]     if ep_row else "Unknown",
        "ip_address":   ep_row["ip_address"]   if ep_row else "—",
        "os":           ep_row["os"]           if ep_row else "—",
        "agent_version": ep_row.get("agent_version", "—") if ep_row else "—",
    }

    scan_stats      = await get_endpoint_scan_stats(_db, endpoint_id)
    timeline_events = await get_timeline(_db, endpoint_id, limit=500)
    threats         = await get_threats_for_endpoint(_db, endpoint_id, limit=200)
    security_status = await get_endpoint_security_status(_db, endpoint_id)

    # ── Generate PDF ─────────────────────────────────────────────────────────
    try:
        pdf_bytes = generate_timeline_pdf(
            endpoint_info=endpoint_info,
            scan_stats=scan_stats,
            timeline_events=timeline_events,
            threats=threats,
            security_status=security_status,
        )
    except RuntimeError as e:
        raise HTTPException(503, detail=str(e))

    filename = f"Endpoint_Timeline_{endpoint_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/download/report/{endpoint_id}")
async def download_scan_report_pdf(endpoint_id: str,
                                   scan_id: Optional[str] = Query(None),
                                   api_key: str = Depends(_verify_api_key)):
    """
    Generate a PDF for a single scan report (latest or specified).
    Useful for per-scan forensic evidence bundles.
    """
    from scan_manager import (
        get_scan, get_scans_for_endpoint, get_threats_for_scan,
        get_endpoint_security_status,
    )
    from forensic_pdf import generate_timeline_pdf

    if scan_id:
        scan = await get_scan(_db, scan_id)
    else:
        scans = await get_scans_for_endpoint(_db, endpoint_id, limit=1)
        scan  = scans[0] if scans else None

    if not scan:
        raise HTTPException(404, "No scan report found for this endpoint")

    threats = await get_threats_for_scan(_db, scan["id"])

    ep_row = await _db._fetchone(
        "SELECT * FROM endpoints WHERE endpoint_id=?", (endpoint_id,)
    )
    endpoint_info = {
        "endpoint_id": endpoint_id,
        "hostname":    ep_row["hostname"]  if ep_row else "Unknown",
        "ip_address":  ep_row["ip_address"] if ep_row else "—",
        "os":          ep_row["os"]         if ep_row else "—",
        "agent_version": "—",
    }

    # Build minimal timeline from scan events only
    from scan_manager import get_timeline
    timeline = await get_timeline(_db, endpoint_id, event_type_filter="scan", limit=50)

    pdf_bytes = generate_timeline_pdf(
        endpoint_info=endpoint_info,
        scan_stats={
            "total_scans":      1,
            "threats_found":    scan["threats_found"],
            "sandbox_analyses": 0,
            "isolation_events": 0,
            "last_scan":        scan.get("completed_at"),
        },
        timeline_events=timeline,
        threats=threats,
        security_status=await get_endpoint_security_status(_db, endpoint_id),
    )

    filename = f"ScanReport_{scan['id'][:8]}_{endpoint_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─────────────────────────────────────────────────────────────────────────────
# SANDBOX INTEGRATION HOOK
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/sandbox/result")
async def sandbox_result(data: dict, api_key: str = Depends(_verify_api_key)):
    """
    Called by the sandbox service when analysis completes.

    Payload:
        endpoint_id  : str
        file_path    : str
        verdict      : "malware" | "clean" | "suspicious"
        threat_name  : str (if malware)
        severity     : str
        block_ip     : str | null   — if set, block this IP via existing pathway
        block_url    : str | null   — if set, block this URL via existing pathway

    Blocking is handled by issuing block_ip / block_url commands through
    the standard command-queue → network_blocking.py pathway — NOT by
    calling network_blocking directly from the server.
    """
    from scan_manager import log_event, add_threat

    ep_id     = data.get("endpoint_id", "")
    verdict   = (data.get("verdict") or "clean").lower()
    file_path = data.get("file_path", "")
    threat    = data.get("threat_name", "Unknown")
    severity  = data.get("severity", "high")

    # ── Log sandbox completion ───────────────────────────────────────────────
    await log_event(_db, ep_id, "sandbox",
                    f"Sandbox Analysis Completed — verdict: {verdict.upper()}",
                    severity="info")

    if verdict == "malware":
        await log_event(_db, ep_id, "malware",
                        f"Malware Confirmed: {threat} → {file_path}",
                        severity=severity)

        # ── Automatic threat block via existing network_blocking pathway ──────
        # We issue the standard block_ip / block_url commands.
        # These go through: command-queue → agent_core → IPBlocker/URLBlocker
        # (network_blocking.py) — exactly how the Blocklist Manager works.

        if data.get("block_ip"):
            ip = data["block_ip"]
            await log_event(_db, ep_id, "block",
                            f"Auto-Block IP: {ip} (sandbox verdict: malware)",
                            severity="high")
            await _issue_command(ep_id, "block_ip", {"ip": ip})

        if data.get("block_url"):
            url = data["block_url"]
            await log_event(_db, ep_id, "block",
                            f"Auto-Block URL: {url} (sandbox verdict: malware)",
                            severity="high")
            await _issue_command(ep_id, "block_url", {"url": url})

    return {"status": "logged", "verdict": verdict}
