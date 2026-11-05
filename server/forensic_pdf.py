"""
forensic_pdf.py — Malabar Sentinel
=====================================
Generate professional PDF forensic reports for endpoint security timelines.

Uses ReportLab.  Install: pip install reportlab

Blocking / unblocking details are pulled from endpoint_timeline entries
of type 'block' — written there by the existing network_blocking pathway.
"""

from __future__ import annotations

import io
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("forensic-pdf")

# ── ReportLab imports (graceful fallback if not installed) ────────────────────
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
        TableStyle,
    )
    _REPORTLAB_OK = True
except ImportError:
    _REPORTLAB_OK = False
    logger.warning("reportlab not installed — PDF generation unavailable")


# ─────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE  (dark-SOC theme adapted for print)
# ─────────────────────────────────────────────────────────────────────────────

C_HEADER_BG   = colors.HexColor("#0b1e2d")   # dark navy
C_HEADER_TEXT = colors.HexColor("#00f5c4")   # teal accent
C_SUBHEAD_BG  = colors.HexColor("#0d2137")
C_TABLE_HDR   = colors.HexColor("#122b40")
C_TABLE_ALT   = colors.HexColor("#f0f6ff")
C_BORDER      = colors.HexColor("#1a3f5c")
C_CRITICAL    = colors.HexColor("#ff3860")
C_HIGH        = colors.HexColor("#ff8c42")
C_MEDIUM      = colors.HexColor("#ffd700")
C_LOW         = colors.HexColor("#3db8ff")
C_OK          = colors.HexColor("#00f5c4")
C_BODY_TEXT   = colors.HexColor("#0b1e2d")
C_LIGHT_GREY  = colors.HexColor("#e8f0f7")
C_WHITE       = colors.white
C_BLACK       = colors.HexColor("#0b1e2d")


# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY → colour map
# ─────────────────────────────────────────────────────────────────────────────

_SEV_COLOR = {
    "critical": C_CRITICAL,
    "high":     C_HIGH,
    "medium":   C_MEDIUM,
    "low":      C_LOW,
    "info":     C_OK,
}

_STATUS_COLOR = {
    "CRITICAL": C_CRITICAL,
    "WARNING":  C_HIGH,
    "SECURE":   C_OK,
}

_RECOMMENDATIONS = {
    "CRITICAL": [
        "Immediately isolate the endpoint from the network.",
        "Run a full forensic memory dump before remediation.",
        "Escalate to Tier-2 SOC analysts for incident response.",
        "Rotate all credentials that may have been accessible on this host.",
        "Review all lateral-movement indicators on adjacent hosts.",
    ],
    "WARNING": [
        "Schedule a Full Scan during the next maintenance window.",
        "Update antivirus signatures to the latest build.",
        "Review quarantine folder and confirm disposition of flagged files.",
        "Verify endpoint isolation policies are up-to-date.",
        "Investigate suspicious processes flagged in the timeline.",
    ],
    "SECURE": [
        "Continue scheduled Quick Scans every 24 hours.",
        "Maintain current signature update cadence (daily recommended).",
        "Monitor USB activity logs for anomalous insertions.",
        "Ensure agent auto-update is enabled.",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# MAIN GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_timeline_pdf(
    endpoint_info:  Dict[str, Any],
    scan_stats:     Dict[str, Any],
    timeline_events: List[Dict[str, Any]],
    threats:        List[Dict[str, Any]],
    security_status: str = "SECURE",
) -> bytes:
    """
    Build a PDF forensic report and return the raw bytes.

    Parameters
    ----------
    endpoint_info   : {endpoint_id, hostname, ip_address, os, agent_version}
    scan_stats      : {total_scans, threats_found, sandbox_analyses, isolation_events, last_scan}
    timeline_events : list of endpoint_timeline rows (dicts)
    threats         : list of threat_details rows (dicts)
    security_status : "SECURE" | "WARNING" | "CRITICAL"

    Returns
    -------
    bytes — PDF document ready to stream.
    """
    if not _REPORTLAB_OK:
        raise RuntimeError(
            "reportlab is not installed. Run: pip install reportlab"
        )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=1.8 * cm,
        leftMargin=1.8 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title=f"Malabar Sentinel — Endpoint Report {endpoint_info.get('endpoint_id','?')}",
        author="Malabar Sentinel EPMS",
    )

    styles = _build_styles()
    story  = []

    # ── 1. Header banner ─────────────────────────────────────────────────────
    _add_header(story, styles, endpoint_info)

    # ── 2. Endpoint information table ────────────────────────────────────────
    story.append(Paragraph("Endpoint Information", styles["section"]))
    story.append(_endpoint_info_table(endpoint_info, styles))
    story.append(Spacer(1, 8 * mm))

    # ── 3. Scan summary KPI row ───────────────────────────────────────────────
    story.append(Paragraph("Scan Summary", styles["section"]))
    story.append(_scan_summary_table(scan_stats, styles))
    story.append(Spacer(1, 8 * mm))

    # ── 4. Threat analysis table ──────────────────────────────────────────────
    if threats:
        story.append(Paragraph("Threat Analysis", styles["section"]))
        story.append(_threats_table(threats, styles))
        story.append(Spacer(1, 8 * mm))

    # ── 5. Complete security timeline ────────────────────────────────────────
    story.append(Paragraph("Complete Security Timeline", styles["section"]))
    if timeline_events:
        story.append(_timeline_table(timeline_events, styles))
    else:
        story.append(Paragraph("No timeline events recorded.", styles["body"]))
    story.append(Spacer(1, 8 * mm))

    # ── 6. Security recommendations ──────────────────────────────────────────
    story.append(Paragraph("Security Recommendations", styles["section"]))
    recs = _RECOMMENDATIONS.get(security_status, _RECOMMENDATIONS["SECURE"])
    for i, rec in enumerate(recs, 1):
        story.append(Paragraph(f"  {i}.  {rec}", styles["rec"]))
    story.append(Spacer(1, 10 * mm))

    # ── 7. Final verdict ─────────────────────────────────────────────────────
    story.append(_verdict_banner(security_status, styles))

    # ── 8. Footer note ────────────────────────────────────────────────────────
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=C_BORDER, spaceAfter=4 * mm))
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(
        f"Report generated by Malabar Sentinel EPMS  ·  {ts}  ·  CONFIDENTIAL",
        styles["footer"],
    ))

    doc.build(story, onFirstPage=_page_frame, onLaterPages=_page_frame)
    buf.seek(0)
    return buf.read()


# ─────────────────────────────────────────────────────────────────────────────
# STYLE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _build_styles() -> dict:
    base = getSampleStyleSheet()
    def _ps(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    return {
        "title":   _ps("ms-title",   fontSize=22, textColor=C_HEADER_TEXT,
                        spaceAfter=4, fontName="Helvetica-Bold", alignment=TA_CENTER),
        "subtitle":_ps("ms-sub",     fontSize=9,  textColor=C_LIGHT_GREY,
                        spaceAfter=2, alignment=TA_CENTER),
        "section": _ps("ms-sec",     fontSize=11, textColor=C_HEADER_TEXT,
                        fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=3,
                        borderPadding=(0,0,2,0)),
        "body":    _ps("ms-body",    fontSize=8,  textColor=C_BODY_TEXT, spaceAfter=2),
        "th":      _ps("ms-th",      fontSize=7.5, textColor=C_WHITE,
                        fontName="Helvetica-Bold", alignment=TA_LEFT),
        "td":      _ps("ms-td",      fontSize=7.5, textColor=C_BODY_TEXT),
        "rec":     _ps("ms-rec",     fontSize=8,  textColor=C_BODY_TEXT,
                        leftIndent=10, spaceAfter=3),
        "verdict": _ps("ms-verd",    fontSize=28, fontName="Helvetica-Bold",
                        alignment=TA_CENTER),
        "footer":  _ps("ms-foot",    fontSize=7,  textColor=colors.HexColor("#6a9bc3"),
                        alignment=TA_CENTER),
    }


def _page_frame(canvas, doc):
    """Minimal page border drawn on every page."""
    canvas.saveState()
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.rect(10 * mm, 10 * mm,
                A4[0] - 20 * mm, A4[1] - 20 * mm,
                stroke=1, fill=0)
    canvas.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
# SECTION BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def _add_header(story, styles, endpoint_info):
    ep_id = endpoint_info.get("endpoint_id", "UNKNOWN")

    # Dark banner table
    banner_data = [[
        Paragraph("MALABAR SENTINEL", styles["title"]),
    ], [
        Paragraph("Endpoint Security Timeline &amp; Forensic Report", styles["subtitle"]),
    ], [
        Paragraph(f"Endpoint: {ep_id}", styles["subtitle"]),
    ]]
    tbl = Table(banner_data, colWidths=["100%"])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_HEADER_BG),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_HEADER_BG]),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 6 * mm))


def _endpoint_info_table(endpoint_info, styles):
    rows = [
        ["Endpoint ID",    endpoint_info.get("endpoint_id", "—")],
        ["Hostname",       endpoint_info.get("hostname", "—")],
        ["IP Address",     endpoint_info.get("ip_address", "—")],
        ["Operating System", endpoint_info.get("os", "—")],
        ["Agent Version",  endpoint_info.get("agent_version", "—")],
        ["Generated",      datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
    ]
    tbl = Table(
        [[Paragraph(r[0], styles["th"]), Paragraph(str(r[1]), styles["td"])]
         for r in rows],
        colWidths=[5 * cm, None],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, -1), C_TABLE_HDR),
        ("ROWBACKGROUNDS",(0, 0), (-1,-1), [C_WHITE, C_LIGHT_GREY]),
        ("GRID",          (0, 0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1,-1), 4),
        ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
        ("LEFTPADDING",   (0, 0), (-1,-1), 6),
    ]))
    return tbl


def _scan_summary_table(stats, styles):
    kpis = [
        ("Total Scans",       stats.get("total_scans", 0),       C_OK),
        ("Threats Found",     stats.get("threats_found", 0),     C_HIGH if stats.get("threats_found",0) else C_OK),
        ("Sandbox Analyses",  stats.get("sandbox_analyses", 0),  C_LOW),
        ("Isolation Events",  stats.get("isolation_events", 0),  C_CRITICAL if stats.get("isolation_events",0) else C_OK),
    ]
    cells = []
    for label, val, col in kpis:
        inner = Table([
            [Paragraph(str(val), ParagraphStyle(
                "kpi-v", parent=getSampleStyleSheet()["Normal"],
                fontSize=22, textColor=col, fontName="Helvetica-Bold",
                alignment=TA_CENTER,
            ))],
            [Paragraph(label, ParagraphStyle(
                "kpi-l", parent=getSampleStyleSheet()["Normal"],
                fontSize=7, textColor=colors.HexColor("#4a7a9b"),
                alignment=TA_CENTER,
            ))],
        ], colWidths=["100%"])
        inner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_SUBHEAD_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, col),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        cells.append(inner)

    tbl = Table([cells], colWidths=[None]*len(kpis))
    tbl.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1,-1), 4),
        ("RIGHTPADDING",  (0, 0), (-1,-1), 4),
        ("VALIGN",        (0, 0), (-1,-1), "MIDDLE"),
    ]))
    return tbl


def _threats_table(threats, styles):
    headers = ["File Path", "Threat Name", "Severity", "Action Taken", "Detected At"]
    data = [[Paragraph(h, styles["th"]) for h in headers]]
    for t in threats:
        sev = (t.get("severity") or "medium").lower()
        sev_color = _SEV_COLOR.get(sev, C_MEDIUM)
        data.append([
            Paragraph(_truncate(t.get("file_path", "—"), 45), styles["td"]),
            Paragraph(t.get("threat_name", "—"), styles["td"]),
            Paragraph(
                sev.upper(),
                ParagraphStyle("sev", parent=getSampleStyleSheet()["Normal"],
                               fontSize=7.5, textColor=sev_color,
                               fontName="Helvetica-Bold"),
            ),
            Paragraph(t.get("action_taken", "logged"), styles["td"]),
            Paragraph(_fmt_ts(t.get("detected_at")), styles["td"]),
        ])

    col_w = [6.5*cm, 4*cm, 1.8*cm, 2.5*cm, 3*cm]
    tbl = Table(data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HDR),
        ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_WHITE, C_LIGHT_GREY]),
        ("GRID",          (0, 0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1,-1), 3),
        ("BOTTOMPADDING", (0, 0), (-1,-1), 3),
        ("LEFTPADDING",   (0, 0), (-1,-1), 5),
        ("VALIGN",        (0, 0), (-1,-1), "MIDDLE"),
    ]))
    return tbl


def _timeline_table(events, styles):
    headers = ["Time", "Type", "Message", "Severity"]
    data = [[Paragraph(h, styles["th"]) for h in headers]]

    for ev in reversed(events):        # chronological order in PDF
        sev = (ev.get("severity") or "info").lower()
        sev_color = _SEV_COLOR.get(sev, C_OK)
        icon = ev.get("icon", "📌")
        etype = ev.get("event_type", "system")
        data.append([
            Paragraph(_fmt_ts(ev.get("created_at")), styles["td"]),
            Paragraph(f"{icon} {etype}", styles["td"]),
            Paragraph(_truncate(ev.get("event_message", ""), 70), styles["td"]),
            Paragraph(
                sev.upper(),
                ParagraphStyle("tl-sev", parent=getSampleStyleSheet()["Normal"],
                               fontSize=7, textColor=sev_color,
                               fontName="Helvetica-Bold"),
            ),
        ])

    col_w = [3.2*cm, 2.4*cm, None, 1.8*cm]
    tbl = Table(data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HDR),
        ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_WHITE, C_LIGHT_GREY]),
        ("GRID",          (0, 0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1,-1), 3),
        ("BOTTOMPADDING", (0, 0), (-1,-1), 3),
        ("LEFTPADDING",   (0, 0), (-1,-1), 5),
        ("VALIGN",        (0, 0), (-1,-1), "MIDDLE"),
        ("FONTSIZE",      (0, 0), (-1,-1), 7.5),
    ]))
    return tbl


def _verdict_banner(status: str, styles) -> Table:
    color = _STATUS_COLOR.get(status, C_OK)
    banner_data = [[
        Paragraph("FINAL SECURITY STATUS", ParagraphStyle(
            "vs-label", parent=getSampleStyleSheet()["Normal"],
            fontSize=9, textColor=C_LIGHT_GREY, alignment=TA_CENTER,
        )),
    ], [
        Paragraph(status, ParagraphStyle(
            "vs-val", parent=getSampleStyleSheet()["Normal"],
            fontSize=30, textColor=color, fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        )),
    ]]
    tbl = Table(banner_data, colWidths=["100%"])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1,-1), C_HEADER_BG),
        ("BOX",           (0, 0), (-1,-1), 1.5, color),
        ("TOPPADDING",    (0, 0), (-1,-1), 10),
        ("BOTTOMPADDING", (0, 0), (-1,-1), 10),
    ]))
    return tbl


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY
# ─────────────────────────────────────────────────────────────────────────────

def _truncate(s: str, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def _fmt_ts(ts: Optional[str]) -> str:
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)[:19]
