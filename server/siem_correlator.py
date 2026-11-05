"""
SIEM Correlation Engine
Correlates events from multiple sources to detect complex attack patterns
"""

import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger("siem-correlator")


class CorrelationRule:
    def __init__(self, name: str, description: str, severity: str, time_window: int, conditions: list):
        self.name = name
        self.description = description
        self.severity = severity
        self.time_window = time_window  # seconds
        self.conditions = conditions


CORRELATION_RULES = [
    CorrelationRule(
        name="Brute Force Attack",
        description="Multiple failed logins followed by suspicious process execution",
        severity="critical",
        time_window=300,
        conditions=[
            {"type": "login_failure", "count": 5},
            {"type": "process_execution", "count": 1}
        ]
    ),
    CorrelationRule(
        name="Credential Dump + Lateral Movement",
        description="Credential access followed by remote connection attempts",
        severity="critical",
        time_window=600,
        conditions=[
            {"alert_type": "credential_dump"},
            {"alert_type": "lateral_movement"}
        ]
    ),
    CorrelationRule(
        name="Ransomware Campaign",
        description="Mass file modification + process creation + network activity",
        severity="emergency",
        time_window=120,
        conditions=[
            {"alert_type": "ransomware"},
            {"alert_type": "process_execution"},
            {"alert_type": "network_exfiltration"}
        ]
    ),
    CorrelationRule(
        name="Insider Threat - Data Exfiltration",
        description="Sensitive file access followed by USB insertion and file copy",
        severity="critical",
        time_window=600,
        conditions=[
            {"alert_type": "sensitive_file"},
            {"alert_type": "usb_exfiltration"}
        ]
    ),
    CorrelationRule(
        name="APT Reconnaissance",
        description="Network scan + system discovery + file discovery in sequence",
        severity="high",
        time_window=900,
        conditions=[
            {"alert_type": "network_scan"},
            {"alert_type": "process_discovery"},
            {"alert_type": "file_discovery"}
        ]
    ),
    CorrelationRule(
        name="Living off the Land Attack",
        description="Legitimate tools used for malicious purposes: PowerShell + scheduled task",
        severity="high",
        time_window=300,
        conditions=[
            {"alert_type": "powershell"},
            {"alert_type": "scheduled_task"}
        ]
    ),
    CorrelationRule(
        name="Process Injection Attack",
        description="Process injection followed by network connection to malicious IP",
        severity="critical",
        time_window=180,
        conditions=[
            {"alert_type": "process_injection"},
            {"alert_type": "malicious_ip"}
        ]
    ),
    CorrelationRule(
        name="Privilege Escalation Chain",
        description="UAC bypass followed by credential dumping",
        severity="critical",
        time_window=300,
        conditions=[
            {"alert_type": "uac_bypass"},
            {"alert_type": "credential_dump"}
        ]
    ),
]


class SIEMCorrelator:
    def __init__(self, db, alert_handler):
        self.db = db
        self.alert_handler = alert_handler
        self.rules = CORRELATION_RULES
        # Per-endpoint event buffer: endpoint_id -> deque of recent events
        self.event_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._running = False

    async def add_event(self, event: dict):
        """Add event to buffer for correlation"""
        endpoint_id = event.get("endpoint_id", "unknown")
        event["_ts"] = datetime.utcnow().timestamp()
        self.event_buffer[endpoint_id].append(event)

    async def run_correlation_loop(self):
        """Continuous correlation loop"""
        self._running = True
        logger.info("SIEM Correlator started")
        while self._running:
            try:
                await self._correlate_all()
            except Exception as e:
                logger.error(f"Correlation error: {e}")
            await asyncio.sleep(30)  # Run every 30 seconds

    async def _correlate_all(self):
        """Run all rules against all endpoints"""
        for endpoint_id, events in self.event_buffer.items():
            events_list = list(events)
            for rule in self.rules:
                await self._apply_rule(endpoint_id, events_list, rule)

    async def _apply_rule(self, endpoint_id: str, events: List[dict], rule: CorrelationRule):
        """Apply a single correlation rule"""
        now = datetime.utcnow().timestamp()
        window_start = now - rule.time_window
        recent_events = [e for e in events if e.get("_ts", 0) >= window_start]

        matched_events = []
        for condition in rule.conditions:
            matched = self._find_matching_event(recent_events, condition)
            if matched:
                matched_events.append(matched)
            else:
                return  # Rule not satisfied

        # All conditions matched - generate correlation alert
        alert_ids = [e.get("alert_id") for e in matched_events if e.get("alert_id")]
        if alert_ids:
            # Check if we already correlated this recently (dedup)
            existing = await self.db.get_correlations(limit=10)
            for corr in existing:
                if corr.get("rule_name") == rule.name and corr.get("endpoint_id") == endpoint_id:
                    # Check if it was created in the last time_window seconds
                    try:
                        corr_time = datetime.fromisoformat(corr.get("created_at", ""))
                        if (datetime.utcnow() - corr_time).seconds < rule.time_window:
                            return  # Skip duplicate
                    except Exception:
                        pass

        corr_id = await self.db.store_correlation(
            rule.name, rule.description, alert_ids, rule.severity
        )
        logger.warning(
            f"SIEM CORRELATION [{rule.severity.upper()}]: {rule.name} on {endpoint_id}"
        )

        # Emit alert for the correlation
        await self.alert_handler.process_alert({
            "endpoint_id": endpoint_id,
            "hostname": matched_events[0].get("hostname", "unknown") if matched_events else "unknown",
            "alert_type": "siem_correlation",
            "severity": rule.severity,
            "title": f"SIEM Correlation: {rule.name}",
            "description": rule.description,
            "raw_data": {"correlation_id": corr_id, "matched_rules": len(matched_events)}
        })

    def _find_matching_event(self, events: List[dict], condition: dict) -> Optional[dict]:
        """Find an event matching the condition"""
        for event in events:
            match = True
            if "alert_type" in condition and event.get("alert_type") != condition["alert_type"]:
                match = False
            if "type" in condition and event.get("type") != condition["type"]:
                match = False
            if match:
                return event
        return None

    def get_rule_count(self) -> int:
        return len(self.rules)
