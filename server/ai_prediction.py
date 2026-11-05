"""
AI Attack Prediction Engine
Analyzes historical alert patterns to predict likely future attacks
"""

import asyncio
import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List

logger = logging.getLogger("ai-predictor")


ATTACK_CHAINS = [
    {
        "name": "Ransomware Attack",
        "indicators": ["process_execution", "network_scan", "privilege_escalation", "credential_dump"],
        "prediction": "Ransomware deployment likely within 2-4 hours",
        "confidence": 0.87,
        "severity": "emergency",
        "mitre": "T1486"
    },
    {
        "name": "APT Intrusion",
        "indicators": ["network_scan", "process_discovery", "lateral_movement", "credential_dump"],
        "prediction": "Advanced Persistent Threat - data exfiltration imminent",
        "confidence": 0.82,
        "severity": "critical",
        "mitre": "T1041"
    },
    {
        "name": "Insider Threat",
        "indicators": ["sensitive_file", "usb_insertion", "usb_exfiltration"],
        "prediction": "Insider threat data exfiltration in progress",
        "confidence": 0.91,
        "severity": "critical",
        "mitre": "T1052.001"
    },
    {
        "name": "Brute Force → Compromise",
        "indicators": ["brute_force", "login_failure"],
        "prediction": "Account compromise attempt - lockout recommended",
        "confidence": 0.78,
        "severity": "high",
        "mitre": "T1110"
    },
    {
        "name": "Supply Chain Attack",
        "indicators": ["malware_hash", "process_injection", "dll_injection"],
        "prediction": "Supply chain compromise detected - isolate endpoint",
        "confidence": 0.85,
        "severity": "critical",
        "mitre": "T1195"
    },
    {
        "name": "Cryptomining Campaign",
        "indicators": ["malicious_ip", "high_cpu", "network_exfiltration"],
        "prediction": "Cryptomining malware detected - resource theft in progress",
        "confidence": 0.75,
        "severity": "high",
        "mitre": "T1496"
    },
    {
        "name": "C2 Beacon Activity",
        "indicators": ["c2_communication", "malicious_ip", "dns_tunneling"],
        "prediction": "Active C2 channel - full compromise suspected",
        "confidence": 0.89,
        "severity": "critical",
        "mitre": "T1071"
    },
]


class AIPredictionEngine:
    def __init__(self, db):
        self.db = db
        self.predictions: List[Dict] = []
        self._running = False

    async def run_prediction_loop(self):
        """Continuous prediction analysis"""
        self._running = True
        logger.info("AI Prediction Engine started")
        while self._running:
            try:
                await self._analyze_patterns()
            except Exception as e:
                logger.error(f"Prediction error: {e}")
            await asyncio.sleep(60)  # Analyze every minute

    async def _analyze_patterns(self):
        """Analyze recent alerts to generate predictions"""
        # Get recent alerts
        recent_alerts = await self.db.get_alerts(limit=200)
        if not recent_alerts:
            return

        # Count alert types in last hour
        now = datetime.utcnow()
        recent_hour = [
            a for a in recent_alerts
            if self._is_recent(a.get("created_at", ""), minutes=60)
        ]

        alert_type_counts = Counter(a.get("alert_type") for a in recent_hour)
        active_endpoints = set(a.get("endpoint_id") for a in recent_hour)

        new_predictions = []
        for chain in ATTACK_CHAINS:
            matched = sum(
                alert_type_counts.get(ind, 0) > 0
                for ind in chain["indicators"]
            )
            coverage = matched / len(chain["indicators"])

            if coverage >= 0.5:  # At least 50% of indicators present
                adjusted_confidence = chain["confidence"] * coverage
                prediction = {
                    "id": f"pred_{chain['name'].replace(' ', '_').lower()}",
                    "attack_name": chain["name"],
                    "prediction": chain["prediction"],
                    "confidence": round(adjusted_confidence, 2),
                    "severity": chain["severity"],
                    "mitre": chain["mitre"],
                    "affected_endpoints": list(active_endpoints)[:5],
                    "indicators_matched": matched,
                    "indicators_total": len(chain["indicators"]),
                    "generated_at": now.isoformat(),
                    "time_to_impact": self._estimate_time_to_impact(adjusted_confidence),
                }
                new_predictions.append(prediction)

        # Sort by confidence
        self.predictions = sorted(new_predictions, key=lambda x: x["confidence"], reverse=True)

        if self.predictions:
            logger.info(f"AI Predictions updated: {len(self.predictions)} threats predicted")

    def _is_recent(self, ts_str: str, minutes: int = 60) -> bool:
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", ""))
            return (datetime.utcnow() - ts).total_seconds() < minutes * 60
        except Exception:
            return False

    def _estimate_time_to_impact(self, confidence: float) -> str:
        if confidence > 0.9:
            return "< 30 minutes"
        elif confidence > 0.8:
            return "1-2 hours"
        elif confidence > 0.7:
            return "2-4 hours"
        else:
            return "4-8 hours"

    async def get_latest_predictions(self) -> List[Dict]:
        return self.predictions
