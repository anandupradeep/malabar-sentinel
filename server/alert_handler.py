"""
Alert Handler - processes, stores, and broadcasts security alerts
"""

import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("alert-handler")

SEVERITY_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4, "emergency": 5}
ALARM_THRESHOLD = 3  # high and above trigger SOC alarm


class AlertHandler:
    def __init__(self, db, ws_manager):
        self.db = db
        self.ws_manager = ws_manager

    async def process_alert(self, alert_data: dict) -> str:
        """Process an incoming alert: store, broadcast, escalate if needed"""
        alert_id = await self.db.create_alert(alert_data)
        alert_data["alert_id"] = alert_id
        alert_data["timestamp"] = datetime.utcnow().isoformat()

        # Broadcast to dashboard
        await self.ws_manager.broadcast({
            "type": "new_alert",
            "data": alert_data
        })

        # Trigger SOC alarm for high+ severity
        sev_level = SEVERITY_LEVELS.get(alert_data.get("severity", "low"), 1)
        if sev_level >= ALARM_THRESHOLD:
            await self._trigger_soc_alarm(alert_data)
            await self._update_endpoint_threat_level(alert_data)

        # Store geo data if IP present
        if alert_data.get("network_ip"):
            await self._enrich_geo(alert_data["network_ip"])

        logger.info(
            f"Alert processed: [{alert_data.get('severity','?').upper()}] "
            f"{alert_data.get('title')} | Endpoint: {alert_data.get('endpoint_id')}"
        )
        return alert_id

    async def _trigger_soc_alarm(self, alert_data: dict):
        await self.ws_manager.broadcast({
            "type": "soc_alarm",
            "severity": alert_data.get("severity"),
            "title": alert_data.get("title"),
            "endpoint_id": alert_data.get("endpoint_id"),
            "hostname": alert_data.get("hostname"),
            "alert_id": alert_data.get("alert_id"),
            "timestamp": alert_data.get("timestamp")
        })

    async def _update_endpoint_threat_level(self, alert_data: dict):
        sev = alert_data.get("severity", "low")
        endpoint_id = alert_data.get("endpoint_id")
        if endpoint_id and sev in ["critical", "emergency"]:
            await self.db._execute(
                "UPDATE endpoints SET threat_level = ? WHERE endpoint_id = ?",
                (sev, endpoint_id)
            )

    async def _enrich_geo(self, ip: str):
        """Simulate geo enrichment (replace with real API in production)"""
        import random
        # Simulated geo data for non-private IPs
        if ip.startswith(("192.168.", "10.", "172.")):
            return
        geo_samples = [
            ("Russia", "Moscow", "Rostelecom", 55.75, 37.62),
            ("China", "Beijing", "China Telecom", 39.91, 116.39),
            ("North Korea", "Pyongyang", "Star JV", 39.02, 125.75),
            ("Iran", "Tehran", "TCI", 35.69, 51.42),
            ("Brazil", "Sao Paulo", "Claro", -23.55, -46.63),
            ("Germany", "Berlin", "Deutsche Telekom", 52.52, 13.40),
            ("USA", "New York", "Verizon", 40.71, -74.00),
        ]
        geo = random.choice(geo_samples)
        await self.db.store_geo_data(ip, *geo)
