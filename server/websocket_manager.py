"""
WebSocket Manager
Manages real-time connections for dashboard clients and endpoint agents
"""

import asyncio
import json
import logging
from typing import Dict, List, Set

from fastapi import WebSocket

logger = logging.getLogger("ws-manager")


class WebSocketManager:
    def __init__(self):
        self.dashboard_connections: Set[WebSocket] = set()
        self.agent_connections: Dict[str, WebSocket] = {}

    async def connect_dashboard(self, ws: WebSocket):
        await ws.accept()
        self.dashboard_connections.add(ws)
        logger.info(f"Dashboard connected. Total: {len(self.dashboard_connections)}")

    def disconnect_dashboard(self, ws: WebSocket):
        self.dashboard_connections.discard(ws)
        logger.info(f"Dashboard disconnected. Total: {len(self.dashboard_connections)}")

    async def connect_agent(self, endpoint_id: str, ws: WebSocket):
        await ws.accept()
        self.agent_connections[endpoint_id] = ws
        logger.info(f"Agent connected: {endpoint_id}")

    def disconnect_agent(self, endpoint_id: str):
        self.agent_connections.pop(endpoint_id, None)
        logger.info(f"Agent disconnected: {endpoint_id}")

    async def broadcast(self, message: dict):
        """Broadcast message to all dashboard clients"""
        if not self.dashboard_connections:
            return
        dead = set()
        payload = json.dumps(message)
        for ws in self.dashboard_connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.dashboard_connections.discard(ws)

    async def send_to_endpoint(self, endpoint_id: str, message: dict):
        """Send command to specific endpoint agent"""
        ws = self.agent_connections.get(endpoint_id)
        if ws:
            try:
                await ws.send_json(message)
                return True
            except Exception as e:
                logger.error(f"Failed to send to {endpoint_id}: {e}")
                self.agent_connections.pop(endpoint_id, None)
        return False

    async def handle_dashboard_message(self, data: str, ws: WebSocket):
        """Handle incoming messages from dashboard"""
        try:
            msg = json.loads(data)
            msg_type = msg.get("type")
            if msg_type == "ping":
                await ws.send_json({"type": "pong"})
            elif msg_type == "subscribe":
                await ws.send_json({"type": "subscribed", "channel": msg.get("channel")})
        except Exception as e:
            logger.error(f"Dashboard message error: {e}")

    async def handle_agent_message(self, endpoint_id: str, data: dict,
                                     alert_handler=None, db=None):
        """Handle incoming messages from agent over WebSocket."""
        msg_type = data.get("type", "")

        if msg_type == "ping" or msg_type == "agent_ready":
            ws = self.agent_connections.get(endpoint_id)
            if ws:
                try:
                    await ws.send_json({"type": "pong", "endpoint_id": endpoint_id})
                except Exception:
                    pass
            # Broadcast that agent is live
            await self.broadcast({
                "type": "agent_connected",
                "endpoint_id": endpoint_id,
                "hostname": data.get("hostname", ""),
            })

        elif msg_type == "alert":
            # Agent pushed an alert over WS — process + broadcast immediately
            alert_data = data.get("data", data)
            alert_data["endpoint_id"] = alert_data.get("endpoint_id", endpoint_id)
            if alert_handler:
                try:
                    await alert_handler.process_alert(alert_data)
                except Exception as e:
                    logger.error("WS alert processing error: %s", e)
                    await self.broadcast({"type": "new_alert", "data": alert_data})
            else:
                await self.broadcast({"type": "new_alert", "data": alert_data})

        elif msg_type == "command_result":
            # Agent reported execution result over WS
            await self.broadcast({
                "type":        "command_result",
                "command_id":  data.get("command_id", ""),
                "status":      data.get("status", "executed"),
                "detail":      data.get("detail", ""),
                "command":     data.get("command", ""),
                "endpoint_id": endpoint_id,
                "hostname":    data.get("hostname", ""),
                "timestamp":   data.get("reported_at", ""),
            })
            if db:
                try:
                    await db.update_command_result(data.get("command_id",""), data)
                except Exception:
                    pass

        elif msg_type == "heartbeat":
            # Lightweight heartbeat over WS — no HTTP needed
            await self.broadcast({
                "type": "endpoint_update",
                "data": {**data, "endpoint_id": endpoint_id, "status": "active"},
            })

    def get_stats(self) -> dict:
        return {
            "dashboard_connections": len(self.dashboard_connections),
            "agent_connections": len(self.agent_connections),
            "connected_agents": list(self.agent_connections.keys())
        }