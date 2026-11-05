"""
Secure Sender - handles all agent → SOC server communication
with retry logic, queuing, and encrypted transport
"""

import json
import logging
import queue
import threading
import time
from typing import Optional, Dict, Any

logger = logging.getLogger("sender")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SecureSender:
    """
    Manages outbound communication from agent to SOC server.
    - Queues events if server is unreachable
    - Retries with exponential backoff
    - Supports batch sending for efficiency
    """

    def __init__(self, server_url: str, api_key: str, endpoint_id: str):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.endpoint_id = endpoint_id
        self._queue: queue.Queue = queue.Queue(maxsize=500)
        self._connected = False
        self._send_thread: Optional[threading.Thread] = None
        self._running = False
        self._sent_count = 0
        self._failed_count = 0

        if HAS_REQUESTS:
            self._session = self._build_session()
        else:
            self._session = None
            logger.warning("requests not installed — sender disabled")

    def _build_session(self):
        session = requests.Session()
        session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Agent-ID": self.endpoint_id,
        })
        retry = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def start(self):
        """Start background send thread"""
        self._running = True
        self._send_thread = threading.Thread(
            target=self._send_loop, daemon=True, name="SenderThread"
        )
        self._send_thread.start()
        logger.info("Sender started")

    def stop(self):
        self._running = False

    def queue_alert(self, alert: Dict[str, Any]) -> bool:
        """Add alert to send queue (non-blocking)"""
        try:
            self._queue.put_nowait({"type": "alert", "payload": alert})
            return True
        except queue.Full:
            logger.warning("Send queue full — dropping alert")
            return False

    def queue_telemetry(self, events: list) -> bool:
        """Add telemetry batch to queue"""
        try:
            self._queue.put_nowait({
                "type": "telemetry",
                "payload": {
                    "endpoint_id": self.endpoint_id,
                    "events": events,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
            })
            return True
        except queue.Full:
            return False

    def send_now(self, endpoint: str, payload: Dict) -> Optional[Dict]:
        """Send immediately and return response (blocking)"""
        if not self._session:
            return None
        try:
            r = self._session.post(
                f"{self.server_url}/api/{endpoint}",
                json=payload,
                timeout=10
            )
            if r.status_code == 200:
                self._connected = True
                return r.json()
            else:
                logger.warning(f"HTTP {r.status_code} for {endpoint}")
                return None
        except Exception as e:
            self._connected = False
            logger.error(f"Send error ({endpoint}): {e}")
            return None

    def get_json(self, endpoint: str) -> Optional[Dict]:
        """GET request to server"""
        if not self._session:
            return None
        try:
            r = self._session.get(
                f"{self.server_url}/api/{endpoint}",
                timeout=10
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.error(f"GET error ({endpoint}): {e}")
        return None

    def _send_loop(self):
        """Background thread: drain queue and send to server"""
        batch = []
        while self._running:
            try:
                # Collect up to 10 items or wait 2 seconds
                deadline = time.time() + 2.0
                while time.time() < deadline:
                    try:
                        item = self._queue.get(timeout=0.1)
                        batch.append(item)
                        if len(batch) >= 10:
                            break
                    except queue.Empty:
                        break

                if not batch:
                    continue

                # Send each item
                remaining = []
                for item in batch:
                    success = self._dispatch(item)
                    if not success:
                        remaining.append(item)
                    else:
                        self._sent_count += 1

                # Re-queue failed items (up to 50 backed up)
                if remaining:
                    self._failed_count += len(remaining)
                    for item in remaining[:50]:
                        try:
                            self._queue.put_nowait(item)
                        except queue.Full:
                            break
                    time.sleep(5)  # Back off on failure

                batch = []

            except Exception as e:
                logger.error(f"Send loop error: {e}")
                batch = []
                time.sleep(2)

    def _dispatch(self, item: Dict) -> bool:
        """Send a single queued item to the appropriate endpoint"""
        if not self._session:
            return False
        item_type = item.get("type")
        payload = item.get("payload", {})

        endpoint_map = {
            "alert": "alerts",
            "telemetry": "telemetry",
            "heartbeat": "endpoints/heartbeat",
        }
        ep = endpoint_map.get(item_type)
        if not ep:
            return True  # Unknown type, discard

        result = self.send_now(ep, payload)
        return result is not None

    def test_connection(self) -> bool:
        """Test connectivity to SOC server"""
        if not self._session:
            return False
        try:
            r = self._session.get(f"{self.server_url}/health", timeout=5)
            self._connected = r.status_code == 200
            return self._connected
        except Exception:
            self._connected = False
            return False

    @property
    def is_connected(self) -> bool:
        return self._connected

    def get_stats(self) -> Dict:
        return {
            "connected": self._connected,
            "queue_size": self._queue.qsize(),
            "sent": self._sent_count,
            "failed": self._failed_count,
        }
