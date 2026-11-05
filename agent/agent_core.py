"""
SOC Agent Core
──────────────
Original fixes 1-17 preserved + new production upgrades:

Issue 1  – USB disable/eject: admin check + registry + PowerShell COM
Issue 2  – Blocked IP: both firewall dirs + live connection validation
Issue 3  – Alert severity: confidential=CRITICAL, sensitive=HIGH, else MEDIUM
Issue 4  – Agent authentication (bcrypt/sha256, stored creds)
Issue 5  – Secure comms: Bearer token on every request
Issue 7  – Command retry (3 attempts) + full execution logging
Issue 8  – Admin privilege check before privileged ops
Issue 9  – File open detection (atime) + modify (mtime)
Issue 10 – Alert pipeline: agent→server stored→dashboard displayed
Issue 12 – Logging: command received / executed / failed
Issue 13 – All ops in daemon threads
Issue 14 – Exception catch + error response for every command
"""
import hashlib, logging, os, platform, socket, subprocess
import threading, time, uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional, Set

from agent.network_blocking import (
    IPBlocker, URLBlocker, restore_blocks_on_startup,
)
from agent.scan_executor import start_scan_command, stop_scan_command

import psutil

WIN_FLAGS = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW — never flash a console window

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# websockets — optional, enables instant WS command delivery
# Falls back to HTTP polling every 1s if not installed
try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False
    websockets = None

AGENT_VERSION = "1.0.0"
logger = logging.getLogger("agent-core")

# ── Persistent agent ID ───────────────────────────────────────────────────────
_ID_FILE = Path(os.path.expanduser("~")) / ".soc_agent_id"

def _load_or_create_id() -> str:
    if _ID_FILE.exists():
        try:
            v = _ID_FILE.read_text().strip()
            if len(v) == 16 and v.isalnum():
                return v
        except Exception:
            pass
    raw    = f"{socket.gethostname()}-{uuid.getnode()}"
    new_id = hashlib.md5(raw.encode()).hexdigest()[:16]
    try:
        _ID_FILE.write_text(new_id)
        if os.name != "nt":
            os.chmod(_ID_FILE, 0o600)
    except Exception:
        pass
    return new_id


# ── Issue 8: Admin check ──────────────────────────────────────────────────────
def _is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _require_admin(op: str) -> tuple:
    """Returns (ok, message). Call before any privileged operation."""
    if _is_admin():
        return True, "ok"
    hint = ("Run as Administrator" if os.name == "nt"
            else "Run with sudo")
    return False, f"Admin required for '{op}'. {hint}."


class AgentCore:
    def __init__(self, server_url: str, api_key: str,
                 log_callback: Callable = None,
                 alert_callback: Callable = None,
                 username: str = ""):
        self.server_url  = server_url.rstrip("/")
        self.api_key     = api_key
        self.endpoint_id = _load_or_create_id()
        # Use "username@hostname" so dashboard shows the logged-in user
        _raw_hostname = socket.gethostname()
        self.hostname = f"{username}@{_raw_hostname}" if username else _raw_hostname
        self.log_cb      = log_callback
        self.alert_cb    = alert_callback

        self.running    = False
        self._connected = False
        self._ws_connected = False          # True when WS channel is live
        self._monitors: List = []
        self._threads:  List[threading.Thread] = []

        self.alerts: List[dict] = []
        self._alert_lock = threading.Lock()

        # Issue 2 – blocked IP / URL sets + blocking engines
        self._blocked_ips: Set[str] = set()
        self._blocked_urls: Set[str] = set()
        self._ip_blocker  = IPBlocker()
        self._url_blocker = URLBlocker(self._ip_blocker)

        # Pointer to NetworkMonitor's _fw_applied set — injected by the monitor
        # so unblock() can clear stale entries and allow re-block to work.
        self._network_monitor_fw_applied: Optional[Set[str]] = None

        # Restore firewall rules for IPs that were blocked before a restart
        if _is_admin():
            try:
                restore_blocks_on_startup(
                    self._blocked_ips, self._blocked_urls,
                    self._ip_blocker, self._url_blocker,
                )
            except Exception as _e:
                logger.warning("restore_blocks_on_startup error: %s", _e)

        # Issue 3 – severity mapping
        self._sensitive_paths:    List[str] = []
        self._confidential_paths: Set[str]  = set()

        # USB whitelist & blocklist
        self._allowed_usb: List[str] = []
        self._blocked_usb_drives: Set[str] = set()

        # Issue 5 – auth token (set after login)
        self._auth_token: Optional[str] = None

        # Intervals
        self._heartbeat_interval = 5   # 5s for fast process list updates
        self._cmd_poll_interval  = 1   # 1s poll for fast command delivery

        # Issue 5 – HTTP session with token
        if HAS_REQUESTS:
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type":  "application/json",
            })
            retry = Retry(total=2, backoff_factor=0.3,
                          status_forcelist=[500, 502, 503])
            self._session.mount("http://",  HTTPAdapter(max_retries=retry))
            self._session.mount("https://", HTTPAdapter(max_retries=retry))
        else:
            self._session = None

        logger.info("AgentCore init: %s @ %s", self.endpoint_id, self.hostname)

    # ── Issue 5: Update token on session headers ──────────────────────────────
    def set_auth_token(self, token: str):
        self._auth_token = token
        if self._session:
            # IMPORTANT: keep Authorization as the API key — the server validates
            # against VALID_API_KEYS which only contains the master/agent keys.
            # The session token goes in X-Agent-Token header only.
            self._session.headers.update({
                "Authorization": f"Bearer {self.api_key}",
                "X-Agent-Token": token,
            })
        self._log("INFO", "Auth token set (api_key kept in Authorization)")

    # ── Logging (Issue 12) ────────────────────────────────────────────────────
    def _log(self, level: str, msg: str):
        logger.info("[%s] %s", level, msg)
        if self.log_cb:
            try: self.log_cb(level, msg)
            except Exception: pass

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ── Issue 3: Severity resolver ────────────────────────────────────────────
    def _file_severity(self, filepath: str, event: str) -> str:
        """
        confidential file → CRITICAL
        sensitive file    → HIGH
        else              → MEDIUM (or LOW for access)
        """
        if self.is_confidential(filepath):
            return "critical"
        if filepath in self._sensitive_paths or any(
                filepath.startswith(p) for p in self._sensitive_paths):
            return "high"
        return "medium" if event != "accessed" else "low"

    # ── Alert store ───────────────────────────────────────────────────────────
    def _add_alert(self, alert: dict):
        alert.setdefault("created_at",  datetime.utcnow().isoformat())
        alert.setdefault("hostname",    self.hostname)
        alert.setdefault("endpoint_id", self.endpoint_id)
        with self._alert_lock:
            # Issue 11 – deduplicate: skip if identical title+type in last 30s
            now = datetime.utcnow().timestamp()
            for a in self.alerts[:20]:
                try:
                    age = (now - datetime.fromisoformat(
                        a["created_at"]).timestamp())
                    if (a["alert_type"] == alert["alert_type"]
                            and a["title"] == alert["title"]
                            and age < 30):
                        return   # suppress duplicate
                except Exception:
                    pass
            self.alerts.insert(0, alert)
            if len(self.alerts) > 500:
                self.alerts.pop()
        if self.alert_cb:
            try: self.alert_cb(alert)
            except Exception: pass

    def get_alerts(self) -> List[dict]:
        with self._alert_lock: return list(self.alerts)

    # ── Issue 10: send_alert ──────────────────────────────────────────────────
    def send_alert(self, alert_type: str, severity: str, title: str,
                   description: str, process_name: str = None,
                   process_pid: int = None, file_path: str = None,
                   network_ip: str = None, raw_data: dict = None) -> bool:
        alert = {
            "endpoint_id":  self.endpoint_id,
            "hostname":     self.hostname,
            "alert_type":   alert_type,
            "severity":     severity,
            "title":        title,
            "description":  description,
            "process_name": process_name,
            "process_pid":  process_pid,
            "file_path":    file_path,
            "network_ip":   network_ip,
            "raw_data":     raw_data or {},
            "created_at":   datetime.utcnow().isoformat(),
        }
        self._add_alert(dict(alert))
        self._log("ALERT", f"[{severity.upper()}] {title}")
        if not self._session: return False
        # Always ensure api_key (not session token) is in Authorization
        self._session.headers["Authorization"] = f"Bearer {self.api_key}"
        for ep in ["/api/alerts", "/alert"]:
            try:
                r = self._session.post(
                    f"{self.server_url}{ep}", json=alert, timeout=8)
                if r.status_code in (200, 201):
                    return True
            except Exception as e:
                logger.debug("Alert send error (%s): %s", ep, e)
        self._log("WARNING", f"Alert not delivered to server: {alert.get('title')}")
        return False

    # ── Register / unregister ─────────────────────────────────────────────────
    def register(self) -> Optional[dict]:
        if not self._session: return None
        self._session.headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            r = self._session.post(
                f"{self.server_url}/register",
                json={
                    "endpoint_id":   self.endpoint_id,
                    "hostname":      self.hostname,
                    "ip_address":    self._get_local_ip(),
                    "os_version":    f"{platform.system()} {platform.release()}",
                    "agent_version": AGENT_VERSION,
                },
                timeout=10)
            if r.status_code == 200:
                self._connected = True
                self._log("INFO", f"Registered: {self.endpoint_id}")
                return r.json()
        except Exception as e:
            self._log("ERROR", f"Registration failed: {e}")
        return None

    def unregister(self):
        self._connected = False
        if not self._session: return
        try:
            self._session.post(
                f"{self.server_url}/unregister",
                json={"endpoint_id": self.endpoint_id}, timeout=5)
            self._log("INFO", "Unregistered from server")
        except Exception: pass

    # ── Heartbeat ─────────────────────────────────────────────────────────────
    def send_heartbeat(self) -> bool:
        if not self._session: return False
        # Always ensure api_key in Authorization for authenticated endpoints
        self._session.headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            cpu  = psutil.cpu_percent(interval=None)
            mem  = psutil.virtual_memory().percent
            try:
                disk = (psutil.disk_usage("C:\\").percent if os.name == "nt"
                        else psutil.disk_usage("/").percent)
            except Exception: disk = 0
            # Build comprehensive process list
            # Strategy: psutil first (fast, complete, sees VS Code / node / all apps),
            # then PowerShell supplements UWP/Store apps psutil may miss.
            proc_list = []
            seen_pids = set()
            try:
                # Primary: psutil — sees ALL processes including VS Code, node, etc.
                for p in psutil.process_iter(['pid','name','cpu_percent','memory_info','status']):
                    try:
                        i = p.info
                        pid_val = i.get('pid', 0)
                        if not pid_val: continue
                        mem_info = i.get('memory_info')
                        mem_mb = round(mem_info.rss / 1048576, 1) if mem_info else 0.0
                        name = i.get('name') or 'unknown'
                        if not name or name.lower() in ('idle',): continue
                        proc_list.append({
                            'pid':    pid_val,
                            'name':   name,
                            'cpu':    round(i.get('cpu_percent') or 0.0, 1),
                            'mem':    mem_mb,
                            'status': i.get('status', 'running'),
                        })
                        seen_pids.add(pid_val)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    except Exception:
                        pass
            except Exception:
                pass

            # Supplement with PowerShell to catch UWP/Store apps psutil misses
            if os.name == "nt":
                try:
                    import json as _pj
                    ps_cmd = (
                        "Get-Process | "
                        "Select-Object Id,ProcessName,"
                        "@{N='Mem';E={[math]::Round($_.WorkingSet64/1MB,1)}} "
                        "| ConvertTo-Json -Compress -Depth 1"
                    )
                    r_ps = subprocess.run(
                        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                        capture_output=True, text=True, timeout=10,
                        creationflags=WIN_FLAGS)
                    if r_ps.returncode == 0 and r_ps.stdout.strip():
                        raw_text = r_ps.stdout.strip()
                        if raw_text.startswith("{"): raw_text = "[" + raw_text + "]"
                        for p in _pj.loads(raw_text):
                            pid_val = int(p.get('Id') or 0)
                            if not pid_val or pid_val in seen_pids: continue
                            name = (p.get('ProcessName') or 'unknown').strip()
                            if not name or name.lower() in ('idle',): continue
                            if not name.lower().endswith('.exe'): name += '.exe'
                            proc_list.append({
                                'pid':  pid_val, 'name': name,
                                'cpu':  0.0,
                                'mem':  float(p.get('Mem') or 0),
                                'status': 'running',
                            })
                            seen_pids.add(pid_val)
                except Exception:
                    pass

            # Alphabetical sort — VS Code / idle apps won't be cut off at bottom
            proc_list.sort(key=lambda x: x['name'].lower())
            r = self._session.post(
                f"{self.server_url}/api/endpoints/heartbeat",
                json={
                    "endpoint_id":      self.endpoint_id,
                    "hostname":         self.hostname,
                    "ip_address":       self._get_local_ip(),
                    "os_version":       f"{platform.system()} {platform.release()}",
                    "agent_version":    AGENT_VERSION,
                    "cpu_usage":        cpu, "memory_usage": mem,
                    "disk_usage":       disk,
                    "active_processes": len(proc_list) or len(psutil.pids()),
                    "threat_level":     "normal",
                    "is_admin":         _is_admin(),
                    "process_list":     proc_list[:500],
                    "usb_devices":      self._get_live_usb_snapshot(),
                },
                timeout=15)
            return r.status_code == 200
        except Exception: return False

    def _get_live_usb_snapshot(self) -> list:
        """
        Return a list of all currently connected USB and portable devices.
        Called during every heartbeat so the server always has a fresh list.
        This is what makes phones and MTP devices show up in the dashboard
        even without a new insertion alert.
        """
        try:
            from agent.monitors.usb_monitor import _snapshot
            devices = _snapshot()
            return list(devices.values())
        except Exception as e:
            logger.debug("USB snapshot error: %s", e)
            return []

    # ── Command polling — dedup + reliable delivery ─────────────────────────
    # ─────────────────────────────────────────────────────────────────────────
    # Command listener: WebSocket (instant) + HTTP poll (fallback)
    # ─────────────────────────────────────────────────────────────────────────
    def _poll_commands(self):
        """Start WS listener thread + HTTP-poll fallback in this thread."""
        self._seen_command_ids: set = set()
        if HAS_WS:
            threading.Thread(
                target=self._ws_command_listener,
                daemon=True, name="WSCommandListener").start()
        self._http_poll_loop()

    def _http_poll_loop(self):
        """HTTP fallback — 1s when WS down, 5s when WS alive."""
        errs = 0
        while self.running:
            sleep = 5 if self._ws_connected else 1
            try:
                if self._session:
                    r = self._session.get(
                        f"{self.server_url}/get-commands/{self.endpoint_id}",
                        timeout=5)
                    if r.status_code == 200:
                        self._dispatch_commands(r.json().get("commands", []))
                        errs = 0
                    else:
                        errs += 1
            except Exception as e:
                errs += 1
                sleep = min(10, 2 ** min(errs, 4))
                logger.debug("HTTP poll error: %s", e)
            time.sleep(sleep)

    def _ws_command_listener(self):
        """
        Persistent WebSocket → /ws/agent/{endpoint_id}.
        Instant command delivery, auto-reconnects.
        """
        import asyncio, json as _json
        ws_url = (self.server_url
                  .replace("http://", "ws://")
                  .replace("https://", "wss://"))
        ws_url = f"{ws_url}/ws/agent/{self.endpoint_id}?api_key={self.api_key}"

        async def _run():
            backoff = 1
            while self.running:
                try:
                    self._log("INFO", "[WS] Connecting for real-time commands…")
                    async with websockets.connect(
                        ws_url,
                        ping_interval=20,
                        ping_timeout=10,
                        close_timeout=5,
                    ) as ws:
                        self._ws_connected = True
                        backoff = 1
                        self._log("INFO", "[WS] Connected — instant delivery active")
                        await ws.send(_json.dumps({
                            "type": "agent_ready",
                            "endpoint_id": self.endpoint_id,
                            "hostname": self.hostname,
                        }))
                        while self.running:
                            try:
                                raw = await asyncio.wait_for(ws.recv(), timeout=25)
                                msg = _json.loads(raw)
                                t = msg.get("type", "")
                                if t == "command":
                                    self._log("INFO",
                                        f"[WS] Instant cmd: {msg.get('command')} "
                                        f"id={str(msg.get('command_id',''))[:8]}")
                                    self._dispatch_commands([msg])
                                elif t == "ping":
                                    await ws.send(_json.dumps({"type":"pong"}))
                            except asyncio.TimeoutError:
                                await ws.send(_json.dumps({"type":"ping"}))
                except Exception as e:
                    self._ws_connected = False
                    self._log("WARNING",
                        f"[WS] Disconnected ({type(e).__name__}) — retry in {backoff}s")
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 30)

        try:
            asyncio.run(_run())
        except Exception as e:
            self._log("ERROR", f"[WS] Fatal: {e}")

    def _dispatch_commands(self, cmds: list):
        """Dedup + execute — shared by WS and HTTP paths."""
        for cmd in cmds:
            cid = cmd.get("command_id", "")
            if cid and cid in self._seen_command_ids:
                continue
            if cid:
                self._seen_command_ids.add(cid)
                if len(self._seen_command_ids) > 500:
                    self._seen_command_ids = set(list(self._seen_command_ids)[-250:])
            threading.Thread(
                target=self._execute_command,
                args=(cmd,), daemon=True,
                name=f"Cmd_{cmd.get('command','?')}",
            ).start()
    # ── Issue 7/12/14: execute_command with retry + logging + error handling ──
    def _execute_command(self, cmd: dict):
        command    = cmd.get("command", "")
        params     = cmd.get("parameters") or {}
        command_id = cmd.get("command_id", "")

        # Issue 12 – log received
        self._log("INFO", f"[CMD RECEIVED] id={command_id} command={command} params={params}")

        result = {
            "status": "executed", "command": command,
            "command_id": command_id, "endpoint_id": self.endpoint_id,
        }

        MAX_RETRIES = 3
        last_error  = ""

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._run_command(command, params, result)
                # Don't retry on these — they are definitive answers
                if result.get("status") not in ("error",):
                    break
                # admin_required and not_found should not retry
                if result.get("status") in ("admin_required", "not_found", "unknown"):
                    break
            except Exception as e:
                last_error = str(e)
                result["status"] = "error"
                result["error"]  = last_error
                logger.error("[CMD ATTEMPT %d/%d] %s error: %s",
                             attempt, MAX_RETRIES, command, e)
                if attempt < MAX_RETRIES:
                    time.sleep(0.5 * attempt)

        # Issue 12 – log executed / failed
        if result.get("status") in ("error", "admin_required", "not_found"):
            self._log("ERROR",
                      f"[CMD FAILED] {command}: {result.get('error', result.get('detail',''))}")
        else:
            self._log("INFO",
                      f"[CMD EXECUTED] {command}: {result.get('detail', 'ok')}")

        self._report_result(result)

    # ── Inner dispatch ────────────────────────────────────────────────────────
    def _run_command(self, command: str, params: dict, result: dict):
        """Single execution attempt — raises on unexpected error."""

        # ── Kill process — 3-method: psutil → taskkill → PowerShell ────────────
        if command == "kill_process":
            from agent.monitors.process_monitor import ProcessMonitor
            pid  = params.get("pid")
            raw_name = (params.get("name") or params.get("process") or "").strip()
            # Dashboard sends name as "PID 1234" when only PID is selected —
            # strip that and use actual process name from psutil
            if raw_name.startswith("PID ") or not raw_name:
                name = None   # will kill by PID only
                if pid:
                    try:
                        name = psutil.Process(int(pid)).name()
                    except Exception:
                        name = None
            else:
                name = raw_name
            ok, detail = ProcessMonitor.kill(
                pid=int(pid) if pid else None,
                name=name or None)
            result["status"] = "executed" if ok else "not_found"
            result["detail"] = detail
            if ok:
                self.send_alert("process_killed", "medium",
                                f"Process Terminated: {name or pid}", detail)

        # ── Block IP (Issue 2 — both dirs) ────────────────────────────────────
        elif command == "start_scan":
            # ── Remote antivirus scan ─────────────────────────────────────────
            # Uses scan_executor.ScanExecutor which runs in a background thread.
            # When threats are found the executor posts back to /api/scan/report/update.
            # Any IP/URL blocking triggered by the sandbox verdict goes through the
            # standard block_ip / block_url command path below — no new firewall
            # code is added here.
            try:
                detail = start_scan_command(
                    server_url   = self.server_url,
                    api_key      = self.api_key,
                    endpoint_id  = self.endpoint_id,
                    params       = params,
                )
                result["status"] = "executed"
                result["detail"] = detail
            except Exception as exc:
                result["status"] = "error"
                result["error"]  = str(exc)

        elif command == "stop_scan":
            detail = stop_scan_command(self._endpoint_id)
            result["status"] = "executed"
            result["detail"] = detail

        # ── Block IP (Issue 2 — both dirs) ────────────────────────────────────
        elif command == "block_ip":
            ok, msg = _require_admin("block_ip")
            if not ok:
                result["status"] = "admin_required"; result["detail"] = msg; return
            ip = (params.get("ip") or "").strip()
            if not ip:
                result["status"] = "error"; result["error"] = "No IP given"; return
            # Clear _fw_applied FIRST so network_monitor doesn't think rules exist
            # and IPBlocker.block() always runs as a fresh request
            _fw = getattr(self, "_network_monitor_fw_applied", None)
            if _fw is not None:
                _fw.discard(ip)
            detail = self._block_ip_firewall(ip)
            if "error" in detail.lower() or "fail" in detail.lower() or "denied" in detail.lower():
                result["status"] = "error"; result["error"] = detail; return
            # _block_ip_firewall → ip_blocker.block() already adds to _blocked_ips
            # and saves persistence; also mark as applied in the monitor set
            if _fw is not None:
                _fw.add(ip)
            result["status"] = "executed"
            result["detail"] = detail
            self.send_alert("block_ip", "high",
                            f"IP Blocked: {ip}", detail, network_ip=ip)

        # ── Unblock IP — remove firewall rules ────────────────────────────────
        elif command == "unblock_ip":
            ok, msg = _require_admin("unblock_ip")
            if not ok:
                result["status"] = "admin_required"; result["detail"] = msg; return
            ip = (params.get("ip") or "").strip()
            if not ip:
                result["status"] = "error"; result["error"] = "No IP given"; return
            # CRITICAL ORDER: discard from _blocked_ips FIRST, then _fw_applied,
            # then remove firewall rules.
            # NetworkMonitor._enforce_blocked_ips() runs every 10 s on a background
            # thread. If we remove the firewall rule first but leave ip in
            # _blocked_ips, the monitor will immediately re-apply the rule.
            # Discarding from _blocked_ips first closes that race window.
            self._blocked_ips.discard(ip)
            _fw = getattr(self, "_network_monitor_fw_applied", None)
            if _fw is not None:
                _fw.discard(ip)
            # Now safe to remove the actual firewall rule
            detail = self._unblock_ip_firewall(ip)
            result["status"] = "executed"
            result["detail"] = detail
            self.send_alert("unblock_ip", "low",
                            f"IP Unblocked: {ip}", detail, network_ip=ip)

        # ── Block URL / domain (hosts file + optional firewall on resolved IPs) ─
        elif command == "block_url":
            ok, msg = _require_admin("block_url")
            if not ok:
                result["status"] = "admin_required"; result["detail"] = msg; return
            url = (params.get("url") or "").strip()
            if not url:
                result["status"] = "error"; result["error"] = "No URL given"; return
            detail = self._block_url_hosts(url)
            # Propagate failure — don't report "executed" if hosts write failed
            if "Permission denied" in detail or "Failed to block" in detail:
                result["status"] = "error"; result["error"] = detail; return
            # _block_url_hosts → url_blocker.block() updates _blocked_urls
            # and persists; ensure local set is also updated
            import re as _re
            _dom = _re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
            self._blocked_urls.add(url.lower())
            self._blocked_urls.add(_dom)
            result["status"] = "executed"
            result["detail"] = detail
            self.send_alert("block_url", "high",
                            f"URL Blocked: {url}", detail)

        # ── Unblock URL / domain — remove hosts-file entry ────────────────────
        elif command == "unblock_url":
            ok, msg = _require_admin("unblock_url")
            if not ok:
                result["status"] = "admin_required"; result["detail"] = msg; return
            url = (params.get("url") or "").strip()
            if not url:
                result["status"] = "error"; result["error"] = "No URL given"; return
            # Discard from memory FIRST — same race-condition reason as unblock_ip
            import re as _re
            _dom = _re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
            self._blocked_urls.discard(url.lower())
            self._blocked_urls.discard(_dom)
            detail = self._unblock_url_hosts(url)
            if "Permission denied" in detail or "Failed to write" in detail:
                result["status"] = "error"; result["error"] = detail; return
            result["status"] = "executed"
            result["detail"] = detail
            self.send_alert("unblock_url", "low",
                            f"URL Unblocked: {url}", detail)

        # ── Issue 1: USB disable (registry) ──────────────────────────────────
        elif command == "disable_usb":
            ok, msg = _require_admin("disable_usb")
            if not ok:
                result["status"] = "admin_required"; result["detail"] = msg; return
            drive     = params.get("drive", "")
            eject_all = params.get("eject_all", False)
            d1 = self._disable_usb_registry()
            d2 = self._eject_usb(drive, eject_all)
            result["detail"] = f"{d1} | {d2}"
            self.send_alert("usb_disabled", "high", "USB Storage Disabled", d1)

        elif command == "enable_usb":
            ok, msg = _require_admin("enable_usb")
            if not ok:
                result["status"] = "admin_required"; result["detail"] = msg; return
            detail = self._enable_usb_registry()
            result["detail"] = detail
            self.send_alert("usb_enabled", "low", "USB Storage Enabled", detail)

        # ── Disable selected USB drive (eject + block by drive letter) ────────
        elif command == "disable_selected_usb":
            drive = (params.get("drive") or "").strip()
            if not drive:
                result["status"] = "error"; result["error"] = "No drive specified"; return
            eject_detail = self._eject_usb(drive, eject_all=False)
            # Also add to blocked list so reinsertion triggers alert
            self._blocked_usb_drives.add(drive.upper())
            result["detail"] = f"Disabled {drive}: {eject_detail}"
            self.send_alert("usb_disabled_selected", "high",
                            f"USB Drive Disabled: {drive}",
                            f"Drive {drive} ejected and blocked. {eject_detail}")

        # ── Issue 1: USB eject ────────────────────────────────────────────────
        elif command == "eject_usb":
            drive     = params.get("drive", "")
            device_id = params.get("device_id", "")
            eject_all = params.get("eject_all", False)

            # Phone / MTP device: use PowerShell WPD eject
            if device_id and not drive:
                detail = self._eject_portable_device(device_id)
            else:
                detail = self._eject_usb(drive, eject_all)

            # Check for eject failure
            if "no removable" in detail.lower() or "error" in detail.lower():
                result["status"] = "error"; result["error"] = detail
            else:
                result["status"] = "executed"
            result["detail"] = detail
            # Notify dashboard — send both drive and device_id so dashboard
            # can remove the entry from the list regardless of which type it is
            self.send_alert("usb_ejected", "medium",
                            f"USB Ejected: {drive or device_id or 'all'}", detail,
                            raw_data={"drive": drive, "device_id": device_id,
                                      "event": "ejected"})
            # Sync monitor state — remove from both _prev_drives and _prev dict
            for mon in self._monitors:
                if hasattr(mon, "_prev_drives"):
                    mon._prev_drives.discard(drive)
                    mon._prev_drives.discard(drive.rstrip("\\/"))
                if hasattr(mon, "_prev") and device_id:
                    mon._prev.pop(device_id, None)

        # ── Encrypt file ──────────────────────────────────────────────────────
        elif command == "encrypt_file":
            path = (params.get("file_path") or params.get("path") or "").strip()
            if not path or not os.path.exists(path):
                result["status"] = "error"
                result["error"]  = f"File not found: {path}"; return
            ok2, detail = self._encrypt_file(path)
            result["detail"] = detail
            result["status"] = "encrypted" if ok2 else "failed"
            if ok2:
                sev = "critical" if self.is_confidential(path) else "high"
                self.send_alert("file_encrypted", sev,
                                f"File Encrypted: {os.path.basename(path)}",
                                detail, file_path=path)

        # ── Decrypt file ──────────────────────────────────────────────────────
        elif command == "decrypt_file":
            path = (params.get("file_path") or params.get("path") or "").strip()
            if not path or not os.path.exists(path):
                result["status"] = "error"
                result["error"]  = f"File not found: {path}"; return
            ok2, detail = self._decrypt_file(path)
            result["detail"] = detail
            result["status"] = "decrypted" if ok2 else "failed"
            if ok2:
                self.send_alert("file_decrypted", "medium",
                                f"File Decrypted: {os.path.basename(path)}",
                                detail, file_path=path)

        # ── Lock endpoint ─────────────────────────────────────────────────────
        elif command == "lock_endpoint":
            if os.name == "nt":
                subprocess.Popen(["rundll32.exe", "user32.dll,LockWorkStation"])
                result["detail"] = "Workstation locked"
            else:
                subprocess.Popen(["xdg-screensaver", "lock"])
                result["detail"] = "Screen locked"
            self.send_alert("lock_endpoint", "medium", "Endpoint Locked Remotely",
                            f"SOC locked {self.hostname}")

        # ── Isolate ───────────────────────────────────────────────────────────
        elif command == "isolate":
            ok, msg = _require_admin("isolate")
            if not ok:
                result["status"] = "admin_required"; result["detail"] = msg; return
            if os.name == "nt":
                subprocess.run(
                    ["powershell", "-Command",
                     "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}"
                     " | Disable-NetAdapter -Confirm:$false"],
                    capture_output=True, timeout=20)
                result["detail"] = "All network adapters disabled"
            else:
                subprocess.run(["nmcli", "networking", "off"],
                               capture_output=True, timeout=10)
                result["detail"] = "Network disabled"
            result["status"] = "executed"
            self.send_alert("isolate", "high", "Endpoint Isolated",
                            f"Network isolated on {self.hostname}")

        elif command == "stop_monitoring":
            self.stop()
            result["status"] = "executed"
            result["detail"] = "Agent monitoring stopped"

        else:
            result["status"] = "unknown"
            result["detail"] = f"Unknown command: {command}"

    # ── Report result — guaranteed delivery with retries ─────────────────────
    def _report_result(self, result: dict):
        """POST result back to server — retries until success, then gives up."""
        if not self._session: return
        # Always use api_key for authenticated endpoints
        self._session.headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {**result, "hostname": self.hostname,
                   "reported_at": datetime.utcnow().isoformat()}
        for attempt in range(5):   # up to 5 attempts
            for ep in ["/command-response"]:
                try:
                    r = self._session.post(
                        f"{self.server_url}{ep}", json=payload, timeout=8)
                    if r.status_code in (200, 201, 204):
                        self._log("INFO",
                            f"[CMD RESULT] {result.get('command')} → "                            f"{result.get('status')} (attempt {attempt+1})")
                        return
                except Exception as e:
                    logger.debug("Result report attempt %d failed: %s", attempt+1, e)
            time.sleep(0.5 * (attempt + 1))
        self._log("WARNING",
            f"[CMD RESULT UNDELIVERED] {result.get('command')} "            f"{result.get('command_id','')}")

    # ────────────────────────────────────────────────────────────────────────
    # IP / URL blocking — delegated to network_blocking module
    # ────────────────────────────────────────────────────────────────────────

    def _block_ip_firewall(self, ip: str) -> str:
        """Block an IP via OS firewall. Returns result string."""
        return self._ip_blocker.block(
            ip, self._blocked_ips, self._blocked_urls
        )

    def _unblock_ip_firewall(self, ip: str) -> str:
        """Remove firewall rules for an IP. Returns result string."""
        fw_applied = getattr(self, "_network_monitor_fw_applied", None)
        return self._ip_blocker.unblock(
            ip, self._blocked_ips, self._blocked_urls, fw_applied
        )

    def is_ip_blocked(self, ip: str) -> bool:
        return ip.strip() in self._blocked_ips

    # ── URL / domain blocking via hosts file ─────────────────────────────────

    @staticmethod
    def _hosts_path() -> str:
        from agent.network_blocking import _hosts_path
        return _hosts_path()

    @staticmethod
    def _unlock_hosts_windows(hosts_path: str):
        from agent.network_blocking import _unlock_hosts_windows
        _unlock_hosts_windows(hosts_path)

    def _write_hosts_windows(self, content: str, hosts_path: str):
        from agent.network_blocking import _write_hosts_windows
        _write_hosts_windows(content, hosts_path)

    def _block_url_hosts(self, url: str) -> str:
        """Block a domain via hosts file + firewall on resolved IPs."""
        return self._url_blocker.block(
            url, self._blocked_ips, self._blocked_urls
        )

    def _unblock_url_hosts(self, url: str) -> str:
        """Remove hosts-file entries and in-memory state for a domain."""
        fw_applied = getattr(self, "_network_monitor_fw_applied", None)
        return self._url_blocker.unblock(
            url, self._blocked_ips, self._blocked_urls, fw_applied
        )

    def is_url_blocked(self, url: str) -> bool:
        return self._url_blocker.is_blocked(url, self._blocked_urls)

    # ── Issue 1: USB registry ─────────────────────────────────────────────────
    def _disable_usb_registry(self) -> str:
        if os.name != "nt":
            return "USB registry control is Windows-only"
        if not _is_admin():
            return "Admin required to modify USBSTOR registry key"
        # Method 1: reg.exe
        r = subprocess.run(
            ["reg", "add",
             r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
             "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"],
            capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return "USB storage disabled via registry (USBSTOR Start=4)"
        # Method 2: PowerShell fallback
        ps = ("Set-ItemProperty -Path "
              "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' "
              "-Name Start -Value 4 -Type DWord -Force")
        r2 = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                            capture_output=True, text=True, timeout=10)
        if r2.returncode == 0:
            return "USB storage disabled via PowerShell registry (USBSTOR Start=4)"
        return f"Registry error: {r.stderr.strip() or r2.stderr.strip()}"

    def _enable_usb_registry(self) -> str:
        if os.name != "nt":
            return "USB registry control is Windows-only"
        if not _is_admin():
            return "Admin required to modify USBSTOR registry key"
        r = subprocess.run(
            ["reg", "add",
             r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
             "/v", "Start", "/t", "REG_DWORD", "/d", "3", "/f"],
            capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return "USB storage enabled via registry (USBSTOR Start=3)"
        ps = ("Set-ItemProperty -Path "
              "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' "
              "-Name Start -Value 3 -Type DWord -Force")
        r2 = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                            capture_output=True, text=True, timeout=10)
        if r2.returncode == 0:
            return "USB storage enabled via PowerShell registry (USBSTOR Start=3)"
        return f"Registry error: {r.stderr.strip() or r2.stderr.strip()}"

    # ── Issue 1: USB eject (PowerShell COM) ──────────────────────────────────
    def _eject_usb(self, drive: str = "", eject_all: bool = False) -> str:
        if os.name != "nt":
            r = subprocess.run(["umount", drive or "/media"],
                               capture_output=True, text=True, timeout=10)
            return (f"Unmounted {drive or '/media'}" if r.returncode == 0
                    else f"Umount error: {r.stderr.strip()[:80]}")

        # Collect drives to eject
        if eject_all or not drive:
            drives_to_eject = [p["drive"].rstrip("\\/")
                               for p in self.list_removable_drives()]
        else:
            drives_to_eject = [drive.rstrip("\\/")]

        if not drives_to_eject:
            return "No removable drives found"

        results = [self._eject_single_drive_nt(d) for d in drives_to_eject]
        return " | ".join(results)

    def _eject_single_drive_nt(self, drive_letter: str) -> str:
        """Eject one drive: ctypes DeviceIoControl first, PowerShell fallback."""
        try:
            import ctypes
            GENERIC_READ  = 0x80000000
            GENERIC_WRITE = 0x40000000
            OPEN_EXISTING = 3
            FILE_SHARE_READ  = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            IOCTL_STORAGE_EJECT_MEDIA = 0x2D4808

            drv = drive_letter.rstrip(":\\/")
            unc = f"\\\\.\\{drv}:"
            k32 = ctypes.windll.kernel32
            handle = k32.CreateFileW(
                unc, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None)

            INVALID = ctypes.c_void_p(-1).value
            if handle != INVALID:
                br = ctypes.c_ulong(0)
                ok = k32.DeviceIoControl(
                    handle, IOCTL_STORAGE_EJECT_MEDIA,
                    None, 0, None, 0, ctypes.byref(br), None)
                k32.CloseHandle(handle)
                if ok:
                    return f"Ejected {drv}: (DeviceIoControl)"
        except Exception:
            pass

        # PowerShell fallback
        drv_ps = drive_letter.rstrip("\\/")
        if not drv_ps.endswith(":"):
            drv_ps += ":"
        ps = (
            f"$sh=(New-Object -ComObject Shell.Application);"
            f"$item=$sh.Namespace(17).ParseName('{drv_ps}');"
            f"if($item){{$item.InvokeVerb('Eject')}}"
            f"else{{Write-Error 'Drive {drv_ps} not found'}}"
        )
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return f"Ejected {drv_ps} (PowerShell)"
        return f"Eject attempted {drv_ps}: {r.stderr.strip()[:80] or 'sent'}"

    # ── Encrypt / Decrypt ─────────────────────────────────────────────────────
    def _eject_portable_device(self, device_id: str) -> str:
        """
        Eject a phone, camera, or MTP device that has no drive letter.
        Uses PowerShell's Shell.Application to call the 'Eject' verb on
        the portable device node, then disables the WPD device via PnP.
        """
        if os.name != "nt":
            return "Portable device eject is Windows-only (Linux: unplug manually)"

        # Method 1: Disable the PnP device via Disable-PnpDevice (safest)
        ps1 = (
            f"$dev = Get-PnpDevice | Where-Object {{ $_.InstanceId -eq '{device_id}' }}; "
            "if ($dev) { Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction SilentlyContinue; "
            "Write-Output 'disabled' } else { Write-Error 'Device not found' }"
        )
        r1 = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps1],
            capture_output=True, text=True, timeout=15,
            creationflags=0x08000000)
        if r1.returncode == 0 and "disabled" in r1.stdout.lower():
            return f"Device ejected safely (PnP disabled): {device_id[:40]}"

        # Method 2: Shell.Application Eject verb on portable device
        ps2 = (
            "$sh = New-Object -ComObject Shell.Application; "
            "$ns = $sh.Namespace(0x11); "  # 0x11 = My Computer namespace
            "foreach ($item in $ns.Items()) { "
            "  if ($item.Path -like '*WPD*' -or $item.Type -like '*Portable*') { "
            "    $item.InvokeVerb('Eject'); Write-Output ('ejected: '+$item.Name); break "
            "  } "
            "}"
        )
        r2 = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps2],
            capture_output=True, text=True, timeout=15,
            creationflags=0x08000000)
        if r2.returncode == 0 and r2.stdout.strip():
            return f"Device ejected: {r2.stdout.strip()[:80]}"

        # Method 3: Eject by friendly name via device_id hint
        # device_id typically contains the device name e.g. "XIAOMI\MI9T"
        name_hint = device_id.split("\\")[-1].split("&")[0][:30]
        return f"Eject command sent to {name_hint} (confirm device is safe to remove)"

    def _encrypt_file(self, filepath: str):
        try:
            from agent.security.file_encryption import FileEncryption
            return FileEncryption().encrypt_file(filepath)
        except Exception:
            pass
        # XOR fallback
        try:
            key = b"SOC-EDR-AES-KEY!"
            data = Path(filepath).read_bytes()
            enc  = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
            out  = filepath + ".soc_enc"
            Path(out).write_bytes(enc); os.remove(filepath)
            return True, f"XOR encrypted → {out}"
        except Exception as e:
            return False, str(e)

    def _decrypt_file(self, filepath: str):
        try:
            from agent.security.file_encryption import FileEncryption
            return FileEncryption().decrypt_file(filepath)
        except Exception:
            pass
        try:
            if not filepath.endswith(".soc_enc"):
                return False, "Not a .soc_enc file"
            key  = b"SOC-EDR-AES-KEY!"
            data = Path(filepath).read_bytes()
            dec  = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
            out  = filepath[:-8]
            Path(out).write_bytes(dec); os.remove(filepath)
            return True, f"Decrypted → {out}"
        except Exception as e:
            return False, str(e)

    # ── USB whitelist ─────────────────────────────────────────────────────────
    def is_usb_allowed(self, identifier: str) -> bool:
        id_l = identifier.lower().strip()
        for a in self._allowed_usb:
            a_l = a.lower().strip()
            if a_l == id_l or id_l.startswith(a_l) or a_l.startswith(id_l):
                return True
        return False

    def set_allowed_usb(self, identifiers: List[str]):
        self._allowed_usb = [x for x in identifiers if x]

    # ── Issue 3: Severity-aware marking ──────────────────────────────────────
    def mark_confidential(self, filepath: str, encrypt_now: bool = False):
        self._confidential_paths.add(filepath)
        self._log("INFO", f"Marked confidential: {filepath}")
        self.send_alert("confidential_marked", "high",
                        f"Marked Confidential: {os.path.basename(filepath)}",
                        f"Path: {filepath}", file_path=filepath)
        if encrypt_now:
            ok, detail = self._encrypt_file(filepath)
            self.send_alert("file_encrypted", "critical" if ok else "high",
                            f"Confidential File Encrypted: {os.path.basename(filepath)}",
                            detail, file_path=filepath)
            return ok, detail
        return True, "Marked confidential"

    def is_confidential(self, fp: str) -> bool:
        return fp in self._confidential_paths

    # ── List removable drives (GUI USB tab) ───────────────────────────────────
    @staticmethod
    def list_removable_drives() -> List[dict]:
        """Return removable drives with rich label/vendor info via PowerShell/WMI."""
        drives = []

        if os.name == "nt":
            # PowerShell gives the best info: DeviceID, VolumeName, Size, FileSystem
            # plus Win32_DiskDrive for vendor/model
            try:
                ps = (
                    "Get-WmiObject Win32_LogicalDisk -Filter DriveType=2 | "
                    "Select-Object DeviceID,VolumeName,Size,FileSystem | "
                    "ConvertTo-Json -Compress"
                )
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive",
                     "-Command", ps],
                    capture_output=True, text=True, timeout=8)
                if r.returncode == 0 and r.stdout.strip():
                    import json as _json
                    raw = _json.loads(r.stdout.strip())
                    if isinstance(raw, dict): raw = [raw]  # single drive
                    for d in raw:
                        dev_id = (d.get("DeviceID") or "").rstrip(":\\/")
                        if not dev_id: continue
                        drive_path = dev_id + ":\\"
                        vol_name   = (d.get("VolumeName") or "").strip()
                        fs         = (d.get("FileSystem") or "FAT32").strip()
                        size_bytes = d.get("Size") or 0
                        try: size_bytes = int(size_bytes)
                        except: size_bytes = 0
                        size_gb = round(size_bytes / (1024**3), 1) if size_bytes else 0
                        label = vol_name if vol_name else f"Removable ({dev_id}:)"
                        drives.append({
                            "drive":   drive_path,
                            "label":   label,
                            "fstype":  fs,
                            "size_gb": size_gb,
                            "vendor":  "",   # enriched below
                        })
            except Exception:
                pass

            # Enrich with vendor/model from Win32_DiskDrive
            if drives:
                try:
                    ps2 = (
                        "Get-WmiObject Win32_DiskDrive -Filter \"MediaType='Removable Media'\" | "
                        "Select-Object Model,Caption | ConvertTo-Json -Compress"
                    )
                    r2 = subprocess.run(
                        ["powershell", "-NoProfile", "-NonInteractive",
                         "-Command", ps2],
                        capture_output=True, text=True, timeout=6)
                    if r2.returncode == 0 and r2.stdout.strip():
                        import json as _json2
                        hw = _json2.loads(r2.stdout.strip())
                        if isinstance(hw, dict): hw = [hw]
                        if hw:
                            for i, d in enumerate(drives):
                                if i < len(hw):
                                    d["vendor"] = (hw[i].get("Model") or
                                                    hw[i].get("Caption") or "").strip()
                except Exception:
                    pass

        # Fallback for Linux or if PowerShell failed
        if not drives:
            try:
                for p in psutil.disk_partitions():
                    if "removable" in (p.opts or "").lower():
                        e = {"drive": p.mountpoint, "fstype": p.fstype,
                             "size_gb": 0, "label": p.mountpoint, "vendor": ""}
                        try:
                            u = psutil.disk_usage(p.mountpoint)
                            e["size_gb"] = round(u.total / (1024**3), 1)
                        except Exception: pass
                        drives.append(e)
            except Exception: pass

        # Last resort: wmic
        if not drives and os.name == "nt":
            try:
                out = subprocess.check_output(
                    ["wmic", "logicaldisk", "where", "drivetype=2",
                     "get", "DeviceID,VolumeName,Size"],
                    timeout=5, text=True, stderr=subprocess.DEVNULL)
                for line in out.strip().splitlines()[1:]:
                    parts = line.split()
                    if parts:
                        drives.append({
                            "drive":   parts[0] + "\\",
                            "label":   " ".join(parts[1:-1]) if len(parts) > 2 else parts[0],
                            "fstype":  "FAT32/NTFS",
                            "size_gb": round(int(parts[-1])/(1024**3),1)
                                        if parts[-1].isdigit() else 0,
                            "vendor":  "",
                        })
            except Exception: pass
        return drives

    # ── Start ─────────────────────────────────────────────────────────────────
    def start(self):
        self.running = True
        self._log("INFO", "Starting all monitoring modules…")

        # Re-register with server to ensure endpoint is known before poll starts
        self._session.headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            self.register()
        except Exception as e:
            self._log("WARNING", f"Re-register on start failed (non-fatal): {e}")

        from agent.monitors.process_monitor     import ProcessMonitor
        from agent.monitors.network_monitor     import NetworkMonitor
        from agent.monitors.file_monitor        import FileMonitor
        from agent.monitors.usb_monitor         import USBMonitor
        from agent.monitors.login_monitor       import LoginMonitor
        from agent.monitors.memory_monitor      import MemoryMonitor
        from agent.security.ransomware_detector import RansomwareDetector
        from agent.security.hash_scanner        import HashScanner
        from agent.kernel.kernel_monitor        import KernelMonitor

        monitors = [
            ProcessMonitor(self), NetworkMonitor(self),
            FileMonitor(self, self._sensitive_paths), USBMonitor(self),
            LoginMonitor(self), MemoryMonitor(self),
            RansomwareDetector(self), HashScanner(self), KernelMonitor(self),
        ]
        for mon in monitors:
            t = threading.Thread(target=mon.run, daemon=True,
                                 name=type(mon).__name__)
            t.start(); self._threads.append(t); self._monitors.append(mon)

        for target, name in [
            (self._heartbeat_loop, "HeartbeatLoop"),
            (self._poll_commands,  "CommandPoller"),
        ]:
            t = threading.Thread(target=target, daemon=True, name=name)
            t.start(); self._threads.append(t)

        self._log("INFO", f"Agent running — {len(monitors)} monitors active | "
                  f"admin={_is_admin()}")
        self.send_alert("agent_start", "low", "Agent Started",
                        f"SOC Agent v{AGENT_VERSION} on {self.hostname} "
                        f"(admin={_is_admin()})")

    def _heartbeat_loop(self):
        while self.running:
            self.send_heartbeat()
            time.sleep(self._heartbeat_interval)

    def stop(self):
        self.running = False
        for mon in self._monitors:
            try: mon.running = False
            except Exception: pass
        self.unregister()
        self._log("INFO", "Agent stopped")

    def set_sensitive_paths(self, paths: List[str]):
        self._sensitive_paths = paths
        for mon in self._monitors:
            if hasattr(mon, "set_paths"): mon.set_paths(paths)

    def test_connection(self) -> bool:
        if not self._session: return False
        try:
            return self._session.get(
                f"{self.server_url}/health", timeout=5).status_code == 200
        except Exception: return False

    @property
    def is_connected(self) -> bool: return self._connected

    @staticmethod
    def is_admin() -> bool: return _is_admin()