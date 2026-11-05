"""
Malabar Sentinel — Process Monitor
• Detects malware, suspicious processes, UWP/Store apps (WhatsApp etc.)
• 3-method kill: psutil → taskkill → PowerShell Stop-Process
• 3s poll interval for faster detection
"""
import json, logging, os, subprocess, time
import psutil

logger = logging.getLogger("process-monitor")

# CREATE_NO_WINDOW — must be defined here so every subprocess call in this
# module suppresses console flash on Windows.  agent_core defines its own
# copy; we cannot import from there because that would create a circular
# dependency (agent_core imports ProcessMonitor lazily, but a top-level import
# of agent_core here would force it to load before the patch in main.py runs).
WIN_FLAGS = 0x08000000 if os.name == "nt" else 0

MALWARE_NAMES = {
    "mimikatz","meterpreter","cobalt","beacon","empire",
    "powersploit","veil","shellcode","exploit","payload",
    "nc.exe","ncat.exe","netcat","psexec","wce.exe",
    "procdump","lsass_dump","fgdump","pwdump",
}
SUSPICIOUS_PATHS = ("\\temp\\","\\tmp\\","\\appdata\\local\\temp\\","%temp%","\\downloads\\")
SUSPICIOUS_ARGS  = (
    "-enc","-encodedcommand","downloadstring","iex","invoke-expression",
    "bypass","hidden","windowstyle","frombase64string","webclient",
    "shellcode","virtualalloc","createthread",
)

# System-level Windows processes — never alert on these, never show for kill
# (killing them would crash Windows)
KNOWN_SAFE_APPS = {
    "runtimebroker.exe","applicationframehost.exe","startmenuexperiencehost.exe",
    "searchapp.exe","lockapp.exe","shellexperiencehost.exe","textinputhost.exe",
    "systemsettings.exe","settingssynchost.exe","useroobebroker.exe",
    "fontdrvhost.exe","dwm.exe","winlogon.exe","wininit.exe",
    "csrss.exe","lsass.exe","smss.exe","services.exe",
}

# Apps that ARE user processes — show in kill list but don't raise alerts
# (WhatsApp, Teams, etc should be visible for termination from SOC)
USER_APPS_NO_ALERT = {
    "whatsapp.exe","teams.exe","slack.exe","zoom.exe","discord.exe",
    "telegram.exe","signal.exe","spotify.exe","netflix.exe","onedrive.exe",
    "dropbox.exe","googledrive.exe","microsoftedgewebview2.exe",
    "chrome.exe","firefox.exe","msedge.exe","opera.exe","brave.exe",
    "vlc.exe","wmplayer.exe","winamp.exe",
    "notepad.exe","notepad++.exe","wordpad.exe",
    "taskmgr.exe","msiexec.exe",
}

class ProcessMonitor:
    def __init__(self, agent):
        self.agent          = agent
        self.running        = False
        self._seen_pids     = set()
        self._allowed_cache = set()
        self._allowed_ts    = 0.0
        self.check_interval = 3   # 3s — faster than default 5s

    def run(self):
        self.running    = True
        self._seen_pids = {p.pid for p in psutil.process_iter()}
        logger.info("ProcessMonitor started — %d existing PIDs", len(self._seen_pids))
        _tick = 0
        while self.running:
            try:
                self._check_processes()
                # PowerShell scan every 15s to catch UWP/Store apps
                # PowerShell process scan DISABLED — caused a new console window
                # every 15s. The heartbeat in agent_core.py already uses psutil
                # (which sees ALL processes including VS Code) + PS supplement.
                # Prune dead PIDs to prevent unbounded growth
                if len(self._seen_pids) > 2000:
                    alive = {p.pid for p in psutil.process_iter()}
                    self._seen_pids &= alive
            except Exception as e:
                logger.error("ProcessMonitor error: %s", e)
            time.sleep(self.check_interval)
            _tick += 1

    # ── Allowed list (cached 30s) ─────────────────────────────────────────────
    def _get_allowed(self) -> set:
        now = time.time()
        if now - self._allowed_ts < 30:
            return self._allowed_cache
        default = {
            # Core Windows processes only — apps must appear in the kill list
            "explorer.exe","svchost.exe","lsass.exe",
            "dwm.exe","taskhostw.exe","sihost.exe","ctfmon.exe",
            "winlogon.exe","wininit.exe","csrss.exe","services.exe",
            "spoolsv.exe","searchindexer.exe","fontdrvhost.exe",
            # Agent's own processes — don't show them for termination
            "python.exe","python3.exe","pythonw.exe",
        }
        try:
            rules_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                '..', 'config', 'agent_rules.json')
            with open(rules_path) as f:
                rules_list = json.load(f).get('allowed_processes', [])
                if rules_list:
                    default = {p.lower() for p in rules_list}
        except Exception:
            pass
        self._allowed_cache = default
        self._allowed_ts    = now
        return default

    # ── Main psutil scan ──────────────────────────────────────────────────────
    def _check_processes(self):
        allowed = self._get_allowed()
        for p in psutil.process_iter(['pid','name','exe','cmdline']):
            try:
                info = p.info
                pid  = info['pid']
                name = (info['name'] or '').lower()
                exe  = (info['exe']  or '').lower()
                cmdl = ' '.join(info['cmdline'] or []).lower()

                if any(m in name for m in MALWARE_NAMES):
                    if pid not in self._seen_pids:
                        self._alert(pid, info['name'], exe, "Malware name match")
                    continue

                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)

                # System processes: never alert, skip
                if name in KNOWN_SAFE_APPS:
                    continue
                # User apps (WhatsApp, Teams etc): skip ALERT but keep in seen list
                # so they appear in process list for manual termination
                if name in USER_APPS_NO_ALERT:
                    continue
                if any(sp in exe for sp in SUSPICIOUS_PATHS):
                    self._alert(pid, info['name'], exe, "Launched from suspicious path")
                elif any(a in cmdl for a in SUSPICIOUS_ARGS):
                    self._alert(pid, info['name'], exe, "Suspicious command-line arguments")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    # ── PowerShell scan for UWP/Store/sandboxed apps ─────────────────────────
    def _check_via_powershell(self):
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=8,
                creationflags=WIN_FLAGS)
            if r.returncode != 0 or not r.stdout.strip():
                return
            procs = json.loads(r.stdout.strip())
            if isinstance(procs, dict):
                procs = [procs]
            allowed = self._get_allowed()
            for proc in procs:
                pid  = proc.get("Id", 0)
                raw  = (proc.get("ProcessName") or "")
                name = raw.lower() + ".exe"
                path = (proc.get("Path") or "").lower()
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)
                # System processes: never alert, skip
                if name in KNOWN_SAFE_APPS:
                    continue
                # User apps (WhatsApp, Teams etc): skip ALERT but keep in seen list
                # so they appear in process list for manual termination
                if name in USER_APPS_NO_ALERT:
                    continue
                if any(m in name for m in MALWARE_NAMES):
                    self._alert(pid, name, path, "Malware name match (PS scan)")
        except Exception as e:
            logger.debug("PS process scan error: %s", e)

    # ── Kill (3-method) ───────────────────────────────────────────────────────
    @staticmethod
    def kill(pid: int = None, name: str = None) -> tuple:
        """
        Kill by PID or name. Returns (success: bool, detail: str).
        Methods: psutil → taskkill /F → PowerShell Stop-Process
        """
        killed, errors = [], []

        if name:
            proc = name.split()[0]
            # Method 1: taskkill /F /IM
            r = subprocess.run(["taskkill", "/F", "/IM", proc],
                               capture_output=True, text=True, timeout=10,
                                   creationflags=WIN_FLAGS)
            if r.returncode == 0 or "SUCCESS" in r.stdout.upper():
                killed.append(f"taskkill:{proc}")
            else:
                # Method 2: taskkill /F /IM /T (kill entire tree)
                r2 = subprocess.run(["taskkill", "/F", "/IM", proc, "/T"],
                                    capture_output=True, text=True, timeout=10,
                                        creationflags=WIN_FLAGS)
                if r2.returncode == 0 or "SUCCESS" in r2.stdout.upper():
                    killed.append(f"taskkill/tree:{proc}")
                else:
                    # Method 3: PowerShell Stop-Process (works for UWP/Store apps)
                    clean = proc.replace(".exe", "")
                    ps = f"Stop-Process -Name '{clean}' -Force -ErrorAction SilentlyContinue"
                    r3 = subprocess.run(
                        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                        capture_output=True, text=True, timeout=10,
                            creationflags=WIN_FLAGS)
                    if r3.returncode == 0:
                        killed.append(f"powershell:{proc}")
                    else:
                        errors.append(r.stderr.strip() or f"Cannot terminate {proc}")

        if pid and not killed:
            try:
                psutil.Process(int(pid)).kill()
                killed.append(f"psutil:{pid}")
            except psutil.AccessDenied:
                r = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                   capture_output=True, text=True, timeout=10,
                                       creationflags=WIN_FLAGS)
                if r.returncode == 0:
                    killed.append(f"taskkill:{pid}")
                else:
                    ps = f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"
                    r2 = subprocess.run(
                        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                        capture_output=True, text=True, timeout=10,
                            creationflags=WIN_FLAGS)
                    if r2.returncode == 0:
                        killed.append(f"powershell:{pid}")
                    else:
                        errors.append(f"Access denied — PID {pid}")
            except psutil.NoSuchProcess:
                errors.append(f"PID {pid} not found")

        if killed:
            return True, f"Terminated: {', '.join(killed)}"
        return False, f"Failed: {'; '.join(errors) or 'No matching process'}"

    def _alert(self, pid, name, exe, reason):
        self.agent.send_alert(
            "suspicious_process", "high",
            f"Suspicious Process: {name}",
            f"{reason} — PID {pid} — {exe}",
            process_name=name, process_pid=pid,
            raw_data={"pid": pid, "name": name, "exe": exe, "reason": reason}
        )
        logger.warning("Suspicious process: %s (PID %s) — %s", name, pid, reason)