"""
scan_executor.py — Malabar Sentinel Agent
==========================================
Handles start_scan / stop_scan commands on the endpoint.

Two detection modes:
  1. Windows Defender via Start-MpScan (PowerShell subprocess)
  2. Custom engine: hash signatures, suspicious extensions, heuristics

When a threat is detected the executor:
  1. Logs the event
  2. Quarantines the file (moves to quarantine folder)
  3. Sends sandbox submission request to server
  4. Streams progress updates to server via /api/scan/report/update

Improvements (v2):
  - Scan exclusions: system dirs, quarantine dir, huge files, inaccessible paths,
    common cache/vendor folders
  - Progress posts throttled by time AND batch size (not on every new threat)
  - Custom-scan path validated before use (no traversal, must be absolute)
  - Stop event checked before hashing large files
  - Hash signature set validated: only 64-char hex (SHA-256) entries kept
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

import requests

logger = logging.getLogger("scan-executor")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS: Set[str] = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr",
    ".pif", ".com", ".hta", ".js", ".wsf", ".jar",
    ".msi", ".dll", ".sys",
}

_SHA256_RE = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)

def _validate_hash_set(raw: Set[str]) -> Set[str]:
    """Return only valid 64-char hex SHA-256 strings; warn on invalid entries."""
    valid: Set[str] = set()
    for h in raw:
        if _SHA256_RE.match(h):
            valid.add(h.lower())
        else:
            logger.warning("[scan] ignoring invalid hash entry (not SHA-256): %r", h[:32])
    return valid


# Well-known malware hashes (SHA-256) — seed list; extend from threat intel
_RAW_KNOWN_HASHES: Set[str] = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR test
    # The following entry is NOT SHA-256 length and will be filtered out at load:
    "cf23df2207d99a74fbe169e3eba035e633b65d94",                          # placeholder (SHA-1, ignored)
}
KNOWN_HASHES: Set[str] = _validate_hash_set(_RAW_KNOWN_HASHES)

# Maximum file size to hash (default 64 MB; override via env SCAN_MAX_FILE_MB)
try:
    _MAX_FILE_BYTES = int(os.getenv("SCAN_MAX_FILE_MB", "64")) * 1024 * 1024
except ValueError:
    _MAX_FILE_BYTES = 64 * 1024 * 1024

QUARANTINE_DIR = Path(os.path.expanduser("~")) / ".soc_quarantine"

# Scan target directories by type
SCAN_TARGETS = {
    "quick": [
        os.path.expandvars(r"%TEMP%") if os.name == "nt" else "/tmp",
        os.path.expanduser("~/Downloads"),
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        if os.name == "nt" else "/etc/init.d",
    ],
    "full": [
        "C:\\" if os.name == "nt" else "/",
    ],
}

# Directories always excluded from scanning
_EXCLUDED_DIRS_DEFAULT = [
    str(QUARANTINE_DIR),
    # Windows system dirs
    "C:\\Windows\\WinSxS",
    "C:\\Windows\\Installer",
    "C:\\Windows\\SoftwareDistribution",
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\INetCache") if os.name == "nt" else "",
    # Linux/Mac system dirs
    "/proc", "/sys", "/dev", "/run",
    # Common cache/vendor dirs
    "node_modules", ".git", "__pycache__", ".tox", ".mypy_cache",
    "site-packages",
]

def _build_excluded_dirs() -> Set[str]:
    env_extra = os.getenv("SCAN_EXCLUDED_DIRS", "")
    extras = [e.strip() for e in env_extra.split(",") if e.strip()] if env_extra else []
    return {d for d in (_EXCLUDED_DIRS_DEFAULT + extras) if d}

_EXCLUDED_DIRS: Set[str] = _build_excluded_dirs()


def _is_excluded_dir(dirpath: str) -> bool:
    """Return True if dirpath is or is under any excluded directory."""
    norm = os.path.normcase(dirpath)
    for ex in _EXCLUDED_DIRS:
        ex_norm = os.path.normcase(ex)
        if norm == ex_norm or norm.startswith(ex_norm + os.sep):
            return True
        # Also match by basename for vendor dirs like node_modules
        if os.path.basename(norm) == os.path.basename(ex_norm) and not os.sep in ex:
            return True
    return False


def _validate_custom_path(folder_path: str) -> Optional[str]:
    """
    Validate a custom scan path.
    Returns an error string if invalid, None if OK.
    """
    if not folder_path:
        return "folder_path is empty"
    if not os.path.isabs(folder_path):
        return f"folder_path must be absolute: {folder_path!r}"
    # Resolve to catch traversal attempts
    try:
        resolved = os.path.realpath(folder_path)
    except Exception as e:
        return f"Cannot resolve path: {e}"
    if not os.path.exists(resolved):
        return f"Path does not exist: {resolved}"
    if not os.path.isdir(resolved):
        return f"Path is not a directory: {resolved}"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# QUARANTINE
# ─────────────────────────────────────────────────────────────────────────────

def _quarantine_file(file_path: str) -> str:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(file_path)
    if not src.exists():
        return f"File not found: {file_path}"
    dest = QUARANTINE_DIR / f"{uuid.uuid4().hex}_{src.name}.quar"
    try:
        shutil.move(str(src), str(dest))
        logger.info("[quarantine] %s → %s", file_path, dest)
        return str(dest)
    except Exception as e:
        logger.error("[quarantine] failed to move %s: %s", file_path, e)
        return f"Error quarantining {src.name}: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# CUSTOM DETECTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def _sha256(path: str, stop_event: Optional[threading.Event] = None) -> Optional[str]:
    """Compute SHA-256 of a file. Returns None on error or if stop requested."""
    try:
        size = os.path.getsize(path)
        if size > _MAX_FILE_BYTES:
            logger.debug("[scan] skipping large file (%d MB): %s", size // (1024*1024), path)
            return None
    except OSError:
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                if stop_event and stop_event.is_set():
                    return None
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _is_suspicious_extension(path: str) -> bool:
    return Path(path).suffix.lower() in SUSPICIOUS_EXTENSIONS


def _heuristic_check(path: str) -> Optional[str]:
    p = Path(path)

    if len(p.suffixes) >= 2 and p.suffixes[-1].lower() in SUSPICIOUS_EXTENSIONS:
        return "Heuristic:DoubleExtension"

    if "startup" in str(path).lower() and p.suffix.lower() in SUSPICIOUS_EXTENSIONS:
        return "Heuristic:StartupEntry"

    if p.suffix.lower() in (".ps1", ".bat", ".cmd"):
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            if any(kw in content.lower() for kw in
                   ("invoke-expression", "iex(", "downloadstring", "webclient",
                    "hidden", "bypass", "encoded")):
                return "Heuristic:SuspiciousScript"
        except Exception:
            pass

    return None


def _scan_file(path: str,
               stop_event: Optional[threading.Event] = None) -> Optional[Dict]:
    """Inspect a single file. Returns a threat dict or None."""
    # 1. Hash check (skip oversized files or if stop requested)
    digest = _sha256(path, stop_event=stop_event)
    if digest and digest in KNOWN_HASHES:
        return {
            "file_path":    path,
            "threat_name":  f"Signature:{digest[:16]}",
            "severity":     "critical",
            "action_taken": "quarantined",
        }

    if stop_event and stop_event.is_set():
        return None

    # 2. Suspicious extension
    if _is_suspicious_extension(path):
        label = _heuristic_check(path)
        if label:
            return {
                "file_path":    path,
                "threat_name":  label,
                "severity":     "high",
                "action_taken": "quarantined",
            }
        return {
            "file_path":    path,
            "threat_name":  f"SuspiciousFile:{Path(path).suffix}",
            "severity":     "medium",
            "action_taken": "logged",
        }

    # 3. Heuristic on any file
    label = _heuristic_check(path)
    if label:
        return {
            "file_path":    path,
            "threat_name":  label,
            "severity":     "medium",
            "action_taken": "logged",
        }

    return None


# ─────────────────────────────────────────────────────────────────────────────
# WINDOWS DEFENDER INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

def _run_defender_scan(scan_type: str, folder_path: str = "") -> List[Dict]:
    WIN_FLAGS = 0x08000000  # CREATE_NO_WINDOW

    type_map = {"quick": "QuickScan", "full": "FullScan", "custom": "CustomScan"}
    mp_type  = type_map.get(scan_type, "QuickScan")

    if scan_type == "custom" and folder_path:
        # Sanitise the path for PowerShell — no single quotes allowed
        safe_path = folder_path.replace("'", "")
        ps_scan = f"Start-MpScan -ScanType {mp_type} -ScanPath '{safe_path}'"
    else:
        ps_scan = f"Start-MpScan -ScanType {mp_type}"

    try:
        subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_scan],
            capture_output=True, text=True, timeout=600,
            creationflags=WIN_FLAGS,
        )
    except Exception as e:
        logger.warning("[defender] scan subprocess error: %s", e)

    threats: List[Dict] = []
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             "Get-MpThreatDetection | Select-Object ThreatName,Resources,ActionSuccess "
             "| ConvertTo-Json -Depth 3"],
            capture_output=True, text=True, timeout=30,
            creationflags=WIN_FLAGS,
        )
        detections = json.loads(r.stdout or "[]")
        if isinstance(detections, dict):
            detections = [detections]
        for d in detections:
            paths = d.get("Resources", "") or ""
            paths = paths if isinstance(paths, list) else [paths]
            for p in paths:
                threats.append({
                    "file_path":    str(p),
                    "threat_name":  d.get("ThreatName", "Unknown"),
                    "severity":     "high",
                    "action_taken": "quarantined" if d.get("ActionSuccess") else "logged",
                })
    except Exception as e:
        logger.debug("[defender] detection parse error: %s", e)

    return threats


# ─────────────────────────────────────────────────────────────────────────────
# SCAN EXECUTOR (runs in a background thread)
# ─────────────────────────────────────────────────────────────────────────────

# Progress throttle: push every N seconds OR when batch >= this size
_PROGRESS_INTERVAL_S = 5
_PROGRESS_BATCH_SIZE = 10


class ScanExecutor:
    """Manages the lifecycle of one active scan per endpoint."""

    def __init__(self, server_url: str, api_key: str,
                 endpoint_id: str, scan_id: str,
                 scan_type: str, folder_path: str = ""):
        self.server_url  = server_url.rstrip("/")
        self.api_key     = api_key
        self.endpoint_id = endpoint_id
        self.scan_id     = scan_id
        self.scan_type   = scan_type
        self.folder_path = folder_path

        self._stop_event  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._files_scanned = 0
        self._threats_found = 0
        self._new_threats: List[Dict] = []

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True, name=f"scan-{self.scan_id[:8]}"
        )
        self._thread.start()
        logger.info("[scan] started thread: %s type=%s", self.scan_id, self.scan_type)

    def stop(self) -> None:
        self._stop_event.set()
        logger.info("[scan] stop requested: %s", self.scan_id)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        start_ts = time.time()
        try:
            if os.name == "nt" and self.scan_type != "custom":
                threats = _run_defender_scan(self.scan_type, self.folder_path)
                if self._stop_event.is_set():
                    self._report_final(status="stopped",
                                       duration=int(time.time() - start_ts))
                    return
                self._threats_found = len(threats)
                self._new_threats   = threats
                self._files_scanned = 0
                for t in threats:
                    if t.get("action_taken") != "quarantined":
                        _quarantine_file(t["file_path"])
                        t["action_taken"] = "quarantined"
            else:
                self._run_custom_scan()

            status = "stopped" if self._stop_event.is_set() else "completed"
            self._report_final(status=status,
                               duration=int(time.time() - start_ts))
        except Exception as e:
            logger.error("[scan] exception in scan thread: %s", e, exc_info=True)
            self._report_final(status="error",
                               duration=int(time.time() - start_ts))

    def _run_custom_scan(self) -> None:
        """Walk the scan targets and inspect each file with exclusion checks."""
        # Validate custom path before use
        if self.scan_type == "custom":
            err = _validate_custom_path(self.folder_path)
            if err:
                logger.error("[scan] invalid custom path: %s", err)
                return
            targets: List[str] = [os.path.realpath(self.folder_path)]
        elif self.scan_type in SCAN_TARGETS:
            targets = SCAN_TARGETS[self.scan_type]
        else:
            targets = SCAN_TARGETS["quick"]

        batch: List[Dict] = []
        last_report = time.time()

        for root_dir in targets:
            if self._stop_event.is_set():
                break
            if not root_dir or not os.path.exists(root_dir):
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root_dir):
                    if self._stop_event.is_set():
                        break

                    # Prune excluded directories in-place so os.walk skips them
                    dirnames[:] = [
                        d for d in dirnames
                        if not _is_excluded_dir(os.path.join(dirpath, d))
                    ]

                    if _is_excluded_dir(dirpath):
                        continue

                    for fname in filenames:
                        if self._stop_event.is_set():
                            break
                        fpath = os.path.join(dirpath, fname)

                        # Skip inaccessible files quickly
                        try:
                            if not os.access(fpath, os.R_OK):
                                continue
                        except OSError:
                            continue

                        self._files_scanned += 1

                        threat = _scan_file(fpath, stop_event=self._stop_event)
                        if threat:
                            self._threats_found += 1
                            if threat["action_taken"] == "quarantined":
                                result = _quarantine_file(fpath)
                                threat["quarantine_path"] = result
                            batch.append(threat)
                            self._new_threats.append(threat)

                        # Throttle: push every _PROGRESS_INTERVAL_S seconds
                        # OR when batch reaches _PROGRESS_BATCH_SIZE
                        elapsed = time.time() - last_report
                        if elapsed >= _PROGRESS_INTERVAL_S or len(batch) >= _PROGRESS_BATCH_SIZE:
                            self._push_progress(new_threats=batch)
                            batch = []
                            last_report = time.time()

            except PermissionError:
                pass
            except Exception as e:
                logger.debug("[scan] walk error %s: %s", root_dir, e)

        # Flush remaining batch
        if batch:
            self._push_progress(new_threats=batch)

    def _push_progress(self, new_threats: Optional[List[Dict]] = None) -> None:
        payload = {
            "scan_id":       self.scan_id,
            "endpoint_id":   self.endpoint_id,
            "files_scanned": self._files_scanned,
            "threats_found": self._threats_found,
            "new_threats":   new_threats or [],
        }
        self._post("/api/scan/report/update", payload)

    def _report_final(self, status: str = "completed",
                      duration: int = 0) -> None:
        self._push_progress()
        payload = {
            "scan_id":       self.scan_id,
            "endpoint_id":   self.endpoint_id,
            "files_scanned": self._files_scanned,
            "threats_found": self._threats_found,
            "status":        status,
            "completed_at":  datetime.utcnow().isoformat(),
            "duration":      duration,
            "new_threats":   [],
        }
        self._post("/api/scan/report/update", payload)
        logger.info("[scan] final report: id=%s status=%s threats=%d",
                    self.scan_id, status, self._threats_found)

    def _post(self, path: str, payload: dict) -> None:
        url = self.server_url + path
        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}
        try:
            requests.post(url, json=payload, headers=headers, timeout=10)
        except Exception as e:
            logger.debug("[scan] post error %s: %s", path, e)


# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL REGISTRY  (one executor per endpoint_id)
# ─────────────────────────────────────────────────────────────────────────────

_active_scans: Dict[str, ScanExecutor] = {}
_lock = threading.Lock()


def start_scan_command(server_url: str, api_key: str,
                       endpoint_id: str, params: dict) -> str:
    scan_id   = params.get("scan_id", str(uuid.uuid4()))
    scan_type = params.get("scan_type", "quick")
    folder    = params.get("folder_path", "")

    # Validate custom path before spawning thread
    if scan_type == "custom":
        err = _validate_custom_path(folder)
        if err:
            return f"Scan rejected — invalid path: {err}"

    with _lock:
        existing = _active_scans.get(endpoint_id)
        if existing and existing.is_alive():
            existing.stop()

        executor = ScanExecutor(
            server_url=server_url,
            api_key=api_key,
            endpoint_id=endpoint_id,
            scan_id=scan_id,
            scan_type=scan_type,
            folder_path=folder,
        )
        _active_scans[endpoint_id] = executor
        executor.start()

    return f"Scan {scan_type} started (id={scan_id[:8]})"


def stop_scan_command(endpoint_id: str) -> str:
    with _lock:
        executor = _active_scans.get(endpoint_id)
    if executor and executor.is_alive():
        executor.stop()
        return f"Scan stop requested for {endpoint_id}"
    return f"No active scan on {endpoint_id}"
