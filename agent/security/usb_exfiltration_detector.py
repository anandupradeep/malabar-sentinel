"""
USB Exfiltration Detector
Advanced detection of data theft via removable media
"""

import hashlib
import logging
import os
import time
from typing import Dict, List, Set

logger = logging.getLogger("usb-exfil-detector")

SENSITIVE_EXTENSIONS = {
    # Documents
    '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.csv', '.rtf', '.odt', '.ods', '.odp',
    # Data / DB
    '.mdb', '.accdb', '.db', '.sqlite', '.sql', '.json', '.xml',
    # Credentials / Keys
    '.key', '.pem', '.p12', '.pfx', '.kdbx', '.keystore',
    '.ppk', '.cer', '.crt', '.p7b',
    # Source code (IP)
    '.py', '.java', '.cs', '.cpp', '.h', '.go', '.rb',
    # Archives (bulk exfil)
    '.zip', '.rar', '.7z', '.tar', '.gz',
    # Config
    '.conf', '.config', '.env', '.ini', '.yaml', '.yml',
}

SUSPICIOUS_COPY_THRESHOLD = 10  # files
LARGE_COPY_SIZE_MB = 50


class USBExfiltrationDetector:
    """
    Monitors USB drives for suspicious file copy operations.
    Tracks file counts, total size, and sensitive file types.
    """

    def __init__(self, agent):
        self.agent = agent
        self.running = False
        self._drive_snapshots: Dict[str, Dict] = {}  # drive -> {path: size}
        self._alerted_drives: Set[str] = set()
        self.check_interval = 15

    def run(self):
        self.running = True
        logger.info("USB Exfiltration Detector started")
        while self.running:
            try:
                self._scan_usb_drives()
            except Exception as e:
                logger.error(f"USB exfil detector error: {e}")
            time.sleep(self.check_interval)

    def _get_usb_drives(self) -> List[str]:
        """Platform-aware USB drive detection"""
        import platform
        drives = []
        if platform.system() == "Windows":
            try:
                import subprocess
                result = subprocess.run(
                    ["wmic", "logicaldisk", "where", "drivetype=2", "get", "deviceid"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if len(line) == 2 and line[1] == ':':
                        drives.append(line + "\\")
            except Exception:
                pass
        else:
            for base in ["/media", "/mnt", "/run/media"]:
                if os.path.exists(base):
                    for item in os.listdir(base):
                        full = os.path.join(base, item)
                        if os.path.ismount(full):
                            drives.append(full)
        return drives

    def _scan_drive(self, drive: str) -> Dict:
        """Take a snapshot of a drive's contents"""
        snapshot = {}
        total_size = 0
        try:
            for root, _, files in os.walk(drive):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        size = os.path.getsize(fpath)
                        snapshot[fpath] = size
                        total_size += size
                    except OSError:
                        pass
        except (PermissionError, OSError):
            pass
        return {"files": snapshot, "total_size": total_size}

    def _scan_usb_drives(self):
        drives = self._get_usb_drives()
        for drive in drives:
            current = self._scan_drive(drive)
            previous = self._drive_snapshots.get(drive)

            if previous is None:
                # First scan — baseline
                self._drive_snapshots[drive] = current
                self._check_initial_contents(drive, current)
                continue

            # Detect new files added since last scan
            new_files = set(current["files"]) - set(previous["files"])
            if new_files:
                self._analyze_new_files(drive, list(new_files), current["total_size"])

            self._drive_snapshots[drive] = current

    def _check_initial_contents(self, drive: str, snapshot: Dict):
        """Check drive contents when first detected"""
        if drive in self._alerted_drives:
            return
        sensitive = [
            f for f in snapshot["files"]
            if os.path.splitext(f)[1].lower() in SENSITIVE_EXTENSIONS
        ]
        total_mb = snapshot["total_size"] / (1024 * 1024)

        if len(sensitive) > 0:
            self._alerted_drives.add(drive)
            self.agent.send_alert(
                "usb_exfiltration", "critical",
                f"Sensitive Files Found on USB: {drive}",
                f"USB drive {drive} contains {len(sensitive)} sensitive file(s), "
                f"total {total_mb:.1f} MB. Files: {', '.join(os.path.basename(f) for f in sensitive[:5])}",
                raw_data={
                    "drive": drive,
                    "sensitive_count": len(sensitive),
                    "sensitive_files": [f for f in sensitive[:10]],
                    "total_mb": round(total_mb, 2)
                }
            )

    def _analyze_new_files(self, drive: str, new_files: List[str], total_size: int):
        """Analyze newly added files for exfiltration patterns"""
        sensitive_new = [f for f in new_files
                         if os.path.splitext(f)[1].lower() in SENSITIVE_EXTENSIONS]
        total_mb = total_size / (1024 * 1024)
        new_mb = sum(
            self._drive_snapshots.get(drive, {}).get("files", {}).get(f, 0)
            for f in new_files
        ) / (1024 * 1024)

        if sensitive_new:
            self.agent.send_alert(
                "usb_exfiltration", "critical",
                f"Sensitive Files Copied to USB",
                f"{len(sensitive_new)} sensitive file(s) copied to USB {drive}: "
                f"{', '.join(os.path.basename(f) for f in sensitive_new[:3])}",
                raw_data={
                    "drive": drive,
                    "new_files": len(new_files),
                    "sensitive_files": sensitive_new[:10],
                    "size_mb": round(new_mb, 2)
                }
            )
        elif len(new_files) >= SUSPICIOUS_COPY_THRESHOLD:
            self.agent.send_alert(
                "usb_exfiltration", "high",
                f"Bulk File Copy to USB Detected",
                f"{len(new_files)} files ({new_mb:.1f} MB) copied to USB drive {drive} — "
                f"possible bulk exfiltration",
                raw_data={
                    "drive": drive,
                    "new_files": len(new_files),
                    "size_mb": round(new_mb, 2)
                }
            )
        elif new_mb > LARGE_COPY_SIZE_MB:
            self.agent.send_alert(
                "usb_exfiltration", "medium",
                f"Large Data Transfer to USB",
                f"{new_mb:.1f} MB transferred to USB drive {drive}",
                raw_data={"drive": drive, "size_mb": round(new_mb, 2)}
            )

    def compute_file_hash(self, filepath: str) -> str:
        """SHA256 hash of a file on USB"""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ""
