"""
Hash Scanner - calculates SHA256 of suspicious files and compares against malware hash feeds
"""

import hashlib
import logging
import os
import re
import time
from typing import Dict, Set

import psutil

logger = logging.getLogger("hash-scanner")

_SHA256_RE = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)

def _validate_hash_db(raw: Dict[str, str]) -> Dict[str, str]:
    """Return only entries whose key is a valid 64-char SHA-256 hex string."""
    valid: Dict[str, str] = {}
    for h, name in raw.items():
        if _SHA256_RE.match(h):
            valid[h.lower()] = name
        else:
            logger.warning("[hash-scanner] ignoring invalid hash entry (%s chars): %r → %s",
                           len(h), h[:16], name)
    return valid


# Simulated malware hash database (SHA256)
_RAW_KNOWN_MALWARE_HASHES: Dict[str, str] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty file (test)",
    "7bc1e8a98d6e3b7c4f4ad2b1e6f9c8d2a3b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8": "WannaCry Ransomware",
    # The following are NOT SHA-256 and will be filtered out:
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test (MD5 — ignored)",
    "cf8bd9dfddff007f75adf4c2be48005cea317c62": "Zeus Trojan (SHA-1 — ignored)",
}
KNOWN_MALWARE_HASHES: Dict[str, str] = _validate_hash_db(_RAW_KNOWN_MALWARE_HASHES)

SCAN_EXTENSIONS = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.hta', '.msi', '.cmd', '.scr'}


class HashScanner:
    def __init__(self, agent):
        self.agent = agent
        self.running = False
        self.scanned_files: Set[str] = set()
        self.check_interval = 60
        self.known_hashes = KNOWN_MALWARE_HASHES.copy()

    def run(self):
        self.running = True
        logger.info("Hash scanner started")
        while self.running:
            try:
                self._scan_running_processes()
                self._scan_suspicious_directories()
            except Exception as e:
                logger.error(f"Hash scanner error: {e}")
            time.sleep(self.check_interval)

    def hash_file(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, PermissionError, OSError):
            return ""

    def check_hash(self, file_hash: str) -> str:
        """Check hash against known malware database"""
        return self.known_hashes.get(file_hash, "")

    def _scan_running_processes(self):
        """Scan executables of running processes"""
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                exe = proc.info.get('exe')
                if not exe or exe in self.scanned_files:
                    continue
                if not os.path.exists(exe):
                    continue

                ext = os.path.splitext(exe)[1].lower()
                if ext not in SCAN_EXTENSIONS:
                    self.scanned_files.add(exe)
                    continue

                file_hash = self.hash_file(exe)
                if file_hash:
                    malware_name = self.check_hash(file_hash)
                    if malware_name:
                        self.agent.send_alert(
                            "malware_hash", "critical",
                            f"Malware Detected by Hash: {proc.info['name']}",
                            f"Running process matches known malware: {malware_name}. "
                            f"File: {exe}, SHA256: {file_hash[:16]}...",
                            process_name=proc.info['name'],
                            process_pid=proc.info['pid'],
                            file_path=exe,
                            raw_data={"sha256": file_hash, "malware": malware_name}
                        )
                    self.scanned_files.add(exe)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_suspicious_directories(self):
        """Scan high-risk directories for malware"""
        home = os.path.expanduser("~")
        scan_dirs = [
            os.path.join(home, "Downloads"),
            os.path.join(home, "AppData", "Local", "Temp") if os.name == 'nt' else "/tmp",
        ]

        for directory in scan_dirs:
            if not os.path.exists(directory):
                continue
            try:
                for root, _, files in os.walk(directory):
                    for fname in files:
                        ext = os.path.splitext(fname)[1].lower()
                        if ext not in SCAN_EXTENSIONS:
                            continue
                        fpath = os.path.join(root, fname)
                        if fpath in self.scanned_files:
                            continue
                        file_hash = self.hash_file(fpath)
                        if file_hash:
                            malware = self.check_hash(file_hash)
                            if malware:
                                self.agent.send_alert(
                                    "malware_hash", "critical",
                                    f"Malware File Found: {fname}",
                                    f"File matches known malware: {malware}. Path: {fpath}",
                                    file_path=fpath,
                                    raw_data={"sha256": file_hash, "malware": malware}
                                )
                        self.scanned_files.add(fpath)
            except PermissionError:
                continue
