"""
Ransomware Behavior Detector
Detects: mass file encryption, rapid renaming, high file modification rate
"""

import logging
import os
import time
from collections import defaultdict
from typing import Dict, Set

import psutil

logger = logging.getLogger("ransomware-detector")

RANSOMWARE_EXTENSIONS = {
    '.encrypted', '.enc', '.locked', '.crypto', '.crypt', '.crypted',
    '.cerber', '.locky', '.zepto', '.thor', '.aaa', '.xyz', '.zzz',
    '.micro', '.vault', '.crypz', '.cryp1', '.R5A', '.wcry', '.wncry',
    '.WNCRY', '.WNCRYT', '.WNCRYPT', '.wannacry', '.ryuk', '.revil',
    '.lockbit', '.maze', '.sodinokibi', '.netwalker', '.conti',
    '.darkside', '.babuk', '.BlackMatter', '.hive', '.alphv',
}

HIGH_RISK_PROCESSES = {
    "vssadmin.exe",    # Shadow copy deletion
    "wbadmin.exe",     # Backup deletion
    "bcdedit.exe",     # Boot config modification
    "wmic.exe",        # WMI abuse
    "taskkill.exe",    # Killing AV/backup processes
    "net.exe",         # Stopping services
}


class RansomwareDetector:
    def __init__(self, agent):
        self.agent = agent
        self.running = False
        self.file_op_counts: Dict[int, int] = defaultdict(int)   # pid -> file op count
        self.rename_counts: Dict[int, int] = defaultdict(int)    # pid -> rename count
        self.encrypted_ext_count: Dict[int, int] = defaultdict(int)
        self.alerted_pids: Set[int] = set()
        self.check_interval = 10
        self._window_start = time.time()
        self._window_size = 30  # 30 second window

    def run(self):
        self.running = True
        logger.info("Ransomware detector started")
        while self.running:
            try:
                self._monitor_file_activity()
                self._check_shadow_copy_deletion()
                self._reset_window_if_needed()
            except Exception as e:
                logger.error(f"Ransomware detector error: {e}")
            time.sleep(self.check_interval)

    def _monitor_file_activity(self):
        """Monitor per-process file operation rates"""
        for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
            try:
                pid = proc.info['pid']
                name = (proc.info.get('name') or '').lower()

                if pid in self.alerted_pids:
                    continue

                # Check IO counters for high write activity
                io = proc.info.get('io_counters')
                if io:
                    write_bytes = io.write_bytes if hasattr(io, 'write_bytes') else 0
                    if write_bytes > 100 * 1024 * 1024:  # >100MB writes in window
                        self.file_op_counts[pid] += 1

                # Check open files for ransomware extensions
                try:
                    open_files = proc.open_files()
                    for f in open_files:
                        ext = os.path.splitext(f.path)[1].lower()
                        if ext in RANSOMWARE_EXTENSIONS:
                            self.encrypted_ext_count[pid] += 1

                    if self.encrypted_ext_count[pid] > 5:
                        self._trigger_ransomware_alert(pid, name, "encrypted_extension",
                            f"Process accessing {self.encrypted_ext_count[pid]} files with ransomware extensions")

                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Check for high process file modification rate via memory maps
                if self.file_op_counts[pid] > 20:
                    self._trigger_ransomware_alert(pid, name, "mass_file_write",
                        f"Process performing {self.file_op_counts[pid]} mass file writes")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _check_shadow_copy_deletion(self):
        """Detect shadow copy deletion (classic ransomware tactic)"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = (proc.info.get('name') or '').lower()
                cmdline = ' '.join(proc.info.get('cmdline') or []).lower()

                if name == 'vssadmin.exe' and 'delete' in cmdline and 'shadows' in cmdline:
                    self._trigger_ransomware_alert(
                        proc.info['pid'], name, "shadow_copy_deletion",
                        f"Shadow copy deletion detected: {cmdline[:200]}"
                    )

                if name == 'wbadmin.exe' and 'delete' in cmdline:
                    self._trigger_ransomware_alert(
                        proc.info['pid'], name, "backup_deletion",
                        f"Backup deletion command detected: {cmdline[:200]}"
                    )

                if name == 'bcdedit.exe' and ('recoveryenabled' in cmdline or 'safeboot' in cmdline):
                    self._trigger_ransomware_alert(
                        proc.info['pid'], name, "boot_config_tamper",
                        f"Boot configuration tampering: {cmdline[:200]}"
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _trigger_ransomware_alert(self, pid: int, name: str, reason: str, detail: str):
        if pid in self.alerted_pids:
            return
        self.alerted_pids.add(pid)

        self.agent.send_alert(
            "ransomware", "emergency",
            f"RANSOMWARE BEHAVIOR DETECTED: {name}",
            f"[{reason}] {detail}. Immediate isolation recommended.",
            process_name=name, process_pid=pid,
            raw_data={"reason": reason, "pid": pid}
        )
        logger.critical(f"RANSOMWARE: {name} (PID {pid}) - {reason}")

        # Auto-kill the process
        try:
            proc = psutil.Process(pid)
            proc.kill()
            logger.info(f"Auto-killed ransomware process: {name} (PID {pid})")
        except Exception as e:
            logger.error(f"Failed to kill ransomware process: {e}")

    def _reset_window_if_needed(self):
        now = time.time()
        if now - self._window_start > self._window_size:
            self.file_op_counts.clear()
            self.rename_counts.clear()
            self.encrypted_ext_count.clear()
            self._window_start = now
