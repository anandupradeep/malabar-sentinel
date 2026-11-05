"""
Kernel-Level Monitor (Lightweight Userspace Implementation)
Monitors: process creation, driver loading, privilege escalation, system call anomalies
"""

import logging
import os
import platform
import subprocess
import time
from typing import Set

import psutil

logger = logging.getLogger("kernel-monitor")

SYSTEM_PRIVILEGES = {"SYSTEM", "NT AUTHORITY\\SYSTEM", "root"}
SUSPICIOUS_DRIVERS = {
    "mimikatz_driver", "be4pay", "gdrv", "physmem", "dbutil",
    "probmon", "sen", "winring0", "asmmap64", "rtcore64",
}

PRIVILEGED_PROCESSES = {
    "lsass.exe", "winlogon.exe", "services.exe", "svchost.exe",
    "csrss.exe", "wininit.exe", "smss.exe", "system",
}


class KernelMonitor:
    def __init__(self, agent):
        self.agent = agent
        self.running = False
        self.known_drivers: Set[str] = set()
        self.check_interval = 20
        self._baseline_privileges: dict = {}

    def run(self):
        self.running = True
        logger.info("Kernel monitor started")
        self._load_baseline()
        while self.running:
            try:
                self._monitor_process_creation()
                self._monitor_driver_loading()
                self._monitor_privilege_escalation()
                self._monitor_system_integrity()
            except Exception as e:
                logger.error(f"Kernel monitor error: {e}")
            time.sleep(self.check_interval)

    def _load_baseline(self):
        """Load baseline of normal drivers and process privileges"""
        if platform.system() == "Windows":
            self._load_windows_drivers()
        self._load_process_privileges()

    def _load_windows_drivers(self):
        try:
            result = subprocess.run(
                ["driverquery", "/FO", "CSV"], capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines()[1:]:
                parts = line.strip('"').split('","')
                if parts:
                    self.known_drivers.add(parts[0].lower())
        except Exception:
            pass

    def _load_process_privileges(self):
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                pid = proc.info['pid']
                username = proc.info.get('username') or ''
                self._baseline_privileges[pid] = username
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _monitor_process_creation(self):
        """Detect privileged process creation anomalies"""
        for proc in psutil.process_iter(['pid', 'name', 'username', 'ppid']):
            try:
                pid = proc.info['pid']
                name = (proc.info.get('name') or '').lower()
                username = proc.info.get('username') or ''
                ppid = proc.info.get('ppid', 0)

                # Detect processes spawned from unusual parents
                if name in PRIVILEGED_PROCESSES and ppid:
                    try:
                        parent = psutil.Process(ppid)
                        parent_name = (parent.name() or '').lower()
                        if parent_name not in PRIVILEGED_PROCESSES and parent_name not in {
                            "services.exe", "wininit.exe", "smss.exe"
                        }:
                            # A privileged process spawned from non-standard parent
                            if name == "lsass.exe":
                                self.agent.send_alert(
                                    "lsass_access", "critical",
                                    f"LSASS Spawned from Suspicious Parent",
                                    f"lsass.exe spawned from {parent_name} (PID {ppid}) - "
                                    f"possible credential dumping",
                                    process_name=name, process_pid=pid,
                                    raw_data={"parent": parent_name, "parent_pid": ppid}
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _monitor_driver_loading(self):
        """Detect new/suspicious driver loads"""
        if platform.system() != "Windows":
            return
        try:
            result = subprocess.run(
                ["driverquery", "/FO", "CSV"], capture_output=True, text=True, timeout=10
            )
            current_drivers = set()
            for line in result.stdout.splitlines()[1:]:
                parts = line.strip('"').split('","')
                if parts:
                    driver_name = parts[0].lower()
                    current_drivers.add(driver_name)

                    # Check for known malicious drivers
                    for sus_drv in SUSPICIOUS_DRIVERS:
                        if sus_drv in driver_name:
                            self.agent.send_alert(
                                "rootkit", "critical",
                                f"Suspicious Driver Loaded: {driver_name}",
                                f"Known malicious/vulnerable driver detected: {driver_name}",
                                raw_data={"driver": driver_name}
                            )

                    # New driver since baseline
                    if driver_name not in self.known_drivers:
                        self.agent.send_alert(
                            "new_service", "medium",
                            f"New Driver Loaded: {driver_name}",
                            f"Previously unseen driver loaded: {driver_name}",
                            raw_data={"driver": driver_name}
                        )
                        self.known_drivers.add(driver_name)

        except Exception:
            pass

    def _monitor_privilege_escalation(self):
        """Detect privilege escalation by comparing current vs baseline"""
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                pid = proc.info['pid']
                name = (proc.info.get('name') or '').lower()
                current_user = proc.info.get('username') or ''
                baseline_user = self._baseline_privileges.get(pid)

                if baseline_user and current_user != baseline_user:
                    # Process changed privilege context
                    if current_user in SYSTEM_PRIVILEGES:
                        self.agent.send_alert(
                            "privilege_escalation", "critical",
                            f"Privilege Escalation: {name}",
                            f"Process {name} (PID {pid}) escalated from '{baseline_user}' "
                            f"to '{current_user}'",
                            process_name=name, process_pid=pid,
                            raw_data={"from_user": baseline_user, "to_user": current_user}
                        )
                    self._baseline_privileges[pid] = current_user

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self._baseline_privileges.pop(pid, None)

    def _monitor_system_integrity(self):
        """Monitor critical system file integrity"""
        critical_files = []
        if platform.system() == "Windows":
            system32 = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32")
            critical_files = [
                os.path.join(system32, "ntdll.dll"),
                os.path.join(system32, "kernel32.dll"),
                os.path.join(system32, "lsass.exe"),
            ]
        elif platform.system() == "Linux":
            critical_files = ["/bin/sh", "/usr/bin/sudo", "/etc/passwd", "/etc/shadow"]

        if not hasattr(self, '_file_hashes'):
            self._file_hashes = {}

        import hashlib
        for filepath in critical_files:
            try:
                if not os.path.exists(filepath):
                    continue
                h = hashlib.md5()
                with open(filepath, 'rb') as f:
                    h.update(f.read(4096))
                current_hash = h.hexdigest()

                if filepath in self._file_hashes:
                    if self._file_hashes[filepath] != current_hash:
                        self.agent.send_alert(
                            "rootkit", "emergency",
                            f"Critical System File Modified: {os.path.basename(filepath)}",
                            f"System file integrity check FAILED: {filepath}",
                            file_path=filepath,
                            raw_data={"expected": self._file_hashes[filepath], "actual": current_hash}
                        )
                self._file_hashes[filepath] = current_hash
            except (PermissionError, IOError):
                continue
