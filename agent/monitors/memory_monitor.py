"""
Memory Monitor - detects memory-based malware: DLL injection, process hollowing, reflective loading
"""

import ctypes
import logging
import platform
import time
from typing import Dict, Set

import psutil

logger = logging.getLogger("memory-monitor")

SUSPICIOUS_MEMORY_PATTERNS = [
    b"MZ",          # PE header in unexpected region
    b"TVqQ",        # Base64-encoded PE header
    b"4D5A",        # Hex-encoded MZ
]

HOLLOWING_INDICATORS = [
    "ntdll.dll", "kernel32.dll", "kernelbase.dll",
]

INJECTION_SUSPECT_PROCESSES = {
    "notepad.exe", "calc.exe", "mspaint.exe",
    "svchost.exe", "explorer.exe", "iexplore.exe",
}


class MemoryMonitor:
    def __init__(self, agent):
        self.agent = agent
        self.running = False
        self.scanned_pids: Set[int] = set()
        self.suspicious_pids: Set[int] = set()
        self.check_interval = 30
        self._baseline_modules: Dict[int, Set[str]] = {}

    def run(self):
        self.running = True
        logger.info("Memory monitor started")
        while self.running:
            try:
                self._scan_memory()
            except Exception as e:
                logger.error(f"Memory monitor error: {e}")
            time.sleep(self.check_interval)

    def _scan_memory(self):
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = (proc.info.get('name') or '').lower()

                if pid in self.suspicious_pids:
                    continue

                # Check loaded DLLs/modules for anomalies
                self._check_loaded_modules(proc, name)

                # Check memory maps for suspicious regions
                if platform.system() == "Windows":
                    self._check_windows_memory(proc, name)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _check_loaded_modules(self, proc: psutil.Process, name: str):
        """Check for unusual DLL loads"""
        try:
            maps = proc.memory_maps()
            module_paths = set(m.path.lower() for m in maps if m.path)

            # Detect modules loaded from temp/suspicious paths
            suspicious_modules = []
            for path in module_paths:
                if any(p in path for p in ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"]):
                    suspicious_modules.append(path)

            if suspicious_modules:
                self.suspicious_pids.add(proc.pid)
                self.agent.send_alert(
                    "dll_injection", "critical",
                    f"Suspicious DLL Loaded in {name}",
                    f"Process {name} (PID {proc.pid}) loaded DLL from suspicious path: "
                    f"{suspicious_modules[0]}",
                    process_name=name, process_pid=proc.pid,
                    raw_data={"suspicious_modules": suspicious_modules[:5]}
                )

        except (psutil.AccessDenied, Exception):
            pass

    def _check_windows_memory(self, proc: psutil.Process, name: str):
        """Check Windows process memory for injection indicators"""
        if platform.system() != "Windows":
            return

        try:
            # Check for executable memory regions outside known modules (simplified)
            maps = proc.memory_maps()
            exec_regions = [m for m in maps if 'x' in m.perms and not m.path]

            if len(exec_regions) > 5:  # Unusual number of executable anonymous regions
                self.suspicious_pids.add(proc.pid)
                self.agent.send_alert(
                    "process_injection", "critical",
                    f"Possible Process Injection: {name}",
                    f"Process {name} (PID {proc.pid}) has {len(exec_regions)} "
                    f"suspicious executable memory regions - possible shellcode injection",
                    process_name=name, process_pid=proc.pid,
                    raw_data={"exec_regions": len(exec_regions)}
                )

            # Check for process hollowing indicators
            if name in INJECTION_SUSPECT_PROCESSES:
                try:
                    exe = proc.exe()
                    if exe and "system32" not in exe.lower() and name in exe.lower():
                        pass  # Normal
                    elif exe and "system32" not in exe.lower():
                        self.agent.send_alert(
                            "process_hollowing", "critical",
                            f"Process Hollowing Detected: {name}",
                            f"Legitimate process {name} running from unusual location: {exe}",
                            process_name=name, process_pid=proc.pid,
                            raw_data={"exe_path": exe}
                        )
                except Exception:
                    pass

        except (psutil.AccessDenied, Exception):
            pass
