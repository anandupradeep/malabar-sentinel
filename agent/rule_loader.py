"""
Rule Loader - loads detection rules from config files and server policy.

Improvements (v2):
  - Deep-copy defaults so nested mutable structures are not shared
  - Precompute lowercase whitelist sets for O(1) lookups
  - Validate external rules.json shape before accepting it
  - Deterministic policy merge that preserves rule ordering
"""

import copy
import json
import logging
import os
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("rule-loader")

DEFAULT_RULES: Dict[str, Any] = {
    "process_rules": [
        {"name": "Encoded PowerShell", "match": "powershell", "cmdline_contains": ["-enc", "-encodedcommand"], "severity": "high"},
        {"name": "LSASS Access", "match": "lsass.exe", "spawned_from": ["cmd.exe", "powershell.exe"], "severity": "critical"},
        {"name": "Suspicious Scripting", "match_any": ["wscript.exe", "cscript.exe", "mshta.exe"], "severity": "high"},
        {"name": "Certutil Download", "match": "certutil.exe", "cmdline_contains": ["-urlcache", "-decode"], "severity": "high"},
        {"name": "Scheduled Task Creation", "match": "schtasks.exe", "cmdline_contains": ["/create"], "severity": "medium"},
        {"name": "Registry Persistence", "match": "reg.exe", "cmdline_contains": ["run", "runonce"], "severity": "medium"},
        {"name": "Net User Commands", "match": "net.exe", "cmdline_contains": ["user", "localgroup"], "severity": "medium"},
        {"name": "WMI Execution", "match": "wmic.exe", "cmdline_contains": ["process", "call"], "severity": "high"},
        {"name": "Shadow Copy Deletion", "match": "vssadmin.exe", "cmdline_contains": ["delete"], "severity": "emergency"},
        {"name": "Disabling Windows Defender", "match": "sc.exe", "cmdline_contains": ["windefend", "stop"], "severity": "critical"},
    ],
    "network_rules": [
        {"name": "Tor Exit Nodes", "ip_list": ["185.220.101.0/24", "185.220.100.0/24"], "severity": "high"},
        {"name": "Suspicious Ports", "ports": [4444, 1234, 5555, 6666, 31337, 9999], "severity": "high"},
        {"name": "High Outbound Volume", "bytes_out_threshold": 10485760, "window_seconds": 60, "severity": "medium"},
    ],
    "file_rules": [
        {"name": "Executable in Temp", "path_contains": ["\\temp\\", "\\tmp\\"], "extensions": [".exe", ".dll", ".bat"], "severity": "high"},
        {"name": "Ransomware Extensions", "extensions": [".encrypted", ".enc", ".locked", ".wcry", ".wncry", ".ryuk"], "severity": "emergency"},
        {"name": "Script in Downloads", "path_contains": ["\\downloads\\"], "extensions": [".ps1", ".vbs", ".js", ".hta"], "severity": "medium"},
    ],
    "login_rules": [
        {"name": "Brute Force", "failed_attempts": 5, "window_seconds": 300, "severity": "critical"},
        {"name": "Multiple Failed Logins", "failed_attempts": 3, "window_seconds": 300, "severity": "medium"},
        {"name": "After Hours Login", "hours_start": 22, "hours_end": 6, "severity": "medium"},
    ],
    "whitelist": {
        "processes": [
            "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "taskhost.exe", "taskhostw.exe", "dwm.exe", "conhost.exe",
            "spoolsv.exe", "searchindexer.exe", "msiexec.exe", "dllhost.exe",
            "sihost.exe", "runtimebroker.exe", "applicationframehost.exe",
            "chrome.exe", "msedge.exe", "firefox.exe",
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "teams.exe",
            "onedrive.exe", "code.exe", "python.exe", "python3.exe",
        ],
        "paths": [
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
        ],
        "network": ["127.0.0.1", "::1"],
    },
}

RULES_FILE = os.path.join(os.path.dirname(__file__), "..", "config", "rules.json")

# Required top-level keys for external rules validation
_REQUIRED_KEYS = {"process_rules", "network_rules", "file_rules", "login_rules", "whitelist"}


def _validate_rules(rules: Any) -> Optional[str]:
    """
    Validate the shape of an externally loaded rules dict.
    Returns an error message string on failure, or None if valid.
    """
    if not isinstance(rules, dict):
        return "rules must be a JSON object"
    missing = _REQUIRED_KEYS - rules.keys()
    if missing:
        return f"rules missing required keys: {sorted(missing)}"
    for key in ("process_rules", "network_rules", "file_rules", "login_rules"):
        if not isinstance(rules.get(key), list):
            return f"rules[{key!r}] must be a list"
    wl = rules.get("whitelist")
    if not isinstance(wl, dict):
        return "rules['whitelist'] must be an object"
    for sub in ("processes", "paths", "network"):
        if sub in wl and not isinstance(wl[sub], list):
            return f"rules['whitelist'][{sub!r}] must be a list"
    return None


class RuleLoader:
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        # Precomputed lowercase sets for fast whitelist lookups
        self._wl_processes: Set[str] = set()
        self._wl_paths: List[str] = []
        self.load()

    def load(self) -> Dict:
        """Load rules from file, fall back to defaults. Always deep-copies."""
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    candidate = json.load(f)
                error = _validate_rules(candidate)
                if error:
                    logger.warning("Rejecting rules file (%s): %s — using defaults", RULES_FILE, error)
                else:
                    self.rules = copy.deepcopy(candidate)
                    self._rebuild_whitelist_cache()
                    logger.info("Rules loaded from %s", RULES_FILE)
                    return self.rules
            except Exception as e:
                logger.warning("Failed to load rules file: %s — using defaults", e)

        self.rules = copy.deepcopy(DEFAULT_RULES)
        self._rebuild_whitelist_cache()
        logger.info("Using default detection rules")
        return self.rules

    def _rebuild_whitelist_cache(self) -> None:
        """Precompute lowercase sets/lists from the whitelist for fast checks."""
        wl = self.rules.get("whitelist", {})
        self._wl_processes = {p.lower() for p in wl.get("processes", [])}
        self._wl_paths = [p.lower() for p in wl.get("paths", [])]

    def save(self, rules: Dict = None) -> None:
        """Save current rules to file."""
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(rules or self.rules, f, indent=2)
        logger.info("Rules saved")

    def get_process_rules(self) -> List[Dict]:
        return self.rules.get("process_rules", [])

    def get_network_rules(self) -> List[Dict]:
        return self.rules.get("network_rules", [])

    def get_file_rules(self) -> List[Dict]:
        return self.rules.get("file_rules", [])

    def get_login_rules(self) -> List[Dict]:
        return self.rules.get("login_rules", [])

    def get_whitelist(self) -> Dict:
        return self.rules.get("whitelist", {})

    def is_whitelisted_process(self, process_name: str) -> bool:
        return process_name.lower() in self._wl_processes

    def is_whitelisted_path(self, path: str) -> bool:
        path_lower = path.lower()
        return any(wp in path_lower for wp in self._wl_paths)

    def merge_server_policy(self, policy: Dict) -> None:
        """
        Merge rules received from SOC server policy.
        Preserves existing rule ordering; new whitelist entries are appended
        once (no duplicates). Deterministic regardless of call order.
        """
        if not policy:
            return
        if "whitelist_processes" in policy:
            existing = self.rules.setdefault("whitelist", {}).setdefault("processes", [])
            existing_lower = {p.lower() for p in existing}
            for proc in policy["whitelist_processes"]:
                if proc.lower() not in existing_lower:
                    existing.append(proc)
                    existing_lower.add(proc.lower())
            self._rebuild_whitelist_cache()
        if "alert_thresholds" in policy:
            self.rules["thresholds"] = policy["alert_thresholds"]
        logger.info("Server policy merged into rules")
