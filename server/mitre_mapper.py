"""
MITRE ATT&CK Framework Mapper
Maps detected events to MITRE ATT&CK tactics and techniques
"""

from typing import Dict, Optional, List


TECHNIQUE_MAP = {
    # Execution
    "process_execution": {"tactic": "Execution", "technique": "T1059", "name": "Command and Scripting Interpreter"},
    "powershell": {"tactic": "Execution", "technique": "T1059.001", "name": "PowerShell"},
    "cmd_execution": {"tactic": "Execution", "technique": "T1059.003", "name": "Windows Command Shell"},
    "wscript": {"tactic": "Execution", "technique": "T1059.005", "name": "Visual Basic"},
    "scheduled_task": {"tactic": "Execution", "technique": "T1053", "name": "Scheduled Task/Job"},
    "service_execution": {"tactic": "Execution", "technique": "T1569", "name": "System Services"},

    # Persistence
    "registry_run_key": {"tactic": "Persistence", "technique": "T1547.001", "name": "Registry Run Keys"},
    "startup_folder": {"tactic": "Persistence", "technique": "T1547.001", "name": "Startup Folder"},
    "new_service": {"tactic": "Persistence", "technique": "T1543", "name": "Create or Modify System Process"},
    "account_creation": {"tactic": "Persistence", "technique": "T1136", "name": "Create Account"},

    # Privilege Escalation
    "privilege_escalation": {"tactic": "Privilege Escalation", "technique": "T1068", "name": "Exploitation for Privilege Escalation"},
    "uac_bypass": {"tactic": "Privilege Escalation", "technique": "T1548.002", "name": "Bypass User Account Control"},
    "token_impersonation": {"tactic": "Privilege Escalation", "technique": "T1134", "name": "Access Token Manipulation"},

    # Defense Evasion
    "process_injection": {"tactic": "Defense Evasion", "technique": "T1055", "name": "Process Injection"},
    "dll_injection": {"tactic": "Defense Evasion", "technique": "T1055.001", "name": "DLL Injection"},
    "process_hollowing": {"tactic": "Defense Evasion", "technique": "T1055.012", "name": "Process Hollowing"},
    "obfuscation": {"tactic": "Defense Evasion", "technique": "T1027", "name": "Obfuscated Files or Information"},
    "rootkit": {"tactic": "Defense Evasion", "technique": "T1014", "name": "Rootkit"},
    "masquerading": {"tactic": "Defense Evasion", "technique": "T1036", "name": "Masquerading"},
    "disable_security": {"tactic": "Defense Evasion", "technique": "T1562", "name": "Impair Defenses"},

    # Credential Access
    "credential_dump": {"tactic": "Credential Access", "technique": "T1003", "name": "OS Credential Dumping"},
    "lsass_access": {"tactic": "Credential Access", "technique": "T1003.001", "name": "LSASS Memory"},
    "brute_force": {"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"},
    "keylogging": {"tactic": "Credential Access", "technique": "T1056.001", "name": "Keylogging"},
    "password_spray": {"tactic": "Credential Access", "technique": "T1110.003", "name": "Password Spraying"},

    # Discovery
    "network_scan": {"tactic": "Discovery", "technique": "T1046", "name": "Network Service Discovery"},
    "process_discovery": {"tactic": "Discovery", "technique": "T1057", "name": "Process Discovery"},
    "system_info": {"tactic": "Discovery", "technique": "T1082", "name": "System Information Discovery"},
    "file_discovery": {"tactic": "Discovery", "technique": "T1083", "name": "File and Directory Discovery"},

    # Lateral Movement
    "lateral_movement": {"tactic": "Lateral Movement", "technique": "T1021", "name": "Remote Services"},
    "pass_the_hash": {"tactic": "Lateral Movement", "technique": "T1550.002", "name": "Pass the Hash"},
    "rdp": {"tactic": "Lateral Movement", "technique": "T1021.001", "name": "Remote Desktop Protocol"},

    # Collection
    "data_collection": {"tactic": "Collection", "technique": "T1005", "name": "Data from Local System"},
    "screen_capture": {"tactic": "Collection", "technique": "T1113", "name": "Screen Capture"},
    "clipboard": {"tactic": "Collection", "technique": "T1115", "name": "Clipboard Data"},
    "sensitive_file": {"tactic": "Collection", "technique": "T1005", "name": "Data from Local System"},

    # Exfiltration
    "data_exfiltration": {"tactic": "Exfiltration", "technique": "T1041", "name": "Exfiltration Over C2 Channel"},
    "usb_exfiltration": {"tactic": "Exfiltration", "technique": "T1052.001", "name": "Exfiltration over USB"},
    "network_exfiltration": {"tactic": "Exfiltration", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},

    # Impact
    "ransomware": {"tactic": "Impact", "technique": "T1486", "name": "Data Encrypted for Impact"},
    "disk_wipe": {"tactic": "Impact", "technique": "T1561", "name": "Disk Wipe"},
    "service_stop": {"tactic": "Impact", "technique": "T1489", "name": "Service Stop"},
    "defacement": {"tactic": "Impact", "technique": "T1491", "name": "Defacement"},

    # Command and Control
    "c2_communication": {"tactic": "Command and Control", "technique": "T1071", "name": "Application Layer Protocol"},
    "malicious_ip": {"tactic": "Command and Control", "technique": "T1071.001", "name": "Web Protocols"},
    "dns_tunneling": {"tactic": "Command and Control", "technique": "T1071.004", "name": "DNS"},

    # Initial Access
    "phishing": {"tactic": "Initial Access", "technique": "T1566", "name": "Phishing"},
    "exploit": {"tactic": "Initial Access", "technique": "T1190", "name": "Exploit Public-Facing Application"},
    "usb_insertion": {"tactic": "Initial Access", "technique": "T1091", "name": "Replication Through Removable Media"},

    # Memory
    "memory_injection": {"tactic": "Defense Evasion", "technique": "T1055", "name": "Process Injection"},
    "reflective_loading": {"tactic": "Defense Evasion", "technique": "T1620", "name": "Reflective Code Loading"},
    "malware_hash": {"tactic": "Execution", "technique": "T1204", "name": "User Execution"},
}

KEYWORD_MAP = {
    "powershell": "powershell",
    "cmd": "cmd_execution",
    "lsass": "lsass_access",
    "mimikatz": "credential_dump",
    "ransomware": "ransomware",
    "encrypt": "ransomware",
    "usb": "usb_exfiltration",
    "injection": "process_injection",
    "hollow": "process_hollowing",
    "dll": "dll_injection",
    "brute": "brute_force",
    "failed login": "brute_force",
    "malicious ip": "malicious_ip",
    "c2": "c2_communication",
    "privilege": "privilege_escalation",
    "exfiltrat": "data_exfiltration",
    "sensitive file": "sensitive_file",
    "hash": "malware_hash",
    "memory": "memory_injection",
    "scan": "network_scan",
}


class MITREMapper:
    def __init__(self):
        self.technique_map = TECHNIQUE_MAP
        self.keyword_map = KEYWORD_MAP

    def map_alert(self, alert_type: str, description: str = "") -> Dict:
        """Map an alert to MITRE ATT&CK tactic and technique"""
        # Direct alert type mapping
        if alert_type in self.technique_map:
            return self.technique_map[alert_type]

        # Keyword search in description
        desc_lower = description.lower()
        for keyword, technique_key in self.keyword_map.items():
            if keyword in desc_lower:
                return self.technique_map.get(technique_key, {})

        # Partial alert type match
        for key, mapping in self.technique_map.items():
            if key in alert_type or alert_type in key:
                return mapping

        return {"tactic": "Unknown", "technique": "T0000", "name": "Unknown Technique"}

    def get_all_techniques(self) -> List[Dict]:
        """Return all known MITRE techniques"""
        seen = set()
        techniques = []
        for key, val in self.technique_map.items():
            t = val.get("technique")
            if t not in seen:
                seen.add(t)
                techniques.append({
                    "id": t,
                    "name": val.get("name"),
                    "tactic": val.get("tactic"),
                    "alert_type": key
                })
        return techniques

    def get_tactics(self) -> List[str]:
        tactics = set()
        for v in self.technique_map.values():
            tactics.add(v.get("tactic", "Unknown"))
        return sorted(list(tactics))
