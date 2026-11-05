"""
Policy Engine - manages and deploys security policies to endpoints
"""
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("policy-engine")

DEFAULT_POLICIES = {
    "baseline": {
        "whitelist_processes": [
            "explorer.exe", "svchost.exe", "lsass.exe", "winlogon.exe",
            "services.exe", "csrss.exe", "smss.exe", "wininit.exe",
            "chrome.exe", "msedge.exe", "firefox.exe",
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "OneDrive.exe", "Teams.exe", "slack.exe", "zoom.exe",
        ],
        "alert_thresholds": {
            "file_ops_per_sec": 50,
            "network_connections": 100,
            "failed_logins": 5,
            "process_cpu": 90,
        },
        "monitoring": {
            "process_monitor": True,
            "network_monitor": True,
            "file_monitor": True,
            "usb_monitor": True,
            "login_monitor": True,
            "memory_monitor": True,
        },
        "response": {
            "auto_kill_malware": True,
            "auto_block_malicious_ip": True,
            "quarantine_suspicious_files": True,
        }
    }
}


class PolicyEngine:
    def __init__(self, db):
        self.db = db
        self.active_policies: Dict = {}

    async def get_policy_for_endpoint(self, endpoint_id: str) -> Dict:
        policy = await self.db.get_policy_for_endpoint(endpoint_id)
        if policy and isinstance(policy.get("rules"), dict):
            return policy["rules"]
        return DEFAULT_POLICIES["baseline"]

    async def deploy_policy(self, policy_id: str, endpoints: List[str]):
        logger.info(f"Deploying policy {policy_id} to {len(endpoints)} endpoints")
        for ep in endpoints:
            self.active_policies[ep] = policy_id

    def get_default_policy(self) -> Dict:
        return DEFAULT_POLICIES["baseline"]
