"""
Threat Intelligence Engine
Ingests and queries threat intel feeds: malicious IPs, hashes, C2 servers
"""

import asyncio
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger("threat-intel")

# Simulated threat intel feeds (replace with real MISP/OTX/VirusTotal in production)
MALICIOUS_IPS = {
    "185.220.101.1": {"desc": "Tor Exit Node", "severity": "high", "source": "TOR Project"},
    "45.142.212.100": {"desc": "Known C2 Server", "severity": "critical", "source": "AlienVault OTX"},
    "194.165.16.77": {"desc": "Botnet C&C", "severity": "critical", "source": "EmergingThreats"},
    "91.108.4.0": {"desc": "Telegram C2 Infrastructure", "severity": "high", "source": "Internal"},
    "198.251.83.56": {"desc": "Cobalt Strike Beacon", "severity": "critical", "source": "Shodan"},
    "185.234.218.68": {"desc": "Ransomware Distribution", "severity": "emergency", "source": "Ransomware Tracker"},
    "43.154.59.147": {"desc": "APT Infrastructure", "severity": "critical", "source": "CrowdStrike"},
    "165.22.28.1": {"desc": "Cryptominer Pool", "severity": "medium", "source": "CoinBlockerLists"},
}

MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "name": "Mimikatz", "type": "credential_stealer", "severity": "critical"
    },
    "7bc1e8a98d6e3b7c4f4ad2b1e6f9c8d2a3b4e5f6a7b8c9d0e1f2a3b4c5d6e7f": {
        "name": "WannaCry", "type": "ransomware", "severity": "emergency"
    },
    "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4": {
        "name": "NotPetya", "type": "wiper_ransomware", "severity": "emergency"
    },
    "8f14e45fceea167a5a36dedd4bea2543": {
        "name": "CobaltStrike Beacon", "type": "rat", "severity": "critical"
    },
}

C2_DOMAINS = {
    "evil-c2.xyz": {"desc": "Known C2 Domain", "severity": "critical"},
    "malware-dist.net": {"desc": "Malware Distribution", "severity": "critical"},
    "botnet-cmd.org": {"desc": "Botnet Command", "severity": "emergency"},
}

DARK_WEB_BREACHES = {
    "example.com": {"emails": ["admin@example.com"], "breach": "DataBreach2023", "date": "2023-06"},
    "company.org": {"emails": ["ceo@company.org"], "breach": "LinkedIn2021", "date": "2021-04"},
}


class ThreatIntelligence:
    def __init__(self, db):
        self.db = db
        self.malicious_ips: Dict = {}
        self.malicious_hashes: Dict = {}
        self.c2_domains: Dict = {}
        self.dark_web: Dict = {}
        self._loaded = False

    async def load_feeds(self):
        """Load threat intelligence feeds into database"""
        logger.info("Loading threat intelligence feeds...")

        for ip, data in MALICIOUS_IPS.items():
            await self.db.add_threat_intel("ip", ip, data["desc"], data["source"], data["severity"])
        for h, data in MALICIOUS_HASHES.items():
            await self.db.add_threat_intel("hash", h, data["name"], data["type"], data["severity"])
        for domain, data in C2_DOMAINS.items():
            await self.db.add_threat_intel("domain", domain, data["desc"], "feed", data["severity"])

        self.malicious_ips = MALICIOUS_IPS.copy()
        self.malicious_hashes = MALICIOUS_HASHES.copy()
        self.c2_domains = C2_DOMAINS.copy()
        self.dark_web = DARK_WEB_BREACHES.copy()
        self._loaded = True

        counts = await self.db.get_threat_intel_count()
        logger.info(f"Threat intel loaded: {counts}")

    async def refresh_feeds_loop(self):
        """Periodically refresh feeds"""
        while True:
            await asyncio.sleep(3600)  # Refresh every hour
            await self.load_feeds()
            logger.info("Threat intel feeds refreshed")

    async def check_ip(self, ip: Optional[str]) -> Optional[str]:
        """Check if IP is in malicious feeds"""
        if not ip:
            return None
        # In-memory check first
        if ip in self.malicious_ips:
            return f"{self.malicious_ips[ip]['desc']} (Source: {self.malicious_ips[ip]['source']})"
        # DB check
        result = await self.db.check_threat_intel("ip", ip)
        if result:
            return result.get("description")
        return None

    async def check_file_hash(self, file_hash: Optional[str]) -> Optional[str]:
        """Check if file hash matches known malware"""
        if not file_hash:
            return None
        if file_hash in self.malicious_hashes:
            data = self.malicious_hashes[file_hash]
            return f"Malware: {data['name']} ({data['type']})"
        result = await self.db.check_threat_intel("hash", file_hash)
        if result:
            return result.get("description")
        return None

    async def check_domain(self, domain: Optional[str]) -> Optional[str]:
        """Check if domain is in threat intel"""
        if not domain:
            return None
        if domain in self.c2_domains:
            return self.c2_domains[domain]["desc"]
        result = await self.db.check_threat_intel("domain", domain)
        if result:
            return result.get("description")
        return None

    async def check_dark_web(self, email_domain: str) -> Optional[Dict]:
        """Check dark web breach data for email domain"""
        return self.dark_web.get(email_domain)

    async def get_summary(self) -> Dict:
        counts = await self.db.get_threat_intel_count()
        return {
            "malicious_ips": counts.get("ip", 0),
            "malware_hashes": counts.get("hash", 0),
            "c2_domains": counts.get("domain", 0),
            "last_updated": datetime.utcnow().isoformat(),
            "feeds_active": self._loaded,
            "sources": ["AlienVault OTX", "EmergingThreats", "Ransomware Tracker", "CrowdStrike", "Shodan"]
        }

    def hash_file_content(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()
