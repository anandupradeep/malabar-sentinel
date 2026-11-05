"""
Network Monitor — Malabar Sentinel
====================================
Monitors active network connections, enforces IP blocklist,
and detects connections to known-malicious hosts.

Block / Unblock / Re-Block cycle — how state flows:
----------------------------------------------------
  _blocked_ips   : authoritative set owned by AgentCore.
                   ONLY the command handlers touch this.
  _fw_applied    : IPs whose firewall rules are currently installed.
                   Managed here; shared reference given to AgentCore
                   so command handlers can clear it on unblock.

  Block:
    1. Command handler clears _fw_applied[ip] (so monitor re-applies fresh)
    2. Command handler calls IPBlocker.block() -> adds firewall rule
    3. Command handler adds ip to _blocked_ips
    4. Command handler adds ip to _fw_applied
    ✓ Monitor sees ip in _fw_applied → does NOT try to re-apply

  Unblock:
    1. Command handler removes ip from _blocked_ips  ← FIRST
    2. Command handler removes ip from _fw_applied   ← SECOND
    3. Command handler calls IPBlocker.unblock() -> removes firewall rule
    ✓ Monitor checks _blocked_ips → ip gone → does NOT re-apply

  Re-block (same IP):
    Identical to initial Block above — all state is clean.
"""
import logging
import time
from typing import TYPE_CHECKING, Set

import psutil

logger = logging.getLogger("network-monitor")

if TYPE_CHECKING:
    from agent.agent_core import AgentCore

# Threat-intel seed — known malicious IPs
_KNOWN_MAL: Set[str] = {
    "185.220.101.1", "185.220.101.2", "185.220.101.3",
    "45.142.212.100", "198.251.83.56", "194.165.16.77",
    "185.234.218.68", "165.22.28.1",
}


class NetworkMonitor:
    def __init__(self, agent: "AgentCore"):
        self.agent   = agent
        self.running = False

        # IPs whose firewall rules are currently installed on this machine.
        # Shared reference: command handlers read/write this set directly.
        self._fw_applied: Set[str] = set()

        # Give AgentCore a reference so block/unblock handlers can update it
        agent._network_monitor_fw_applied = self._fw_applied

        # Connection keys already seen — prevents duplicate alerts
        self._seen: Set[str] = set()

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self):
        self.running = True
        logger.info("NetworkMonitor started")
        _tick = 0
        while self.running:
            try:
                self._check_connections()
                if _tick % 2 == 0:          # every ~10 s
                    self._enforce_blocked_ips()
            except Exception as e:
                logger.error("NetworkMonitor loop error: %s", e)
            time.sleep(5)
            _tick += 1

    # ── Connection scanning ───────────────────────────────────────────────────

    def _check_connections(self):
        """Scan active connections; alert and re-enforce on policy violations."""
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue
                rip   = conn.raddr.ip
                rport = conn.raddr.port
                key   = f"{rip}:{rport}:{conn.pid}"
                if key in self._seen:
                    continue
                self._seen.add(key)

                if rip in _KNOWN_MAL:
                    self._alert_malicious(rip, rport, conn)

                # Active connection to a blocked IP — enforce immediately
                if rip in self.agent._blocked_ips:
                    logger.warning(
                        "Active connection to blocked IP %s detected — enforcing", rip
                    )
                    self._apply_fw_rule(rip)

                    # Kill existing TCP sessions to this IP (Windows + Linux)
                    self._kill_connections_to(rip)

        except Exception:
            pass  # psutil can throw on restricted processes; ignore silently

    # ── Periodic rule enforcement ─────────────────────────────────────────────

    def _enforce_blocked_ips(self):
        """
        Re-apply firewall rules for every IP in _blocked_ips that does not
        already have a rule installed (_fw_applied).

        IMPORTANT: we iterate a snapshot of _blocked_ips (list()) and
        re-check membership inside the loop so that a concurrent unblock
        (which discards from _blocked_ips first) is respected immediately.
        """
        for ip in list(self.agent._blocked_ips):
            # Re-check: may have been unblocked between snapshot and now
            if ip not in self.agent._blocked_ips:
                self._fw_applied.discard(ip)
                continue
            if ip not in self._fw_applied:
                self._apply_fw_rule(ip)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _apply_fw_rule(self, ip: str):
        """Install/re-install firewall DROP rule for *ip*."""
        try:
            self.agent._ip_blocker.reapply(ip)
            self._fw_applied.add(ip)
            logger.info("Firewall rule applied/refreshed for blocked IP: %s", ip)
        except Exception as e:
            logger.error("Failed to apply fw rule for %s: %s", ip, e)

    def _kill_connections_to(self, ip: str):
        """
        Terminate any ESTABLISHED TCP connections to *ip* so the block
        takes effect immediately without waiting for timeouts.
        Windows: uses netsh to reset the connection.
        Linux:   uses ss --kill or conntrack -D.
        """
        import os, subprocess
        if os.name == "nt":
            # netsh can't kill individual connections; reset the route cache
            # so the next packet hits the firewall rule
            subprocess.run(
                ["netsh", "interface", "ip", "delete", "destinationcache"],
                capture_output=True, creationflags=0x08000000, timeout=5
            )
        else:
            # Try conntrack first; fall back to ss
            r = subprocess.run(
                ["conntrack", "-D", "-d", ip],
                capture_output=True, timeout=5
            )
            if r.returncode != 0:
                subprocess.run(
                    ["ss", "--kill", f"dst {ip}"],
                    capture_output=True, timeout=5
                )

    def _alert_malicious(self, ip: str, port: int, conn):
        try:
            proc  = psutil.Process(conn.pid) if conn.pid else None
            pname = proc.name() if proc else "unknown"
        except Exception:
            pname = "unknown"

        self.agent.send_alert(
            "malicious_ip", "critical",
            f"Malicious IP Connection: {ip}",
            f"Connection to known-bad host {ip}:{port} by '{pname}'",
            network_ip=ip, process_name=pname,
            raw_data={"ip": ip, "port": port, "pid": conn.pid},
        )
        # Auto-block only if not already in the list
        if ip not in self.agent._blocked_ips:
            result = self.agent._ip_blocker.block(
                ip, self.agent._blocked_ips, self.agent._blocked_urls
            )
            self._fw_applied.add(ip)
            logger.info("Auto-blocked malicious IP %s — %s", ip, result)
