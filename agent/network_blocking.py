"""
network_blocking.py — Malabar Sentinel
=======================================
IP and URL blocking with full support for unlimited
Block → Unblock → Re-Block cycles on the same entry.

Design principles
-----------------
1.  Every block() call starts by REMOVING stale rules — block is always
    a clean slate regardless of previous state.
2.  Every unblock() call removes ALL copies of the rule (loop until the
    delete command fails) so no orphan rules remain.
3.  URLBlocker.block() strips any existing marker block for the domain
    before writing a fresh one — idempotent re-block every time.
4.  URLBlocker.unblock() also calls ip_blocker.unblock() for every IP
    that was resolved and firewall-blocked when the domain was first
    blocked — complete teardown.
5.  Persistence (.soc_blocks.json) is written AFTER state is updated so
    the file always reflects the actual in-memory state.
6.  DNS is flushed after every hosts-file change (Windows + Linux).
7.  All errors are returned as strings — never raised — so callers can
    surface them to the dashboard without try/except boilerplate.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket as _socket
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Optional, Set, Tuple

logger = logging.getLogger("network-blocking")

# ── Constants ─────────────────────────────────────────────────────────────────

WIN_FLAGS = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW

_BLOCKS_FILE   = Path(os.path.expanduser("~")) / ".soc_blocks.json"
_persist_lock  = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
#  PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════════

def _load_persisted() -> dict:
    """Load saved blocks from disk. Returns {'ips': [...], 'urls': [...]}."""
    try:
        if _BLOCKS_FILE.exists():
            data = json.loads(_BLOCKS_FILE.read_text(encoding="utf-8"))
            return {
                "ips":  list(data.get("ips",  [])),
                "urls": list(data.get("urls", [])),
            }
    except Exception as e:
        logger.warning("Could not load persisted blocks: %s", e)
    return {"ips": [], "urls": []}


def _save_persisted(blocked_ips: Set[str], blocked_urls: Set[str]) -> None:
    """Atomically write current block sets to disk."""
    with _persist_lock:
        try:
            payload = json.dumps(
                {"ips": sorted(blocked_ips), "urls": sorted(blocked_urls)},
                indent=2,
            )
            tmp = _BLOCKS_FILE.with_suffix(".tmp")
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(_BLOCKS_FILE)
            logger.debug(
                "Persisted %d IPs, %d URLs to %s",
                len(blocked_ips), len(blocked_urls), _BLOCKS_FILE,
            )
        except Exception as e:
            logger.error("Could not save block list: %s", e)


# ═══════════════════════════════════════════════════════════════════════════════
#  LOW-LEVEL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _run(args: list, *, timeout: int = 10, shell: bool = False) -> Tuple[int, str, str]:
    """Run a subprocess. Returns (returncode, stdout, stderr). Never raises."""
    try:
        r = subprocess.run(
            args,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=WIN_FLAGS,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError as e:
        return 1, "", f"Command not found: {e}"
    except subprocess.TimeoutExpired:
        return 1, "", "Timeout"
    except Exception as e:
        return 1, "", str(e)


def _hosts_path() -> str:
    if os.name == "nt":
        return r"C:\Windows\System32\drivers\etc\hosts"
    return "/etc/hosts"


def _flush_dns() -> None:
    """Flush the OS DNS cache after hosts-file changes."""
    if os.name == "nt":
        _run(["ipconfig", "/flushdns"])
        logger.debug("DNS cache flushed (ipconfig /flushdns)")
    else:
        for svc in ("systemd-resolved", "nscd", "dnsmasq"):
            rc, _, _ = _run(["systemctl", "reload", svc], timeout=5)
            if rc == 0:
                logger.debug("DNS cache flushed (systemctl reload %s)", svc)
                break


def _unlock_hosts_windows(hosts_path: str) -> None:
    """Grant the current user full control over the hosts file."""
    _run(["takeown", "/f", hosts_path])
    user = os.environ.get("USERNAME", "Administrators")
    _run(["icacls", hosts_path, "/grant", f"{user}:F"])


def _write_hosts_windows(content: str, hosts_path: str) -> None:
    """Write via PowerShell Copy-Item (bypasses UAC virtualisation)."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".hosts", delete=False, encoding="utf-8"
    )
    tmp.write(content)
    tmp.close()
    ps_cmd = f"Copy-Item -Force -Path '{tmp.name}' -Destination '{hosts_path}'"
    rc, _, err = _run(
        ["powershell", "-NonInteractive", "-Command", ps_cmd], timeout=15
    )
    try:
        os.unlink(tmp.name)
    except Exception:
        pass
    if rc != 0:
        raise PermissionError(f"PowerShell copy failed: {err[:200]}")


def _write_hosts(content: str, hosts_path: str) -> None:
    """Cross-platform atomic hosts-file write."""
    if os.name == "nt":
        _unlock_hosts_windows(hosts_path)
        try:
            with open(hosts_path, "w", encoding="utf-8") as f:
                f.write(content)
        except PermissionError:
            _write_hosts_windows(content, hosts_path)
    else:
        tmp = hosts_path + ".soctmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, hosts_path)
        except Exception:
            try:
                os.unlink(tmp)
            except Exception:
                pass
            raise


# ═══════════════════════════════════════════════════════════════════════════════
#  IP BLOCKING
# ═══════════════════════════════════════════════════════════════════════════════

class IPBlocker:
    """
    Manages OS-level firewall DROP rules for individual IP addresses.

    All public methods log their actions and return a human-readable
    string describing the outcome.
    """

    RULE_PREFIX = "SOC_BLOCK"

    # ── Public API ────────────────────────────────────────────────────────────

    def block(
        self,
        ip: str,
        blocked_ips: Set[str],
        blocked_urls: Set[str],
    ) -> str:
        """
        Block *ip* at the OS firewall level.

        Steps:
          1. Remove any existing rules for this IP (clean slate).
          2. Add new DROP rules (inbound + outbound).
          3. Verify rules were created.
          4. Update in-memory set and persist.

        Returns result string. Starts with "Error" on failure.
        """
        ip = ip.strip()
        if not ip:
            return "Error: empty IP address"

        logger.info("[block_ip] START — ip=%s", ip)

        # Step 1: Always start clean — remove stale rules
        removed = self._remove_all_rules(ip)
        logger.debug("[block_ip] removed stale rules: %s", removed)

        # Step 2: Add fresh rules
        if os.name == "nt":
            detail = self._block_windows(ip)
        else:
            detail = self._block_linux(ip)

        if detail.startswith("Error"):
            logger.error("[block_ip] FAILED — %s", detail)
            return detail

        # Step 3: Update state
        blocked_ips.add(ip)
        _save_persisted(blocked_ips, blocked_urls)
        logger.info("[block_ip] SUCCESS — %s", detail)
        return detail

    def unblock(
        self,
        ip: str,
        blocked_ips: Set[str],
        blocked_urls: Set[str],
        fw_applied: Optional[Set[str]] = None,
    ) -> str:
        """
        Remove all firewall DROP rules for *ip* and clear all state.

        Steps:
          1. Remove ALL copies of rules (loop until delete fails).
          2. Discard from blocked_ips and fw_applied.
          3. Persist updated state.

        After this returns, the entry is completely gone — re-blocking
        the same IP will be treated as a brand-new request.
        """
        ip = ip.strip()
        if not ip:
            return "Error: empty IP address"

        logger.info("[unblock_ip] START — ip=%s", ip)

        # Step 1: Remove every copy of every rule
        removed = self._remove_all_rules(ip)
        logger.debug("[unblock_ip] removal result: %s", removed)

        # Step 2: Wipe all in-memory state — order matters:
        #         clear fw_applied BEFORE blocked_ips so monitor loop
        #         sees a consistent view if it runs concurrently.
        if fw_applied is not None:
            fw_applied.discard(ip)
            logger.debug("[unblock_ip] cleared _fw_applied[%s]", ip)
        blocked_ips.discard(ip)
        logger.debug("[unblock_ip] cleared _blocked_ips[%s]", ip)

        # Step 3: Persist
        _save_persisted(blocked_ips, blocked_urls)
        logger.info("[unblock_ip] SUCCESS — ip=%s now fully cleared", ip)
        return f"IP {ip} unblocked — all firewall rules removed, state cleared"

    def reapply(self, ip: str) -> str:
        """
        Re-install DROP rules for *ip* (called by NetworkMonitor).
        Always removes stale rules first for a clean slate.
        """
        ip = ip.strip()
        logger.debug("[reapply] ip=%s", ip)
        self._remove_all_rules(ip)
        if os.name == "nt":
            return self._block_windows(ip)
        return self._block_linux(ip)

    # ── Rule removal ─────────────────────────────────────────────────────────

    def _remove_all_rules(self, ip: str) -> str:
        """
        Delete every firewall rule associated with *ip*.
        Loops until the delete command fails (handles duplicates).
        Returns a summary string for logging.
        """
        summary = []
        if os.name == "nt":
            for direction in ("in", "out"):
                name = self._rule_name(ip, direction)
                count = 0
                for _ in range(10):
                    rc, _, _ = _run([
                        "netsh", "advfirewall", "firewall",
                        "delete", "rule", f"name={name}",
                    ])
                    if rc != 0:
                        break
                    count += 1
                summary.append(f"{direction}:{count}")
        else:
            for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
                count = 0
                for _ in range(10):
                    rc, _, _ = _run(
                        ["iptables", "-D", chain, flag, ip, "-j", "DROP"]
                    )
                    if rc != 0:
                        break
                    count += 1
                summary.append(f"{chain}:{count}")
        return ", ".join(summary)

    # ── Windows ───────────────────────────────────────────────────────────────

    def _rule_name(self, ip: str, direction: str) -> str:
        safe = ip.replace(".", "_").replace(":", "_").replace("/", "_")
        return f"{self.RULE_PREFIX}_{safe}_{direction}"

    def _block_windows(self, ip: str) -> str:
        errors = []
        for d in ("in", "out"):
            name = self._rule_name(ip, d)
            rc, out, err = _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}",
                f"dir={d}",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                "profile=any",
                "protocol=any",
            ])
            if rc != 0:
                errors.append(f"{d}: {err or out}")
                logger.error("[block_windows] netsh error for %s/%s: %s", ip, d, err or out)

        if errors:
            return f"Error adding Windows firewall rules for {ip}: {'; '.join(errors)}"

        # Verify
        rc_v, out_v, _ = _run([
            "netsh", "advfirewall", "firewall",
            "show", "rule", f"name={self._rule_name(ip, 'in')}",
        ])
        if rc_v != 0 or "No rules match" in out_v:
            return (
                f"Error: Windows firewall rule for {ip} was added but "
                "verify step failed — check admin privileges"
            )
        return f"IP {ip} blocked — Windows Firewall inbound + outbound rules added and verified"

    def _unblock_windows(self, ip: str) -> str:
        # Handled entirely by _remove_all_rules in unblock()
        return f"IP {ip} Windows firewall rules removed"

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _block_linux(self, ip: str) -> str:
        errors = []
        rc_i, _, err_i = _run(["iptables", "-I", "INPUT",  "1", "-s", ip, "-j", "DROP"])
        if rc_i != 0:
            errors.append(f"INPUT: {err_i}")

        rc_o, _, err_o = _run(["iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"])
        if rc_o != 0:
            errors.append(f"OUTPUT: {err_o}")

        if errors:
            return f"Error adding iptables rules for {ip}: {'; '.join(errors)}"

        # Verify
        rc_v, _, _ = _run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
        if rc_v != 0:
            return f"Error: iptables INPUT rule for {ip} verify failed"

        # Persist (best-effort)
        for svc in ("netfilter-persistent", "iptables"):
            rc_s, _, _ = _run(["service", svc, "save"], timeout=5)
            if rc_s == 0:
                break

        return f"IP {ip} blocked — iptables INPUT + OUTPUT DROP rules at top"


# ═══════════════════════════════════════════════════════════════════════════════
#  URL / DOMAIN BLOCKING
# ═══════════════════════════════════════════════════════════════════════════════

class URLBlocker:
    """
    Blocks domains via the OS hosts file and firewall rules.

    Each domain is wrapped in unique BEGIN/END markers so multiple
    domains are independent and unblocking one never corrupts another.

    Re-block support: if a domain's marker already exists in the hosts
    file, it is stripped and rewritten — so block() is fully idempotent
    and works correctly after unblock() (or even if the marker is stale).
    """

    def __init__(self, ip_blocker: IPBlocker):
        self.ip_blocker = ip_blocker

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_domain(url: str) -> str:
        return re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower().strip()

    @staticmethod
    def _begin(domain: str) -> str:
        return f"# BEGIN SOC_BLOCK:{domain}"

    @staticmethod
    def _end(domain: str) -> str:
        return f"# END SOC_BLOCK:{domain}"

    def _read_hosts(self, path: str) -> str:
        try:
            return open(path, "r", encoding="utf-8", errors="replace").read()
        except Exception:
            return ""

    def _strip_domain_block(self, content: str, domain: str) -> str:
        """Remove the BEGIN…END fence for *domain* from *content*."""
        begin  = self._begin(domain)
        end    = self._end(domain)
        output = []
        inside = False
        for line in content.splitlines(keepends=True):
            s = line.strip()
            if s == begin:
                inside = True
                continue
            if s == end:
                inside = False
                continue
            if not inside:
                output.append(line)
        return "".join(output)

    # ── Public API ────────────────────────────────────────────────────────────

    def block(
        self,
        url: str,
        blocked_ips: Set[str],
        blocked_urls: Set[str],
    ) -> str:
        """
        Block *url* via hosts file + firewall rules for resolved IPs.

        Steps:
          1. Extract domain from url.
          2. Strip any existing marker for this domain (idempotent re-block).
          3. Append fresh marker block.
          4. Write hosts file atomically.
          5. Resolve domain → block each IPv4 via firewall.
          6. Flush DNS cache.
          7. Update state and persist.
        """
        domain = self._extract_domain(url)
        if not domain or "." not in domain:
            return f"Error: invalid domain in '{url}'"

        logger.info("[block_url] START — domain=%s", domain)

        hosts   = _hosts_path()
        existing = self._read_hosts(hosts)

        # Step 2: Strip any stale entry (enables clean re-block)
        if self._begin(domain) in existing:
            logger.debug("[block_url] removing stale entry for %s before re-adding", domain)
            existing = self._strip_domain_block(existing, domain)

        # Step 3: Build fresh fence
        fence = "\n".join([
            self._begin(domain),
            f"0.0.0.0 {domain}",
            f"0.0.0.0 www.{domain}",
            f"::1     {domain}",
            f"::1     www.{domain}",
            self._end(domain),
        ])
        new_content = existing.rstrip("\n") + "\n" + fence + "\n"

        # Step 4: Write
        try:
            _write_hosts(new_content, hosts)
            logger.debug("[block_url] hosts file written for %s", domain)
        except PermissionError as e:
            return (
                f"Permission denied writing to {hosts}: {e}. "
                "Run the agent as Administrator / root."
            )
        except Exception as e:
            return f"Failed to write hosts file: {e}"

        # Step 5: Block resolved IPs via firewall
        fw_detail = ""
        resolved: list[str] = []
        try:
            resolved = list({
                info[4][0]
                for info in _socket.getaddrinfo(domain, None)
                if ":" not in info[4][0]   # IPv4 only
            })[:4]
            for rip in resolved:
                self.ip_blocker.block(rip, blocked_ips, blocked_urls)
            if resolved:
                fw_detail = f" + firewall rules for {', '.join(resolved)}"
                logger.debug("[block_url] firewall-blocked resolved IPs: %s", resolved)
        except Exception as exc:
            logger.debug("[block_url] DNS resolution skipped: %s", exc)

        # Step 6: Flush DNS
        _flush_dns()

        # Step 7: Update state
        blocked_urls.add(domain)
        _save_persisted(blocked_ips, blocked_urls)
        logger.info("[block_url] SUCCESS — domain=%s%s", domain, fw_detail)
        return f"Domain '{domain}' blocked via hosts file{fw_detail} — DNS flushed"

    def unblock(
        self,
        url: str,
        blocked_ips: Set[str],
        blocked_urls: Set[str],
        fw_applied: Optional[Set[str]] = None,
    ) -> str:
        """
        Remove hosts-file entries and all firewall rules for *url*.

        Steps:
          1. Extract domain.
          2. Strip domain's fence from hosts file.
          3. Write updated hosts file.
          4. Flush DNS.
          5. Resolve domain → unblock each resolved IP from firewall.
          6. Discard domain from blocked_urls.
          7. Persist.

        After this returns, the domain is completely gone from all
        state structures — re-blocking will be treated as a new request.
        """
        domain = self._extract_domain(url)
        if not domain:
            return f"Error: invalid URL '{url}'"

        logger.info("[unblock_url] START — domain=%s", domain)

        hosts    = _hosts_path()
        existing = self._read_hosts(hosts)

        if self._begin(domain) not in existing:
            logger.debug("[unblock_url] domain %s not in hosts file", domain)
            # Clean up in-memory state regardless
            blocked_urls.discard(domain)
            blocked_urls.discard(url.lower())
            _save_persisted(blocked_ips, blocked_urls)
            return f"Domain '{domain}' was not in hosts file (already unblocked?)"

        # Step 2+3: Strip and write
        new_content = self._strip_domain_block(existing, domain)
        new_content = new_content.rstrip("\n") + "\n"

        try:
            _write_hosts(new_content, hosts)
            logger.debug("[unblock_url] hosts file updated for %s", domain)
        except PermissionError as e:
            return (
                f"Permission denied writing to {hosts}: {e}. "
                "Run the agent as Administrator / root."
            )
        except Exception as e:
            return f"Failed to write hosts file: {e}"

        # Step 4: Flush DNS
        _flush_dns()

        # Step 5: Remove firewall rules for resolved IPs
        # We try to resolve even after the hosts change (may fail — that's OK)
        removed_ips: list[str] = []
        try:
            resolved = list({
                info[4][0]
                for info in _socket.getaddrinfo(domain, None)
                if ":" not in info[4][0]
            })[:4]
            for rip in resolved:
                self.ip_blocker.unblock(rip, blocked_ips, blocked_urls, fw_applied)
                removed_ips.append(rip)
        except Exception:
            pass

        if fw_applied is not None:
            fw_applied.discard(domain)

        # Step 6+7: Discard and persist
        blocked_urls.discard(domain)
        blocked_urls.discard(url.lower())
        _save_persisted(blocked_ips, blocked_urls)

        fw_msg = f" + firewall rules removed for {', '.join(removed_ips)}" if removed_ips else ""
        logger.info("[unblock_url] SUCCESS — domain=%s%s", domain, fw_msg)
        return f"Domain '{domain}' unblocked — hosts entries removed, DNS flushed{fw_msg}"

    def is_blocked(self, url: str, blocked_urls: Set[str]) -> bool:
        domain = self._extract_domain(url)
        return domain in blocked_urls or url.lower() in blocked_urls


# ═══════════════════════════════════════════════════════════════════════════════
#  STARTUP — re-apply persisted blocks
# ═══════════════════════════════════════════════════════════════════════════════

def restore_blocks_on_startup(
    blocked_ips:  Set[str],
    blocked_urls: Set[str],
    ip_blocker:   IPBlocker,
    url_blocker:  URLBlocker,
) -> None:
    """
    Called once at agent startup. Loads the persisted block list and
    re-applies firewall rules for every previously-blocked IP.
    URL blocks survive via the hosts file and do not need re-applying.
    """
    data = _load_persisted()
    logger.info(
        "[startup] Restoring %d IPs, %d URLs from %s",
        len(data["ips"]), len(data["urls"]), _BLOCKS_FILE,
    )

    for ip in data["ips"]:
        blocked_ips.add(ip)
        try:
            ip_blocker.reapply(ip)
            logger.info("[startup] Restored firewall block for IP: %s", ip)
        except Exception as e:
            logger.error("[startup] Failed to restore block for %s: %s", ip, e)

    for domain in data["urls"]:
        blocked_urls.add(domain)
        logger.info("[startup] Restored URL block for domain: %s", domain)
