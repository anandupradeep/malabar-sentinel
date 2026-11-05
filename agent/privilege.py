"""
Privilege helper — Issue 8
Check admin/root status before executing privileged operations.
"""
import os
import sys


def is_admin() -> bool:
    """Return True if the current process has administrator/root privileges."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def require_admin(operation: str) -> tuple:
    """
    Returns (ok: bool, message: str).
    ok=False means the operation must not proceed.
    """
    if is_admin():
        return True, "Admin/root privileges confirmed"
    if os.name == "nt":
        msg = (
            f"'{operation}' requires Administrator privileges.\n"
            "Right-click the Agent shortcut → Run as Administrator."
        )
    else:
        msg = (
            f"'{operation}' requires root privileges.\n"
            "Run the agent with: sudo python agent/main.py"
        )
    return False, msg


def admin_status_str() -> str:
    if is_admin():
        return "✓ Administrator" if os.name == "nt" else "✓ root"
    return "⚠ NOT Admin — USB/Firewall commands limited"
