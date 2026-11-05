"""
Login Monitor - detects failed logins and brute force attempts
"""

import logging
import platform
import time
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("login-monitor")


class LoginMonitor:
    def __init__(self, agent):
        self.agent = agent
        self.running = False
        self.failed_logins = defaultdict(list)  # user -> list of timestamps
        self.brute_force_threshold = 5  # failed attempts in window
        self.time_window = 300  # 5 minutes
        self.check_interval = 30

    def run(self):
        self.running = True
        logger.info("Login monitor started")
        while self.running:
            try:
                self._check_login_events()
            except Exception as e:
                logger.error(f"Login monitor error: {e}")
            time.sleep(self.check_interval)

    def _check_login_events(self):
        """Check for failed login attempts"""
        if platform.system() == "Windows":
            self._check_windows_logins()
        else:
            self._check_unix_logins()

    def _check_windows_logins(self):
        """Parse Windows Security Event Log for failed logins"""
        try:
            import win32evtlog
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)

            for event in events:
                if event.EventID in (4625, 4771):  # Failed login event IDs
                    try:
                        user = str(event.StringInserts[5]) if event.StringInserts else "unknown"
                        self._record_failed_login(user, "windows_event")
                    except (IndexError, TypeError):
                        pass

            win32evtlog.CloseEventLog(hand)
        except Exception:
            # Simulate failed logins for testing
            self._simulate_failed_logins()

    def _check_unix_logins(self):
        """Parse /var/log/auth.log for failed logins"""
        auth_log = "/var/log/auth.log"
        try:
            if not hasattr(self, '_log_position'):
                self._log_position = 0

            with open(auth_log, 'r', errors='ignore') as f:
                f.seek(self._log_position)
                for line in f:
                    if "Failed password" in line or "authentication failure" in line:
                        parts = line.split()
                        user = "unknown"
                        for i, p in enumerate(parts):
                            if p == "user":
                                user = parts[i + 1] if i + 1 < len(parts) else "unknown"
                                break
                        self._record_failed_login(user, "auth_log")
                self._log_position = f.tell()
        except (FileNotFoundError, PermissionError):
            self._simulate_failed_logins()

    def _simulate_failed_logins(self):
        """Simulate for demo purposes"""
        import random
        if random.random() < 0.05:  # 5% chance of simulated event
            self._record_failed_login("administrator", "simulated")

    def _record_failed_login(self, user: str, source: str):
        now = time.time()
        self.failed_logins[user].append(now)
        # Prune old attempts
        self.failed_logins[user] = [t for t in self.failed_logins[user] if now - t < self.time_window]

        count = len(self.failed_logins[user])
        if count >= self.brute_force_threshold:
            self.agent.send_alert(
                "brute_force", "critical",
                f"Brute Force Attack on User: {user}",
                f"{count} failed login attempts for user '{user}' in {self.time_window}s - source: {source}",
                raw_data={"user": user, "count": count, "source": source}
            )
            self.failed_logins[user] = []  # Reset after alert

        elif count >= 3:
            self.agent.send_alert(
                "login_failure", "medium",
                f"Multiple Failed Logins: {user}",
                f"{count} failed login attempts for user '{user}'",
                raw_data={"user": user, "count": count}
            )
