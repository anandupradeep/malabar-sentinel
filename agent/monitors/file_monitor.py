"""
File Monitor — Issue 3/9
• Issue 3: severity = CRITICAL (confidential), HIGH (sensitive), MEDIUM/LOW (other)
• Issue 9: detect file OPEN via atime polling; modify via mtime; create/delete/move via watchdog
"""
import logging, os, threading, time
from typing import TYPE_CHECKING, List

logger = logging.getLogger("file-monitor")

if TYPE_CHECKING:
    from agent.agent_core import AgentCore


class FileMonitor:
    def __init__(self, agent: "AgentCore", paths: List[str] = None):
        self.agent   = agent
        self.running = False
        self._paths  = [p for p in (paths or []) if p]
        self._lock   = threading.Lock()
        self._mtime_snap: dict = {}
        self._atime_snap: dict = {}

    def set_paths(self, paths: List[str]):
        with self._lock: self._paths = [p for p in paths if p]
        self._rebuild_snapshot()
        logger.info("FileMonitor paths → %s", self._paths)

    def _all_files(self) -> List[str]:
        files = []
        with self._lock: paths = list(self._paths)
        for path in paths:
            if os.path.isfile(path):
                files.append(path)
            elif os.path.isdir(path):
                for root, _, fns in os.walk(path):
                    for fn in fns: files.append(os.path.join(root, fn))
        return files

    def _rebuild_snapshot(self):
        ms = {}; as_ = {}
        for fp in self._all_files():
            try:
                st = os.stat(fp)
                ms[fp] = st.st_mtime; as_[fp] = st.st_atime
            except Exception: pass
        with self._lock: self._mtime_snap = ms; self._atime_snap = as_

    def run(self):
        self.running = True
        logger.info("FileMonitor started")
        self._rebuild_snapshot()
        try:
            from watchdog.observers import Observer
            from watchdog.events    import FileSystemEventHandler
            mon = self
            class _H(FileSystemEventHandler):
                def on_modified(self, e):
                    if not e.is_directory: mon._handle_event(e.src_path, "modified")
                def on_created(self,  e):
                    if not e.is_directory: mon._handle_event(e.src_path, "created")
                def on_deleted(self,  e):
                    if not e.is_directory: mon._handle_event(e.src_path, "deleted")
                def on_moved(self,    e):
                    if not e.is_directory: mon._handle_event(e.src_path, "moved")
            handler = _H(); observer = Observer(); watched = set()
            def _sched():
                with self._lock: paths = list(self._paths)
                for p in paths:
                    d = p if os.path.isdir(p) else os.path.dirname(p)
                    if d and d not in watched and os.path.exists(d):
                        observer.schedule(handler, d, recursive=True)
                        watched.add(d)
            _sched(); observer.start()
            while self.running:
                time.sleep(2)
                self._poll_atime()   # Issue 9 — file open detection
                _sched()
            observer.stop(); observer.join()
        except ImportError:
            logger.warning("watchdog not installed — polling fallback")
            self._run_polling()

    def _poll_atime(self):
        """Issue 9 — detect file opens by atime change."""
        for fp in self._all_files():
            try:
                st = os.stat(fp)
                old_a = self._atime_snap.get(fp)
                if old_a is not None and st.st_atime > old_a + 0.5:
                    self._handle_event(fp, "accessed")
                with self._lock: self._atime_snap[fp] = st.st_atime
            except Exception: pass

    def _run_polling(self):
        while self.running:
            time.sleep(5)
            if not self._paths: continue
            new_m = {}; new_a = {}
            for fp in self._all_files():
                try:
                    st = os.stat(fp); new_m[fp] = st.st_mtime; new_a[fp] = st.st_atime
                    old_m = self._mtime_snap.get(fp)
                    old_a = self._atime_snap.get(fp)
                    if old_m is None:              self._handle_event(fp, "created")
                    elif st.st_mtime > old_m + 0.5: self._handle_event(fp, "modified")
                    elif old_a and st.st_atime > old_a + 0.5: self._handle_event(fp, "accessed")
                except Exception:
                    if fp in self._mtime_snap: self._handle_event(fp, "deleted")
            with self._lock: old_m = dict(self._mtime_snap)
            for fp in old_m:
                if fp not in new_m and not os.path.exists(fp):
                    self._handle_event(fp, "deleted")
            with self._lock: self._mtime_snap = new_m; self._atime_snap = new_a

    def _handle_event(self, filepath: str, event_type: str):
        name    = os.path.basename(filepath)
        is_conf = self.agent.is_confidential(filepath)

        # Issue 3 — severity mapping
        sev = self.agent._file_severity(filepath, event_type)

        if event_type == "deleted":
            title = f"Sensitive File Deleted: {name}"
            desc  = f"File was deleted: {filepath}"
        elif event_type == "modified":
            title = f"Sensitive File Modified: {name}"
            desc  = f"Content was changed: {filepath}"
        elif event_type == "accessed":
            # Issue 9 — on_open simulation
            title = f"Sensitive File Opened/Read: {name}"
            desc  = f"File was accessed (opened): {filepath}"
        elif event_type == "created":
            title = f"New File in Protected Location: {name}"
            desc  = f"Created: {filepath}"
        elif event_type == "moved":
            title = f"Sensitive File Moved: {name}"
            desc  = f"Relocated: {filepath}"
        else:
            title = f"File Event [{event_type}]: {name}"; desc = filepath

        if is_conf:
            title = "⚠ CONFIDENTIAL — " + title

        self.agent.send_alert(
            "sensitive_file", sev, title, desc,
            file_path=filepath,
            raw_data={"event": event_type, "path": filepath, "confidential": is_conf},
        )
        logger.info("FileMonitor [%s] %s (%s)", event_type.upper(), filepath, sev)
