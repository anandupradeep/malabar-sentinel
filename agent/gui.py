"""
Malabar Sentinel GUI — Production upgrade
Issues 4/5/6/8 added; all prior fixes preserved.

Issue 4  – Agent login system (first-run create / every-run login)
Issue 5  – Session token attached to all HTTP requests
Issue 6  – QMessageBox confirmation on every Rule Apply/Save
Issue 8  – Admin badge in header; blocked ops show error dialog
"""
import json, os, socket, sys, threading, time
from datetime import datetime

# ── Qt ─────────────────────────────────────────────────────────────────────
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QTabWidget, QTextEdit, QLineEdit, QGroupBox,
        QListWidget, QFileDialog, QComboBox, QCheckBox, QProgressBar,
        QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
        QMessageBox, QSystemTrayIcon, QMenu, QAction, QStatusBar, QSplitter,
        QDialog, QDialogButtonBox, QFormLayout, QInputDialog,
    )
    from PyQt5.QtCore  import Qt, pyqtSignal, QTimer
    from PyQt5.QtGui   import QFont, QColor
    QT = 5
except ImportError:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QTabWidget, QTextEdit, QLineEdit, QGroupBox,
        QListWidget, QFileDialog, QComboBox, QCheckBox, QProgressBar,
        QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
        QMessageBox, QSystemTrayIcon, QMenu, QAction, QStatusBar, QSplitter,
        QDialog, QDialogButtonBox, QFormLayout, QInputDialog,
    )
    from PyQt6.QtCore  import Qt, pyqtSignal, QTimer
    from PyQt6.QtGui   import QFont, QColor
    QT = 6

import psutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.auth      import (credentials_exist, save_credentials,
                               verify_credentials, get_stored_username,
                               create_session_token, get_token)
from agent.privilege import admin_status_str, is_admin

# ── Auto-elevate to Administrator on Windows ──────────────────────────────────
def _ensure_admin():
    """
    If we are NOT running as Administrator on Windows, re-launch this
    exact process with 'runas' (which triggers the UAC prompt) and exit
    the non-elevated copy.  On Linux this is a no-op (use sudo/service).
    """
    if os.name != "nt":
        return  # Linux handles privilege via sudo / systemd service
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return  # Already admin — nothing to do
    except Exception:
        return

    # Re-launch with elevation
    import ctypes
    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    # ShellExecuteW with 'runas' triggers UAC
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas",
        sys.executable,
        f'"{script}" {params}',
        os.path.dirname(script),
        1   # SW_SHOWNORMAL
    )
    if ret > 32:
        sys.exit(0)  # Elevated copy is starting — exit this one
    # ret <= 32 means user cancelled UAC — continue without elevation


# ── Windows Task Scheduler — persist agent as a startup task ─────────────────
TASK_NAME = "MalabarSentinelAgent"

def _register_startup_task():
    """
    Register a Windows Task Scheduler task using XML (most reliable method —
    avoids all path-quoting issues with spaces in Python installation paths).
    - Triggers at logon of any user (30s delay to let network settle)
    - Runs with HIGHEST privileges (no UAC prompt)
    - Auto-restarts up to 3 times if it crashes
    - Uses the project root as working directory
    """
    if os.name != "nt":
        return False, "Task Scheduler is Windows-only. On Linux use a systemd service."
    try:
        import subprocess as _sp
        import tempfile

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Prefer pythonw.exe (no console window) over python.exe
        pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if not os.path.exists(pythonw):
            pythonw = sys.executable
        agent_script = os.path.join(project_root, "agent", "main.py")

        # Build Task XML — completely sidesteps schtasks /TR quoting problems
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Malabar Sentinel EDR Agent — auto-starts at logon with admin privileges</Description>
    <Author>Malabar Sentinel</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c "set MALABAR_AUTOSTART=1 &amp;&amp; start /B {pythonw} \"{agent_script}\""</Arguments>
      <WorkingDirectory>{project_root}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"""

        # Write XML to a temp file (UTF-16 required by schtasks /XML)
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.xml',
                                          delete=False, encoding='utf-16')
        tmp.write(xml)
        tmp.close()

        # Delete any existing task first
        _sp.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                capture_output=True, timeout=10)

        # Import via XML
        r = _sp.run(
            ["schtasks", "/Create", "/TN", TASK_NAME, "/XML", tmp.name, "/F"],
            capture_output=True, text=True, timeout=20
        )
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

        if r.returncode == 0:
            return True, (
                f"✓ Startup task '{TASK_NAME}' created successfully.\n\n"
                f"  Trigger   : At logon (30s delay)\n"
                f"  Privilege : Highest (no UAC prompt)\n"
                f"  Python    : {pythonw}\n"
                f"  Script    : {agent_script}\n"
                f"  Workdir   : {project_root}\n\n"
                f"The agent will auto-start and auto-connect on next Windows login."
            )
        else:
            err = r.stderr.strip() or r.stdout.strip()
            return False, (
                f"Task creation failed (code {r.returncode}):\n{err}\n\n"
                f"Make sure you are running the agent as Administrator."
            )
    except Exception as e:
        return False, f"Failed to register startup task: {e}"


def _unregister_startup_task():
    """Remove the startup task."""
    if os.name != "nt":
        return False, "Windows-only."
    try:
        import subprocess as _sp
        r = _sp.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                    capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return True, f"✓ Startup task '{TASK_NAME}' removed."
        else:
            return False, f"Could not remove task: {r.stderr.strip()}"
    except Exception as e:
        return False, f"Error: {e}"


def _startup_task_exists() -> bool:
    if os.name != "nt":
        return False
    try:
        import subprocess as _sp
        r = _sp.run(["schtasks", "/Query", "/TN", TASK_NAME],
                    capture_output=True, text=True, timeout=8)
        return r.returncode == 0
    except Exception:
        return False

# ── Rules file ─────────────────────────────────────────────────────────────
RULES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "agent_rules.json",
)
os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)

DEFAULT_RULES = {
    "allowed_processes": [
        "explorer.exe", "svchost.exe", "lsass.exe", "chrome.exe",
        "msedge.exe", "winword.exe", "excel.exe", "teams.exe",
        "outlook.exe", "code.exe", "python.exe", "python3.exe", "notepad.exe",
    ],
    "blocked_ips":        [],
    "allowed_usb":        [],
    "sensitive_paths":    [],
    "confidential_paths": [],
    "monitoring": {
        "process_monitor": True, "network_monitor": True,
        "file_monitor":    True, "usb_monitor":     True,
        "login_monitor":   True, "memory_monitor":  True,
        "ransomware_detector": True, "hash_scanner": True,
        "kernel_monitor":  True,
    },
}

def load_rules():
    try:
        if os.path.exists(RULES_FILE):
            d = json.load(open(RULES_FILE))
            for k, v in DEFAULT_RULES.items():
                d.setdefault(k, v)
            return d
    except Exception:
        pass
    return DEFAULT_RULES.copy()

def save_rules(rules):
    try:
        json.dump(rules, open(RULES_FILE, "w"), indent=2)
    except Exception:
        pass

# ── Style ──────────────────────────────────────────────────────────────────
STYLE = """
QMainWindow,QWidget{background:#0d1117;color:#c9d1d9;
  font-family:"Segoe UI",Consolas,sans-serif;font-size:13px}
#header{background:#010409;border-bottom:2px solid #00ff88}
QTabWidget::pane{border:1px solid #21262d;background:#0d1117}
QTabBar::tab{background:#010409;color:#8b949e;
  padding:10px 16px;border:none;font-size:11px;letter-spacing:1px}
QTabBar::tab:selected{background:#0d1117;color:#00ff88;
  border-bottom:2px solid #00ff88}
QPushButton{background:#21262d;color:#c9d1d9;border:1px solid #30363d;
  border-radius:4px;padding:6px 14px;font-family:Consolas;font-size:11px}
QPushButton:hover{background:#30363d;border-color:#58a6ff}
QPushButton#ok{background:#196c2e;color:#00ff88;border-color:#00ff88}
QPushButton#ok:hover{background:#1f8237}
QPushButton#stop{background:#6e1419;color:#ff4444;border-color:#ff4444}
QPushButton#stop:hover{background:#8a1c22}
QPushButton#red_btn{background:#4a0a0a;color:#ff6b6b;border-color:#ff4444}
QPushButton#red_btn:hover{background:#5c1010}
QPushButton#conn{background:#0f3d5c;color:#4fc3f7;border-color:#4fc3f7}
QPushButton#conn:hover{background:#1a5470}
QPushButton#disc{background:#4a1a00;color:#ff8c42;border-color:#ff8c42}
QPushButton#disc:hover{background:#6b2500}
QPushButton#warn{background:#4a3300;color:#ffcc44;border-color:#ffcc44}
QPushButton#warn:hover{background:#6b4a00}
QPushButton#del{background:#3d1f1f;color:#ff6b6b;border-color:#ff6b6b;
  font-size:10px;padding:3px 9px}
QGroupBox{border:1px solid #21262d;border-radius:5px;margin-top:8px;
  padding:10px;color:#8b949e;font-size:11px}
QGroupBox::title{color:#8b949e;subcontrol-position:top left;padding:0 6px}
QListWidget,QTableWidget,QTextEdit,QLineEdit{
  background:#010409;border:1px solid #21262d;color:#c9d1d9;border-radius:3px}
QLineEdit{padding:5px 8px;font-family:Consolas}
QTableWidget::item:selected{background:#1f6feb}
QHeaderView::section{background:#161b22;color:#8b949e;border:none;
  padding:5px;font-family:Consolas;font-size:9px;letter-spacing:1px}
QProgressBar{border:1px solid #21262d;border-radius:3px;
  background:#010409;text-align:center;height:14px}
QProgressBar::chunk{background:#00ff88;border-radius:2px}
QCheckBox{color:#c9d1d9;spacing:6px}
QCheckBox::indicator{width:14px;height:14px;border:1px solid #30363d;
  border-radius:2px;background:#21262d}
QCheckBox::indicator:checked{background:#00ff88;border-color:#00ff88}
QComboBox{background:#21262d;border:1px solid #30363d;
  border-radius:3px;padding:4px 8px;color:#c9d1d9}
QStatusBar{background:#010409;color:#555;border-top:1px solid #21262d}
#stat_card{background:#161b22;border:1px solid #21262d;
  border-radius:6px;margin:4px;padding:12px}
QDialog{background:#0d1117;color:#c9d1d9}
"""

SEV_COLOR = {
    "emergency": "#ff00ff", "critical": "#ff4444",
    "high":      "#ff8800", "medium":   "#ffcc00",
    "low":       "#aaaaaa",
}

# ══════════════════════════════════════════════════════════════════════════════
# Professional styled dialog — replaces plain QMessageBox
# ══════════════════════════════════════════════════════════════════════════════
class SentinelDialog(QDialog):
    """
    Kerala Police EDR — Professional notification dialog.
    Replaces plain QMessageBox with styled, branded dialogs.
    """
    INFO    = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR   = "error"
    CONFIRM = "confirm"

    _ICONS = {
        "info":    "ℹ",
        "success": "✅",
        "warning": "⚠",
        "error":   "🚨",
        "confirm": "❓",
    }
    _COLORS = {
        "info":    "#4fc3f7",
        "success": "#00ff88",
        "warning": "#ffcc00",
        "error":   "#ff4444",
        "confirm": "#ff8c42",
    }

    def __init__(self, parent, kind: str, title: str, message: str):
        super().__init__(parent)
        self.setModal(True)
        self.setStyleSheet(STYLE + """
            SentinelDialog {min-width:420px}
            #dlg_header{background:#010409;border-bottom:2px solid """ +
            self._COLORS.get(kind, "#4fc3f7") + """;padding:14px 18px}
            #dlg_body{padding:18px 20px}
            #dlg_footer{background:#010409;border-top:1px solid #21262d;padding:10px 18px}
        """)
        self.setWindowTitle(f"Malabar Sentinel — {title}")
        self._result = False
        self._build(kind, title, message)

    def _build(self, kind, title, message):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Header
        hdr = QFrame(); hdr.setObjectName("dlg_header")
        hl  = QHBoxLayout(hdr); hl.setContentsMargins(14, 10, 14, 10)
        icon_lbl = QLabel(self._ICONS.get(kind, "ℹ"))
        icon_lbl.setFont(QFont("Segoe UI Emoji", 22))
        icon_lbl.setStyleSheet(f"color:{self._COLORS.get(kind,'#4fc3f7')}")
        title_lbl = QLabel(title)
        title_lbl.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color:{self._COLORS.get(kind,'#4fc3f7')};letter-spacing:1px")
        badge = QLabel("MALABAR SENTINEL")
        badge.setStyleSheet("color:#555;font-family:Consolas;font-size:9px;letter-spacing:2px")
        hl.addWidget(icon_lbl); hl.addWidget(title_lbl); hl.addStretch(); hl.addWidget(badge)
        lay.addWidget(hdr)

        # Body
        body = QFrame(); body.setObjectName("dlg_body")
        bl   = QVBoxLayout(body); bl.setContentsMargins(20, 16, 20, 16)
        msg  = QLabel(message)
        msg.setWordWrap(True)
        msg.setStyleSheet("color:#c9d1d9;font-size:13px;line-height:1.5")
        msg.setFont(QFont("Segoe UI", 10))
        bl.addWidget(msg)
        lay.addWidget(body)

        # Footer buttons
        ftr = QFrame(); ftr.setObjectName("dlg_footer")
        fl  = QHBoxLayout(ftr); fl.setContentsMargins(14, 8, 14, 8)
        fl.addStretch()
        if kind == self.CONFIRM:
            btn_no  = QPushButton("  Cancel  "); btn_no.setObjectName("disc")
            btn_yes = QPushButton("  Confirm  "); btn_yes.setObjectName("stop")
            btn_yes.setDefault(True)
            btn_no.clicked.connect(self.reject)
            btn_yes.clicked.connect(self._on_yes)
            fl.addWidget(btn_no); fl.addWidget(btn_yes)
        else:
            btn_ok = QPushButton("  OK  ")
            btn_ok.setObjectName("ok" if kind == "success" else "conn")
            btn_ok.setDefault(True)
            btn_ok.clicked.connect(self.accept)
            fl.addWidget(btn_ok)
        lay.addWidget(ftr)

    def _on_yes(self):
        self._result = True
        self.accept()

    # ── Static convenience methods ────────────────────────────────────────────
    @staticmethod
    def info(parent, title, message):
        d = SentinelDialog(parent, SentinelDialog.INFO, title, message)
        d.exec()

    @staticmethod
    def success(parent, title, message):
        d = SentinelDialog(parent, SentinelDialog.SUCCESS, title, message)
        d.exec()

    @staticmethod
    def warning(parent, title, message):
        d = SentinelDialog(parent, SentinelDialog.WARNING, title, message)
        d.exec()

    @staticmethod
    def error(parent, title, message):
        d = SentinelDialog(parent, SentinelDialog.ERROR, title, message)
        d.exec()

    @staticmethod
    def confirm(parent, title, message) -> bool:
        d = SentinelDialog(parent, SentinelDialog.CONFIRM, title, message)
        d.exec()
        return d._result



# ══════════════════════════════════════════════════════════════════════════════
# Issue 4: Login / Register Dialog
# ══════════════════════════════════════════════════════════════════════════════
class LoginDialog(QDialog):
    """
    Shows on every launch.
    • First run  → Register tab (create username + password)
    • Subsequent → Login tab
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Malabar Sentinel — Authentication")
        self.setMinimumWidth(400)
        self.setStyleSheet(STYLE)
        self.setModal(True)
        self.authenticated = False
        self.username      = ""
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)

        title = QLabel("🛡  MALABAR SENTINEL")
        title.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        title.setStyleSheet("color:#00ff88;letter-spacing:3px;"
                            "padding:12px;text-align:center")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title)

        first_run = not credentials_exist()
        if first_run:
            lay.addWidget(self._setup_panel())
        else:
            lay.addWidget(self._login_panel())

    def _login_panel(self):
        grp = QGroupBox("Login to Agent")
        fl  = QFormLayout()

        stored = get_stored_username()
        self._lu = QLineEdit(stored)
        self._lu.setPlaceholderText("Username")
        self._lp = QLineEdit()
        self._lp.setEchoMode(QLineEdit.EchoMode.Password)
        self._lp.setPlaceholderText("Password")
        self._lp.returnPressed.connect(self._do_login)

        fl.addRow("Username:", self._lu)
        fl.addRow("Password:", self._lp)
        grp.setLayout(fl)

        self._lerr = QLabel("")
        self._lerr.setStyleSheet("color:#ff4444;font-family:Consolas;font-size:11px")

        btn = QPushButton("🔓  Login")
        btn.setObjectName("ok"); btn.setFixedHeight(38)
        btn.clicked.connect(self._do_login)

        w = QWidget(); vl = QVBoxLayout(w)
        vl.addWidget(grp); vl.addWidget(self._lerr); vl.addWidget(btn)
        return w

    def _setup_panel(self):
        grp = QGroupBox("First Run — Create Agent Credentials")
        fl  = QFormLayout()

        self._su = QLineEdit(); self._su.setPlaceholderText("Choose a username")
        self._sp = QLineEdit(); self._sp.setEchoMode(QLineEdit.EchoMode.Password)
        self._sp.setPlaceholderText("Choose a password (min 6 chars)")
        self._sp2 = QLineEdit(); self._sp2.setEchoMode(QLineEdit.EchoMode.Password)
        self._sp2.setPlaceholderText("Confirm password")
        self._sp2.returnPressed.connect(self._do_register)

        fl.addRow("Username:", self._su)
        fl.addRow("Password:", self._sp)
        fl.addRow("Confirm:",  self._sp2)
        grp.setLayout(fl)

        self._serr = QLabel("")
        self._serr.setStyleSheet("color:#ff4444;font-family:Consolas;font-size:11px")
        self._serr.setWordWrap(True)

        btn = QPushButton("✓  Create Account & Login")
        btn.setObjectName("ok"); btn.setFixedHeight(38)
        btn.clicked.connect(self._do_register)

        w = QWidget(); vl = QVBoxLayout(w)
        vl.addWidget(grp); vl.addWidget(self._serr); vl.addWidget(btn)
        return w

    def _do_login(self):
        u = self._lu.text().strip()
        p = self._lp.text()
        if not u or not p:
            self._lerr.setText("Username and password required"); return
        if verify_credentials(u, p):
            self.username      = u
            self.authenticated = True
            create_session_token(u)
            self.accept()
        else:
            self._lerr.setText("❌  Invalid username or password")
            self._lp.clear()

    def _do_register(self):
        u  = self._su.text().strip()
        p  = self._sp.text()
        p2 = self._sp2.text()
        if not u:
            self._serr.setText("Username required"); return
        if len(p) < 6:
            self._serr.setText("Password must be at least 6 characters"); return
        if p != p2:
            self._serr.setText("Passwords do not match"); return
        if save_credentials(u, p):
            self.username      = u
            self.authenticated = True
            create_session_token(u)
            self.accept()
        else:
            self._serr.setText("Failed to save credentials — check permissions")


# ══════════════════════════════════════════════════════════════════════════════
# Main Window
# ══════════════════════════════════════════════════════════════════════════════
class AgentGUI(QMainWindow):
    _sig_connected   = pyqtSignal(str, dict)
    _sig_conn_failed = pyqtSignal(str)
    _sig_log         = pyqtSignal(str, str)
    _sig_status      = pyqtSignal(str)
    _sig_alert       = pyqtSignal(dict)
    _sig_cmd_notify  = pyqtSignal(str, str)   # (type, message)  type: ok|warn|err

    def __init__(self, logged_in_user: str = ""):
        super().__init__()
        self.agent_core      = None
        self.monitoring      = False
        self.connected       = False
        self.rules           = load_rules()
        self._start_time     = None
        self._alert_count    = 0
        self._logged_in_user = logged_in_user

        self.setWindowTitle("Malabar Sentinel v1.0 — Kerala Police EDR")
        self.setMinimumSize(1200, 820)
        self.setStyleSheet(STYLE)

        self._build_ui()
        self._setup_tray()

        self._sig_connected.connect(self._on_connected)
        self._sig_conn_failed.connect(self._on_conn_fail)
        self._sig_log.connect(self._append_log)
        self._sig_status.connect(lambda m: self.status_bar.showMessage(m))
        self._sig_alert.connect(self._on_new_alert)

        QTimer(self, timeout=self._refresh_metrics,    interval=3000).start()
        QTimer(self, timeout=self._refresh_alert_table, interval=2000).start()
        QTimer(self, timeout=self._refresh_usb_drives,  interval=3000).start()
        QTimer.singleShot(1500, self._auto_connect)

    # ── Build UI ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        root.addWidget(self._build_header())

        # ── Command flash banner (hidden by default) ──────────────────────────
        self._cmd_banner = QLabel("")
        self._cmd_banner.setFixedHeight(32)
        self._cmd_banner.setAlignment(Qt.AlignmentFlag.Center if hasattr(Qt.AlignmentFlag,'Center') else Qt.AlignCenter)
        self._cmd_banner.setStyleSheet(
            "font-family:monospace;font-size:12px;font-weight:bold;"
            "padding:0 16px;letter-spacing:1px;")
        self._cmd_banner.hide()
        root.addWidget(self._cmd_banner)
        self._cmd_banner_timer = QTimer(self); self._cmd_banner_timer.setSingleShot(True)
        self._cmd_banner_timer.timeout.connect(self._cmd_banner.hide)
        self._sig_cmd_notify.connect(self._show_cmd_banner)

        tabs = QTabWidget()
        tabs.addTab(self._tab_overview(),     "⬛  Overview")
        tabs.addTab(self._tab_alerts(),       "⚠  Alerts")
        tabs.addTab(self._tab_monitors(),     "⬡  Monitors")
        tabs.addTab(self._tab_rules(),        "⚙  Rules")
        tabs.addTab(self._tab_usb(),          "🔌  USB Control")
        tabs.addTab(self._tab_file_protect(), "🔒  File Protection")
        tabs.addTab(self._tab_logs(),         "📋  Logs")
        tabs.addTab(self._tab_settings(),     "⚙  Settings")
        root.addWidget(tabs)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Initializing…")

    def _show_cmd_banner(self, btype: str, message: str):
        """Show a flash banner at the top of the window for command events."""
        styles = {
            "ok":   "background:#0d2e20;color:#00f5c4;border-bottom:2px solid #00f5c4;",
            "warn": "background:#2e1e00;color:#ffd700;border-bottom:2px solid #ffd700;",
            "err":  "background:#2e0010;color:#ff6b8a;border-bottom:2px solid #ff3860;",
            "info": "background:#0d1e2e;color:#4fc3f7;border-bottom:2px solid #4fc3f7;",
        }
        icons = {"ok": "✓", "warn": "⚠", "err": "✗", "info": "⚙"}
        self._cmd_banner.setStyleSheet(
            "font-family:monospace;font-size:12px;font-weight:bold;"
            "padding:0 16px;letter-spacing:1px;" + styles.get(btype, styles["info"]))
        self._cmd_banner.setText(f"  {icons.get(btype,'•')}  {message}")
        self._cmd_banner.show()
        self._cmd_banner_timer.start(4500)

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = QFrame(); hdr.setObjectName("header"); hdr.setFixedHeight(66)
        lay = QHBoxLayout(hdr); lay.setContentsMargins(18,8,18,8)

        title = QLabel("🛡  MALABAR SENTINEL")
        title.setFont(QFont("Consolas", 15, QFont.Weight.Bold))
        title.setStyleSheet("color:#00ff88;letter-spacing:3px")

        self.dot      = QLabel("●")
        self.dot.setFont(QFont("Arial", 22))
        self.dot.setStyleSheet("color:#ff4444")

        self.conn_lbl = QLabel("OFFLINE")
        self.conn_lbl.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self.conn_lbl.setStyleSheet("color:#ff4444")

        # Issue 8 — Admin badge
        admin_ok  = is_admin()
        admin_col = "#00ff88" if admin_ok else "#ff8c42"
        admin_txt = "✓ ADMIN" if admin_ok else "⚠ NOT ADMIN"
        self._admin_lbl = QLabel(admin_txt)
        self._admin_lbl.setStyleSheet(
            f"color:{admin_col};font-family:Consolas;font-size:10px;"
            f"padding:3px 8px;border:1px solid {admin_col};border-radius:3px")

        # Issue 4 — logged-in user badge
        user_lbl = QLabel(f"👤 {self._logged_in_user}")
        user_lbl.setStyleSheet(
            "color:#4fc3f7;font-family:Consolas;font-size:10px;"
            "padding:3px 8px;border:1px solid #1a4a6b;border-radius:3px")

        self.btn_connect    = QPushButton("⟳  CONNECT")
        self.btn_connect.setObjectName("conn"); self.btn_connect.setFixedHeight(36)
        self.btn_connect.clicked.connect(self._do_connect)

        self.btn_disconnect = QPushButton("⏏  DISCONNECT")
        self.btn_disconnect.setObjectName("disc"); self.btn_disconnect.setFixedHeight(36)
        self.btn_disconnect.setEnabled(False)
        self.btn_disconnect.clicked.connect(self._do_disconnect)

        self.btn_start = QPushButton("▶  START MONITORING")
        self.btn_start.setObjectName("ok"); self.btn_start.setFixedHeight(36)
        self.btn_start.setEnabled(False)
        self.btn_start.clicked.connect(self._start_monitoring)

        self.btn_stop = QPushButton("■  STOP")
        self.btn_stop.setObjectName("stop"); self.btn_stop.setFixedHeight(36)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop_monitoring)

        lay.addWidget(title); lay.addStretch()
        for w in [self._admin_lbl, user_lbl, self.dot, self.conn_lbl]:
            lay.addWidget(w)
        lay.addSpacing(10)
        for w in [self.btn_connect, self.btn_disconnect,
                  self.btn_start, self.btn_stop]:
            lay.addWidget(w)
        return hdr

    # ── Overview ──────────────────────────────────────────────────────────────
    def _tab_overview(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(16,14,16,14)
        row = QHBoxLayout()
        self._sc_alerts   = self._stat_card("ALERTS SENT",     "0",        "#ff6b35")
        self._sc_critical = self._stat_card("CRITICAL",         "0",        "#ff4444")
        self._sc_monitors = self._stat_card("MONITORS ACTIVE",  "0",        "#00ff88")
        self._sc_uptime   = self._stat_card("UPTIME",           "00:00:00", "#4fc3f7")
        for c in [self._sc_alerts, self._sc_critical,
                  self._sc_monitors, self._sc_uptime]:
            row.addWidget(c)
        lay.addLayout(row)

        mg = QGroupBox("System Metrics"); ml = QVBoxLayout()
        self._cpu_bar  = self._metric_row("CPU")
        self._mem_bar  = self._metric_row("Memory")
        self._disk_bar = self._metric_row("Disk")
        for r in [self._cpu_bar, self._mem_bar, self._disk_bar]:
            ml.addLayout(r[0])
        mg.setLayout(ml); lay.addWidget(mg)

        ig = QGroupBox("Endpoint Info"); il = QVBoxLayout()
        self._info_lbl = QLabel("Initializing…")
        self._info_lbl.setStyleSheet(
            "color:#aaa;font-family:Consolas;font-size:11px")
        self._info_lbl.setWordWrap(True)
        il.addWidget(self._info_lbl); ig.setLayout(il); lay.addWidget(ig)
        return w

    def _stat_card(self, label, value, color):
        card = QFrame(); card.setObjectName("stat_card")
        lay  = QVBoxLayout(card)
        vl = QLabel(value); vl.setFont(QFont("Consolas", 26, QFont.Weight.Bold))
        vl.setStyleSheet(f"color:{color}")
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ll = QLabel(label); ll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ll.setStyleSheet("color:#777;font-size:10px;letter-spacing:1px")
        lay.addWidget(vl); lay.addWidget(ll); card._vl = vl; return card

    def _metric_row(self, label):
        lay = QHBoxLayout()
        lbl = QLabel(f"{label}:"); lbl.setFixedWidth(72)
        lbl.setStyleSheet("color:#aaa")
        bar = QProgressBar(); bar.setMaximum(100); bar.setFixedHeight(14)
        pct = QLabel("0%"); pct.setFixedWidth(42)
        pct.setStyleSheet("color:#aaa;font-family:Consolas;font-size:11px")
        lay.addWidget(lbl); lay.addWidget(bar); lay.addWidget(pct)
        return lay, bar, pct

    # ── Alerts tab ────────────────────────────────────────────────────────────
    def _tab_alerts(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(16,14,16,14)
        ctrl = QHBoxLayout()
        self._alert_filter = QComboBox()
        self._alert_filter.addItems(
            ["All","Emergency","Critical","High","Medium","Low"])
        self._alert_filter.currentTextChanged.connect(self._refresh_alert_table)
        btn_clr = QPushButton("Clear All")
        btn_clr.clicked.connect(self._clear_alerts)
        self._alert_count_lbl = QLabel("0 alerts")
        self._alert_count_lbl.setStyleSheet(
            "color:#aaa;font-family:Consolas;font-size:11px")
        ctrl.addWidget(QLabel("Filter:"))
        ctrl.addWidget(self._alert_filter)
        ctrl.addWidget(btn_clr); ctrl.addStretch()
        ctrl.addWidget(self._alert_count_lbl)
        lay.addLayout(ctrl)

        self._alert_table = QTableWidget()
        self._alert_table.setColumnCount(6)
        self._alert_table.setHorizontalHeaderLabels(
            ["Time","Severity","Title","Type","Endpoint","Description"])
        h = self._alert_table.horizontalHeader()
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._alert_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._alert_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self._alert_table.setAlternatingRowColors(True)
        lay.addWidget(self._alert_table)
        return w

    def _refresh_alert_table(self):
        if not self.agent_core: return
        all_alerts = self.agent_core.get_alerts()
        filt = self._alert_filter.currentText().lower()
        if filt != "all":
            all_alerts = [a for a in all_alerts
                          if a.get("severity","").lower() == filt]
        count = len(all_alerts)
        self._alert_count_lbl.setText(f"{count} alerts")
        if self._alert_table.rowCount() == count: return
        self._alert_table.setRowCount(0)
        for a in all_alerts:
            row = self._alert_table.rowCount()
            self._alert_table.insertRow(row)
            sev   = a.get("severity","low")
            color = SEV_COLOR.get(sev, "#aaaaaa")
            vals  = [
                a.get("created_at","")[:19].replace("T"," "),
                sev.upper(), a.get("title",""),
                a.get("alert_type",""), a.get("hostname",""),
                a.get("description","")[:120],
            ]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                item.setForeground(QColor(color))
                self._alert_table.setItem(row, col, item)
        if self.agent_core:
            total = len(self.agent_core.get_alerts())
            crit  = sum(1 for a in self.agent_core.get_alerts()
                        if a.get("severity") in ("critical","emergency"))
            self._sc_alerts._vl.setText(str(total))
            self._sc_critical._vl.setText(str(crit))

    def _clear_alerts(self):
        if self.agent_core:
            with self.agent_core._alert_lock: self.agent_core.alerts.clear()
        self._alert_table.setRowCount(0)
        self._alert_count_lbl.setText("0 alerts")

    def _on_new_alert(self, alert: dict):
        self._alert_count += 1
        sev = alert.get("severity","?").upper()
        self.status_bar.showMessage(f"[{sev}] {alert.get('title','Alert')}", 4000)

    # ── Monitors tab ──────────────────────────────────────────────────────────
    def _tab_monitors(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(16,14,16,14)
        MONS = [
            ("process_monitor",     "Process Monitor",     "Suspicious execution"),
            ("network_monitor",     "Network Monitor",     "Malicious IP / C2"),
            ("file_monitor",        "File Monitor",        "Access/modify of sensitive paths"),
            ("usb_monitor",         "USB Monitor",         "Insertion + exfiltration"),
            ("login_monitor",       "Login Monitor",       "Brute force detection"),
            ("memory_monitor",      "Memory Monitor",      "DLL injection, process hollowing"),
            ("ransomware_detector", "Ransomware Detector", "Mass encryption detection"),
            ("hash_scanner",        "Hash Scanner",        "SHA256 malware matching"),
            ("kernel_monitor",      "Kernel Monitor",      "Driver loads, privilege esc"),
        ]
        self._monitor_checks: dict = {}
        for key, name, desc in MONS:
            box = QGroupBox(); bl = QHBoxLayout(box)
            chk = QCheckBox(name)
            chk.setChecked(self.rules.get("monitoring",{}).get(key, True))
            chk.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            chk.setStyleSheet("color:#00ff88")
            chk.stateChanged.connect(lambda s, k=key: self._toggle_monitor(k, s))
            dl = QLabel(desc); dl.setStyleSheet("color:#777;font-size:11px")
            sl = QLabel("● ACTIVE")
            sl.setStyleSheet("color:#00ff88;font-family:Consolas;font-size:10px")
            bl.addWidget(chk); bl.addWidget(dl); bl.addStretch(); bl.addWidget(sl)
            lay.addWidget(box)
            self._monitor_checks[key] = (chk, sl)
        lay.addStretch(); return w

    def _toggle_monitor(self, key, state):
        self.rules.setdefault("monitoring",{})[key] = (state != 0)
        save_rules(self.rules)

    # ── Rules tab — Issue 6: confirmation on every Save/Apply ─────────────────
    def _tab_rules(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(16,14,16,14)
        lay.addWidget(QLabel("Detection rules — saved to config/agent_rules.json"))
        spl = QSplitter(Qt.Orientation.Horizontal)

        # Allowed processes
        pg = QGroupBox("✓ Allowed Processes"); pl = QVBoxLayout()
        self._proc_list = QListWidget(); self._proc_list.setFixedHeight(155)
        for p in self.rules.get("allowed_processes",[]): self._proc_list.addItem(p)
        pr = QHBoxLayout()
        self._proc_in = QLineEdit(); self._proc_in.setPlaceholderText("e.g. myapp.exe")
        self._proc_in.returnPressed.connect(self._add_proc)
        b1 = QPushButton("+ Add"); b1.setObjectName("ok"); b1.clicked.connect(self._add_proc)
        b2 = QPushButton("✕");    b2.setObjectName("del"); b2.clicked.connect(self._rem_proc)
        pr.addWidget(self._proc_in); pr.addWidget(b1); pr.addWidget(b2)
        pl.addWidget(self._proc_list); pl.addLayout(pr); pg.setLayout(pl)
        spl.addWidget(pg)

        # Blocked IPs
        ig = QGroupBox("🚫 Blocked IPs"); il = QVBoxLayout()
        self._ip_list = QListWidget(); self._ip_list.setFixedHeight(155)
        for ip in self.rules.get("blocked_ips",[]): self._ip_list.addItem(ip)
        ir = QHBoxLayout()
        self._ip_in = QLineEdit(); self._ip_in.setPlaceholderText("e.g. 1.2.3.4")
        self._ip_in.returnPressed.connect(self._add_ip)
        b3 = QPushButton("🚫 Block");  b3.setObjectName("ok");   b3.clicked.connect(self._add_ip)
        b4 = QPushButton("✅ Unblock"); b4.setObjectName("conn"); b4.clicked.connect(self._unblock_ip)
        b4e= QPushButton("✏ Edit");    b4e.setObjectName("ok");  b4e.clicked.connect(self._edit_ip)
        b5 = QPushButton("✕");         b5.setObjectName("del");  b5.clicked.connect(self._rem_ip)
        ir.addWidget(self._ip_in); ir.addWidget(b3); ir.addWidget(b4); ir.addWidget(b4e); ir.addWidget(b5)
        il.addWidget(self._ip_list); il.addLayout(ir); ig.setLayout(il)
        spl.addWidget(ig)
        lay.addWidget(spl)

        brow = QHBoxLayout()
        bs = QPushButton("💾 Save Rules"); bs.setObjectName("ok")
        bs.clicked.connect(self._save_all_rules_with_feedback)  # Issue 6
        br = QPushButton("↺ Reset"); br.clicked.connect(self._reset_rules)
        brow.addWidget(bs); brow.addWidget(br); brow.addStretch()
        lay.addLayout(brow)
        return w

    def _add_proc(self):
        v = self._proc_in.text().strip()
        if v and v not in [self._proc_list.item(i).text()
                            for i in range(self._proc_list.count())]:
            self._proc_list.addItem(v); self._proc_in.clear()
            self._save_rules_silent()
            # Issue 6
            self.status_bar.showMessage(f"✓ Process '{v}' added to allowlist", 3000)

    def _rem_proc(self):
        items = self._proc_list.selectedItems()
        for i in items: self._proc_list.takeItem(self._proc_list.row(i))
        self._save_rules_silent()
        if items: self.status_bar.showMessage("✓ Process removed from allowlist", 3000)

    def _add_ip(self):
        v = self._ip_in.text().strip()
        if not v: return
        # Duplicate guard — prevents silent failure when re-blocking a
        # previously-unblocked IP that is still shown in the list.
        existing = [self._ip_list.item(i).text()
                    for i in range(self._ip_list.count())]
        if v in existing:
            QMessageBox.warning(self, "Already Blocked",
                                f"⚠ IP {v} is already in the block list.")
            return
        self._ip_list.addItem(v); self._ip_in.clear()
        self._save_rules_silent()
        # Always re-add to the in-memory set so a previously-unblocked IP
        # is properly re-armed in agent_core (the set may have been cleared
        # by _unblock_ip; add() is safe to call even if already present).
        if self.agent_core:
            self.agent_core._blocked_ips.add(v)
            threading.Thread(target=self.agent_core._block_ip_firewall,
                             args=(v,), daemon=True).start()
        QMessageBox.information(
            self, "IP Blocked",
            f"✓ IP {v} added to block list.\n"
            f"Firewall rule applied (inbound + outbound).")

    def _rem_ip(self):
        items = self._ip_list.selectedItems()
        for i in items: self._ip_list.takeItem(self._ip_list.row(i))
        self._save_rules_silent()
        if items: self.status_bar.showMessage("✓ IP removed from block list", 3000)

    def _unblock_ip(self):
        """Remove firewall rules for selected IP and remove from block list."""
        items = self._ip_list.selectedItems()
        if not items:
            SentinelDialog.info(self, "Info", "Select an IP to unblock first")
            return
        ip = items[0].text().strip()
        self._ip_list.takeItem(self._ip_list.row(items[0]))
        self._save_rules_silent()
        if self.agent_core:
            # CRITICAL: discard from the in-memory set FIRST so that the
            # network-monitor background thread (which re-applies rules every
            # 10 s) does not immediately re-block the IP before the firewall
            # removal completes.  This also ensures that a subsequent
            # _add_ip() call for the same IP will correctly re-arm the set
            # and re-apply the firewall rule (add() on an already-present
            # element is a no-op, so the set must be clean here).
            self.agent_core._blocked_ips.discard(ip)
            threading.Thread(
                target=lambda: self._sig_log.emit(
                    "INFO", self.agent_core._unblock_ip_firewall(ip)),
                daemon=True).start()
        QMessageBox.information(
            self, "IP Unblocked",
            f"✅ IP {ip} unblocked.\n"
            "Firewall rules (inbound + outbound) removed.\n"
            "Traffic to/from this IP is now permitted.\n\n"
            "You can re-block this IP at any time by entering it above.")

    def _edit_ip(self):
        """Edit the selected IP in the block list in-place.

        The old firewall rule is removed before the new one is applied so
        there is no window where the old IP remains unblocked.
        """
        items = self._ip_list.selectedItems()
        if not items:
            SentinelDialog.info(self, "Info", "Select an IP to edit first")
            return
        item = items[0]
        old_ip = item.text().strip()
        new_ip, ok = QInputDialog.getText(
            self, "Edit Blocked IP",
            "Update IP address:", QLineEdit.EchoMode.Normal, old_ip)
        new_ip = new_ip.strip()
        if not ok or not new_ip or new_ip == old_ip:
            return
        # Check the new value is not already present (excluding the current row)
        existing = [self._ip_list.item(i).text()
                    for i in range(self._ip_list.count())
                    if self._ip_list.item(i) is not item]
        if new_ip in existing:
            QMessageBox.warning(self, "Already Blocked",
                                f"⚠ IP {new_ip} is already in the block list.")
            return
        # Remove old firewall rule and update in-memory set
        if self.agent_core:
            self.agent_core._blocked_ips.discard(old_ip)
            threading.Thread(
                target=self.agent_core._unblock_ip_firewall,
                args=(old_ip,), daemon=True).start()
        # Update the list widget in place
        item.setText(new_ip)
        self._save_rules_silent()
        # Apply new firewall rule
        if self.agent_core:
            self.agent_core._blocked_ips.add(new_ip)
            threading.Thread(target=self.agent_core._block_ip_firewall,
                             args=(new_ip,), daemon=True).start()
        QMessageBox.information(
            self, "IP Updated",
            f"✓ Block rule updated:\n  {old_ip}  →  {new_ip}\n"
            "Old firewall rule removed; new rule applied.")



    def _save_all_rules_with_feedback(self):
        """Issue 6 — Save with confirmation dialog."""
        self._collect_rules(); save_rules(self.rules)
        QMessageBox.information(
            self, "Rules Saved",
            "✓ All rules saved successfully.\n\n"
            "Changes are applied immediately to the running agent.")

    def _collect_rules(self):
        self.rules["allowed_processes"] = [
            self._proc_list.item(i).text() for i in range(self._proc_list.count())]
        self.rules["blocked_ips"] = [
            self._ip_list.item(i).text() for i in range(self._ip_list.count())]
        if hasattr(self, "_usb_allowed_list"):
            self.rules["allowed_usb"] = [
                self._usb_allowed_list.item(i).text()
                for i in range(self._usb_allowed_list.count())]
        if hasattr(self, "_fp_list"):
            self.rules["sensitive_paths"] = [
                self._fp_list.item(i).text() for i in range(self._fp_list.count())]
        if hasattr(self, "_conf_list"):
            self.rules["confidential_paths"] = [
                self._conf_list.item(i).text() for i in range(self._conf_list.count())]

    def _reset_rules(self):
        if SentinelDialog.confirm(self, "Reset", "Reset all rules to defaults?"):
            self.rules = DEFAULT_RULES.copy(); save_rules(self.rules)
            self._proc_list.clear(); self._ip_list.clear()
            for p in self.rules["allowed_processes"]: self._proc_list.addItem(p)
            SentinelDialog.success(self, "Reset", "✓ Rules reset to defaults.")

    # ── USB Control tab ───────────────────────────────────────────────────────
    def _tab_usb(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(16,14,16,14)

        # Issue 8 — show admin warning if not admin
        if not is_admin():
            warn = QLabel(
                "⚠  USB disable/enable requires Administrator privileges.\n"
                "   Right-click the Agent → Run as Administrator to unlock these controls.")
            warn.setStyleSheet(
                "color:#ff8c42;background:rgba(255,140,66,0.08);"
                "border:1px solid #ff8c42;border-radius:4px;"
                "padding:8px;font-family:Consolas;font-size:11px")
            warn.setWordWrap(True)
            lay.addWidget(warn)

        dg = QGroupBox("🔌 Connected Removable Drives")
        dl = QVBoxLayout()
        self._usb_drive_table = QTableWidget()
        self._usb_drive_table.setColumnCount(4)
        self._usb_drive_table.setHorizontalHeaderLabels(
            ["Drive","Label","Size (GB)","Status"])
        self._usb_drive_table.horizontalHeader().setStretchLastSection(True)
        self._usb_drive_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._usb_drive_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self._usb_drive_table.setFixedHeight(175)
        dl.addWidget(self._usb_drive_table)

        # Live USB status label
        self._usb_status_lbl = QLabel("No drives detected")
        self._usb_status_lbl.setStyleSheet(
            "color:#8b949e;font-family:Consolas;font-size:11px;padding:4px 0")
        self._usb_status_lbl.setWordWrap(True)
        dl.addWidget(self._usb_status_lbl)

        dr = QHBoxLayout()
        for lbl, fn, obj in [
            ("⟳ Refresh",              self._refresh_usb_drives,    "conn"),
            ("✓ Whitelist Selected",    self._allow_selected_usb,    "ok"),
            ("⏏ Eject Selected",        self._eject_selected_usb,    "disc"),
            ("🚫 Disable Selected",     self._disable_selected_usb,  "stop"),
            ("✓ Enable USB",            self._enable_all_usb,        "ok"),
        ]:
            b = QPushButton(lbl); b.setObjectName(obj)
            b.clicked.connect(fn); dr.addWidget(b)
        dl.addLayout(dr); dg.setLayout(dl); lay.addWidget(dg)

        ag = QGroupBox("✅ Allowed USB Whitelist (no alert if matched)")
        al = QVBoxLayout()
        al.addWidget(QLabel(
            "Drive letters or labels in this list will NOT trigger alerts."))
        self._usb_allowed_list = QListWidget(); self._usb_allowed_list.setFixedHeight(110)
        for u in self.rules.get("allowed_usb",[]): self._usb_allowed_list.addItem(u)
        ar = QHBoxLayout()
        self._usb_manual_in = QLineEdit()
        self._usb_manual_in.setPlaceholderText("E:\\ or USB label")
        self._usb_manual_in.returnPressed.connect(self._add_usb_manual)
        bam = QPushButton("+ Add Manual"); bam.setObjectName("ok")
        bam.clicked.connect(self._add_usb_manual)
        bru = QPushButton("✕ Remove"); bru.setObjectName("del")
        bru.clicked.connect(self._rem_usb_allowed)
        ar.addWidget(self._usb_manual_in); ar.addWidget(bam); ar.addWidget(bru)
        al.addWidget(self._usb_allowed_list); al.addLayout(ar)
        ag.setLayout(al); lay.addWidget(ag)

        QTimer.singleShot(200, self._refresh_usb_drives)
        return w

    def _refresh_usb_drives(self):
        from agent.agent_core import AgentCore
        drives = AgentCore.list_removable_drives()
        # Filter out drives that USB monitor already removed from prev_drives
        if self.agent_core:
            ejected = set()
            for mon in self.agent_core._monitors:
                if hasattr(mon, "_prev_drives"):
                    # drives not in prev_drives are gone
                    all_drive_letters = {d["drive"] for d in drives}
                    ejected = mon._prev_drives - all_drive_letters
            drives = [d for d in drives if d["drive"] not in ejected]
        self._usb_drive_table.setRowCount(0)
        allowed  = self.rules.get("allowed_usb", [])
        # Blacklisted = drives the agent has disabled this session
        blocked  = (self.agent_core._blocked_usb_drives
                    if self.agent_core else set())

        if not drives:
            if hasattr(self, "_usb_status_lbl"):
                self._usb_status_lbl.setText("No removable drives detected")
            self._sig_status.emit("USB refresh — no drives found")
            return

        status_parts = []
        for d in drives:
            row = self._usb_drive_table.rowCount()
            self._usb_drive_table.insertRow(row)

            drive_str  = d["drive"]
            label      = d.get("label") or "(no label)"
            vendor     = d.get("vendor") or ""
            size_gb    = d.get("size_gb", 0)
            display_name = f"{label}" + (f" [{vendor}]" if vendor else "")

            is_allowed  = any(drive_str.lower().startswith(a.lower())
                              or a.lower() == drive_str.lower()
                              for a in allowed)
            is_blocked  = drive_str.upper().rstrip("\\/") in blocked

            if is_blocked:
                status_str = "DISABLED 🚫"
                color      = "#ff4444"
            elif is_allowed:
                status_str = "WHITELISTED ✓"
                color      = "#00ff88"
            else:
                status_str = "UNKNOWN ⚠"
                color      = "#ffcc00"

            status_parts.append(
                f"{drive_str} {display_name} — {status_str}")

            for col, val in enumerate([
                drive_str, display_name, f"{size_gb} GB", status_str
            ]):
                item = QTableWidgetItem(val)
                item.setForeground(QColor(color))
                self._usb_drive_table.setItem(row, col, item)

        if hasattr(self, "_usb_status_lbl"):
            self._usb_status_lbl.setText(
                "  |  ".join(status_parts) if status_parts
                else "No removable drives detected")
        self._sig_status.emit(
            f"USB drives refreshed — {len(drives)} found")

    def _allow_selected_usb(self):
        row = self._usb_drive_table.currentRow()
        if row < 0:
            SentinelDialog.info(self, "Info", "Select a drive row first"); return
        drive_item = self._usb_drive_table.item(row, 0)
        if not drive_item: return
        val = drive_item.text().strip()
        existing = [self._usb_allowed_list.item(i).text()
                    for i in range(self._usb_allowed_list.count())]
        if val not in existing:
            self._usb_allowed_list.addItem(val)
            if self.agent_core: self.agent_core._allowed_usb.append(val)
            self._save_rules_silent()
            self._refresh_usb_drives()
            # Issue 6
            QMessageBox.information(
                self, "USB Allowed",
                f"✓ Drive '{val}' added to whitelist.\n"
                "Future insertions will NOT trigger an alert.")

    def _add_usb_manual(self):
        v = self._usb_manual_in.text().strip()
        if v:
            self._usb_allowed_list.addItem(v)
            if self.agent_core: self.agent_core._allowed_usb.append(v)
            self._usb_manual_in.clear(); self._save_rules_silent()
            self.status_bar.showMessage(f"✓ '{v}' added to USB whitelist", 3000)

    def _rem_usb_allowed(self):
        for item in self._usb_allowed_list.selectedItems():
            self._usb_allowed_list.takeItem(self._usb_allowed_list.row(item))
        self._save_rules_silent()

    def _eject_selected_usb(self):
        row = self._usb_drive_table.currentRow()
        if row < 0:
            SentinelDialog.info(self, "Info", "Select a drive row first"); return
        drive = (self._usb_drive_table.item(row, 0) or
                 type("_",(),{"text":lambda s:""})()).text()
        if not self.agent_core:
            SentinelDialog.warning(self, "Not Connected", "Agent must be running"); return
        def _do():
            det = self.agent_core._eject_usb(drive, eject_all=False)
            self._sig_log.emit("INFO", f"Eject {drive}: {det}")
        threading.Thread(target=_do, daemon=True).start()
        self.status_bar.showMessage(f"Ejecting {drive}…")

    def _disable_selected_usb(self):
        """Eject and block the selected drive (not all USB)."""
        row = self._usb_drive_table.currentRow()
        if row < 0:
            SentinelDialog.info(self, "Info", "Select a drive row first")
            return
        drive_item = self._usb_drive_table.item(row, 0)
        if not drive_item: return
        drive = drive_item.text().strip()
        label_item = self._usb_drive_table.item(row, 1)
        label = label_item.text() if label_item else drive

        if not is_admin():
            SentinelDialog.warning(self, "Admin Required", "Disabling USB requires Administrator privileges.\n"
                "Right-click → Run as Administrator.")
            return
        if not self.agent_core:
            SentinelDialog.warning(self, "Not Connected", "Start monitoring first")
            return
        if QMessageBox.question(
            self, "Disable USB Drive",
            f"Eject and disable drive {drive} ({label})?\n"
            "It will be marked as DISABLED and ejected.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes: return

        def _do():
            det = self.agent_core._eject_usb(drive, eject_all=False)
            self.agent_core._blocked_usb_drives.add(drive.upper())
            self._sig_log.emit("INFO", f"USB disabled {drive}: {det}")
            self.agent_core.send_alert("usb_disabled_selected", "high",
                f"USB Drive Disabled: {drive} ({label})", det)
            self._sig_status.emit(f"Drive {drive} disabled and ejected")
            # Refresh table on main thread
            QTimer.singleShot(800, self._refresh_usb_drives)

        threading.Thread(target=_do, daemon=True).start()
        QMessageBox.information(
            self, "Drive Disabled",
            f"✓ Eject command sent for {drive} ({label}).\n"
            "Drive is now marked DISABLED in the table.\n"
            "Reinsertion will trigger a high-severity alert.")

    def _enable_all_usb(self):
        ok, msg = (True,"ok") if is_admin() else (False,
            "Enabling USB storage requires Administrator privileges.")
        if not ok:
            SentinelDialog.warning(self, "Admin Required", msg); return
        if not self.agent_core:
            SentinelDialog.warning(self, "Not Connected", "Start monitoring first"); return
        def _do():
            det = self.agent_core._enable_usb_registry()
            self._sig_log.emit("INFO", f"USB registry enable: {det}")
        threading.Thread(target=_do, daemon=True).start()
        QMessageBox.information(
            self, "USB Enabled",
            "✓ USB enable command sent.\n"
            "Registry key: USBSTOR Start=3")

    # ── File Protection tab ───────────────────────────────────────────────────
    def _tab_file_protect(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(16,14,16,14)

        sg = QGroupBox("🔍 Sensitive Files — HIGH alert on modify/delete/access")
        sl = QVBoxLayout()
        sl.addWidget(QLabel("Any change generates a HIGH severity alert."))
        self._fp_list = QListWidget()
        for p in self.rules.get("sensitive_paths",[]): self._fp_list.addItem(p)
        sl.addWidget(self._fp_list)
        sr = QHBoxLayout()
        for lbl, fn in [("+ File", self._browse_file),
                         ("+ Folder", self._browse_folder),
                         ("✕ Remove", self._rem_fp),
                         ("✓ Apply", self._apply_fp)]:
            b = QPushButton(lbl)
            if "Apply" in lbl:  b.setObjectName("ok")
            if "Remove" in lbl: b.setObjectName("del")
            b.clicked.connect(fn); sr.addWidget(b)
        sl.addLayout(sr); sg.setLayout(sl); lay.addWidget(sg)

        cg = QGroupBox(
            "🔐 Highly Confidential Files — CRITICAL alert; encrypt/decrypt remotely")
        cl = QVBoxLayout()
        cl.addWidget(QLabel(
            "• Access/modify → CRITICAL severity alert\n"
            "• AES-256 encrypt or decrypt from dashboard or here"))
        self._conf_list = QListWidget()
        for p in self.rules.get("confidential_paths",[]): self._conf_list.addItem(p)
        cl.addWidget(self._conf_list)
        cr = QHBoxLayout()
        for lbl, fn in [
            ("+ Mark Confidential",  self._browse_confidential),
            ("✕ Remove",             self._rem_conf),
            ("🔒 Encrypt Now",       self._encrypt_selected),
            ("🔓 Decrypt Now",       self._decrypt_selected),
        ]:
            b = QPushButton(lbl)
            if "Encrypt" in lbl: b.setObjectName("stop")
            if "Decrypt" in lbl: b.setObjectName("warn")
            if "Remove"  in lbl: b.setObjectName("del")
            b.clicked.connect(fn); cr.addWidget(b)
        cl.addLayout(cr)
        self._conf_log = QTextEdit(); self._conf_log.setReadOnly(True)
        self._conf_log.setMaximumHeight(90)
        self._conf_log.setPlaceholderText("Confidential file events…")
        cl.addWidget(self._conf_log); cg.setLayout(cl); lay.addWidget(cg)
        return w

    def _browse_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Sensitive File")
        if p: self._fp_list.addItem(p); self._save_rules_silent()

    def _browse_folder(self):
        p = QFileDialog.getExistingDirectory(self, "Select Sensitive Folder")
        if p: self._fp_list.addItem(p); self._save_rules_silent()

    def _rem_fp(self):
        for i in self._fp_list.selectedItems():
            self._fp_list.takeItem(self._fp_list.row(i))
        self._save_rules_silent()

    def _apply_fp(self):
        paths = [self._fp_list.item(i).text() for i in range(self._fp_list.count())]
        if self.agent_core: self.agent_core.set_sensitive_paths(paths)
        self._save_rules_silent()
        # Issue 6
        QMessageBox.information(
            self, "File Protection Applied",
            f"✓ File monitoring applied to {len(paths)} path(s).\n"
            "Alerts will be generated on modify, delete, or access.")

    def _browse_confidential(self):
        p, _ = QFileDialog.getOpenFileName(self, "Mark File as Highly Confidential")
        if p:
            self._conf_list.addItem(p); self._save_rules_silent()
            if self.agent_core: self.agent_core.mark_confidential(p)
            self._conf_log.append(
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Marked confidential: {p}")
            # Issue 6
            QMessageBox.information(
                self, "File Marked Confidential",
                f"✓ File marked as HIGHLY CONFIDENTIAL:\n{p}\n\n"
                "Any access/modify will generate a CRITICAL alert.")

    def _rem_conf(self):
        for i in self._conf_list.selectedItems():
            self._conf_list.takeItem(self._conf_list.row(i))
        self._save_rules_silent()

    def _encrypt_selected(self):
        items = self._conf_list.selectedItems()
        if not items:
            SentinelDialog.info(self, "Info", "Select a file first"); return
        if not self.agent_core:
            SentinelDialog.warning(self, "Not Connected", "Agent must be running"); return
        for item in items:
            path = item.text()
            if not os.path.exists(path):
                self._conf_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] NOT FOUND: {path}")
                continue
            def _do(p=path):
                ok, det = self.agent_core._encrypt_file(p)
                self._sig_log.emit("INFO" if ok else "ERROR", f"Encrypt: {det}")
                self._conf_log.append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    f"{'✓' if ok else '✗'} {det}")
            threading.Thread(target=_do, daemon=True).start()

    def _decrypt_selected(self):
        items = self._conf_list.selectedItems()
        if not items:
            p, _ = QFileDialog.getOpenFileName(
                self, "Select encrypted file", "", "Encrypted (*.soc_enc);;All (*)")
            if not p: return
            class _FakeItem:
                def text(self): return p
            items = [_FakeItem()]
        if not self.agent_core:
            SentinelDialog.warning(self, "Not Connected", "Agent must be running"); return
        for item in items:
            path = item.text()
            def _do(p=path):
                ok, det = self.agent_core._decrypt_file(p)
                self._sig_log.emit("INFO" if ok else "ERROR", f"Decrypt: {det}")
                self._conf_log.append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    f"{'✓ Decrypted' if ok else '✗'} {det}")
            threading.Thread(target=_do, daemon=True).start()

    # ── Logs tab ──────────────────────────────────────────────────────────────
    def _tab_logs(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(16,14,16,14)
        ctrl = QHBoxLayout()
        self._log_lvl = QComboBox()
        self._log_lvl.addItems(["ALL","INFO","WARNING","ERROR","CRITICAL","ALERT"])
        btn_clr = QPushButton("Clear"); btn_clr.clicked.connect(lambda: self._log_box.clear())
        ctrl.addWidget(QLabel("Level:")); ctrl.addWidget(self._log_lvl)
        ctrl.addWidget(btn_clr); ctrl.addStretch()
        lay.addLayout(ctrl)
        self._log_box = QTextEdit(); self._log_box.setReadOnly(True)
        self._log_box.setFont(QFont("Consolas", 9))
        self._log_box.setStyleSheet("color:#00ff88;background:#010409")
        lay.addWidget(self._log_box); return w

    # ── Settings tab ──────────────────────────────────────────────────────────
    def _tab_settings(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(16,14,16,14)
        sg = QGroupBox("SOC Server Configuration"); sl = QVBoxLayout()

        r1 = QHBoxLayout(); r1.addWidget(QLabel("Server URL:"))
        self._srv_url = QLineEdit("http://localhost:9001"); r1.addWidget(self._srv_url)

        r2 = QHBoxLayout(); r2.addWidget(QLabel("API Key:   "))
        self._api_key = QLineEdit("SOC-MASTER-KEY-2024")
        self._api_key.setEchoMode(QLineEdit.EchoMode.Password)
        r2.addWidget(self._api_key)

        r3 = QHBoxLayout(); r3.addWidget(QLabel("Heartbeat: "))
        self._hb_int = QLineEdit("10"); r3.addWidget(self._hb_int)
        r3.addWidget(QLabel("seconds"))

        from agent.agent_core import _load_or_create_id
        r4 = QHBoxLayout(); r4.addWidget(QLabel("Agent ID:  "))
        self._ep_id_lbl = QLabel(_load_or_create_id())
        self._ep_id_lbl.setStyleSheet("color:#00ff88;font-family:Consolas;font-size:11px")
        r4.addWidget(self._ep_id_lbl)
        r4.addWidget(QLabel("(persistent — stored in ~/.soc_agent_id)"))

        r5 = QHBoxLayout(); r5.addWidget(QLabel("Logged in: "))
        _user_lbl = QLabel(self._logged_in_user)
        _user_lbl.setStyleSheet("color:#4fc3f7;font-family:Consolas")
        r5.addWidget(_user_lbl)

        r6 = QHBoxLayout(); r6.addWidget(QLabel("Privilege: "))
        adm_lbl = QLabel(admin_status_str())
        adm_lbl.setStyleSheet(
            f"color:{'#00ff88' if is_admin() else '#ff8c42'};"
            "font-family:Consolas;font-size:11px")
        r6.addWidget(adm_lbl)

        btn_test = QPushButton("Test Connection"); btn_test.setObjectName("conn")
        btn_test.clicked.connect(self._do_connect)
        btn_save = QPushButton("Save Settings"); btn_save.setObjectName("ok")
        btn_save.clicked.connect(lambda: SentinelDialog.success(
            self, "Saved", "✓ Settings saved."))

        for row in [r1, r2, r3, r4, r5, r6]: sl.addLayout(row)
        sl.addWidget(btn_test); sl.addWidget(btn_save)
        sg.setLayout(sl); lay.addWidget(sg)

        self._test_result = QLabel("")
        self._test_result.setWordWrap(True)
        self._test_result.setStyleSheet(
            "font-family:Consolas;font-size:11px;padding:8px")
        lay.addWidget(self._test_result)

        # ── Startup / Auto-run section ─────────────────────────────────────
        stg = QGroupBox("Auto-Start on System Boot  (Windows Task Scheduler)")
        stl = QVBoxLayout()

        task_exists = _startup_task_exists()
        self._task_status_lbl = QLabel(
            "✓ Startup task REGISTERED — agent will auto-start at logon"
            if task_exists else
            "✗ Startup task NOT registered"
        )
        self._task_status_lbl.setStyleSheet(
            f"color:{'#00ff88' if task_exists else '#ff8c42'};"
            "font-family:Consolas;font-size:11px;padding:4px")
        self._task_status_lbl.setWordWrap(True)
        stl.addWidget(self._task_status_lbl)

        info_lbl = QLabel(
            "When registered: agent launches automatically at Windows logon "
            "with Administrator privilege — no UAC prompt, no manual start needed.")
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet("color:#8b949e;font-size:10px;padding:2px 0")
        stl.addWidget(info_lbl)

        btn_row = QHBoxLayout()
        btn_reg = QPushButton("✓ Register Auto-Start")
        btn_reg.setObjectName("ok")
        btn_unreg = QPushButton("✗ Remove Auto-Start")
        btn_unreg.setObjectName("red_btn")

        def _do_register():
            ok, msg = _register_startup_task()
            self._task_status_lbl.setText(
                "✓ Startup task REGISTERED — agent will auto-start at logon"
                if ok else f"✗ Failed: {msg.splitlines()[0]}")
            self._task_status_lbl.setStyleSheet(
                f"color:{'#00ff88' if ok else '#ff4444'};"
                "font-family:Consolas;font-size:11px;padding:4px")
            SentinelDialog.success(self, "Auto-Start", msg) if ok \
                else SentinelDialog.error(self, "Auto-Start Failed", msg)

        def _do_unregister():
            ok, msg = _unregister_startup_task()
            self._task_status_lbl.setText(
                "✗ Startup task NOT registered" if ok
                else f"✗ Could not remove: {msg}")
            self._task_status_lbl.setStyleSheet(
                "color:#ff8c42;font-family:Consolas;font-size:11px;padding:4px")
            SentinelDialog.success(self, "Auto-Start", msg) if ok \
                else SentinelDialog.error(self, "Remove Failed", msg)

        btn_reg.clicked.connect(_do_register)
        btn_unreg.clicked.connect(_do_unregister)
        btn_row.addWidget(btn_reg)
        btn_row.addWidget(btn_unreg)
        stl.addLayout(btn_row)
        stg.setLayout(stl)
        lay.addWidget(stg)

        lay.addStretch()
        return w

    # ── Tray ─────────────────────────────────────────────────────────────────
    def _setup_tray(self):
        self.tray = QSystemTrayIcon(self)
        # Build a simple 16×16 icon programmatically (teal shield shape)
        # so Qt doesn't emit "No Icon set" warnings
        try:
            from PyQt5.QtGui import QPixmap, QPainter, QBrush, QColor as QC5
            pm = QPixmap(16, 16)
            pm.fill(QC5(0, 0, 0, 0))
            p = QPainter(pm)
            p.setRenderHint(QPainter.Antialiasing if hasattr(QPainter, 'Antialiasing')
                            else QPainter.RenderHint.Antialiasing)
            p.setBrush(QBrush(QC5(0, 200, 150)))
            p.setPen(QC5(0, 0, 0, 0))
            p.drawEllipse(1, 1, 14, 14)
            p.end()
            from PyQt5.QtGui import QIcon as QI5
            self.tray.setIcon(QI5(pm))
        except Exception:
            try:
                from PyQt6.QtGui import QPixmap, QPainter, QBrush, QColor as QC6, QIcon as QI6
                pm = QPixmap(16, 16)
                pm.fill(QC6(0, 0, 0, 0))
                p = QPainter(pm)
                p.setBrush(QBrush(QC6(0, 200, 150)))
                p.setPen(QC6(0, 0, 0, 0))
                p.drawEllipse(1, 1, 14, 14)
                p.end()
                self.tray.setIcon(QI6(pm))
            except Exception:
                pass  # Icon optional — tray still works without it
        menu = QMenu()
        menu.addAction(QAction("Show", self, triggered=self.show))
        menu.addAction(QAction("Quit", self, triggered=QApplication.quit))
        self.tray.setContextMenu(menu)
        self.tray.show()

    # ── Metrics ───────────────────────────────────────────────────────────────
    def _refresh_metrics(self):
        try:
            cpu  = psutil.cpu_percent(interval=None)
            mem  = psutil.virtual_memory().percent
            try:
                disk = (psutil.disk_usage("C:\\").percent if os.name == "nt"
                        else psutil.disk_usage("/").percent)
            except Exception: disk = 0
            for (_, bar, pct), val in [
                (self._cpu_bar, cpu), (self._mem_bar, mem), (self._disk_bar, disk)
            ]:
                bar.setValue(int(val)); pct.setText(f"{val:.0f}%")
            if self._start_time:
                el = int(time.time() - self._start_time)
                h, rem = divmod(el, 3600); m, s = divmod(rem, 60)
                self._sc_uptime._vl.setText(f"{h:02d}:{m:02d}:{s:02d}")
            self._info_lbl.setText(
                f"Host: {socket.gethostname()}  |  "
                f"OS: {'Windows' if os.name == 'nt' else 'Linux'}  |  "
                f"Processes: {len(psutil.pids())}  |  "
                f"Server: {self._srv_url.text()}")
        except Exception: pass

    # ── Auto-connect ──────────────────────────────────────────────────────────
    def _auto_connect(self):
        self._sig_log.emit("INFO", "Auto-connecting to server…")
        self._do_connect()

    # ── Connect thread ────────────────────────────────────────────────────────
    def _do_connect(self):
        from agent.agent_core import _load_or_create_id
        url  = self._srv_url.text().strip().rstrip("/")
        key  = self._api_key.text().strip()
        ep_id = _load_or_create_id()
        self._sig_log.emit("INFO", f"Connecting to {url}…")
        self._sig_status.emit(f"Connecting to {url}…")
        self.btn_connect.setEnabled(False)

        def _thread():
            try:
                import requests as _req
                headers = {"Authorization": f"Bearer {key}",
                           "Content-Type": "application/json"}
                # Issue 5 — attach session token if present
                tok = get_token()
                if tok: headers["X-Agent-Token"] = tok
                r = _req.post(
                    f"{url}/register", headers=headers,
                    json={
                        "endpoint_id":   ep_id,
                        "hostname":      f"{self._logged_in_user}@{socket.gethostname()}",
                        "ip_address":    self._get_ip(),
                        "os_version":    "Windows" if os.name == "nt" else "Linux",
                        "agent_version": "1.0.0",
                    }, timeout=8)
                if r.status_code == 200:
                    self._sig_connected.emit(url, r.json())
                else:
                    self._sig_conn_failed.emit(f"HTTP {r.status_code}: {r.text[:200]}")
            except Exception as e:
                self._sig_conn_failed.emit(str(e))

        threading.Thread(target=_thread, daemon=True, name="ConnectThread").start()

    def _on_connected(self, url: str, data: dict):
        self.connected = True; ep_id = data.get("endpoint_id","?")
        self.dot.setStyleSheet("color:#00ff88")
        self.conn_lbl.setText("CONNECTED")
        self.conn_lbl.setStyleSheet(
            "color:#00ff88;font-weight:bold;font-family:Consolas;font-size:11px")
        self.btn_connect.setEnabled(True)
        self.btn_disconnect.setEnabled(True)
        self.btn_start.setEnabled(True)
        self.status_bar.showMessage(f"✓ Connected | Endpoint: {ep_id} | {url}")
        self._test_result.setStyleSheet(
            "color:#00ff88;font-family:Consolas;font-size:11px;padding:10px;"
            "background:rgba(0,255,136,0.05);border:1px solid #00ff88;border-radius:3px")
        self._test_result.setText(
            f"✓  Connected\nEndpoint ID : {ep_id}\nServer      : {url}\n\n"
            f"Auto-starting monitoring…")
        self._sig_log.emit("INFO", f"✓ Connected (ID {ep_id}) — auto-starting monitoring")
        # AUTO-START: begin monitoring immediately after successful connection
        QTimer.singleShot(300, self._start_monitoring)

    def _on_conn_fail(self, msg: str):
        self.connected = False
        self.dot.setStyleSheet("color:#ff4444")
        self.conn_lbl.setText("OFFLINE")
        self.conn_lbl.setStyleSheet(
            "color:#ff4444;font-weight:bold;font-family:Consolas;font-size:11px")
        self.btn_connect.setEnabled(True)
        self.btn_disconnect.setEnabled(False)

        # Auto-retry logic: on startup the server may not be ready yet.
        # Retry up to 10 times with exponential backoff (5s → 10s → 20s … max 60s)
        if not hasattr(self, "_retry_count"):
            self._retry_count = 0
        self._retry_count += 1

        if self._retry_count <= 10:
            wait_sec = min(60, 5 * (2 ** min(self._retry_count - 1, 3)))
            self.status_bar.showMessage(
                f"Connection failed — retrying in {wait_sec}s "
                f"(attempt {self._retry_count}/10)…")
            self._test_result.setStyleSheet(
                "color:#ffcc00;font-family:Consolas;font-size:11px;padding:10px;"
                "background:rgba(255,200,0,0.05);border:1px solid #ffcc00;border-radius:3px")
            self._test_result.setText(
                f"⏳  Retrying connection… ({self._retry_count}/10)\n\n"
                f"Error: {msg}\n\n"
                f"Waiting {wait_sec}s before next attempt.\n"
                f"This is normal if the server is still starting up.")
            self._sig_log.emit("WARNING",
                f"Connection failed (attempt {self._retry_count}) — "
                f"retrying in {wait_sec}s: {msg}")
            QTimer.singleShot(wait_sec * 1000, self._auto_connect)
        else:
            # Give up after 10 attempts — show manual instructions
            self._retry_count = 0
            self.status_bar.showMessage(f"Connection failed — {msg[:70]}")
            self._test_result.setStyleSheet(
                "color:#ff4444;font-family:Consolas;font-size:11px;padding:10px;"
                "background:rgba(255,68,68,0.05);border:1px solid #ff4444;border-radius:3px")
            self._test_result.setText(
                f"✗  Connection Failed (all retries exhausted)\n\n{msg}\n\n"
                f"Checklist:\n"
                f"  1. Server running?  →  cd server && python main.py --port 9001\n"
                f"  2. Correct URL?     →  {self._srv_url.text().strip()}\n"
                f"  3. API key correct? →  SOC-MASTER-KEY-2024\n\n"
                f"Click CONNECT to try again manually.")
            self._sig_log.emit("ERROR", f"Connection failed after 10 retries: {msg}")

    def _do_disconnect(self):
        if self.monitoring: self._stop_monitoring()
        if self.agent_core:
            threading.Thread(target=self.agent_core.unregister, daemon=True).start()
        self.connected = False
        self.dot.setStyleSheet("color:#ff4444")
        self.conn_lbl.setText("OFFLINE")
        self.conn_lbl.setStyleSheet(
            "color:#ff4444;font-weight:bold;font-family:Consolas;font-size:11px")
        self.btn_disconnect.setEnabled(False); self.btn_start.setEnabled(False)
        self.status_bar.showMessage("Disconnected")
        self._sig_log.emit("INFO", "Disconnected from server")
        self._test_result.setStyleSheet(
            "color:#aaa;font-family:Consolas;font-size:11px;padding:10px")
        self._test_result.setText("Disconnected. Click CONNECT to reconnect.")

    # ── Start monitoring ──────────────────────────────────────────────────────
    def _start_monitoring(self):
        if self.monitoring: return
        try:
            sys.path.insert(0, os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))
            from agent.agent_core import AgentCore
            url = self._srv_url.text().strip()
            key = self._api_key.text().strip()
            self.agent_core = AgentCore(
                url, key,
                log_callback   = lambda lv, msg: self._sig_log.emit(lv, msg),
                alert_callback = lambda a:        self._sig_alert.emit(a),
                username       = self._logged_in_user,
            )
            # Issue 5 — attach token
            tok = get_token()
            if tok: self.agent_core.set_auth_token(tok)

            try:
                self.agent_core._heartbeat_interval = int(self._hb_int.text())
            except Exception: pass

            paths = [self._fp_list.item(i).text() for i in range(self._fp_list.count())]
            self.agent_core.set_sensitive_paths(paths)
            for i in range(self._conf_list.count()):
                self.agent_core._confidential_paths.add(self._conf_list.item(i).text())
            for i in range(self._ip_list.count()):
                self.agent_core._blocked_ips.add(self._ip_list.item(i).text())
            if hasattr(self, "_usb_allowed_list"):
                self.agent_core.set_allowed_usb([
                    self._usb_allowed_list.item(i).text()
                    for i in range(self._usb_allowed_list.count())])

            threading.Thread(target=self.agent_core.start,
                             daemon=True, name="AgentStart").start()

            self.monitoring = True; self._start_time = time.time()
            self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
            self._sc_monitors._vl.setText("9")
            self._sig_log.emit("INFO", "Monitoring started — 9 modules active")
            self.status_bar.showMessage("Monitoring ACTIVE")
        except Exception as e:
            SentinelDialog.error(self, "Error", f"Failed to start: {e}")
            self._sig_log.emit("ERROR", str(e))

    def _verify_password_for_action(self, action_name: str) -> bool:
        """Show a minimal password dialog before a protected action."""
        stored_user = get_stored_username()
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Authentication Required — {action_name}")
        dlg.setMinimumWidth(340)
        dlg.setStyleSheet(STYLE)
        lay = QVBoxLayout(dlg)
        lbl = QLabel(f"🔐  Enter password to {action_name}")
        lbl.setStyleSheet("color:#ffcc00;font-family:Consolas;font-size:12px;padding:8px")
        lay.addWidget(lbl)
        pw = QLineEdit()
        pw.setEchoMode(QLineEdit.EchoMode.Password)
        pw.setPlaceholderText("Password")
        lay.addWidget(pw)
        err = QLabel("")
        err.setStyleSheet("color:#ff4444;font-family:Consolas;font-size:11px")
        lay.addWidget(err)
        btns = QHBoxLayout()
        ok_btn  = QPushButton("Confirm"); ok_btn.setObjectName("ok")
        can_btn = QPushButton("Cancel")
        btns.addWidget(ok_btn); btns.addWidget(can_btn)
        lay.addLayout(btns)
        result = [False]
        def _check():
            if verify_credentials(stored_user, pw.text()):
                result[0] = True; dlg.accept()
            else:
                err.setText("✗ Incorrect password"); pw.clear(); pw.setFocus()
        ok_btn.clicked.connect(_check)
        can_btn.clicked.connect(dlg.reject)
        pw.returnPressed.connect(_check)
        dlg.exec()
        return result[0]

    def _stop_monitoring(self):
        # Require password before stopping monitoring
        if not self._verify_password_for_action("Stop Monitoring"):
            return
        if self.agent_core: self.agent_core.stop()
        self.monitoring = False
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        self._sc_monitors._vl.setText("0")
        self._sig_log.emit("INFO", "Monitoring stopped")
        self.status_bar.showMessage("Monitoring stopped")

    # ── Log (thread-safe) ─────────────────────────────────────────────────────
    def _append_log(self, level: str, msg: str):
        import threading as _t
        if _t.current_thread() is not _t.main_thread():
            self._sig_log.emit(level, msg); return
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        colors = {"INFO":"#00ff88","WARNING":"#ffcc00","ERROR":"#ff4444",
                  "CRITICAL":"#ff00ff","ALERT":"#ff8800","DEBUG":"#4fc3f7"}
        col = colors.get(level.upper(), "#aaa")
        self._log_box.append(
            f'<span style="color:#555">[{ts}]</span> '
            f'<span style="color:{col}">[{level}]</span> '
            f'<span style="color:#ddd">{msg}</span>')
        # ── Tray popup for command lifecycle events ───────────────────────────
        self._maybe_tray_notify(level, msg)

    def _maybe_tray_notify(self, level: str, msg: str):
        """Tray popups disabled — alerts stay inside the app only."""
        pass

    def _get_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return ip
        except Exception: return "127.0.0.1"

    def closeEvent(self, event):
        if self.monitoring:
            # Require password to stop monitoring on close
            if not self._verify_password_for_action("Close Agent"):
                event.ignore(); return
            self._stop_monitoring.__wrapped__(self) if hasattr(
                self._stop_monitoring, '__wrapped__') else None
            # Call agent stop directly since password already verified
            if self.agent_core: self.agent_core.stop()
            self.monitoring = False
        event.accept()

    def _save_all_rules(self):
        """Alias kept for backward compat."""
        self._collect_rules(); save_rules(self.rules)
        self.status_bar.showMessage("Rules saved ✓", 3000)


# ══════════════════════════════════════════════════════════════════════════════
# Entry point — auto-start with stored credentials; ask password only on stop
# ══════════════════════════════════════════════════════════════════════════════
def _auto_setup_credentials():
    """
    On first run (no credentials stored), auto-create default credentials
    so the agent can start silently without user interaction.
    Returns the username to use.
    The user can change credentials later from Settings.
    """
    import socket as _sock
    default_user = _sock.gethostname().split(".")[0].lower() or "sentinel"
    default_pass = "Sentinel@2024!"
    save_credentials(default_user, default_pass)
    return default_user


def main():
    # Re-launch as Administrator if not already elevated (Windows).
    # Skip if running under Task Scheduler (MALABAR_AUTOSTART env set)
    # to avoid UAC prompt during system boot.
    # Detect if launched by Windows Task Scheduler (system boot autostart)
    # Methods: 1) env var set by task, 2) parent process is taskeng/svchost/Schedule
    is_autostart = os.environ.get("MALABAR_AUTOSTART", "") == "1"
    if not is_autostart and os.name == "nt":
        try:
            import psutil as _ps2
            parent = _ps2.Process(os.getppid())
            parent_name = parent.name().lower()
            # Task Scheduler parent processes
            if any(p in parent_name for p in
                   ("taskhostw", "taskeng", "svchost", "wininit", "services")):
                is_autostart = True
        except Exception:
            pass
    if not is_autostart:
        _ensure_admin()

    app = QApplication(sys.argv)
    app.setApplicationName("Malabar Sentinel")
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)

    if not credentials_exist():
        if is_autostart:
            # Running at boot via Task Scheduler — create default credentials
            # silently so the agent can start without any user interaction.
            # User can change password later in Settings tab.
            username = _auto_setup_credentials()
        else:
            # Interactive first run — show setup dialog
            setup = LoginDialog()
            if setup.exec() != QDialog.DialogCode.Accepted or not setup.authenticated:
                sys.exit(0)
            username = setup.username
    else:
        # Credentials already exist — start silently (no password prompt)
        username = get_stored_username()

    w = AgentGUI(logged_in_user=username)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()