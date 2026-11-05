# 🛡 Malabar Sentinel
## Kerala Police Cyber Command — Endpoint Detection & Response Platform

> **Malabar Sentinel** is a full-stack EDR (Endpoint Detection & Response) platform
> developed for Kerala Police cybersecurity operations. It provides real-time endpoint
> monitoring, threat detection, remote response, and a centralized SOC dashboard.

## Complete Setup & Deployment Guide

---

## ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENDPOINT AGENTS (agent.exe)                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ Process  │ │ Network  │ │  File    │ │  USB / Memory /  │  │
│  │ Monitor  │ │ Monitor  │ │ Monitor  │ │  Kernel Monitor  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────────┬─────────┘  │
│       └─────────────┴─────────────┴────────────────┘            │
│                          AgentCore                               │
│              ┌────────────────────────────────┐                  │
│              │ REST API + WebSocket (TLS)      │                  │
└──────────────┼────────────────────────────────┼──────────────────┘
               ▼                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                       SOC SERVER (FastAPI)                        │
│  ┌────────────┐ ┌─────────────┐ ┌──────────┐ ┌──────────────┐  │
│  │   Alert    │ │    SIEM     │ │  ML/AI   │ │   Threat     │  │
│  │  Handler   │ │ Correlator  │ │ Engine   │ │  Intel       │  │
│  └────────────┘ └─────────────┘ └──────────┘ └──────────────┘  │
│                      ┌──────────────┐                            │
│                      │   Database   │                            │
│                      │ (SQLite/PG)  │                            │
│                      └──────────────┘                            │
└──────────────────────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────┐
│             SOC DASHBOARD (React - index.html)                    │
│  Overview · Alerts · Endpoints · MITRE ATT&CK · Geo Map          │
│  SIEM · AI Predictions · Threat Intel · Remote Response          │
└──────────────────────────────────────────────────────────────────┘
```

---

## QUICK START

### 1. Server Setup

```bash
# Clone / unzip platform
cd soc-platform/server

# Create virtual environment
python -m venv venv
source venv/bin/activate          # Linux/macOS
venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt

# Start server
python main.py
# Server runs at http://localhost:9001
```

### 2. Dashboard

Open `dashboard/public/index.html` in any browser.
- Works standalone in DEMO mode with simulated data
- Auto-connects to server at localhost:9001 when available
- Real-time WebSocket updates

### 3. Endpoint Agent (GUI)

```bash
cd soc-platform
pip install -r agent/requirements.txt

# Run agent GUI
python agent/main.py
```

**In the GUI:**
1. Go to Settings tab
2. Set Server URL: `http://YOUR_SOC_SERVER:9001`
3. Set API Key: `SOC-MASTER-KEY-2024`
4. Click "Test Connection"
5. Click "START MONITORING"

---

## BUILD AGENT.EXE

```bash
cd soc-platform
python installer/build_agent.py
# Output: dist/SOC-Agent.exe
```

Deploy `SOC-Agent.exe` to all endpoint machines. On first run:
- Configure server URL in Settings tab
- Click Start Monitoring
- Agent auto-registers with SOC server

---

## API AUTHENTICATION

All API calls require Bearer token:
```
Authorization: Bearer SOC-MASTER-KEY-2024
```

Change keys in `server/main.py`:
```python
VALID_API_KEYS = {"YOUR-CUSTOM-KEY-HERE"}
```

---

## KEY API ENDPOINTS

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Server health check |
| POST | /api/alerts | Submit alert from agent |
| GET | /api/alerts | Get all alerts (filterable) |
| POST | /api/endpoints/heartbeat | Agent heartbeat |
| GET | /api/endpoints | List all endpoints |
| POST | /api/commands | Send remote command |
| GET | /api/siem/correlations | SIEM correlations |
| GET | /api/ml/predictions | AI predictions |
| GET | /api/mitre/matrix | MITRE ATT&CK coverage |
| GET | /api/geo/attack-origins | Geo attack data |
| GET | /api/threat-intel | TI summary |
| GET | /api/dashboard/overview | Dashboard overview data |

WebSocket:
- `ws://server:9001/ws/dashboard` — Dashboard real-time feed
- `ws://server:9001/ws/agent/{endpoint_id}?api_key=KEY` — Agent connection

---

## REMOTE COMMANDS

| Command | Description |
|---------|-------------|
| `kill_process` | Kill process by PID (params: {pid}) |
| `block_ip` | Block IP address (params: {ip}) |
| `disable_usb` | Disable USB devices |
| `encrypt_file` | Encrypt sensitive file (params: {file_path}) |
| `lock_endpoint` | Lock workstation |
| `isolate` | Network isolate endpoint |
| `stop_monitoring` | Stop agent monitoring |

---

## DETECTION CAPABILITIES

### Monitors Active
- **Process Monitor** — Suspicious process execution, encoded PowerShell, known malware names
- **Network Monitor** — Malicious IP connections, suspicious ports, C2 communication
- **File Monitor** — Sensitive file access/modification/deletion (watchdog)
- **USB Monitor** — Device insertion, sensitive file exfiltration detection
- **Login Monitor** — Failed login tracking, brute force detection
- **Memory Monitor** — DLL injection, process hollowing, suspicious memory regions
- **Ransomware Detector** — Mass encryption, shadow copy deletion, backup deletion
- **Hash Scanner** — SHA256 matching against malware hash feeds
- **Kernel Monitor** — Driver loading, privilege escalation, system file integrity

### Intelligence
- **MITRE ATT&CK Mapping** — All alerts mapped to MITRE techniques
- **SIEM Correlation** — 8 correlation rules across multi-source events
- **Isolation Forest ML** — Anomaly detection on behavioral features
- **Random Forest ML** — Attack classification
- **AI Prediction Engine** — Pattern-based attack prediction
- **Threat Intel** — IP/hash/domain matching against known malicious feeds
- **Dark Web Monitoring** — Simulated breach dataset checking
- **Geo Visualization** — IP geolocation of attack origins

---

## ALERT SEVERITY LEVELS

| Level | Description | SOC Alarm |
|-------|-------------|-----------|
| LOW | Informational | ✗ |
| MEDIUM | Worth investigating | ✗ |
| HIGH | Requires response | ✓ |
| CRITICAL | Active attack | ✓ |
| EMERGENCY | Immediate action | ✓ |

---

## PROCESS WHITELIST

The agent automatically whitelists:
- Windows system processes (explorer, svchost, lsass, etc.)
- Common browsers (Chrome, Edge, Firefox)
- Office suite (Word, Excel, PowerPoint, Teams)
- Hardware vendor utilities (ASUS, Lenovo, HP, Dell, Acer)
- Development tools (VS Code, Python, Git)

Only processes outside the whitelist in suspicious paths or with suspicious command-line patterns trigger alerts.

---

## PRODUCTION DEPLOYMENT

### PostgreSQL
```bash
# Set env variable
export DATABASE_URL="postgresql://user:password@localhost:5432/socdb"
python main.py
```

### TLS/HTTPS
```bash
uvicorn main:app --host 0.0.0.0 --port 443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

### Systemd Service
```ini
[Unit]
Description=SOC EDR Server
After=network.target

[Service]
Type=simple
User=socuser
WorkingDirectory=/opt/soc-platform/server
ExecStart=/opt/soc-platform/server/venv/bin/python main.py
Restart=on-failure
Environment="DATABASE_URL=postgresql://..."

[Install]
WantedBy=multi-user.target
```

### Change API Keys
In `server/main.py`:
```python
VALID_API_KEYS = {
    os.getenv("SOC_ADMIN_KEY (or SOC_MASTER_KEY for legacy)", "YOUR-SECRET-KEY"),
    os.getenv("AGENT_KEY", "YOUR-AGENT-KEY"),
}
```

---

## TESTING ATTACK SCENARIOS

### Simulate Brute Force
```python
import requests
for i in range(6):
    requests.post("http://localhost:9001/api/alerts",
        headers={"Authorization": "Bearer SOC-MASTER-KEY-2024"},
        json={
            "endpoint_id": "test-ep",
            "hostname": "WORKSTATION-TEST",
            "alert_type": "login_failure",
            "severity": "medium",
            "title": f"Failed Login Attempt #{i+1}",
            "description": "Failed password for user administrator",
        }
    )
```

### Simulate Ransomware Detection
```python
requests.post("http://localhost:9001/api/alerts",
    headers={"Authorization": "Bearer SOC-MASTER-KEY-2024"},
    json={
        "endpoint_id": "test-ep",
        "hostname": "WORKSTATION-TEST",
        "alert_type": "ransomware",
        "severity": "emergency",
        "title": "RANSOMWARE BEHAVIOR DETECTED",
        "description": "Mass file encryption detected: 500 files in 30 seconds. Shadow copies deleted.",
    }
)
```

### Simulate Malicious IP
```python
requests.post("http://localhost:9001/api/alerts",
    headers={"Authorization": "Bearer SOC-MASTER-KEY-2024"},
    json={
        "endpoint_id": "test-ep",
        "hostname": "SERVER-DC1",
        "alert_type": "malicious_ip",
        "severity": "critical",
        "title": "Connection to Known C2 Server",
        "description": "Established connection to known malicious host",
        "network_ip": "45.142.212.100",
    }
)
```

---

## FOLDER STRUCTURE

```
soc-platform/
├── server/
│   ├── main.py              # FastAPI server entry point
│   ├── database.py          # SQLite/PostgreSQL database layer
│   ├── models.py            # Pydantic data models
│   ├── alert_handler.py     # Alert processing & broadcasting
│   ├── policy_engine.py     # Security policy management
│   ├── mitre_mapper.py      # MITRE ATT&CK technique mapping
│   ├── threat_intelligence.py # TI feed ingestion & lookup
│   ├── siem_correlator.py   # Multi-source event correlation
│   ├── ml_detection.py      # Isolation Forest + Random Forest
│   ├── ai_prediction.py     # Attack prediction engine
│   ├── websocket_manager.py # Real-time WS connections
│   └── requirements.txt
│
├── agent/
│   ├── main.py              # Agent entry point
│   ├── gui.py               # PyQt5 desktop GUI
│   ├── agent_core.py        # Core orchestration + API client
│   ├── requirements.txt
│   ├── monitors/
│   │   ├── process_monitor.py
│   │   ├── network_monitor.py
│   │   ├── file_monitor.py
│   │   ├── usb_monitor.py
│   │   ├── login_monitor.py
│   │   └── memory_monitor.py
│   ├── security/
│   │   ├── ransomware_detector.py
│   │   └── hash_scanner.py
│   └── kernel/
│       └── kernel_monitor.py
│
├── dashboard/
│   └── public/
│       └── index.html       # Complete React SOC dashboard
│
├── installer/
│   └── build_agent.py       # PyInstaller build script
│
└── README.md
```
