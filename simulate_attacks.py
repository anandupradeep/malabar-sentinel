"""
SOC Platform - Attack Simulation Script
Sends realistic attack scenarios to the SOC server to test detection pipeline.

Usage:
    python simulate_attacks.py                    # All scenarios
    python simulate_attacks.py --scenario ransomware
    python simulate_attacks.py --scenario brute_force
    python simulate_attacks.py --scenario apt
    python simulate_attacks.py --scenario insider
    python simulate_attacks.py --scenario c2

Requires server running:  cd server && python main.py
"""

import argparse
import time
import sys
import json

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

SERVER = "http://localhost:8000"
API_KEY = "SOC-MASTER-KEY-2024"
HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

ENDPOINTS = [
    {"id": "ep-001", "host": "WORKSTATION-001", "ip": "192.168.1.105"},
    {"id": "ep-002", "host": "SERVER-DC1",       "ip": "192.168.1.10"},
    {"id": "ep-003", "host": "LAPTOP-HR-05",     "ip": "192.168.1.142"},
]


def send_alert(endpoint_id, hostname, alert_type, severity, title, description,
               process_name=None, process_pid=None, file_path=None,
               network_ip=None, raw_data=None):
    payload = {
        "endpoint_id": endpoint_id,
        "hostname": hostname,
        "alert_type": alert_type,
        "severity": severity,
        "title": title,
        "description": description,
        "process_name": process_name,
        "process_pid": process_pid,
        "file_path": file_path,
        "network_ip": network_ip,
        "raw_data": raw_data or {},
    }
    try:
        r = requests.post(f"{SERVER}/api/alerts", headers=HEADERS, json=payload, timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(f"    ✓ [{severity.upper():9s}] {title} (score={data.get('ml_score', '?'):.2f})")
            return True
        else:
            print(f"    ✗ HTTP {r.status_code}: {title}")
            return False
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return False


def send_heartbeat(ep):
    payload = {
        "endpoint_id": ep["id"],
        "hostname": ep["host"],
        "ip_address": ep["ip"],
        "os_version": "Windows 11 22H2",
        "agent_version": "1.0.0",
        "cpu_usage": 12.5,
        "memory_usage": 45.0,
        "disk_usage": 30.0,
        "active_processes": 142,
        "threat_level": "normal",
    }
    try:
        requests.post(f"{SERVER}/api/endpoints/heartbeat", headers=HEADERS, json=payload, timeout=5)
    except Exception:
        pass


def check_server():
    try:
        r = requests.get(f"{SERVER}/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


# ── Scenario: Ransomware Attack ───────────────────────────────────────────────
def scenario_ransomware():
    print("\n🔴 SCENARIO: Ransomware Attack (LockBit-style)")
    print("   Simulating full ransomware kill chain...\n")
    ep = ENDPOINTS[0]

    steps = [
        ("process_execution", "medium", "Suspicious PowerShell Execution",
         "powershell.exe executed with -EncodedCommand flag from user temp directory",
         "powershell.exe", 4821, None, None,
         {"cmdline": "powershell.exe -enc JABjAG0AZAAgAD0AIgBpAGUAeAAo"}),

        ("network_scan", "medium", "Internal Network Reconnaissance",
         "Rapid connection attempts to 254 internal hosts on ports 445, 3389, 139",
         "powershell.exe", 4821, None, None,
         {"scan_range": "192.168.1.0/24", "ports": [445, 3389, 139], "connections": 254}),

        ("lateral_movement", "high", "SMB Lateral Movement Detected",
         "Successful SMB authentication to 3 internal servers using harvested credentials",
         "net.exe", 5012, None, "192.168.1.10",
         {"target_hosts": ["192.168.1.10", "192.168.1.25", "192.168.1.30"]}),

        ("credential_dump", "critical", "LSASS Memory Access — Credential Dump",
         "procdump.exe accessed lsass.exe memory — credential harvesting in progress",
         "procdump.exe", 6234, "C:\\Windows\\System32\\lsass.exe", None,
         {"method": "procdump", "target": "lsass.exe"}),

        ("ransomware", "emergency", "🚨 RANSOMWARE: Shadow Copy Deletion",
         "vssadmin.exe delete shadows /all /quiet — destroying backup copies",
         "vssadmin.exe", 7891, None, None,
         {"cmdline": "vssadmin.exe delete shadows /all /quiet", "reason": "shadow_copy_deletion"}),

        ("ransomware", "emergency", "🚨 RANSOMWARE: Mass File Encryption in Progress",
         "lockbit.exe encrypting files at 847 files/second. Extensions: .lockbit detected. CRITICAL — isolate immediately.",
         "lockbit.exe", 9001, "C:\\Users\\", None,
         {"files_encrypted": 1247, "rate_per_sec": 847, "extension": ".lockbit",
          "ransom_note": "!!-Restore-My-Files-!!.txt"}),
    ]

    for step in steps:
        send_alert(ep["id"], ep["host"], *step)
        time.sleep(0.5)

    print(f"\n   ⚡ Scenario complete. Check dashboard for SIEM correlation: 'Ransomware Campaign'")


# ── Scenario: APT Intrusion ───────────────────────────────────────────────────
def scenario_apt():
    print("\n🟠 SCENARIO: APT — Advanced Persistent Threat (Cobalt Strike)")
    print("   Simulating multi-stage APT intrusion...\n")
    ep = ENDPOINTS[1]

    steps = [
        ("phishing", "medium", "Suspicious Email Attachment Executed",
         "winword.exe launched powershell.exe as child process — macro execution detected",
         "winword.exe", 3201, "C:\\Users\\admin\\Downloads\\invoice_Q4.docm", None,
         {"macro": True, "child_process": "powershell.exe"}),

        ("process_injection", "critical", "Process Injection: Cobalt Strike Beacon",
         "Shellcode injected into svchost.exe via VirtualAllocEx+WriteProcessMemory+CreateRemoteThread",
         "powershell.exe", 3402, None, None,
         {"technique": "CreateRemoteThread", "target_process": "svchost.exe", "shellcode_size": 4096}),

        ("malicious_ip", "critical", "C2 Beacon to Known Cobalt Strike Server",
         "svchost.exe beaconing to 45.142.212.100:443 every 60s — confirmed Cobalt Strike C2",
         "svchost.exe", 3402, None, "45.142.212.100",
         {"beacon_interval": 60, "port": 443, "protocol": "HTTPS", "jitter": "20%"}),

        ("privilege_escalation", "critical", "UAC Bypass — Privilege Escalation",
         "fodhelper.exe UAC bypass executed — SYSTEM privileges obtained",
         "fodhelper.exe", 4521, None, None,
         {"technique": "fodhelper_uac_bypass", "result": "SYSTEM"}),

        ("credential_dump", "critical", "Mimikatz: Credential Harvesting",
         "sekurlsa::logonpasswords executed — NTLM hashes and plaintext passwords extracted",
         "mimikatz.exe", 5601, None, None,
         {"tool": "mimikatz", "command": "sekurlsa::logonpasswords", "accounts_dumped": 12}),

        ("data_exfiltration", "critical", "Data Staging + Exfiltration via HTTPS",
         "7-zip archive of 4.2GB created in C:\\ProgramData, uploading to C2 server over HTTPS",
         "7z.exe", 6701, "C:\\ProgramData\\archive.7z", "45.142.212.100",
         {"archive_size_gb": 4.2, "destination": "45.142.212.100", "protocol": "HTTPS"}),
    ]

    for step in steps:
        send_alert(ep["id"], ep["host"], *step)
        time.sleep(0.5)

    print(f"\n   ⚡ Scenario complete. Check dashboard for SIEM correlation: 'Credential Dump + Lateral Movement'")


# ── Scenario: Brute Force Attack ─────────────────────────────────────────────
def scenario_brute_force():
    print("\n🟡 SCENARIO: Credential Brute Force Attack")
    print("   Simulating RDP + local brute force...\n")
    ep = ENDPOINTS[0]

    # Simulate 8 failed logins
    for i in range(1, 9):
        sev = "medium" if i < 5 else "critical"
        send_alert(ep["id"], ep["host"], "login_failure", sev,
                   f"Failed Login Attempt #{i} — Administrator",
                   f"Failed RDP authentication for user 'administrator' from 194.165.16.77 (attempt {i}/10)",
                   network_ip="194.165.16.77",
                   raw_data={"user": "administrator", "source_ip": "194.165.16.77",
                             "method": "RDP", "attempt": i})
        time.sleep(0.2)

    # Successful login after brute force
    send_alert(ep["id"], ep["host"], "brute_force", "critical",
               "Brute Force SUCCESS — Account Compromised",
               "RDP login SUCCEEDED after 8 failed attempts — account 'administrator' likely compromised",
               network_ip="194.165.16.77",
               raw_data={"user": "administrator", "source_ip": "194.165.16.77",
                         "failed_attempts": 8, "result": "SUCCESS"})
    time.sleep(0.3)

    # Post-compromise activity
    send_alert(ep["id"], ep["host"], "process_execution", "high",
               "Suspicious Command Execution Post-Login",
               "whoami /priv && net user && ipconfig /all executed immediately after RDP login",
               "cmd.exe", 7823,
               raw_data={"cmdline": "whoami /priv && net user && ipconfig /all", "post_login": True})

    print(f"\n   ⚡ Scenario complete. Check dashboard for SIEM correlation: 'Brute Force Attack'")


# ── Scenario: Insider Threat ──────────────────────────────────────────────────
def scenario_insider():
    print("\n🟣 SCENARIO: Insider Threat — Data Exfiltration via USB")
    print("   Simulating malicious employee data theft...\n")
    ep = ENDPOINTS[2]

    steps = [
        ("sensitive_file", "high", "Sensitive File Access: HR Records",
         "Employee HR records accessed outside business hours (11:47 PM)",
         None, None, "C:\\HR\\employee_records_2024.xlsx", None,
         {"file_size_mb": 142, "time": "23:47:12", "user": "jsmith", "after_hours": True}),

        ("sensitive_file", "high", "Sensitive File Copy: Financial Data",
         "Q4 financial projections copied to user's local Downloads folder",
         None, None, "C:\\Finance\\Q4_projections_confidential.xlsx", None,
         {"copied_to": "C:\\Users\\jsmith\\Downloads\\", "user": "jsmith"}),

        ("usb_insertion", "medium", "USB Drive Inserted",
         "SanDisk USB 3.0 drive (32GB) connected to LAPTOP-HR-05",
         None, None, None, None,
         {"device": "SanDisk USB 3.0", "capacity_gb": 32, "user": "jsmith"}),

        ("usb_exfiltration", "critical", "CRITICAL: Sensitive Files Copied to USB",
         "47 sensitive files (HR records, financial data, contracts) copied to USB drive D:\\",
         None, None, "D:\\exfil_2024\\", None,
         {"files_copied": 47, "total_mb": 856, "sensitive_files":
          ["employee_records_2024.xlsx", "Q4_projections_confidential.xlsx",
           "contracts_2024.pdf", "salary_data.csv"], "user": "jsmith"}),

        ("data_exfiltration", "critical", "Large Data Transfer to Personal Email",
         "Outlook sending 850MB attachment to personal Gmail account — data exfiltration",
         "outlook.exe", 4521, None, "142.250.80.5",
         {"destination": "jsmith_personal@gmail.com", "size_mb": 850,
          "attachment": "company_data_backup.zip"}),
    ]

    for step in steps:
        send_alert(ep["id"], ep["host"], *step)
        time.sleep(0.5)

    print(f"\n   ⚡ Scenario complete. Check dashboard for SIEM correlation: 'Insider Threat - Data Exfiltration'")


# ── Scenario: C2 / Malware ────────────────────────────────────────────────────
def scenario_c2():
    print("\n🔵 SCENARIO: Active Malware C2 Communication")
    print("   Simulating active malware beacon + persistence...\n")
    ep = ENDPOINTS[0]

    steps = [
        ("malware_hash", "critical", "Known Malware Hash Detected",
         "File matches WannaCry ransomware SHA256 signature in C:\\Users\\Public\\",
         "update.exe", 8821, "C:\\Users\\Public\\update.exe", None,
         {"sha256": "7bc1e8a98d6e3b7c4f4ad2b1e6f9c8d2a3b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
          "malware_name": "WannaCry", "type": "ransomware"}),

        ("c2_communication", "critical", "DNS Tunneling C2 Channel",
         "Abnormally long DNS TXT queries detected — DNS tunneling to malicious domain",
         "svchost.exe", 2341, None, "185.234.218.68",
         {"domain": "c2.evil-domain.xyz", "query_length": 247, "queries_per_min": 45}),

        ("registry_run_key", "high", "Persistence: Registry Run Key Added",
         "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified — malware persistence",
         "reg.exe", 9012, None, None,
         {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          "value": "WindowsUpdate", "data": "C:\\Users\\Public\\update.exe"}),

        ("dll_injection", "critical", "DLL Injection into Explorer.exe",
         "Malicious DLL loaded into explorer.exe from AppData\\Local\\Temp",
         "explorer.exe", 1024, "C:\\Users\\admin\\AppData\\Local\\Temp\\mal.dll", None,
         {"injected_dll": "mal.dll", "source": "AppData\\Local\\Temp", "technique": "LoadLibrary"}),

        ("disable_security", "critical", "Windows Defender Disabled via Registry",
         "Malware disabled Windows Defender: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
         "reg.exe", 8234, None, None,
         {"key": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
          "value": "DisableAntiSpyware", "data": 1}),
    ]

    for step in steps:
        send_alert(ep["id"], ep["host"], *step)
        time.sleep(0.5)

    print(f"\n   ⚡ Scenario complete. Check dashboard for SIEM correlation: 'Process Injection Attack'")


# ── Scenario: Memory Attacks ──────────────────────────────────────────────────
def scenario_memory():
    print("\n⚪ SCENARIO: Memory-Based Malware (Fileless Attack)")
    print("   Simulating in-memory attack chain...\n")
    ep = ENDPOINTS[1]

    steps = [
        ("process_hollowing", "critical", "Process Hollowing: svchost.exe",
         "svchost.exe process hollowed — legitimate process shell used to hide malware",
         "svchost.exe", 4521, None, None,
         {"technique": "process_hollowing", "target": "svchost.exe",
          "injected_payload_size": 65536}),

        ("reflective_loading", "critical", "Reflective DLL Loading Detected",
         "PE payload loaded directly into memory without touching disk — fileless malware",
         "powershell.exe", 5632, None, None,
         {"technique": "reflective_dll_loading", "payload_size": 524288, "on_disk": False}),

        ("memory_injection", "critical", "Shellcode Injection via WriteProcessMemory",
         "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread pattern detected",
         "wscript.exe", 3421, None, None,
         {"api_calls": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
          "target_pid": 4521, "shellcode_size": 4096}),

        ("malicious_ip", "critical", "Memory Malware Beaconing to C2",
         "In-memory RAT connecting to 198.251.83.56:4444 — Cobalt Strike default port",
         "svchost.exe", 4521, None, "198.251.83.56",
         {"port": 4444, "protocol": "TCP", "beacon_type": "cobalt_strike"}),
    ]

    for step in steps:
        send_alert(ep["id"], ep["host"], *step)
        time.sleep(0.5)

    print(f"\n   ⚡ Scenario complete. Check ML anomaly scores in AI/ML dashboard view")


# ── All Scenarios ─────────────────────────────────────────────────────────────
def run_all():
    print("\n  Running ALL attack scenarios sequentially...\n")
    # First, register all endpoints
    for ep in ENDPOINTS:
        send_heartbeat(ep)
    time.sleep(0.5)

    scenario_ransomware()
    time.sleep(1)
    scenario_apt()
    time.sleep(1)
    scenario_brute_force()
    time.sleep(1)
    scenario_insider()
    time.sleep(1)
    scenario_c2()
    time.sleep(1)
    scenario_memory()

    print("\n" + "=" * 60)
    print("  All scenarios complete!")
    print("  Open the dashboard to review:")
    print("    → Overview: Active alerts + timeline")
    print("    → SIEM: Correlation rules triggered")
    print("    → MITRE: Technique coverage map")
    print("    → AI/ML: Attack predictions")
    print("    → Threat Map: Geo attack origins")
    print("    → Response: Send remote commands")
    print("=" * 60)


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Platform Attack Simulator")
    parser.add_argument("--server", default="http://localhost:8000", help="SOC server URL")
    parser.add_argument("--key", default="SOC-MASTER-KEY-2024", help="API key")
    parser.add_argument("--scenario", choices=["all","ransomware","apt","brute_force",
                                               "insider","c2","memory"], default="all")
    args = parser.parse_args()

    SERVER = args.server
    API_KEY = args.key
    HEADERS["Authorization"] = f"Bearer {API_KEY}"

    print("=" * 60)
    print("  SOC PLATFORM — ATTACK SIMULATION")
    print(f"  Server: {SERVER}")
    print("=" * 60)

    if not check_server():
        print(f"\n  ✗ Cannot reach SOC server at {SERVER}")
        print("  Start it first:  cd server && python main.py")
        sys.exit(1)

    print(f"\n  ✓ Server online at {SERVER}\n")

    # Register endpoints first
    for ep in ENDPOINTS:
        send_heartbeat(ep)

    scenarios = {
        "ransomware": scenario_ransomware,
        "apt":        scenario_apt,
        "brute_force":scenario_brute_force,
        "insider":    scenario_insider,
        "c2":         scenario_c2,
        "memory":     scenario_memory,
        "all":        run_all,
    }
    scenarios[args.scenario]()
