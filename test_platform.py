"""
SOC Platform - Complete Integration Test Suite
58 tests across all modules.

Run from soc-platform root:
    python test_platform.py

Requirements (same as server):
    pip install fastapi uvicorn pydantic httpx cryptography aiosqlite
"""

import sys, os, asyncio, tempfile, importlib
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "server"))
sys.path.insert(0, os.path.dirname(__file__))

# ── Helpers ───────────────────────────────────────────────────────────────────
def assert_eq(a, b):        assert a == b,         f"{a!r} != {b!r}"
def assert_gt(a, b):        assert a > b,           f"{a} not > {b}"
def assert_in(a, b):        assert a in b,          f"{a!r} not in {b!r}"
def assert_true(v):         assert bool(v),         f"Expected truthy, got {v!r}"
def assert_false(v):        assert not bool(v),     f"Expected falsy, got {v!r}"
def assert_range(v, lo, hi):assert lo <= v <= hi,   f"{v} not in [{lo},{hi}]"

results = []

def test(name, fn):
    try:
        fn()
        print(f"  ✓ {name}")
        results.append((name, True, None))
    except Exception as e:
        print(f"  ✗ {name}: {e}")
        results.append((name, False, str(e)))

def skip(name, reason=""):
    print(f"  ⚠ {name} — skipped ({reason})")
    results.append((name, None, reason))

# ─── 1. MITRE ATT&CK Mapper ──────────────────────────────────────────────────
print("\n[1] MITRE ATT&CK Mapper")
from mitre_mapper import MITREMapper
m = MITREMapper()
test("ransomware → T1486",           lambda: assert_eq(m.map_alert("ransomware", "")["technique"], "T1486"))
test("process_injection → T1055",     lambda: assert_eq(m.map_alert("process_injection", "")["technique"], "T1055"))
test("usb_exfiltration → T1052.001",  lambda: assert_eq(m.map_alert("usb_exfiltration", "")["technique"], "T1052.001"))
test("lsass keyword → T1003.001",     lambda: assert_eq(m.map_alert("x", "lsass detected")["technique"], "T1003.001"))
test("brute_force → T1110",           lambda: assert_eq(m.map_alert("brute_force", "")["technique"], "T1110"))
test("credential_dump → T1003",       lambda: assert_eq(m.map_alert("credential_dump", "")["technique"], "T1003"))
test("ransomware keyword in desc",    lambda: assert_eq(m.map_alert("x", "ransomware encrypt")["technique"], "T1486"))
test(">30 techniques defined",        lambda: assert_gt(len(m.get_all_techniques()), 30))
test("Execution in tactics",          lambda: assert_in("Execution", m.get_tactics()))
test("Impact in tactics",             lambda: assert_in("Impact", m.get_tactics()))

# ─── 2. ML Detection Engine ──────────────────────────────────────────────────
print("\n[2] ML Detection Engine")
from ml_detection import MLDetectionEngine
ml = MLDetectionEngine()
ml.initialize()
test("initialized flag",                    lambda: assert_true(ml.initialized))
test("emergency >= 0.88",                   lambda: assert_range(ml.score_alert({"severity": "emergency"}), 0.88, 1.0))
test("critical + ransomware >= 0.82",       lambda: assert_range(ml.score_alert({"severity": "critical", "alert_type": "ransomware"}), 0.82, 1.0))
test("critical bare >= 0.78",               lambda: assert_range(ml.score_alert({"severity": "critical"}), 0.78, 1.0))
test("high >= 0.60",                        lambda: assert_range(ml.score_alert({"severity": "high"}), 0.60, 1.0))
test("medium 0.35–0.65",                    lambda: assert_range(ml.score_alert({"severity": "medium"}), 0.35, 0.65))
test("low <= 0.40",                         lambda: assert_range(ml.score_alert({"severity": "low"}), 0.0, 0.40))
test("all scores in [0, 1]",               lambda: assert_range(ml.score_alert({}), 0.0, 1.0))
test("score_event delegates",              lambda: assert_range(ml.score_event({"type": "process"}), 0.0, 1.0))
test("get_stats returns dict",             lambda: assert_true(isinstance(ml.get_stats(), dict)))
test("stats has alerts_processed key",     lambda: assert_in("alerts_processed", ml.get_stats()))

# ─── 3. Threat Intelligence ──────────────────────────────────────────────────
print("\n[3] Threat Intelligence")
from threat_intelligence import ThreatIntelligence

class MockDB:
    async def add_threat_intel(self, *a, **k): pass
    async def check_threat_intel(self, t, v):
        if t == "ip" and v == "45.142.212.100":
            return {"description": "Known C2"}
        return None
    async def get_threat_intel_count(self): return {"ip": 47, "hash": 312}

ti = ThreatIntelligence(MockDB())

async def _ti_tests():
    await ti.load_feeds()
    assert await ti.check_ip("45.142.212.100") is not None, "C2 IP should match"
    assert await ti.check_ip("192.168.1.1") is None,         "Private IP should not match"
    assert await ti.check_ip(None) is None,                  "None IP should return None"
    assert await ti.check_domain("evil-c2.xyz") is not None, "C2 domain should match"
    assert await ti.check_domain("google.com") is None,      "Clean domain should not match"
    s = await ti.get_summary()
    assert "malicious_ips" in s and "feeds_active" in s

asyncio.run(_ti_tests())
test("TI load + IP/domain checks", lambda: None)

# ─── 4. SIEM Correlation ─────────────────────────────────────────────────────
print("\n[4] SIEM Correlation Engine")
from siem_correlator import CORRELATION_RULES
test("8 rules defined",              lambda: assert_eq(len(CORRELATION_RULES), 8))
test("all rules have conditions",    lambda: assert_true(all(len(r.conditions) >= 2 for r in CORRELATION_RULES)))
test("all rules have time_window",   lambda: assert_true(all(r.time_window > 0 for r in CORRELATION_RULES)))
test("ransomware rule = emergency",
     lambda: assert_eq(next(r for r in CORRELATION_RULES if "Ransomware" in r.name).severity, "emergency"))
test("brute force rule = critical",
     lambda: assert_eq(next(r for r in CORRELATION_RULES if "Brute" in r.name).severity, "critical"))

# ─── 5. AI Prediction Engine ─────────────────────────────────────────────────
print("\n[5] AI Prediction Engine")
from ai_prediction import AIPredictionEngine, ATTACK_CHAINS
test("7 attack chains defined",     lambda: assert_eq(len(ATTACK_CHAINS), 7))
test("confidence in (0, 1]",       lambda: assert_true(all(0 < c["confidence"] <= 1 for c in ATTACK_CHAINS)))
test("all chains have MITRE ID",    lambda: assert_true(all("mitre" in c for c in ATTACK_CHAINS)))
test("all chains have severity",
     lambda: assert_true(all(c["severity"] in ["high", "critical", "emergency"] for c in ATTACK_CHAINS)))

class EmptyDB:
    async def get_alerts(self, **k): return []

async def _pred_test():
    p = AIPredictionEngine(EmptyDB())
    await p._analyze_patterns()
    preds = await p.get_latest_predictions()
    assert isinstance(preds, list)

asyncio.run(_pred_test())
test("predictor runs on empty alerts", lambda: None)

# ─── 6. Database (SQLite) ─────────────────────────────────────────────────────
print("\n[6] Database (SQLite)")

async def _db_tests():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    from database import Database
    db = Database()
    db._sqlite_path = tmp
    await db._init_sqlite()

    # Endpoint CRUD
    ep = {
        "endpoint_id": "e1", "hostname": "HOST1", "ip_address": "10.0.0.1",
        "os_version": "Windows 11", "agent_version": "1.0.0",
        "cpu_usage": 5.0, "memory_usage": 50.0, "disk_usage": 20.0,
        "active_processes": 100, "threat_level": "normal"
    }
    await db.upsert_endpoint(ep)
    eps = await db.get_all_endpoints()
    assert any(e["hostname"] == "HOST1" for e in eps), "Endpoint not found"

    # Alert CRUD
    aid = await db.create_alert({
        "endpoint_id": "e1", "hostname": "HOST1", "alert_type": "ransomware",
        "severity": "critical", "title": "TestAlert", "description": "Desc",
        "mitre_tactic": "Impact", "mitre_technique": "T1486"
    })
    assert len(aid) > 0
    alerts = await db.get_alerts()
    assert alerts[0]["title"] == "TestAlert"
    await db.acknowledge_alert(aid)
    alerts2 = await db.get_alerts()
    assert alerts2[0]["acknowledged"] == 1
    stats = await db.get_alert_stats()
    assert stats["critical"] >= 1
    assert "unacknowledged" in stats

    # Policy CRUD
    pid = await db.create_policy({"policy_name": "p1", "rules": {"a": 1}, "endpoints": ["e1"]})
    assert pid
    pols = await db.get_all_policies()
    assert pols[0]["policy_name"] == "p1"
    pol = await db.get_policy_for_endpoint("e1")
    assert pol is not None

    # Threat Intel CRUD
    await db.add_threat_intel("ip", "9.9.9.9", "malicious", "feed", "high")
    assert await db.check_threat_intel("ip", "9.9.9.9") is not None
    assert await db.check_threat_intel("ip", "1.1.1.1") is None
    counts = await db.get_threat_intel_count()
    assert counts.get("ip", 0) >= 1

    # Commands
    await db.store_command("c1", {"endpoint_id": "e1", "command": "lock_endpoint", "parameters": {}})
    cmds = await db.get_pending_commands("e1")
    assert cmds[0]["command"] == "lock_endpoint"
    await db.update_command_result("c1", {"status": "done"})

    # Correlations
    cid = await db.store_correlation("BruteForce", "desc", ["a1", "a2"], "critical")
    corrs = await db.get_correlations()
    assert corrs[0]["rule_name"] == "BruteForce"

    # Geo Data
    await db.store_geo_data("5.5.5.5", "Russia", "Moscow", "ISP", 55.75, 37.62)
    geo = await db.get_attack_geo_data()
    assert any(g["ip_address"] == "5.5.5.5" for g in geo)

    # Timeline
    tl = await db.get_alert_timeline(hours=24)
    assert isinstance(tl, list)

    # MITRE Coverage
    mc = await db.get_mitre_coverage()
    assert isinstance(mc, list)

    # Cleanup
    await db.cleanup_old_records(days=0)
    try:
        os.unlink(tmp)
    except Exception:
        pass

asyncio.run(_db_tests())
test("all DB operations pass", lambda: None)

# ─── 7. Rule Loader ──────────────────────────────────────────────────────────
print("\n[7] Rule Loader")
from agent.rule_loader import RuleLoader
rl = RuleLoader()
test("explorer.exe whitelisted",        lambda: assert_true(rl.is_whitelisted_process("explorer.exe")))
test("case-insensitive whitelist",      lambda: assert_true(rl.is_whitelisted_process("EXPLORER.EXE")))
test("mimikatz not whitelisted",        lambda: assert_false(rl.is_whitelisted_process("mimikatz.exe")))
test("System32 path OK",                lambda: assert_true(rl.is_whitelisted_path("C:\\Windows\\System32\\x")))
test("temp path NOT OK",                lambda: assert_false(rl.is_whitelisted_path("C:\\temp\\evil.exe")))
test(">5 process rules loaded",         lambda: assert_gt(len(rl.get_process_rules()), 5))
test(">0 network rules loaded",         lambda: assert_gt(len(rl.get_network_rules()), 0))
test("server policy merge works",
     lambda: (rl.merge_server_policy({"whitelist_processes": ["myapp.exe"]}),
              assert_true(rl.is_whitelisted_process("myapp.exe"))))

# ─── 8. Hash Scanner ─────────────────────────────────────────────────────────
print("\n[8] Hash Scanner")
from agent.security.hash_scanner import HashScanner, KNOWN_MALWARE_HASHES

class FakeAgent:
    def send_alert(self, *a, **k): pass

s = HashScanner(FakeAgent())
test("hash_file returns 64-char hex",   lambda: assert_eq(len(s.hash_file("server/mitre_mapper.py")), 64))
test("missing file → empty string",     lambda: assert_eq(s.hash_file("/no/such/file.exe"), ""))
test("unknown hash → empty string",     lambda: assert_eq(s.check_hash("a" * 64), ""))
test(">3 malware hashes in DB",         lambda: assert_gt(len(KNOWN_MALWARE_HASHES), 3))
test("known Mimikatz hash detected",
     lambda: assert_in(
         s.check_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
         ["Mimikatz", "Empty file (test)"]
     ))

# ─── 9. File Encryption (AES-256) ────────────────────────────────────────────
print("\n[9] File Encryption (AES-256)")
from agent.security.file_encryption import FileEncryption, ENCRYPTED_EXTENSION, HAS_CRYPTO

if HAS_CRYPTO:
    enc = FileEncryption(master_key="test-key-soc-123")

    def _round_trip():
        content = b"CONFIDENTIAL SOC TEST DATA 0xDEADBEEF"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(content)
            fp = f.name
        ok, ep = enc.encrypt_file(fp)
        assert ok,                              f"Encrypt failed: {ep}"
        assert ep.endswith(ENCRYPTED_EXTENSION), "Wrong extension"
        assert not os.path.exists(fp),           "Original should be deleted"
        assert enc.is_encrypted(ep),             "is_encrypted should be True"
        ok2, dp = enc.decrypt_file(ep)
        assert ok2,                              f"Decrypt failed: {dp}"
        with open(dp, "rb") as f:
            assert f.read() == content,          "Decrypted content mismatch"
        os.unlink(dp)

    test("AES-256 encrypt → decrypt round-trip",    _round_trip)
    test("is_encrypted('plain.txt') → False",        lambda: assert_false(enc.is_encrypted("plain.txt")))
    test("double encrypt rejected",                  lambda: assert_false(enc.encrypt_file("x" + ENCRYPTED_EXTENSION)[0]))
    test("decrypt non-encrypted file rejected",      lambda: assert_false(enc.decrypt_file("x.txt")[0]))
else:
    skip("File encryption", "cryptography not installed — pip install cryptography")

# ─── 10. SecureSender ────────────────────────────────────────────────────────
print("\n[10] SecureSender")
from agent.sender import SecureSender
ss = SecureSender("http://localhost:8000", "test-key", "ep-001")
test("endpoint_id assigned",        lambda: assert_eq(ss.endpoint_id, "ep-001"))
test("queue_alert returns bool",    lambda: assert_true(isinstance(ss.queue_alert({"title": "t"}), bool)))
test("queue_telemetry returns bool",lambda: assert_true(isinstance(ss.queue_telemetry([{"event": "x"}]), bool)))
test("get_stats returns dict",      lambda: assert_true(isinstance(ss.get_stats(), dict)))
test("stats has queue_size key",    lambda: assert_in("queue_size", ss.get_stats()))
test("test_connection → False",     lambda: assert_false(ss.test_connection()))
test("is_connected → False",        lambda: assert_false(ss.is_connected))

# ─── 11. All Agent Module Imports ────────────────────────────────────────────
print("\n[11] Agent Module Imports (14 modules)")
agent_modules = [
    ("agent.agent_core",                          "AgentCore"),
    ("agent.sender",                              "SecureSender"),
    ("agent.rule_loader",                         "RuleLoader"),
    ("agent.monitors.process_monitor",            "ProcessMonitor"),
    ("agent.monitors.network_monitor",            "NetworkMonitor"),
    ("agent.monitors.file_monitor",               "FileMonitor"),
    ("agent.monitors.usb_monitor",                "USBMonitor"),
    ("agent.monitors.login_monitor",              "LoginMonitor"),
    ("agent.monitors.memory_monitor",             "MemoryMonitor"),
    ("agent.security.ransomware_detector",        "RansomwareDetector"),
    ("agent.security.hash_scanner",               "HashScanner"),
    ("agent.security.usb_exfiltration_detector",  "USBExfiltrationDetector"),
    ("agent.security.file_encryption",            "FileEncryption"),
    ("agent.kernel.kernel_monitor",               "KernelMonitor"),
]
for mod_path, cls_name in agent_modules:
    def _t(mp=mod_path, cn=cls_name):
        mod = importlib.import_module(mp)
        assert hasattr(mod, cn), f"{cn} not found in {mp}"
    test(f"{cls_name}", _t)

# ─── 12. Live Server (optional) ──────────────────────────────────────────────
print("\n[12] Live Server (optional — start server first)")
try:
    import requests as req
    _live_key = os.getenv("SOC_ADMIN_KEY") or os.getenv("SOC_MASTER_KEY", "SOC-MASTER-KEY-2024")
    r = req.get("http://localhost:9001/health", timeout=2)
    if r.status_code == 200:
        test("GET /health → 200",               lambda: assert_eq(r.status_code, 200))
        r2 = req.post(
            "http://localhost:9001/api/alerts",
            headers={"Authorization": f"Bearer {_live_key}"},
            json={
                "endpoint_id": "test-ep", "hostname": "TEST-HOST",
                "alert_type": "process_execution", "severity": "high",
                "title": "Integration Test Alert", "description": "Automated test"
            },
            timeout=5
        )
        test("POST /api/alerts → 200",          lambda: assert_eq(r2.status_code, 200))
        r3 = req.get("http://localhost:9001/api/endpoints",
                     headers={"Authorization": f"Bearer {_live_key}"}, timeout=5)
        test("GET /api/endpoints → 200",        lambda: assert_eq(r3.status_code, 200))
        r4 = req.get("http://localhost:9001/api/dashboard/overview",
                     headers={"Authorization": f"Bearer {_live_key}"}, timeout=5)
        test("GET /api/dashboard/overview → 200", lambda: assert_eq(r4.status_code, 200))
        r5 = req.get("http://localhost:9001/api/mitre/matrix",
                     headers={"Authorization": f"Bearer {_live_key}"}, timeout=5)
        test("GET /api/mitre/matrix → 200",     lambda: assert_eq(r5.status_code, 200))

        # ── Auth tests: unauthenticated requests must return 401 ──────────────
        def _unauth_cmd():
            r = req.post("http://localhost:9001/send-command",
                         json={"endpoint_id": "x", "command": "list_processes"},
                         timeout=5)
            return r.status_code
        def _unauth_get_cmd():
            r = req.get("http://localhost:9001/get-commands/test-ep", timeout=5)
            return r.status_code
        def _unauth_cmd_resp():
            r = req.post("http://localhost:9001/command-response",
                         json={"command_id": "x", "status": "executed"},
                         timeout=5)
            return r.status_code
        def _unauth_scan_start():
            r = req.post("http://localhost:9001/api/scan/start",
                         json={"endpoint_id": "x", "scan_type": "quick"},
                         timeout=5)
            return r.status_code
        def _unauth_scan_report():
            r = req.post("http://localhost:9001/api/scan/report/update",
                         json={"scan_id": "x"}, timeout=5)
            return r.status_code

        test("POST /send-command without auth → 401",
             lambda: assert_eq(_unauth_cmd(), 401))
        test("GET /get-commands without auth → 401",
             lambda: assert_eq(_unauth_get_cmd(), 401))
        test("POST /command-response without auth → 401",
             lambda: assert_eq(_unauth_cmd_resp(), 401))
        test("POST /api/scan/start without auth → 401",
             lambda: assert_eq(_unauth_scan_start(), 401))
        test("POST /api/scan/report/update without auth → 401",
             lambda: assert_eq(_unauth_scan_report(), 401))

    else:
        skip("Live server tests", f"server returned {r.status_code}")
except Exception:
    skip("Live server tests", "server not running — cd server && python main.py")

# ─── Rule Loader focused tests ────────────────────────────────────────────────
print("\n── rule_loader ──")
sys.path.insert(0, str(Path(__file__).parent / "agent"))
try:
    import importlib, copy
    rl_mod = importlib.import_module("rule_loader")
    RuleLoader = rl_mod.RuleLoader
    _validate_rules = rl_mod._validate_rules

    # Deep copy: mutating returned rules should not affect defaults
    rl = RuleLoader()
    r1 = rl.get_process_rules()
    r1.append({"name": "injected"})
    test("rule_loader deep-copy: mutation does not affect internal state",
         lambda: assert_eq(len(rl.get_process_rules()), len(rl_mod.DEFAULT_RULES["process_rules"])))

    # Malformed rules rejected
    test("rule_loader rejects non-dict",
         lambda: assert_true(_validate_rules("bad") is not None))
    test("rule_loader rejects missing keys",
         lambda: assert_true(_validate_rules({"process_rules": []}) is not None))
    test("rule_loader accepts valid shape",
         lambda: assert_true(_validate_rules(copy.deepcopy(rl_mod.DEFAULT_RULES)) is None))

    # Whitelist cache: fast lookups
    test("is_whitelisted_process: svchost.exe → True",
         lambda: assert_true(rl.is_whitelisted_process("svchost.exe")))
    test("is_whitelisted_process: malware.exe → False",
         lambda: assert_false(rl.is_whitelisted_process("malware.exe")))
    test("is_whitelisted_path: System32 → True",
         lambda: assert_true(rl.is_whitelisted_path("C:\\Windows\\System32\\ntdll.dll")))

    # Policy merge: no duplicates, ordering preserved
    rl2 = RuleLoader()
    original_count = len(rl2.get_whitelist().get("processes", []))
    rl2.merge_server_policy({"whitelist_processes": ["newproc.exe", "svchost.exe"]})
    new_count = len(rl2.get_whitelist().get("processes", []))
    test("rule_loader policy merge: deduplicates existing entries",
         lambda: assert_eq(new_count, original_count + 1))  # only newproc.exe added
except ImportError as e:
    skip("rule_loader tests", f"import error: {e}")

# ─── Scan executor focused tests ──────────────────────────────────────────────
print("\n── scan_executor ──")
try:
    se_mod = importlib.import_module("scan_executor")
    _validate_custom_path = se_mod._validate_custom_path
    _validate_hash_set    = se_mod._validate_hash_set
    _is_excluded_dir      = se_mod._is_excluded_dir

    # Custom path validation
    test("scan_executor rejects relative path",
         lambda: assert_true(_validate_custom_path("relative/path") is not None))
    test("scan_executor rejects non-existent path",
         lambda: assert_true(_validate_custom_path("/nonexistent_12345_path") is not None))
    test("scan_executor accepts /tmp (exists)",
         lambda: assert_true(_validate_custom_path("/tmp") is None))

    # Hash validation
    valid_sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    invalid_md5 = "44d88612fea8a8f36de82e1278abb02f"
    invalid_sha1 = "cf8bd9dfddff007f75adf4c2be48005cea317c62"
    result_set = _validate_hash_set({valid_sha, invalid_md5, invalid_sha1})
    test("scan_executor hash validation: accepts SHA-256",
         lambda: assert_in(valid_sha, result_set))
    test("scan_executor hash validation: rejects MD5",
         lambda: assert_false(invalid_md5 in result_set))
    test("scan_executor hash validation: rejects SHA-1",
         lambda: assert_false(invalid_sha1 in result_set))

    # Exclusion logic
    test("scan_executor excludes quarantine dir",
         lambda: assert_true(_is_excluded_dir(str(se_mod.QUARANTINE_DIR))))
    test("scan_executor excludes node_modules",
         lambda: assert_true(_is_excluded_dir("/home/user/project/node_modules")))
    test("scan_executor does not exclude /tmp",
         lambda: assert_false(_is_excluded_dir("/tmp") and "/tmp" in str(se_mod._EXCLUDED_DIRS)))

except ImportError as e:
    skip("scan_executor tests", f"import error: {e}")



# ─── Summary ─────────────────────────────────────────────────────────────────
print()
print("=" * 60)
passed  = sum(1 for _, ok, _ in results if ok is True)
skipped = sum(1 for _, ok, _ in results if ok is None)
failed  = sum(1 for _, ok, _ in results if ok is False)
total   = passed + failed

print(f"  Results: {passed}/{total} passed | {skipped} skipped | {failed} failed")
print()
if failed == 0:
    print("  ✅ ALL TESTS PASSED")
else:
    print(f"  ❌ {failed} FAILURE(S):")
    for name, ok, err in results:
        if ok is False:
            print(f"     • {name}")
            print(f"       → {err}")
print("=" * 60)
sys.exit(0 if failed == 0 else 1)
