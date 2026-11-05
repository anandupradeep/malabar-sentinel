"""
SOC Platform - Auto Setup Script
Handles Python 3.12 / 3.13 / 3.14 automatically.
Run from soc-platform folder:  python setup.py
"""

import subprocess
import sys
import os

PY = sys.executable
VER = sys.version_info

print(f"=== SOC Platform Setup ===")
print(f"Python: {VER.major}.{VER.minor}.{VER.micro}")
print()

def pip(*args):
    cmd = [PY, "-m", "pip", "install", "--upgrade"] + list(args)
    print(f"  Installing: {' '.join(args)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  WARNING: {r.stderr.strip()[-300:]}")
    return r.returncode == 0

print("[1/3] Installing SOC Server dependencies...")

# Core web framework - use latest compatible versions (no pinning)
core = ["fastapi", "uvicorn[standard]", "python-multipart", "httpx",
        "cryptography", "python-dotenv", "websockets"]
for pkg in core:
    pip(pkg)

# Pydantic - Python 3.14 needs >=2.9
pip("pydantic>=2.9.0")

# SQLite async wrapper
pip("aiosqlite")

print()
print("[2/3] Installing ML dependencies (optional)...")
# Try scikit-learn — may fail on 3.14 if no wheel available
try:
    r = subprocess.run([PY, "-m", "pip", "install", "--upgrade", "scikit-learn", "numpy"],
                       capture_output=True, text=True, timeout=120)
    if r.returncode == 0:
        print("  ✓ scikit-learn + numpy installed")
    else:
        print("  ⚠ scikit-learn unavailable on this Python version — ML runs in rule-based fallback mode")
except Exception as e:
    print(f"  ⚠ ML install skipped: {e}")

print()
print("[3/3] Installing Agent dependencies...")
agent_pkgs = ["psutil", "requests", "watchdog", "websockets"]
for pkg in agent_pkgs:
    pip(pkg)

# PyQt5 — try, but might not be available on 3.14
try:
    r = subprocess.run([PY, "-m", "pip", "install", "--upgrade", "PyQt5"],
                       capture_output=True, text=True, timeout=120)
    if r.returncode == 0:
        print("  ✓ PyQt5 installed (agent GUI available)")
    else:
        print("  ⚠ PyQt5 unavailable — agent will run in headless mode")
        print("    Try: pip install PyQt6  (newer alternative)")
except Exception as e:
    print(f"  ⚠ PyQt5 skipped: {e}")

print()
print("=" * 40)
print("✅ Setup complete!")
print()
print("NEXT STEPS:")
print()
print("  Start the SOC Server:")
print("    cd server")
print("    python main.py")
print("    → API at http://localhost:8000")
print("    → Docs at http://localhost:8000/docs")
print()
print("  Open the Dashboard:")
print("    Open dashboard/public/index.html in your browser")
print()
print("  Start the Endpoint Agent:")
print("    python agent/main.py")
print()
print("  Build agent.exe:")
print("    python installer/build_agent.py")
print()