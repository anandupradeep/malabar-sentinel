"""
Build agent.exe using PyInstaller
Usage: python installer/build_agent.py
"""

import os
import subprocess
import sys

def build():
    print("=== SOC Agent Builder ===")
    print("Building agent.exe with PyInstaller...\n")

    # Install PyInstaller if needed
    subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)

    spec_content = """
# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

a = Analysis(
    ['agent/main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('config/', 'config/'),
    ],
    hiddenimports=[
        'psutil', 'requests', 'PyQt5', 'PyQt5.QtWidgets', 'PyQt5.QtCore', 'PyQt5.QtGui',
        'watchdog', 'watchdog.observers', 'watchdog.events',
        'hashlib', 'threading', 'socket', 'platform',
        'agent.agent_core', 'agent.gui',
        'agent.monitors.process_monitor', 'agent.monitors.network_monitor',
        'agent.monitors.file_monitor', 'agent.monitors.usb_monitor',
        'agent.monitors.login_monitor', 'agent.monitors.memory_monitor',
        'agent.security.ransomware_detector', 'agent.security.hash_scanner',
        'agent.kernel.kernel_monitor',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SOC-Agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
"""
    with open("soc_agent.spec", "w") as f:
        f.write(spec_content)

    result = subprocess.run(
        ["pyinstaller", "soc_agent.spec", "--clean", "--noconfirm"],
        capture_output=False
    )

    if result.returncode == 0:
        print("\n✅ Build successful!")
        print("Output: dist/SOC-Agent.exe")
        print("\nDeploy dist/SOC-Agent.exe to endpoint machines.")
        print("Configure the SOC server URL in Settings tab on first launch.")
    else:
        print("\n❌ Build failed. Check output above.")
        sys.exit(1)

if __name__ == "__main__":
    build()
