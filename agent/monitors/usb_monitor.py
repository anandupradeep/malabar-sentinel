"""
USB Monitor — Full Device Detection
Detects ALL USB connections including:
  • Pen drives / flash drives (removable mass storage)
  • Android phones (MTP / PTP mode)
  • iPhones / iPads (Apple Mobile Device)
  • USB-C devices (hubs, phones, tablets, docks)
  • Cameras, card readers, external HDDs
  • Any device visible in Windows Device Manager

Detection strategy (Windows):
  1. Get-PnpDevice -Class 'WPD'         → ALL portable devices (Android/iPhone MTP)
  2. Win32_PnPEntity service='WpdUsb'   → Fallback WPD enumeration
  3. Win32_PnPEntity name-keyword match → Galaxy, Pixel, iPhone, Android, MTP...
  4. psutil + wmic drivetype=2          → Traditional pen drives (drive letters)
Detection strategy (Linux):
  1. /sys/bus/usb/devices               → All USB device nodes
  2. lsblk -J                           → Removable block devices
"""
import logging
import os
import subprocess
import threading
import time
from typing import TYPE_CHECKING, Dict, Set

import psutil

logger = logging.getLogger("usb-monitor")

if TYPE_CHECKING:
    from agent.agent_core import AgentCore


# ── Device record factory ─────────────────────────────────────────────────────
def _dev(device_id, name, device_type, drive="", vendor="", serial="", **kw):
    return {
        "device_id":   device_id,
        "name":        name,
        "device_type": device_type,
        "drive":       drive,
        "vendor":      vendor,
        "serial":      serial,
        **kw,
    }


# ── PowerShell helpers ────────────────────────────────────────────────────────
def _ps(cmd, timeout=8):
    try:
        flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=flags,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _parse_ps_csv(raw):
    """Parse PowerShell ConvertTo-Csv output (skipping header) into list of dicts."""
    rows = []
    lines = [l for l in raw.splitlines() if l.strip()]
    if len(lines) < 2:
        return rows
    headers = [h.strip('"') for h in lines[0].split(',')]
    for line in lines[1:]:
        vals, cur, in_q = [], "", False
        for ch in line:
            if ch == '"':
                in_q = not in_q
            elif ch == ',' and not in_q:
                vals.append(cur); cur = ""
            else:
                cur += ch
        vals.append(cur)
        if len(vals) >= len(headers):
            rows.append(dict(zip(headers, vals)))
    return rows


# ── Device type classifier ────────────────────────────────────────────────────
def _classify(name, vendor=""):
    n = (name + " " + vendor).lower()
    if any(k in n for k in ("iphone", "ipad", "apple mobile", "ipod")):
        return "phone"
    if any(k in n for k in (
        "android", "galaxy", "pixel", "oneplus", "xiaomi", "redmi",
        "huawei", "honor", "oppo", "vivo", "realme", "motorola",
        "lg ", "htc", "sony xperia", "nokia", "asus zenfone",
        "tecno", "infinix", "itel", "poco", "blackberry",
    )):
        return "phone"
    if any(k in n for k in ("mtp", "ptp", "portable device", "wpd", "media player")):
        return "phone"
    if any(k in n for k in ("camera", "dslr", "canon", "nikon", "fujifilm",
                             "olympus", "pentax", "gopro")):
        return "camera"
    if any(k in n for k in ("hub", "dock", "usb-c", "type-c", "thunderbolt",
                             "multiport", "dongle")):
        return "hub"
    if any(k in n for k in ("disk", "storage", "flash", "drive", "pendrive",
                             "thumb drive", "card reader", "sd card",
                             "flash disk", "usb stick", "memory stick")):
        return "storage"
    # Fall back to 'usb_device' so unrecognised but valid devices still
    # appear in the dashboard rather than being silently filtered out.
    return "usb_device"


# ══ Windows snapshot functions ════════════════════════════════════════════════

def _win_removable_drives():
    """Pen drives and flash drives — devices with a Windows drive letter."""
    result = {}
    try:
        for p in psutil.disk_partitions():
            if "removable" in (p.opts or "").lower():
                label = _win_drive_label(p.mountpoint)
                result[p.mountpoint] = _dev(
                    p.mountpoint, label or "Removable Drive",
                    "storage", drive=p.mountpoint)
    except Exception:
        pass
    if not result:  # wmic fallback
        try:
            out = subprocess.check_output(
                ["wmic", "logicaldisk", "where", "drivetype=2",
                 "get", "DeviceID,VolumeName"],
                timeout=6, text=True, stderr=subprocess.DEVNULL)
            for line in out.strip().splitlines()[1:]:
                p = line.split()
                if p:
                    dl = p[0].strip() + "\\"
                    lb = p[1].strip() if len(p) > 1 else ""
                    result[dl] = _dev(dl, lb or "Removable Drive",
                                      "storage", drive=dl)
        except Exception:
            pass
    return result


def _win_drive_label(drive):
    dl = drive.rstrip("\\/").rstrip(":")
    raw = _ps(
        f"(Get-WmiObject Win32_LogicalDisk "
        f"-Filter \"DeviceID='{dl}:'\").VolumeName"
    )
    return raw if raw and raw.lower() not in ("", "null") else ""


def _win_portable_devices():
    """
    Phones, tablets, cameras via Windows Portable Device (WPD) driver.
    This is the key method for Android MTP, iPhone, cameras, etc.
    These never get a drive letter — they appear in Device Manager as
    'Portable Devices'.
    """
    result = {}

    # WPD driver components to exclude — these are Windows USB driver helpers,
    # NOT the actual user device. The real device shows separately (e.g. "Apple iPhone")
    WPD_SKIP = (
        "composite device", "usb device", "usb interface",
        "adb interface", "fastboot interface",
        "mobile device", "android interface",
    )

    # ── Method A: Get-PnpDevice -Class WPD (Windows 8+, most reliable) ──────
    raw = _ps(
        "Get-PnpDevice -Class 'WPD' -Status 'OK' 2>$null | "
        "Select-Object InstanceId,FriendlyName,Manufacturer | "
        "ConvertTo-Csv -NoTypeInformation"
    )
    for row in _parse_ps_csv(raw):
        did  = row.get("InstanceId", "").strip()
        name = row.get("FriendlyName", "").strip() or "Portable Device"
        mfr  = row.get("Manufacturer", "").strip()
        if not did:
            continue
        # Skip Windows USB driver helper components
        nl = name.lower()
        if any(s in nl for s in WPD_SKIP):
            continue
        # Skip network adapters that leaked into WPD (WAN Miniport etc.)
        if "miniport" in nl or "wan" in nl or "ndis" in nl:
            continue
        result[did] = _dev(did, name, _classify(name, mfr), vendor=mfr)

    # ── Method B: Win32_PnPEntity WHERE service='WpdUsb' ────────────────────
    if not result:
        raw = _ps(
            "Get-WmiObject -Query \"SELECT DeviceID,Name,Manufacturer "
            "FROM Win32_PnPEntity WHERE Service='WpdUsb'\" | "
            "Select-Object DeviceID,Name,Manufacturer | "
            "ConvertTo-Csv -NoTypeInformation"
        )
        for row in _parse_ps_csv(raw):
            did  = row.get("DeviceID", "").strip()
            name = row.get("Name", "").strip() or "Portable Device"
            mfr  = row.get("Manufacturer", "").strip()
            if not did or did in result:
                continue
            nl = name.lower()
            if any(s in nl for s in WPD_SKIP):
                continue
            if "miniport" in nl or "wan" in nl:
                continue
            result[did] = _dev(did, name, _classify(name, mfr), vendor=mfr)

    # ── Method C: Keyword scan — catches phones that report wrong class ───────
    kw_filter = (
        "SELECT DeviceID,Name,Manufacturer FROM Win32_PnPEntity WHERE "
        "Name LIKE '%Android%' OR Name LIKE '%iPhone%' OR "
        "Name LIKE '%iPad%' OR Name LIKE '%Apple Mobile%' OR "
        "Name LIKE '%Galaxy%' OR Name LIKE '%Pixel %' OR "
        "Name LIKE '%OnePlus%' OR Name LIKE '%Xiaomi%' OR "
        "Name LIKE '%Redmi%' OR Name LIKE '%OPPO%' OR "
        "Name LIKE '%Vivo%' OR Name LIKE '%Realme%' OR "
        "Name LIKE '%Huawei%' OR Name LIKE '%Motorola%' OR "
        "Name LIKE '%Nokia%' OR Name LIKE '% MTP%' OR "
        "Name LIKE '%PTP%'"
    )
    raw = _ps(
        f"Get-WmiObject -Query \"{kw_filter}\" | "
        "Select-Object DeviceID,Name,Manufacturer | "
        "ConvertTo-Csv -NoTypeInformation"
    )
    for row in _parse_ps_csv(raw):
        did  = row.get("DeviceID", "").strip()
        name = row.get("Name", "").strip()
        mfr  = row.get("Manufacturer", "").strip()
        if did and did not in result:
            result[did] = _dev(did, name, _classify(name, mfr), vendor=mfr)

    return result


def _win_usb_devices():
    """
    Catches remaining USB devices (USB-C docks, dongles) that aren't
    pen drives or WPD phones. Uses a strict blocklist — anything that
    looks like Windows infrastructure is excluded.
    """
    result = {}

    # Anything matching these substrings is Windows infrastructure, not a user device
    SKIP = (
        # USB infrastructure — never a user device
        "host controller", "root hub", "hub (usb", "usb root hub",
        "generic hub", "usb hub", "standard usb hub", "usb hub device",
        "xhci", "ehci", "uhci", "ohci",
        "miniport", "wan miniport",
        "composite device",
        # Serial / COM ports — shown in Device Manager as ports, not drives
        "serial port", "com port", "usb serial", "usb-serial", "serial converter",
        "usb serial port", "serial adapter", "prolific", "ch340", "cp210",
        "ft232", "ftdi", "cdc acm",
        # HID / input devices
        "hid-compliant", "hid keyboard", "hid mouse", "usb input device",
        "hid device", "keyboard", "mouse", "game controller", "joystick",
        # Connectivity / networking
        "bluetooth", "bt ", "wifi", "wireless", "rndis", "cdc ethernet",
        # Audio
        "audio", "sound", "microphone", "speaker", "headset", "headphone",
        # Virtualisation / system
        "virtual", "vmware", "virtualbox", "hyper-v",
        "teredo", "isatap", "ndis", "filter",
        # Security hardware (smart cards, fingerprint readers — not removable storage)
        "smart card", "smartcard", "fingerprint", "biometric", "yubikey",
        # Printing
        "print", "printer",
        # Touchpad / integrated
        "elan", "synaptics", "touchpad",
        # Intel chipset internals
        "intel(r) management", "intel(r) usb",
        # Webcams/IR sensors
        "ir camera", "infrared",
    )

    raw = _ps(
        "Get-WmiObject -Query \"SELECT DeviceID,Name,Manufacturer "
        "FROM Win32_PnPEntity WHERE PNPClass='USB'\" | "
        "Select-Object DeviceID,Name,Manufacturer | "
        "ConvertTo-Csv -NoTypeInformation"
    )
    for row in _parse_ps_csv(raw):
        did  = row.get("DeviceID", "").strip()
        name = row.get("Name", "").strip()
        mfr  = row.get("Manufacturer", "").strip()
        if not did or not name:
            continue
        nl = name.lower()
        # Skip anything matching infrastructure keywords
        if any(s in nl for s in SKIP):
            continue
        # Also skip Standard USB Hub, USB Composite Device etc
        if nl.startswith("usb ") and any(w in nl for w in ("hub", "composite", "root")):
            continue
        if did not in result:
            result[did] = _dev(did, name, _classify(name, mfr), vendor=mfr)
    return result


# ══ Linux snapshot ════════════════════════════════════════════════════════════

def _linux_usb_devices():
    result = {}
    root = "/sys/bus/usb/devices"
    if not os.path.isdir(root):
        return result

    def _r(path):
        try:
            return open(path).read().strip()
        except Exception:
            return ""

    for dev_name in os.listdir(root):
        dev_path = os.path.join(root, dev_name)
        if not os.path.isfile(os.path.join(dev_path, "idVendor")):
            continue
        vid     = _r(os.path.join(dev_path, "idVendor"))
        pid     = _r(os.path.join(dev_path, "idProduct"))
        vendor  = _r(os.path.join(dev_path, "manufacturer"))
        product = _r(os.path.join(dev_path, "product"))
        serial  = _r(os.path.join(dev_path, "serial"))
        if not vid:
            continue
        if "hub" in product.lower() and not vendor:
            continue
        did  = f"usb:{vid}:{pid}:{dev_name}"
        name = product or f"USB {vid}:{pid}"
        result[did] = _dev(did, name, _classify(name, vendor),
                           vendor=vendor, serial=serial)

    # Removable block devices
    try:
        import json as _json
        out = subprocess.check_output(
            ["lsblk", "-J", "-o",
             "NAME,TRAN,RM,MOUNTPOINT,VENDOR,MODEL,SERIAL"],
            text=True, timeout=5)
        for dev in _json.loads(out).get("blockdevices", []):
            if dev.get("tran") == "usb" and dev.get("rm"):
                mp  = dev.get("mountpoint") or ""
                did = f"blk:{dev['name']}"
                if did not in result:
                    result[did] = _dev(
                        did,
                        (dev.get("model") or dev["name"]).strip(),
                        "storage", drive=mp,
                        vendor=(dev.get("vendor") or "").strip(),
                        serial=(dev.get("serial") or "").strip(),
                    )
    except Exception:
        pass
    return result


# ══ Unified snapshot ══════════════════════════════════════════════════════════

def _snapshot() -> Dict[str, dict]:
    if os.name == "nt":
        devices = {}
        devices.update(_win_removable_drives())
        devices.update(_win_portable_devices())
        devices.update(_win_usb_devices())
        return devices
    return _linux_usb_devices()


# ══ Alert metadata ════════════════════════════════════════════════════════════

_LABELS = {
    "phone":      "📱 Mobile Phone",
    "camera":     "📷 Camera",
    "hub":        "🔌 USB Hub/Dock",
    "storage":    "💾 USB Storage",
    "usb_device": "🔌 USB Device",
}
_SEVERITY = {
    "phone":      "critical",
    "camera":     "high",
    "hub":        "medium",
    "storage":    "high",
    "usb_device": "medium",
}
_THREAT_NOTE = {
    "phone":   (
        "Mobile phone connected. Phones can transfer files via MTP, "
        "sideload APKs, charge-and-exfiltrate data, or stage malicious "
        "payloads. Review immediately."
    ),
    "camera":  "Camera/PTP device connected. USB data transfer is possible.",
    "hub":     "USB hub or dock connected. Monitor all downstream devices.",
    "storage": "Removable storage connected. Monitor for data exfiltration.",
    "usb_device": "Unknown USB device connected.",
}


# ══ Monitor ═══════════════════════════════════════════════════════════════════

class USBMonitor:
    def __init__(self, agent: "AgentCore"):
        self.agent         = agent
        self.running       = False
        self._prev: Dict[str, dict] = {}
        self._prev_drives: Set[str] = set()   # kept for agent_core eject compat

    def run(self):
        self.running = True
        self._prev   = _snapshot()
        self._prev_drives = {d["drive"] for d in self._prev.values() if d.get("drive")}
        logger.info("USBMonitor ready. %d device(s) present.", len(self._prev))

        while self.running:
            try:
                curr     = _snapshot()
                curr_ids = set(curr)
                prev_ids = set(self._prev)

                for did in curr_ids - prev_ids:
                    self._on_insert(curr[did])
                for did in prev_ids - curr_ids:
                    self._on_remove(self._prev[did])

                self._prev        = curr
                self._prev_drives = {d["drive"] for d in curr.values() if d.get("drive")}

            except Exception as e:
                logger.error("USBMonitor error: %s", e)

            time.sleep(3)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _allowed(self, dev):
        drive = dev.get("drive", "")
        return bool(drive and self.agent.is_usb_allowed(drive))

    def _blacklisted(self, dev):
        drive = dev.get("drive", "")
        return bool(drive) and (
            drive.upper().rstrip("\\/") in
            getattr(self.agent, "_blocked_usb_drives", set())
        )

    # ── Insert ────────────────────────────────────────────────────────────────
    def _on_insert(self, dev):
        dtype  = dev.get("device_type", "usb_device")
        name   = dev.get("name",   "Unknown Device")
        vendor = dev.get("vendor", "")
        drive  = dev.get("drive",  "")
        did    = dev.get("device_id", "")

        # Build display string
        display = f"{vendor} {name}".strip() if (
            vendor and vendor.lower() not in name.lower()) else name
        if drive:
            display += f" ({drive})"

        label    = _LABELS.get(dtype, "🔌 USB Device")
        severity = _SEVERITY.get(dtype, "medium")
        note     = _THREAT_NOTE.get(dtype, "USB device connected.")

        logger.info("USB insert [%s]: %s", dtype, display)

        if self._allowed(dev):
            self.agent._log("INFO", f"USB WHITELISTED: {display}")
            return

        if self._blacklisted(dev):
            self.agent.send_alert(
                "usb_insertion_blocked", "critical",
                f"BLACKLISTED Device Inserted: {display}",
                f"This device ({display}) was previously blocked.",
                raw_data={**dev, "status": "blacklisted", "event": "inserted"},
            )
            return

        self.agent.send_alert(
            "usb_insertion", severity,
            f"{label} Connected: {display}",
            note,
            raw_data={**dev, "status": "unknown", "event": "inserted"},
        )

        # Exfiltration watch only for storage with a drive letter
        if drive and dtype == "storage":
            threading.Thread(
                target=self._watch_exfiltration, args=(drive,),
                daemon=True,
                name=f"ExfilWatch_{drive.replace(':','').replace(chr(92),'')}",
            ).start()

    # ── Remove ────────────────────────────────────────────────────────────────
    def _on_remove(self, dev):
        dtype  = dev.get("device_type", "usb_device")
        name   = dev.get("name", "Unknown")
        drive  = dev.get("drive", "")
        label  = _LABELS.get(dtype, "🔌 USB Device")
        display = f"{name} ({drive})" if drive else name
        logger.info("USB remove [%s]: %s", dtype, display)
        if not self._allowed(dev):
            self.agent.send_alert(
                "usb_removal", "low",
                f"{label} Disconnected: {display}",
                f"USB device {display} was disconnected.",
                raw_data={**dev, "event": "removed"},
            )

    # ── Exfiltration watcher ──────────────────────────────────────────────────
    def _watch_exfiltration(self, drive):
        WATCH = 120
        TICK  = 3
        seen: Set[str] = set()
        end = time.time() + WATCH
        try:
            for rt, _, fns in os.walk(drive):
                for fn in fns:
                    seen.add(os.path.join(rt, fn))
        except Exception:
            return
        logger.info("Exfil watch: %s", drive)
        while self.running and time.time() < end:
            time.sleep(TICK)
            if not any(d.get("drive") == drive for d in self._prev.values()):
                break
            try:
                new = []
                for rt, _, fns in os.walk(drive):
                    for fn in fns:
                        fp = os.path.join(rt, fn)
                        if fp not in seen:
                            new.append(fp); seen.add(fp)
                if new:
                    sz = round(sum(
                        os.path.getsize(f) for f in new
                        if os.path.exists(f)) / 1048576, 1)
                    self.agent.send_alert(
                        "usb_exfiltration", "critical",
                        f"USB Exfiltration Detected: {drive}",
                        f"{len(new)} file(s) copied to {drive} ({sz} MB).",
                        raw_data={"drive": drive, "files": new[:10],
                                  "file_count": len(new), "size_mb": sz},
                    )
            except Exception as e:
                logger.debug("Exfil watch error %s: %s", drive, e)
