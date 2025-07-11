# WPS-Hunter: OneShot WiFi Security Tool

Welcome to **WPS-Hunter**, a comprehensive WiFi security auditing tool. This project features advanced attacks such as **PMKID**, **WPS Pixie Dust**, **Evil Twin**, and **Default Credentials** in a modern Python 3.8+ framework.

> **Disclaimer:**  
> This tool is for educational and authorized security testing purposes only. Unauthorized use is illegal.

## Features

- PMKID Attack (with GPU acceleration)
- WPS Pixie Dust Attacks (2025 algorithms)
- Evil Twin Access Point Attacks
- Default Credentials Attacks
- Advanced Logging & Session Management
- Python 3.8+ Compatibility

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Kali Linux & Ubuntu](#kali-linux--ubuntu)
  - [Termux (Android)](#termux-android)
  - [Windows](#windows)
- [Downloading WPS-Hunter](#downloading-wps-hunter)
- [Usage](#usage)
  - [PMKID Attack](#pmkid-attack)
  - [Cracking PMKID with Hashcat](#cracking-pmkid-with-hashcat)
  - [WPS Pixie Dust Attack](#wps-pixie-dust-attack)
  - [Evil Twin Attack](#evil-twin-attack)
  - [Default Credentials Attack](#default-credentials-attack)
  - [List All Options](#list-all-options)
- [Monitor Mode](#monitor-mode)
- [Troubleshooting](#troubleshooting)
- [Summary Table](#summary-table)
- [Legal Notice](#legal-notice)

## Prerequisites

- Python 3.8 or newer
- System privileges (root/administrator access)
- Wireless adapter that supports monitor mode and packet injection

## Installation

### Kali Linux & Ubuntu

```bash
sudo apt update
sudo apt install python3 python3-pip git build-essential
sudo apt install hashcat hcxtools hostapd dnsmasq iptables
pip3 install requests
```

### Termux (Android)

```bash
pkg update
pkg install python git clang
pip install requests
```
> **Note:** Wireless attacks requiring monitor mode or packet injection are not fully supported in Termux due to hardware/driver limitations.

### Windows

1. **Install Python:** Download and install Python 3.8+ from the official website.
2. **Install Git:** Download and install Git for Windows.
3. **Install Hashcat:** Download and install Hashcat from the official site.
4. **Install dependencies:**
   ```powershell
   pip install requests
   ```
> **Note:** Most wireless attacks require Linux utilities and compatible hardware. Full functionality is best achieved in a Linux environment.

## Downloading WPS-Hunter

Clone this repository:

```bash
git clone https://github.com/PeterPan9696/WPS-Hunter.git
cd WPS-Hunter
```

Or copy `oneshot.py` into your working directory.

## Usage

Make the script executable and run it:

```bash
chmod +x oneshot.py
sudo python3 oneshot.py --help
```
> **Use `sudo`** for root privileges, required for most attacks.

### PMKID Attack

```bash
sudo python3 oneshot.py --pmkid --interface wlan0
```
- Captures PMKID handshakes for WPA/WPA2 networks.

### Cracking PMKID with Hashcat

```bash
hashcat -m 22000  
```

### WPS Pixie Dust Attack

```bash
sudo python3 oneshot.py --wps --interface wlan0 --target 
```

### Evil Twin Attack

```bash
sudo python3 oneshot.py --eviltwin --interface wlan0 --essid "" --bssid  --channel 
```

### Default Credentials Attack

```bash
sudo python3 oneshot.py --default-creds --interface wlan0
```

### List All Options

```bash
sudo python3 oneshot.py --help
```

## Monitor Mode

Enable monitor mode if not handled by the script:

```bash
sudo ip link set wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ip link set wlan0 up
```

## Troubleshooting

- If you see errors about missing tools (`hcxdumptool`, `hcxpcapngtool`, etc.), install them with:
  ```bash
  sudo apt install hcxtools
  ```
- For GPU acceleration, ensure your drivers and CUDA are correctly installed.
- Logs are saved to `oneshot_ultimate.log` in the working directory.

## Summary Table

| Platform      | Python    | Dependencies (apt/pkg)                      | Extra Steps                |
|---------------|-----------|---------------------------------------------|----------------------------|
| Kali/Ubuntu   | `sudo apt install python3 python3-pip` | `sudo apt install hashcat hcxtools hostapd dnsmasq iptables` | `pip3 install requests`    |
| Termux        | `pkg install python`                  | `pkg install git clang`                        | `pip install requests`     |
| Windows       | Download installer                    | Use pip in CMD/PowerShell                      | Install Hashcat manually   |

## Legal Notice

**Use this tool only on networks you own or have explicit permission to test. Unauthorized use is illegal and strictly prohibited.**

**Happy auditing!**  
If you have suggestions or want to contribute, feel free to open an issue or pull request.

[1] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/51016415/2ce60b91-d096-46dc-a00a-affd65ffe39d/oneshot.py
