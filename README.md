# ReconShell - Advanced Port Scanner
```
   _____                          _____ _           _ _
  |  __ \                        / ____ | |        | | |
  | |__) |___  ___ ___  _ __    | (___  | |__   ___| | |
  |  _  // _ \/ __/ _ \| '_  \   \ ___ \| '_ \ / _ \ | |
  | | \ \  __/ (_| (_) | | | |    ____) | | | |  __/ | |
  |_|  \_\___|\___\___/|_| |_|____|____/|_| |_|\___|_|_|

       =[ ReconShell - Advanced Port Scanner ]
```
       
+ -- --=[ Advanced port scanning tool for penetration testing ]
+ -- --=[ Supports TCP, UDP, SYN scans with service detection ]
+ -- --=[ Use --help for options and usage information ]
+ -- --=[ WARNING: Use only for authorized testing. Unauthorized scanning is illegal. ]

A practical, cross-platform advanced port scanner (like a tiny `nmap`) you can run and extend. Includes three working implementations: TCP Connect, SYN, and UDP scanners that can run simultaneously for faster results.

## Features

- **TCP Connect scanner** (cross-platform, doesn't need root; reliable)
- **SYN scanner** (fast, stealthier, requires root and `scapy`)
- **UDP scanner** (best-effort — UDP is noisy and ambiguous)
- **Parallel scanning** - Run multiple scan types simultaneously for faster results
- **Advanced service version detection** - Parses banners to extract detailed version information including software name, version numbers, and release years for all common protocols (SMTP, HTTP, FTP, SSH, Telnet, MySQL, PostgreSQL, RDP, VNC, SMB, SNMP, NTP, DNS, and more)
- **Real-time custom progress bars** - Visual progress indication with filled bar style
- **Concurrent execution** - High-performance scanning with configurable concurrency
- **Advanced target information** - Detailed IP, hostname, status, and latency display
- **Automatic server detection** - Identifies known servers (e.g., Google Web Server) and provides contextual details
- **CIDR target expansion**
- **Host discovery**
- **Timing profiles**
- **Legal disclaimer** - Promotes responsible and authorized use

## Installation

### Prerequisites
- Python 3.6+
- For SYN scanning: root/admin privileges and `scapy` library

### Setup Steps

1. Clone or download the repository.

2. Create a virtual environment (recommended):
   ```bash
   # Linux/macOS
   python3 -m venv venv
   source venv/bin/activate

   # Windows
   python -m venv venv
   venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Make scripts executable (Linux/macOS):
   ```bash
   chmod +x reconshell.py
   chmod +x scanner/*.py
   chmod +x setup.sh
   chmod +x start.sh
   ```

   Or run the setup script:
   ```bash
   ./setup.sh
   ```

### Windows Specific Notes
- Use PowerShell for running scripts
- For SYN scanning, run PowerShell as Administrator
- Python executable might be `python` instead of `python3`

## Usage

ReconShell automatically scans both TCP and UDP ports simultaneously with real-time progress bars. You can optionally enable SYN scanning for faster TCP results (requires root).

### Basic Scan (TCP + UDP by default, ports 1-1000)
```bash
python3 reconshell.py 192.168.1.10
```

### Quick Common Ports Scan
```bash
python3 reconshell.py www.google.com --common
```

### Custom Ports
```bash
python3 reconshell.py 192.168.1.10 -p 22,80,443
```

### SYN Scan (requires root, adds to TCP/UDP)
```bash
sudo python3 reconshell.py 192.168.1.10 --syn
```

### With Details
```bash
python3 reconshell.py 192.168.1.10 --details
```

## Options

- `target`: Target IP or hostname (positional argument)
- `-p, --ports`: Ports (e.g., 22,80,443,1000-2000) (default: 1-1000)
- `--common`: Scan only common ports (21,22,23,25,53,80,110,143,443,993,995,3306,3389)
- `--syn`: Enable SYN scan (requires root; adds to default TCP/UDP)
- `-c, --concurrency`: Concurrent tasks (default: 200)
- `-T, --timeout`: Timeout in seconds (default: 0.2)
- `--details`: Show detailed IP information

## Security Notes

- SYN scanning and raw packet sending require root.
- Aggressive scans can trigger intrusion detection or block your IP.
- Only scan hosts/networks you own or have explicit permission to test.
- The tool includes a legal disclaimer to promote authorized use only.

## Example Output

```
Target Information:
  IP Address: 142.250.4.106
  Hostname: sa-in-f105.1e100.net
  Host Status: Unknown
  Latency: N/A

Scan Results for www.google.com:
Port     Protocol   State        Service         Version Info
----------------------------------------------------------------------
80       tcp        OPEN         http            gws (Google Web Server)
443      tcp        OPEN         https           gws (Google Web Server)

Total Open Ports: 2
Scan Time: 7.12 seconds

Detected Servers:
  Google Web Server (GWS): Google's proprietary web server software used for their services like Google Search, Gmail, etc. It does not expose version details publicly for security reasons.
```

## Roadmap

- Port ranges and host ranges (CIDR scanning)
- Parallelism & rate-limiting
- OS fingerprinting
- Output formats (JSON, CSV)
- Raw packet capture
- Timing templates
- Host up/down detection