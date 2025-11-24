

                  ____                  ____  _          _ _
                 |  _ \ ___  __ _  ___ / ___|| |__   ___| | |
                 | |_) / _ \/ _` |/ _ \\\___ \| '_ \ / _ \ | |
                 |  _ <  __/ (_| |  __/ ___) | | | |  __/ | |
                 |_| \_\___|\__, |\___||____/|_| |_|\___|_|_|
                                 |___/

                        ReconShell - Advanced Port Scanner

Quick Start (print header + run scanner)

```
# On WSL / Linux
./start.sh -t 64.233.170.101 -p 1-100 --progress

# On Windows PowerShell
.\\\start.ps1 -t 64.233.170.101 -p 1-100 --progress
```

## Running with Scripts

The `start.sh` (Linux/macOS) and `start.ps1` (Windows) scripts provide a convenient way to run the scanner with a header display. They pass all arguments directly to `reconshell.py`.

Example:
```bash
# Linux - Combined TCP and UDP scan
./start.sh --banner --progress -t example.com -p 80,443,53

# Windows PowerShell - SYN scan
.\start.ps1 --syn -t example.com -p 1-1000 -T 0.5
```

# ReconShell - Advanced Port Scanner

A practical, cross-platform advanced port scanner (like a tiny `nmap`) you can run and extend. Includes three working implementations: TCP Connect, SYN, and UDP scanners that can run simultaneously for faster results.

## Features

- **TCP Connect scanner** (cross-platform, doesn't need root; reliable)
- **SYN scanner** (fast, stealthier, requires root and `scapy`)
- **UDP scanner** (best-effort — UDP is noisy and ambiguous)
- **Parallel scanning** - Run multiple scan types simultaneously for faster results
- Optional banner grabbing
- CIDR target expansion
- Host discovery
- Timing profiles

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

ReconShell automatically scans both TCP and UDP ports simultaneously. You can optionally enable SYN scanning for faster TCP results (requires root).

### Basic Scan (TCP + UDP by default)
```bash
python3 reconshell.py -t 192.168.1.10 -p 1-1000 --progress
```

### SYN Scan (requires root, adds to TCP/UDP)
```bash
sudo python3 reconshell.py --syn -t 192.168.1.10 -p 1-1000 -T 0.5
```

### With Banner Grabbing
```bash
python3 reconshell.py --banner -t 192.168.1.10 -p 1-1000 --progress
```

## Options

- `-t, --target`: Target IP or hostname
- `-p, --ports`: Ports (e.g., 22,80,443,1000-2000)
- `--syn`: Enable SYN scan (requires root; adds to default TCP/UDP)
- `--banner`: Attempt banner grabbing
- `-c, --concurrency`: Concurrent tasks (default: 200)
- `-T, --timeout`: Timeout in seconds (default: 0.2)
- `-o, --output`: Output file
- `--progress`: Show progress bar during scanning
- `--details`: Show detailed IP information

## Security Notes

- SYN scanning and raw packet sending require root.
- Aggressive scans can trigger intrusion detection or block your IP.
- Only scan hosts/networks you own or have explicit permission to test.

## Roadmap

- Port ranges and host ranges (CIDR scanning)
- Parallelism & rate-limiting
- Banner grabbing / service probes
- Version detection
- OS fingerprinting
- Output formats (JSON, CSV)
- Raw packet capture
- Timing templates
- Host up/down detection