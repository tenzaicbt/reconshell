

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

# ReconShell - Advanced Port Scanner

A practical, Linux-friendly advanced port scanner (like a tiny `nmap`) you can run and extend. Includes three working implementations: TCP Connect, SYN, and UDP scanners.

## Features

- **TCP Connect scanner** (cross-platform, doesn't need root; reliable)
- **SYN scanner** (fast, stealthier, requires root and `scapy`)
- **UDP scanner** (best-effort — UDP is noisy and ambiguous)
- Optional banner grabbing
- JSON output support
- CIDR target expansion
- Host discovery
- Timing profiles

## Installation

1. Install Python packages:
   ```bash
   sudo apt update
   sudo apt install python3-pip
   pip3 install scapy
   ```

2. Make scripts executable:
   ```bash
   chmod +x reconshell.py
   chmod +x scanner/*.py
   ```

Or run the setup script:
```bash
./setup.sh
```

## Usage

### TCP Connect Scan (no root needed)
```bash
python3 reconshell.py --tcp -t 192.168.1.10 -p 1-1000 --banner -c 300
```

### SYN Scan (requires root)
```bash
sudo python3 reconshell.py --syn -t 192.168.1.10 -p 1-1000 -T 0.5
```

### UDP Scan
```bash
python3 reconshell.py --udp -t 192.168.1.10 -p 53,161,123
```

### Combined Scan with JSON Output
```bash
python3 reconshell.py --tcp --syn --udp -t 192.168.1.10 -p 1-1000 --json -o results.json
```

## Options

- `-t, --target`: Target IP or hostname
- `-p, --ports`: Ports (e.g., 22,80,443,1000-2000)
- `--tcp`: Enable TCP connect scan
- `--syn`: Enable SYN scan (requires root)
- `--udp`: Enable UDP scan
- `--banner`: Attempt banner grabbing
- `-c, --concurrency`: Concurrent tasks (default: 200)
- `-T, --timeout`: Timeout in seconds (default: 1.0)
- `--json`: Output in JSON format
- `-o, --output`: Output file

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