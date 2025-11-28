# ReconShell - Advanced Port Scanner
```
   ## ReconShell - Advanced Port Scanner

       _____                          _____ _           _ _
      |  __ \                        / ____ | |        | | |
      | |__) |___  ___ ___  _ __    | (___  | |__   ___| | |
      |  _  // _ \/ __/ _ \| '_  \   \ ___ \| '_ \ / _ \ | |
      | | \ \  __/ (_| (_) | | | |    ____) | | | |  __/ | |
      |_|  \_\___|\___\___/|_| |_|____|____/|_| |_|\___|_|_|

ReconShell is a compact, extensible port-scanning toolkit inspired by tools like nmap.
It provides multiple scanning modes (TCP connect, SYN, UDP), service/version detection
and a compact CLI UI with msfconsole-style visual cues.

   Highlights

   - Multi-protocol scanning: TCP connect, SYN (raw), UDP
   - Service/version detection for many common protocols
   - Compact progress bars and msf-like colorized CLI output
   - Configurable timeouts, concurrency, and a global SYN scan budget
   - Cross-platform awareness (Windows Admin + Npcap guidance, WSL support)

   Requirements

   - Python 3.6+
   - `scapy` (for SYN scanning)

   Install

   ```bash
   # Create and activate a virtualenv (recommended)
   python3 -m venv venv
   source venv/bin/activate

   # Install dependencies
   pip install -r requirements.txt
   ```

   Linux Dependencies

   On Linux distributions, you may need to install system packages for scapy to work properly:

   - Ubuntu/Debian: `sudo apt update && sudo apt install libpcap-dev python3-dev`
   - CentOS/RHEL: `sudo yum install libpcap-devel python3-devel` or `sudo dnf install libpcap-devel python3-devel`
   - Arch: `sudo pacman -S libpcap`

   After installing system dependencies, install Python packages as above.

   Quick start

   ```bash
   # Default TCP+UDP scan, ports 1-1000
   python3 reconshell.py 192.168.1.10

   # Common ports only
   python3 reconshell.py www.google.com --common

   # SYN scan (requires root/Administrator)
   sudo python3 reconshell.py 192.168.1.10 --syn

   # Narrow ports (fast)
   python3 reconshell.py 10.0.0.1 -p 22,80,443 --syn

   # Use WSL (example)
   wsl bash -lc "cd /mnt/c/path/to/reconshell && sudo python3 reconshell.py 10.0.0.1 --syn"
   ```

   New/Important Flags

   - `-p, --ports` : Port list (e.g., `22,80,443,1000-2000`). Default: `1-1000`.
   - `--common` : Show common ports (open + closed) with known services.
   - `--syn` : Run SYN (raw) scan in addition to TCP/UDP (requires elevated privileges and packet-capture driver on Windows).
   - `-T, --timeout` : Per-probe timeout in seconds (default: `1.0`).
   - `--max-duration` : Abort SYN scan after N seconds (prevents long runs; default: none).
   - `-c, --concurrency` : Number of concurrent tasks for the TCP connect scanner (default: 200).
   - `--details` : Fetch IP intelligence details (uses `ip-api.com`).

   Output modes

   - Default: Minimal output — shows only open ports and a concise summary.
   - `--common`: Lists both open and closed common ports (filters unknown services).
   - `--syn`: Detailed SYN-style report that includes OS guess, per-port RTT (if available), method (syn/connect), service and version. By default the SYN detailed view filters out ports with unknown service names; you can adjust behavior in code.

   What's New (recent updates)

   - SYN scan improvements
      - Preflight checks for raw-socket/driver permissions (root on Linux, Administrator + Npcap on Windows).
      - Batched Scapy sends to improve speed and reliability.
      - Optional global `--max-duration` to abort long SYN runs.

   - UI and output
      - msfconsole-style banner and colorized prefixes.
      - Default open-only output; `--common` and `--syn` provide richer views.

   - Usability
      - Quieted Scapy logging and clearer permission error messages.
      - Faster default behavior for interactive use; tune with `-T` and `-p`.

   Troubleshooting and platform notes

   - Windows
      - For SYN scans, run PowerShell as Administrator and install Npcap (enable WinPcap compatibility).
      - If you see a permission error, confirm Administrator rights and Npcap installation.

   - WSL/Linux
      - Ensure system dependencies are installed (see Linux Dependencies above).
      - Run `sudo` inside WSL for raw socket access. Some WSL versions may limit raw socket capability — test and update WSL if needed.
      - If scapy fails to import or send packets, check that libpcap is installed and accessible.

   - General
      - If Python 3 is not available, install it (e.g., `sudo apt install python3 python3-pip` on Ubuntu).
      - For SYN scans, ensure you have root/admin privileges.

   - Performance
      - To avoid very long runs, scan a smaller port range or reduce `-T` timeout during discovery. Example: `-p 1-500 -T 0.2`.

   Example workflows

   - Quick discovery of likely services:
      ```bash
      python3 reconshell.py 10.0.27.78 -p 22,80,443
      ```

   - Full SYN-assisted scan (fast, requires privileges):
      ```bash
      sudo python3 reconshell.py 10.0.27.78 --syn -p 1-1000 --max-duration 30
      ```

   Contributing

   PRs welcome. When contributing, keep changes focused, add tests where appropriate, and update the README for any user-facing changes.

   License

   Use this tool only on systems you own or are authorized to test. The repository does not grant permission to scan third-party networks.
