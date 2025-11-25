#!/usr/bin/env python3
"""
reconshell.py
Master launcher for ReconShell - Advanced Port Scanner.
"""
import os
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
import sys
import os
import time
import socket
import sys
import subprocess
import concurrent.futures
import argparse
import os
import contextlib
import gc

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
ENDC = '\033[0m'
BOLD = '\033[1m'

TOOL_VERSION = "v1.0-dev"

INFO_PREFIX = f"{BLUE}[*]{ENDC}"
GOOD_PREFIX = f"{GREEN}[+]{ENDC}"
WARN_PREFIX = f"{YELLOW}[!]{ENDC}"
BAD_PREFIX = f"{RED}[-]{ENDC}"

# Add scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner'))
import logging
# Reduce scapy/logging noise (hide non-fatal warnings)
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
logging.getLogger('scapy').setLevel(logging.ERROR)

from scanner.parser import get_parser
from scanner.utils import parse_ports
from scanner.tcp_scan import scan_host as tcp_scan
from scanner.syn_scan import scan_syn
from scanner.udp_scan import udp_probe
from scanner.banner import grab_version_tcp, grab_version_udp
from scanner.progress import ProgressBar
import asyncio
import requests

class ReconArgumentParser(argparse.ArgumentParser):
    """Custom parser that prints colorful error messages."""

    def error(self, message):  # pragma: no cover - CLI UX hook
        sys.stderr.write(f"\n{RED}Argument Error:{ENDC} {message}\n\n")
        self.print_help(sys.stderr)
        sys.stderr.write('\n')
        raise SystemExit(2)


BANNER_LOGO = r"""
     _____                          _____ _           _ _
    |  __ \                        / ____ | |        | | |
    | |__) |___  ___ ___  _ __    | (___  | |__   ___| | |
    |  _  // _ \/ __/ _ \| '_  \   \ ___ \| '_ \ / _ \ | |
    | | \ \  __/ (_| (_) | | | |    ____) | | | |  __/ | |
    |_|  \_\___|\___\___/|_| |_|____|____/|_| |_|\___|_|_|
"""


def print_banner() -> None:
    print(f"{RED}{BANNER_LOGO}{ENDC}")
    print(f"       ={CYAN}[ ReconShell {TOOL_VERSION} - Advanced Port Scanner ]{ENDC}")
    print(f"+ -- --=[ {CYAN}Multi-protocol reconnaissance engine (TCP | UDP | SYN){ENDC} ]")
    print(f"+ -- --=[ {CYAN}Service and version fingerprinting with async workflows{ENDC} ]")
    print(f"+ -- --=[ {CYAN}Use --help for options and usage information{ENDC} ]")
    print(f"+ -- --=[ {YELLOW}WARNING: Authorized testing only. Unauthorized scanning is illegal.{ENDC} ]\n")

def get_target_info(target):
    try:
        ip = socket.gethostbyname(target)
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        ip = target
        hostname = 'N/A'
    return {'ip': ip, 'hostname': hostname}

def get_host_status(ip):
    try:
        result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'time=' in line or 'time<' in line:
                    latency = line.split('time')[1].split('=')[1].split(' ')[0] if '=' in line.split('time')[1] else line.split('time')[1].split('<')[1].split(' ')[0]
                    return 'up', latency + ' ms'
            return 'up', 'N/A'
        else:
            return 'down', 'N/A'
    except:
        return 'unknown', 'N/A'

def get_service_name(port, protocol):
    try:
        return socket.getservbyport(port, protocol)
    except:
        return 'unknown'

def get_ip_details(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'Country': data.get('country', 'N/A'),
                    'Region': data.get('regionName', 'N/A'),
                    'City': data.get('city', 'N/A'),
                    'ISP': data.get('isp', 'N/A'),
                    'Organization': data.get('org', 'N/A'),
                    'Hostname': data.get('hostname', 'N/A')
                }
    except Exception as e:
        pass
    return {}

def run_tcp_scan(args):
    ports = parse_ports(args.ports)
    try:
        results = asyncio.run(tcp_scan(args.target, ports, args.concurrency, args.timeout, False, progress=True))
    except KeyboardInterrupt:
        print("Interrupted")
        return []
    return results

def run_syn_scan(args):
    ports = parse_ports(args.ports)
    # Run the SYN scan while suppressing noisy scapy stderr/stdout output
    syn_results = []
    os_info = "Unknown"
    had_perm_error = False
    had_other_error = False
    err_msg = None
    had_timeout_error = False
    with open(os.devnull, 'w') as devnull:
        with contextlib.redirect_stderr(devnull), contextlib.redirect_stdout(devnull):
            try:
                syn_results, os_info = scan_syn(
                    args.target,
                    ports,
                    timeout=args.timeout,
                    progress=True,
                    version_probe=False,
                    max_duration=20.0,
                )
            except (PermissionError, OSError) as e:
                had_perm_error = True
                err_msg = str(e)
            except TimeoutError as e:
                had_timeout_error = True
                err_msg = str(e)
            except Exception as e:
                had_other_error = True
                err_msg = str(e)
            finally:
                # force cleanup while stderr still redirected to avoid finalizer tracebacks
                try:
                    gc.collect()
                except Exception:
                    pass

    if had_perm_error:
        detail = err_msg or "SYN scan requires raw socket privileges (sudo on Linux, Administrator with Npcap on Windows)."
        print(f"\n{WARN_PREFIX} {detail} Skipping SYN scan.")
        return [], "Unknown"
    if had_timeout_error:
        detail = err_msg or "SYN scan exceeded the maximum runtime and was aborted."
        print(f"\n{WARN_PREFIX} {detail} Skipping SYN scan.")
        return [], "Unknown"
    if had_other_error:
        detail = err_msg or "SYN scan failed for an unknown reason."
        print(f"\n{WARN_PREFIX} {detail} Skipping SYN scan.")
        return [], "Unknown"
    results = []
    for entry in syn_results:
        port = entry.get('port')
        if port is None:
            continue
        record = {
            'port': port,
            'status': entry.get('state', 'open'),
            'protocol': 'tcp',
            'method': 'syn'
        }
        if entry.get('service'):
            record['service'] = entry['service']
        if entry.get('version'):
            record['version'] = entry['version']
        results.append(record)
    return results, os_info

def run_udp_scan(args):
    ports = parse_ports(args.ports)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {executor.submit(udp_probe, args.target, port, args.timeout): port for port in ports}
        pbar = ProgressBar(total=len(ports), desc="UDP", width=10, protocol='udp')
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                status, banner = future.result()
                result = {'port': port, 'status': status, 'protocol': 'udp', 'banner': banner}
                results.append(result)
            except Exception as e:
                result = {'port': port, 'status': f'err:{e}', 'protocol': 'udp', 'banner': None}
                results.append(result)
            pbar.update(1)
        pbar.close()
    return results

def add_versions(results, args):
    for r in results:
        if r.get('status') == 'open':
            if r.get('protocol') == 'tcp':
                r['version'] = grab_version_tcp(args.target, r['port'], args.timeout)
            elif r.get('protocol') == 'udp':
                r['version'] = grab_version_udp(args.target, r['port'], args.timeout)

def output_results(results, args, os_info="Unknown", ip_details={}, target_info={}, host_status='unknown', latency='N/A', scan_time=0):
    # Minimal output: show only open ports
    open_ports = [r for r in results if r.get('status') == 'open']

    print(f"{INFO_PREFIX} Open Ports for {args.target}")
    if not open_ports:
        print(f"{WARN_PREFIX} No open ports found")
        print(f"{INFO_PREFIX} Scan Duration: {scan_time:.2f}s")
        return

    # Header
    header = f"{'PORT':<12}{'PROTO':<8}{'SERVICE':<18}{'VERSION'}"
    print(f"    {header}")
    print(f"    {'-' * len(header)}")

    for r in sorted(open_ports, key=lambda x: x['port']):
        port = r['port']
        proto = r.get('protocol', 'tcp')
        service = r.get('service') or get_service_name(port, proto)
        version = r.get('version', '') or ''
        port_display = f"{port}/{proto}"
        print(f"    {port_display:<12}{proto:<8}{service:<18}{version}")

    print(f"\n{GOOD_PREFIX} Total Open Ports: {len(open_ports)}")
    print(f"{INFO_PREFIX} Scan Duration: {scan_time:.2f}s")

def main():
    print_banner()
    parser = get_parser(parser_cls=ReconArgumentParser)
    args = parser.parse_args()

    # Handle --common option
    if args.common:
        args.ports = "21,22,23,25,53,80,110,143,443,993,995,3306,3389"

    start_time = time.time()
    target_info = get_target_info(args.target)
    host_status, latency = get_host_status(target_info['ip'])

    all_results = []
    os_info = "Unknown"
    ip_details = get_ip_details(args.target) if args.details else {}

    # Run scans sequentially
    tcp_results = run_tcp_scan(args)
    udp_results = run_udp_scan(args)
    if args.syn:
        syn_results, os_info = run_syn_scan(args)
    else:
        syn_results = []

    all_results = tcp_results + syn_results + udp_results

    # Deduplicate results by (port, protocol)
    merged_results = {}
    for r in all_results:
        key = (r['port'], r.get('protocol', 'tcp'))
        if key not in merged_results:
            merged_results[key] = r.copy()
        else:
            existing = merged_results[key]
            # Prefer open status
            if r.get('status') == 'open' and existing.get('status') != 'open':
                existing['status'] = 'open'
            # Merge version if available
            if r.get('version') and not existing.get('version'):
                existing['version'] = r['version']
            # Merge service if available
            if r.get('service') and not existing.get('service'):
                existing['service'] = r['service']

    all_results = list(merged_results.values())

    add_versions(all_results, args)
    scan_time = time.time() - start_time
    output_results(all_results, args, os_info, ip_details, target_info, host_status, latency, scan_time)

if __name__ == '__main__':
    main()