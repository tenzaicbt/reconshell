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
    with open(os.devnull, 'w') as devnull:
        with contextlib.redirect_stderr(devnull), contextlib.redirect_stdout(devnull):
            try:
                syn_results, os_info = scan_syn(args.target, ports, timeout=args.timeout, progress=True, version_probe=False)
            except (PermissionError, OSError) as e:
                had_perm_error = True
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
        print(f"\n{YELLOW}WARNING:{ENDC} SYN scan requires elevated privileges or a packet capture driver (e.g. Npcap) on this platform. Skipping SYN scan.")
        return [], "Unknown"
    if had_other_error:
        print(f"\n{YELLOW}WARNING:{ENDC} SYN scan failed: {err_msg}. Skipping SYN scan.")
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
    def color_state(state):
        if state == 'open':
            return f"{GREEN}{state.upper()}{ENDC}"
        elif state == 'closed':
            return f"{RED}{state.upper()}{ENDC}"
        elif state == 'no-response':
            return f"{YELLOW}{state.upper()}{ENDC}"
        else:
            return f"{BLUE}{state.upper()}{ENDC}"

    # Filter to show only open and closed ports, and known services
    filtered_results = [r for r in results if r['status'] in ['open', 'closed']]
    filtered_results = [r for r in filtered_results if get_service_name(r['port'], r.get('protocol', 'tcp')) != 'unknown']
    
    # Advanced Target Info
    output = f"{CYAN}Target Information:{ENDC}\n"
    output += f"  {CYAN}IP Address:{ENDC} {target_info.get('ip', 'N/A')}\n"
    output += f"  {CYAN}Hostname:{ENDC} {target_info.get('hostname', 'N/A')}\n"
    output += f"  {CYAN}Host Status:{ENDC} {host_status.title()}\n"
    output += f"  {CYAN}Latency:{ENDC} {latency}\n\n"
    
    output += f"{CYAN}Scan Results for {args.target}:{ENDC}\n"
    output += f"{'Port':<8} {'Protocol':<10} {'State':<12} {'Service':<15} {'Version Info'}\n"
    output += "-" * 70 + "\n"
    for r in sorted(filtered_results, key=lambda x: x['port']):
        service = get_service_name(r['port'], r.get('protocol', 'tcp'))
        state_colored = color_state(r['status'])
        version = r.get('version', '') if r.get('version') else ''
        output += f"{r['port']:<8} {r.get('protocol', 'tcp'):<10} {state_colored:<12} {service:<15} {version}\n"
    open_count = len([r for r in filtered_results if r.get('status') == 'open'])
    output += f"\n{CYAN}Total Open Ports:{ENDC} {open_count}\n"
    output += f"{CYAN}Scan Time:{ENDC} {scan_time:.2f} seconds\n"
    output += f"{CYAN}OS Guess:{ENDC} {os_info}\n"
    if ip_details:
        output += f"\n{CYAN}IP Details:{ENDC}\n"
        for k, v in ip_details.items():
            output += f"  {k}: {v}\n"

    # Check for known servers
    detected_servers = set()
    for r in results:
        version = (r.get('version') or '').lower()
        if 'gws' in version:
            detected_servers.add('Google Web Server (GWS)')

    if detected_servers:
        output += f"\n{CYAN}Detected Servers:{ENDC}\n"
        for server in detected_servers:
            if 'Google Web Server' in server:
                output += f"  {server}: Google's proprietary web server software used for their services like Google Search, Gmail, etc. It does not expose version details publicly for security reasons.\n"

    print(output)

def main():
    old_banner = r"""
   _____                          _____ _           _ _
  |  __ \                        / ____ | |        | | |
  | |__) |___  ___ ___  _ __    | (___  | |__   ___| | |
  |  _  // _ \/ __/ _ \| '_  \   \ ___ \| '_ \ / _ \ | |
  | | \ \  __/ (_| (_) | | | |    ____) | | | |  __/ | |
  |_|  \_\___|\___\___/|_| |_|____|____/|_| |_|\___|_|_|

                
"""
    lines = [line.rstrip() for line in old_banner.split('\n') if line.strip()]
    max_len = max(len(line) for line in lines)
    centered_banner = '\n'.join(line.center(max_len) for line in lines)
    print(RED + centered_banner + ENDC)
    
    banner = r"""
       =[ ReconShell - Advanced Port Scanner ]
+ -- --=[ Advanced port scanning tool for penetration testing ]
+ -- --=[ Supports TCP, UDP, SYN scans with service detection ]
+ -- --=[ Use --help for options and usage information ]
+ -- --=[ WARNING: Use only for authorized testing. Unauthorized scanning is illegal. ]
"""
    print(banner)
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