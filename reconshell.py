#!/usr/bin/env python3
"""
reconshell.py
Master launcher for ReconShell - Advanced Port Scanner.
"""
import sys
import os
import time
import socket
import subprocess
import concurrent.futures

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
ENDC = '\033[0m'

# Add scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner'))

from scanner.parser import get_parser
from scanner.utils import parse_ports
from scanner.tcp_scan import scan_host as tcp_scan
from scanner.syn_scan import scan_syn
from scanner.udp_scan import udp_probe
from scanner.banner import grab_banner_tcp, grab_banner_udp
import asyncio
import tqdm
import requests

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
        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'time=' in line:
                    latency = line.split('time=')[1].split(' ')[0]
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
        results = asyncio.run(tcp_scan(args.target, ports, args.concurrency, args.timeout, args.banner, progress=args.progress))
    except KeyboardInterrupt:
        print("Interrupted")
        return []
    return results

def run_syn_scan(args):
    ports = parse_ports(args.ports)
    open_ports, os_info = scan_syn(args.target, ports, timeout=args.timeout, progress=args.progress)
    results = [{'port': p, 'status': 'open', 'protocol': 'tcp', 'method': 'syn'} for p in open_ports]
    return results, os_info

def run_udp_scan(args):
    ports = parse_ports(args.ports)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {executor.submit(udp_probe, args.target, port, args.timeout): port for port in ports}
        with tqdm.tqdm(total=len(ports), desc="UDP Scan", disable=not args.progress) as pbar:
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
    return results

def add_banners(results, args):
    if not args.banner:
        return
    for r in results:
        if r.get('status') == 'open':
            if r.get('protocol') == 'tcp':
                r['banner'] = grab_banner_tcp(args.target, r['port'], args.timeout)
            elif r.get('protocol') == 'udp':
                r['banner'] = grab_banner_udp(args.target, r['port'], args.timeout)

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
    output = f"{CYAN}Target Info:{ENDC} IP: {target_info.get('ip', 'N/A')}, Hostname: {target_info.get('hostname', 'N/A')}\n"
    output += f"{CYAN}Host Status:{ENDC} {host_status.title()}, Latency: {latency}\n\n"
    output += f"{CYAN}Scan Results for {args.target}:{ENDC}\n"
    output += f"{'Port':<8} {'Protocol':<10} {'State':<12} {'Service':<15} {'Banner'}\n"
    output += "-" * 70 + "\n"
    for r in sorted(filtered_results, key=lambda x: x['port']):
        service = get_service_name(r['port'], r.get('protocol', 'tcp'))
        state_colored = color_state(r['status'])
        banner = r.get('banner', '') if r.get('banner') else ''
        output += f"{r['port']:<8} {r.get('protocol', 'tcp'):<10} {state_colored:<12} {service:<15} {banner}\n"
    open_count = len([r for r in filtered_results if r.get('status') == 'open'])
    output += f"\n{CYAN}Total Open Ports:{ENDC} {open_count}\n"
    output += f"{CYAN}Scan Time:{ENDC} {scan_time:.2f} seconds\n"
    output += f"{CYAN}OS Guess:{ENDC} {os_info}\n"
    if ip_details:
        output += f"\n{CYAN}IP Details:{ENDC}\n"
        for k, v in ip_details.items():
            output += f"  {k}: {v}\n"

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        print(output)

def main():
    banner = r"""
____                  ____  _          _ _
                 |  _ \ ___  __ _  ___ / ___|| |__   ___| | |
                 | |_) / _ \/ _` |/ _ \\___ \| '_ \ / _ \ | |
                 |  _ <  __/ (_| |  __/ ___) | | | |  __/ | |
                 |_| \_\___|\__, |\___||____/|_| |_|\___|_|_|
                                 |___/

                        ReconShell - Advanced Port Scanner
"""
    lines = [line.rstrip() for line in banner.split('\n') if line.strip()]
    max_len = max(len(line) for line in lines)
    centered_banner = '\n'.join(line.center(max_len) for line in lines)
    print(centered_banner)
    parser = get_parser()
    args = parser.parse_args()

    start_time = time.time()
    target_info = get_target_info(args.target)
    host_status, latency = get_host_status(target_info['ip'])

    all_results = []
    os_info = "Unknown"
    ip_details = get_ip_details(args.target) if args.details else {}

    # Run scans in parallel
    tcp_results = []
    syn_results = []
    udp_results = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {}
        futures[executor.submit(run_tcp_scan, args)] = 'tcp'
        futures[executor.submit(run_udp_scan, args)] = 'udp'
        if args.syn:
            futures[executor.submit(run_syn_scan, args)] = 'syn'

        for future in concurrent.futures.as_completed(futures):
            scan_type = futures[future]
            if scan_type == 'tcp':
                tcp_results = future.result()
            elif scan_type == 'syn':
                syn_results, os_info = future.result()
            elif scan_type == 'udp':
                udp_results = future.result()

    all_results = tcp_results + syn_results + udp_results

    add_banners(all_results, args)
    scan_time = time.time() - start_time
    output_results(all_results, args, os_info, ip_details, target_info, host_status, latency, scan_time)

if __name__ == '__main__':
    main()