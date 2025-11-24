#!/usr/bin/env python3
"""
reconshell.py
Master launcher for ReconShell - Advanced Port Scanner.
"""
import json
import sys
import os
import time
import socket
import subprocess

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
    with tqdm.tqdm(total=len(ports), desc="UDP Scan", disable=not args.progress) as pbar:
        for port in ports:
            status, banner = udp_probe(args.target, port, timeout=args.timeout)
            result = {'port': port, 'status': status, 'protocol': 'udp', 'banner': banner}
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

    if args.json:
        data = {
            'target_info': target_info,
            'host_status': {'status': host_status, 'latency': latency},
            'results': results,
            'os': os_info,
            'ip_details': ip_details,
            'scan_time': scan_time
        }
        output = json.dumps(data, indent=2)
    else:
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

    # If no scan type specified, default to TCP and UDP
    if not (args.tcp or args.syn or args.udp):
        args.tcp = True
        args.udp = True

    start_time = time.time()
    target_info = get_target_info(args.target)
    host_status, latency = get_host_status(target_info['ip'])

    all_results = []
    os_info = "Unknown"
    ip_details = get_ip_details(args.target) if args.details else {}

    if args.tcp:
        all_results.extend(run_tcp_scan(args))

    if args.syn:
        syn_results, os_info = run_syn_scan(args)
        all_results.extend(syn_results)

    if args.udp:
        all_results.extend(run_udp_scan(args))

    add_banners(all_results, args)
    scan_time = time.time() - start_time
    output_results(all_results, args, os_info, ip_details, target_info, host_status, latency, scan_time)

if __name__ == '__main__':
    main()