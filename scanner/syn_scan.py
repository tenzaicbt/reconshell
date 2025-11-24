#!/usr/bin/env python3
"""
syn_scan.py
SYN scanner using scapy. Requires root.
Usage:
  sudo python3 syn_scan.py 192.168.1.1 -p 1-1024
"""
import argparse
import socket
import time
from typing import List, Dict, Tuple
from scapy.all import IP, TCP, sr1, RandShort, conf, send

try:
    from .banner import grab_version_tcp  # type: ignore
except ImportError:  # pragma: no cover - direct script execution fallback
    from banner import grab_version_tcp

conf.verb = 0  # scapy quiet

class ProgressBar:
    def __init__(self, total, desc=""):
        self.total = total
        self.desc = desc
        self.current = 0

    def update(self, n=1):
        self.current += n
        percent = int(100 * self.current / self.total)
        bar_length = 40
        filled = int(bar_length * self.current / self.total)
        bar = '█' * filled + '░' * (bar_length - filled)
        print(f"\r{self.desc}: [{bar}] {percent}%", end='', flush=True)

    def close(self):
        print()

def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, 'tcp')
    except Exception:
        return 'unknown'

def detect_os(resp):
    if resp is None or not resp.haslayer(IP):
        return "Unknown"
    ttl = resp[IP].ttl
    window = resp[TCP].window if resp.haslayer(TCP) else 0
    # Simple OS fingerprinting based on TTL and window size
    if ttl == 64:
        if window == 5840:
            return "Linux"
        elif window == 65535:
            return "FreeBSD/macOS"
        else:
            return "Linux (generic)"
    elif ttl == 128:
        return "Windows"
    elif ttl == 255:
        return "Cisco/Network Device"
    else:
        return f"TTL:{ttl}, Window:{window}"

def scan_syn(target: str, ports: List[int], timeout: float = 1.0, progress: bool = False, version_probe: bool = True) -> Tuple[List[Dict[str, object]], str]:
    results: List[Dict[str, object]] = []
    os_info = "Unknown"

    if progress:
        pbar = ProgressBar(total=len(ports), desc="SYN Scan")
    else:
        pbar = None

    for port in ports:
        src_port = RandShort()
        pkt = IP(dst=target)/TCP(sport=src_port, dport=port, flags='S')
        send_ts = time.time()
        resp = sr1(pkt, timeout=timeout)
        if pbar:
            pbar.update(1)

        if resp is None:
            continue

        rtt = None
        if hasattr(resp, 'time'):
            rtt = max(resp.time - send_ts, 0)
        else:
            rtt = max(time.time() - send_ts, 0)

        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags & 0x12 == 0x12:  # SYN/ACK -> open
                if os_info == "Unknown":
                    os_info = detect_os(resp)

                service = get_service_name(port)
                entry: Dict[str, object] = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service,
                }

                if rtt is not None:
                    entry['rtt_ms'] = round(rtt * 1000, 2)

                results.append(entry)

                try:
                    send(IP(dst=target)/TCP(sport=src_port, dport=port, flags='R'), verbose=False)
                except Exception:
                    pass

    if pbar:
        pbar.close()

    if version_probe and results:
        if progress:
            vbar = ProgressBar(total=len(results), desc="Service Fingerprint")
        else:
            vbar = None
        for entry in results:
            port = entry['port']  # type: ignore[index]
            version = grab_version_tcp(target, port, timeout=timeout)
            entry['version'] = version or ''
            if vbar:
                vbar.update(1)
        if vbar:
            vbar.close()

    for entry in results:
        entry.setdefault('version', '')
        entry.setdefault('rtt_ms', None)

    return sorted(results, key=lambda x: x['port']), os_info

def parse_ports(spec):
    res = []
    for part in spec.split(','):
        if '-' in part:
            a,b = part.split('-',1)
            res.extend(range(int(a), int(b)+1))
        else:
            res.append(int(part))
    return sorted(set(res))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-p", "--ports", default="1-1024")
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("--no-version", action='store_true', help="Skip service version detection stage")
    args = p.parse_args()
    ports = parse_ports(args.ports)
    print(f"Starting SYN scan against {args.target} ({len(ports)} ports)")
    start_ts = time.time()
    results, os_info = scan_syn(args.target, ports, timeout=args.timeout, progress=True, version_probe=not args.no_version)
    elapsed = time.time() - start_ts

    if results:
        latencies = [entry['rtt_ms'] for entry in results if entry.get('rtt_ms') is not None]
        if latencies:
            best_latency = min(latencies)
            print(f"Host appears up ({best_latency:.2f} ms best RTT)")
        else:
            print("Host appears up (no RTT calculated)")

        header = f"{'PORT':<10}{'STATE':<10}{'SERVICE':<18}{'VERSION'}"
        print(header)
        print('-' * len(header))
        for entry in results:
            port_str = f"{entry['port']}/tcp"  # type: ignore[index]
            state = str(entry.get('state', 'unknown')).upper()
            service = entry.get('service') or 'unknown'
            version = entry.get('version') or ''
            print(f"{port_str:<10}{state:<10}{service:<18}{version}")
    else:
        print("No open ports identified via SYN scan")

    print(f"\nTotal open: {len(results)}")
    print(f"OS guess: {os_info}")
    print(f"Elapsed: {elapsed:.2f}s")

if __name__ == '__main__':
    main()