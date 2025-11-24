#!/usr/bin/env python3
"""
syn_scan.py
SYN scanner using scapy. Requires root.
Usage:
  sudo python3 syn_scan.py 192.168.1.1 -p 1-1024
"""
import argparse
from scapy.all import IP, TCP, sr1, RandShort, conf
import tqdm

conf.verb = 0  # scapy quiet

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

def scan_syn(target, ports, timeout=1, progress=False):
    open_ports = []
    os_info = "Unknown"
    with tqdm.tqdm(total=len(ports), desc="SYN Scan", disable=not progress) as pbar:
        for p in ports:
            pkt = IP(dst=target)/TCP(sport=RandShort(), dport=p, flags='S')
            resp = sr1(pkt, timeout=timeout)
            if resp is None:
                # no response => filtered or host down
                pbar.update(1)
                continue
            if resp.haslayer(TCP):
                flags = resp.getlayer(TCP).flags
                # 0x12 is SYN+ACK
                if flags & 0x12 == 0x12:
                    open_ports.append(p)
                    if os_info == "Unknown":
                        os_info = detect_os(resp)
                    # send RST to close the half-open connection politely
                    rst = IP(dst=target)/TCP(sport=p, dport=resp.sport, flags='R')
                    # we don't wait for reply
                    try:
                        from scapy.all import send
                        send(rst, verbose=False)
                    except Exception:
                        pass
                # RST (0x14) => closed
            pbar.update(1)
    return sorted(open_ports), os_info

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
    args = p.parse_args()
    ports = parse_ports(args.ports)
    print(f"Scanning {args.target} {len(ports)} ports with SYN scan (root required)")
    open_ports, os_info = scan_syn(args.target, ports, timeout=args.timeout)
    for port in open_ports:
        print(f"{args.target}:{port}/tcp OPEN (SYN)")
    print(f"Found {len(open_ports)} open ports")
    print(f"OS: {os_info}")

if __name__ == '__main__':
    main()