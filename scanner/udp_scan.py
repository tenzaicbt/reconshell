#!/usr/bin/env python3
"""
udp_scan.py
Basic UDP probe: send empty UDP packet and wait for ICMP port unreachable.
Usage:
  python3 udp_scan.py 192.168.1.1 -p 53,123,161 -t 2.0
"""
import argparse
import socket
import select

def get_payload(port):
    if port == 53:  # DNS
        # Simple DNS query
        return b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01'
    elif port == 123:  # NTP
        # NTP version 3 client request
        return b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    elif port == 161:  # SNMP
        # SNMP get request for sysDescr
        return b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
    else:
        return b'\x00'

def udp_probe(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        payload = get_payload(port)
        s.sendto(payload, (host, port))
        # try to read something (some services reply)
        data, addr = s.recvfrom(2048)
        return 'open', data.decode(errors='ignore').strip()
    except socket.timeout:
        # no response — could be open|filtered
        return 'no-response', None
    except ConnectionRefusedError:
        # ICMP port unreachable => closed
        return 'closed', None
    except Exception as e:
        return f'err:{e}', None
    finally:
        s.close()

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
    p.add_argument("-p", "--ports", default="53,123,161")
    p.add_argument("-t", "--timeout", type=float, default=2.0)
    args = p.parse_args()
    ports = parse_ports(args.ports)
    for port in ports:
        status, banner = udp_probe(args.target, port, timeout=args.timeout)
        line = f"{args.target}:{port}/udp {status}"
        if banner:
            line += f" — {banner}"
        print(line)

if __name__ == '__main__':
    main()