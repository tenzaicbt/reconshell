
"""
syn_scan.py
SYN scanner using scapy. Requires root.
Usage:
  sudo python3 syn_scan.py 192.168.1.1 -p 1-1024
"""
import argparse
import errno
import os
import random
import socket
import time
from typing import Dict, List, Optional, Tuple
from scapy.all import IP, TCP, sr, conf, send
from scapy.error import Scapy_Exception
from .progress import ProgressBar

try:
    from .banner import grab_version_tcp
except ImportError: 
    from banner import grab_version_tcp

conf.verb = 0 

if os.name == 'nt' and hasattr(conf, 'use_pcap'):
    conf.use_pcap = True


def _is_windows_admin() -> bool:
    if os.name != 'nt':
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _check_raw_socket_access() -> Optional[Exception]:
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except OSError as exc:
        if os.name == 'nt':
            winerror = getattr(exc, 'winerror', None)
            if winerror == 10013 or exc.errno in (errno.EPERM, errno.EACCES):
                return PermissionError(
                    "Raw socket access denied. Install Npcap (enable WinPcap compatibility) and run as Administrator."
                )
            return OSError(f"Unable to open raw socket on Windows: {exc}")
        if exc.errno in (errno.EPERM, errno.EACCES):
            return PermissionError("Raw socket access denied. Ensure CAP_NET_RAW is granted (try sudo or setcap).")
        return OSError(f"Unable to open raw socket: {exc}")
    else:
        test_socket.close()
        return None


def check_syn_requirements() -> Optional[Exception]:
    """Return an exception describing why SYN scan cannot run, or None when ok."""

    if os.name == 'nt':
        if not _is_windows_admin():
            return PermissionError(
                "SYN scan requires administrative privileges on Windows. Run PowerShell as Administrator."
            )
        return _check_raw_socket_access()

    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        return PermissionError("SYN scan requires root privileges (try running with sudo).")

    return _check_raw_socket_access()


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

def scan_syn(
    target: str,
    ports: List[int],
    timeout: float = 1.0,
    progress: bool = False,
    version_probe: bool = True,
    max_duration: Optional[float] = None,
) -> Tuple[List[Dict[str, object]], str]:
    results: List[Dict[str, object]] = []
    os_info = "Unknown"

    prereq_error = check_syn_requirements()
    if prereq_error:
        raise prereq_error

    start_time = time.time()
    if progress:
        pbar = ProgressBar(total=len(ports), desc="SYN", width=10, protocol='syn')
    else:
        pbar = None

    batch_size = 100
    seen_open_ports = set()

    for idx in range(0, len(ports), batch_size):
        if max_duration is not None and (time.time() - start_time) > max_duration:
            if pbar:
                pbar.close()
            raise TimeoutError(f"SYN scan exceeded max duration ({max_duration:.1f}s)")

        batch = ports[idx:idx + batch_size]
        send_ts = time.time()
        packets = []
        for port in batch:
            sport = random.randint(1024, 65535)
            packets.append(IP(dst=target) / TCP(sport=sport, dport=port, flags='S'))

        try:
            answered, _ = sr(packets, timeout=timeout, verbose=False)
        except Scapy_Exception as exc: 
            message = str(exc).strip() or "Scapy failed during SYN scan."
            lowered = message.lower()
            if any(token in lowered for token in ("permission", "npcap", "winpcap", "raw socket")):
                raise PermissionError(message) from exc
            raise

        for sent_pkt, resp in answered:
            port = int(sent_pkt[TCP].dport)
            if not resp.haslayer(TCP):
                continue

            flags = resp.getlayer(TCP).flags
            if flags & 0x12 != 0x12:  # no SYN/ACK
                continue

            if os_info == "Unknown":
                os_info = detect_os(resp)

            rtt = None
            if hasattr(resp, 'time'):
                rtt = max(resp.time - send_ts, 0)
            else:
                rtt = max(time.time() - send_ts, 0)

            service = get_service_name(port)
            if port in seen_open_ports:
                continue
            seen_open_ports.add(port)
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
                send(IP(dst=target)/TCP(sport=sent_pkt[TCP].sport, dport=port, flags='R'), verbose=False)
            except Exception:
                pass

        if pbar:
            pbar.update(len(batch))

    if pbar:
        pbar.close()

    if version_probe and results:
        if progress:
            vbar = ProgressBar(total=len(results), desc="Fingerprint", width=10, protocol='tcp')
        else:
            vbar = None
        for entry in results:
            if max_duration is not None and (time.time() - start_time) > max_duration:
                if vbar:
                    vbar.close()
                raise TimeoutError(f"SYN scan exceeded max duration ({max_duration:.1f}s)")
            port = entry['port'] 
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
    p.add_argument("--max-duration", type=float, default=None, help="Abort scan after N seconds")
    args = p.parse_args()
    ports = parse_ports(args.ports)
    print(f"Starting SYN scan against {args.target} ({len(ports)} ports)")
    start_ts = time.time()
    try:
        results, os_info = scan_syn(
            args.target,
            ports,
            timeout=args.timeout,
            progress=True,
            version_probe=not args.no_version,
            max_duration=args.max_duration,
        )
    except PermissionError as exc:
        print(f"Error: {exc}")
        return
    except OSError as exc:
        print(f"Error: {exc}")
        return
    except TimeoutError as exc:
        print(f"Error: {exc}")
        return

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
            port_str = f"{entry['port']}/tcp" 
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