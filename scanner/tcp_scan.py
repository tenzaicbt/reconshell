#!/usr/bin/env python3
"""
tcp_scan.py
Asyncio TCP connect scanner with optional banner grabbing.
Usage:
  sudo python3 tcp_scan.py 192.168.1.1 -p 1-1024 -c 500 -t 1.0
"""
import argparse
import asyncio
import socket
import tqdm

async def probe_port(semaphore, host, port, timeout, banner):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, limit=2**16), timeout=timeout)
            # connected -> port open
            info = {'port': port, 'status': 'open', 'banner': None}
            if banner:
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=0.3)
                    if data:
                        info['banner'] = data.decode(errors='ignore').strip()
                except Exception:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return info
        except (ConnectionRefusedError, OSError):
            return {'port': port, 'status': 'closed'}
        except asyncio.TimeoutError:
            return {'port': port, 'status': 'filtered'}
        except Exception as e:
            return {'port': port, 'status': f'err:{e}'}

async def scan_host(host, ports, concurrency, timeout, banner, progress=False):
    sem = asyncio.Semaphore(concurrency)
    pbar = tqdm.tqdm(total=len(ports), desc="TCP Scan", disable=not progress)

    async def probe_and_update(port):
        result = await probe_port(sem, host, port, timeout, banner)
        pbar.update(1)
        return result

    tasks = [probe_and_update(p) for p in ports]
    results = await asyncio.gather(*tasks)
    pbar.close()
    return results

def parse_ports(port_str):
    parts = []
    for chunk in port_str.split(','):
        if '-' in chunk:
            a, b = chunk.split('-', 1)
            parts.extend(range(int(a), int(b)+1))
        else:
            parts.append(int(chunk))
    return sorted(set(parts))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("target", help="target IP or hostname")
    p.add_argument("-p", "--ports", default="1-1024", help="ports (e.g. 22,80,443,1000-2000)")
    p.add_argument("-c", "--concurrency", type=int, default=200, help="concurrent tasks")
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="connect timeout (s)")
    p.add_argument("--banner", action='store_true', help="try banner grab")
    args = p.parse_args()

    ports = parse_ports(args.ports)
    try:
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(scan_host(args.target, ports, args.concurrency, args.timeout, args.banner))
    except KeyboardInterrupt:
        print("Interrupted")
        return

    open_ports = [r for r in results if r.get('status') == 'open']
    for r in sorted(results, key=lambda x: x['port']):
        if r.get('status') == 'open':
            line = f"{args.target}:{r['port']}/tcp OPEN"
            if args.banner and r.get('banner'):
                line += f" — {r['banner']}"
            print(line)
    print(f"Scanned {len(ports)} ports. Open: {len(open_ports)}")

if __name__ == '__main__':
    main()