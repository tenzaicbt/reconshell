import argparse

def get_parser():
    parser = argparse.ArgumentParser(description="ReconShell - Advanced Port Scanner")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1000", help="Ports (e.g. 22,80,443,1000-2000)")
    parser.add_argument("--common", action='store_true', help="Scan only common ports (21,22,23,25,53,80,110,143,443,993,995,3306,3389)")
    parser.add_argument("--syn", action='store_true', help="Enable SYN scan (requires root)")
    parser.add_argument("-c", "--concurrency", type=int, default=200, help="Concurrent tasks")
    parser.add_argument("-T", "--timeout", type=float, default=1.0, help="Timeout in seconds")
    parser.add_argument("--details", action='store_true', help="Show detailed IP information")
    return parser