import argparse

def get_parser():
    parser = argparse.ArgumentParser(description="ReconShell - Advanced Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports (e.g. 22,80,443,1000-2000)")
    parser.add_argument("--tcp", action='store_true', help="Enable TCP connect scan")
    parser.add_argument("--syn", action='store_true', help="Enable SYN scan (requires root)")
    parser.add_argument("--udp", action='store_true', help="Enable UDP scan")
    parser.add_argument("--banner", action='store_true', help="Attempt banner grabbing")
    parser.add_argument("-c", "--concurrency", type=int, default=200, help="Concurrent tasks")
    parser.add_argument("-T", "--timeout", type=float, default=0.2, help="Timeout in seconds")
    parser.add_argument("--json", action='store_true', help="Output in JSON format")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--progress", action='store_true', help="Show progress bar during scanning")
    parser.add_argument("--details", action='store_true', help="Show detailed IP information")
    return parser