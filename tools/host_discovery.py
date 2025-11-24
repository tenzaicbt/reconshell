import subprocess
import ipaddress

def ping_host(ip, timeout=1):
    """
    Ping a host and return True if up.
    """
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), ip],
                                capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def discover_hosts(cidr):
    """
    Ping sweep a CIDR network.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    up_hosts = []
    for ip in network.hosts():
        if ping_host(str(ip)):
            up_hosts.append(str(ip))
    return up_hosts

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 host_discovery.py <CIDR>")
        return
    cidr = sys.argv[1]
    hosts = discover_hosts(cidr)
    for host in hosts:
        print(host)

if __name__ == '__main__':
    main()