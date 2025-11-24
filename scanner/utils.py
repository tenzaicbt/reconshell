def parse_ports(port_str):
    """
    Parse port specification like '22,80,443,1000-2000' into a sorted list of ints.
    """
    parts = []
    for chunk in port_str.split(','):
        chunk = chunk.strip()
        if '-' in chunk:
            a, b = chunk.split('-', 1)
            parts.extend(range(int(a), int(b) + 1))
        else:
            parts.append(int(chunk))
    return sorted(set(parts))

def expand_cidr(cidr):
    """
    Expand CIDR notation to list of IPs.
    Requires ipaddress module.
    """
    import ipaddress
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]