from scanner.utils import expand_cidr

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 cidr_expander.py <CIDR>")
        return
    cidr = sys.argv[1]
    ips = expand_cidr(cidr)
    for ip in ips:
        print(ip)

if __name__ == '__main__':
    main()