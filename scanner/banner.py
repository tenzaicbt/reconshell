import socket
import asyncio
import ssl
try:
    from pysnmp.hlapi import *
    HAS_PYSNMP = True
except ImportError:
    HAS_PYSNMP = False

def grab_version_tcp(host, port, timeout=1.0):
    """
    Service version detection for TCP ports.
    """
    try:
        if port in [80, 443]:
            # HTTP/HTTPS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=timeout)
            if port == 443:
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.send(b'GET / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
            response = sock.recv(4096).decode(errors='ignore')
            sock.close()
            for line in response.split('\n'):
                if line.lower().startswith('server:'):
                    return line.split(':', 1)[1].strip()
            return 'HTTP'
        elif port == 22:
            # SSH
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            if 'SSH' in banner:
                return banner.split()[0] + ' ' + banner.split()[1]
            return banner
        elif port == 21:
            # FTP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return banner
        elif port == 25:
            # SMTP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return banner
        elif port == 53:
            # DNS - basic
            return 'DNS'
        elif port == 110:
            # POP3
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return banner
        elif port == 143:
            # IMAP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return banner
        elif port == 993:
            # IMAPS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=timeout)
            sock = context.wrap_socket(sock, server_hostname=host)
            data = sock.recv(1024)
            sock.close()
            banner = data.decode(errors='ignore').strip()
            return banner
        elif port == 995:
            # POP3S
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=timeout)
            sock = context.wrap_socket(sock, server_hostname=host)
            data = sock.recv(1024)
            sock.close()
            banner = data.decode(errors='ignore').strip()
            return banner
        else:
            # Generic banner grab
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b'\r\n')
            data = s.recv(1024)
            s.close()
            return data.decode(errors='ignore').strip()
    except:
        return None

async def grab_version_async(host, port, timeout=1.0):
    """
    Async version detection.
    """
    try:
        if port in [80, 443]:
            # HTTP/HTTPS
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f'http{"s" if port == 443 else ""}://{host}'
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    server = resp.headers.get('Server', 'HTTP')
                    return server
        else:
            # Fallback to sync for now
            return grab_version_tcp(host, port, timeout)
    except:
        return None

def grab_version_udp(host, port, timeout=2.0):
    """
    Service version for UDP ports.
    """
    try:
        if port == 53:
            # DNS
            import dns.query
            import dns.message
            query = dns.message.make_query('version.bind', dns.rdns.TXT)
            response = dns.query.udp(query, host, timeout=timeout)
            for answer in response.answer:
                if hasattr(answer, 'strings'):
                    return ' '.join(s.decode() for s in answer.strings)
            return 'DNS'
        elif port == 123:
            # NTP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            # NTP version 3 request
            s.sendto(b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', (host, port))
            data, _ = s.recvfrom(1024)
            s.close()
            if len(data) >= 4:
                version = (data[0] >> 3) & 0x07
                return f'NTP v{version}'
            return 'NTP'
        elif port == 161:
            # SNMP
            if HAS_PYSNMP:
                # Basic SNMP get
                community = 'public'
                oid = '1.3.6.1.2.1.1.1.0'  # sysDescr
                iterator = getCmd(SnmpEngine(),
                                  CommunityData(community),
                                  UdpTransportTarget((host, port), timeout=int(timeout*100), retries=0),
                                  ContextData(),
                                  ObjectType(ObjectIdentity(oid)))
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                if errorIndication:
                    return 'SNMP'
                elif errorStatus:
                    return 'SNMP'
                else:
                    for varBind in varBinds:
                        return str(varBind[1])
            return 'SNMP'
        else:
            # Generic UDP probe
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b'\x00', (host, port))
            data, _ = s.recvfrom(1024)
            s.close()
            return data.decode(errors='ignore').strip()
    except:
        return None