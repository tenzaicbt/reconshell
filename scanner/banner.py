import socket
import asyncio
import ssl
import re
try:
    from pysnmp.hlapi import *
    HAS_PYSNMP = True
except ImportError:
    HAS_PYSNMP = False

def parse_smtp_banner(banner):
    """
    Parse SMTP banner to extract service name, version, and year.
    """
    if not banner:
        return "SMTP"
    
    patterns = [
        (r'ESMTP\s+Postfix\s+([\d.]+)', 'Postfix'),
        (r'ESMTP\s+Postfix\s*\(([^)]+)\)', 'Postfix'),
        (r'ESMTP\s+Sendmail\s+([\d.]+)', 'Sendmail'), 
        (r'Microsoft\s+ESMTP\s+MAIL\s+Service.*?Version:\s*([\d.]+)', 'Exchange'),
        (r'ESMTP\s+Exim\s+([\d.]+)', 'Exim'),
        (r'ESMTP\s+([A-Za-z]+)\s+([\d.]+)', None),
    ]
    
    for pattern, service_name in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            if service_name:
                version = match.group(1)
            else:
                service_name = match.group(1)
                version = match.group(2)
            
            year_match = re.search(r'\b(20\d{2})\b', banner)
            year = year_match.group(1) if year_match else ""
            
            if year and year in version:
                return f"{service_name} {version}"
            else:
                return f"{service_name} {version}" + (f" ({year})" if year else "")
    
    version_match = re.search(r'([\d]+\.[\d]+(?:\.[\d]+)*)', banner)
    if version_match:
        year_match = re.search(r'\b(20\d{2})\b', banner)
        year = year_match.group(1) if year_match else ""
        return f"SMTP {version_match.group(1)}" + (f" ({year})" if year else "")
    
    return "SMTP"

def grab_version_tcp(host, port, timeout=1.0):
    """
    Service version detection for TCP ports.
    """
    try:
        if port in [80, 443]:
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
                    server_header = line.split(':', 1)[1].strip()
                    return parse_http_server(server_header)
            return 'HTTP'
        elif port == 22:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_ssh_banner(banner)
        elif port == 21:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_ftp_banner(banner)
        elif port == 23:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_telnet_banner(banner)
        elif port == 25:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_smtp_banner(banner)
        elif port == 53:
            return 'DNS'
        elif port == 110:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_pop3_banner(banner)
        elif port == 143:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_imap_banner(banner)
        elif port == 445:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe\x00\x00\x00\x00\x00\x6d\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x31\x2e\x30\x33\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x33\x2e\x30\x00')
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_smb_banner(banner)
        elif port == 993:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=timeout)
            sock = context.wrap_socket(sock, server_hostname=host)
            data = sock.recv(1024)
            sock.close()
            banner = data.decode(errors='ignore').strip()
            return parse_imap_banner(banner)
        elif port == 995:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=timeout)
            sock = context.wrap_socket(sock, server_hostname=host)
            data = sock.recv(1024)
            sock.close()
            banner = data.decode(errors='ignore').strip()
            return parse_pop3_banner(banner)
        elif port == 3306:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_mysql_banner(banner)
        elif port == 5432:

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_postgres_banner(banner)
        elif port == 3389:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_rdp_banner(banner)
        elif port == 5900:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            return parse_vnc_banner(banner)
        else:

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b'\r\n')
            data = s.recv(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()

            try:
                service_name = socket.getservbyport(port, 'tcp')
            except:
                service_name = 'unknown'
            return parse_generic_banner(banner, service_name)
    except:
        return None

def parse_http_server(server_header):
    """
    Parse HTTP Server header for version info.
    """
    if not server_header:
        return "HTTP"
    

    if server_header.lower() == 'gws':
        return "gws (Google Web Server)"
    

    patterns = [
        r'Apache/([\d.]+)',
        r'nginx/([\d.]+)',
        r'IIS/([\d.]+)',
        r'lighttpd/([\d.]+)',
        r'LiteSpeed/([\d.]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, server_header, re.IGNORECASE)
        if match:
            service = pattern.split('/')[0]
            version = match.group(1)
            year_match = re.search(r'\b(20\d{2})\b', server_header)
            year = year_match.group(1) if year_match else ""
            return f"{service} {version}" + (f" ({year})" if year else "")
    
    return server_header

def parse_ftp_banner(banner):
    """
    Parse FTP banner.
    """
    if not banner:
        return "FTP"
    
    if "FileZilla" in banner:
        match = re.search(r'FileZilla\s+Server\s+([\d.]+)', banner, re.IGNORECASE)
        if match:
            return f"FileZilla {match.group(1)}"
    elif "vsftpd" in banner:
        match = re.search(r'vsftpd\s+([\d.]+)', banner, re.IGNORECASE)
        if match:
            return f"vsftpd {match.group(1)}"
    elif "Pure-FTPd" in banner:
        match = re.search(r'Pure-FTPd\s+([\d.]+)', banner, re.IGNORECASE)
        if match:
            return f"Pure-FTPd {match.group(1)}"
    
    return banner

def parse_pop3_banner(banner):
    """
    Parse POP3 banner.
    """
    if not banner:
        return "POP3"
    
    version_match = re.search(r'([\d]+\.[\d]+(?:\.[\d]+)*)', banner)
    if version_match:
        return f"POP3 {version_match.group(1)}"
    
    return "POP3"

def parse_generic_banner(banner, service_name):
    """
    Generic banner parser that tries to extract version info from any banner.
    """
    if not banner:
        return service_name
    
    version_patterns = [
        r'([A-Za-z]+)[/-]([\d]+\.[\d]+(?:\.[\d]+)*)',  # Service/version or Service-version
        r'([A-Za-z]+)\s+([\d]+\.[\d]+(?:\.[\d]+)*)',  # Service version
        r'([\d]+\.[\d]+(?:\.[\d]+)*)',  # Just version number
        r'v([\d]+\.[\d]+(?:\.[\d]+)*)',  # v1.2.3
        r'version\s*([\d]+\.[\d]+(?:\.[\d]+)*)',  # version x.y.z
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            if len(match.groups()) == 1:
                version = match.group(1)
                service_match = re.search(r'([A-Za-z]+)(?=[/-]|\s+[\d])', banner)
                if service_match and service_match.group(1).lower() != service_name.lower():
                    detected_service = service_match.group(1)
                    if detected_service.lower() not in ['the', 'and', 'for', 'with', 'from', 'server', 'service']:
                        service_name = detected_service
            else:
                detected_service = match.group(1)
                version = match.group(2)
                if detected_service.lower() != service_name.lower():
                    service_name = detected_service
            
            year_match = re.search(r'\b(20\d{2})\b', banner)
            year = year_match.group(1) if year_match else ""
            return f"{service_name} {version}" + (f" ({year})" if year else "")
    
    return service_name

def parse_telnet_banner(banner):
    """Parse Telnet banner."""
    return parse_generic_banner(banner, "Telnet")

def parse_mysql_banner(banner):
    """Parse MySQL banner."""
    if not banner:
        return "MySQL"
    
    match = re.search(r'([\d]+\.[\d]+(?:\.[\d]+)*)', banner)
    if match:
        return f"MySQL {match.group(1)}"
    return "MySQL"

def parse_postgres_banner(banner):
    """Parse PostgreSQL banner."""
    if not banner:
        return "PostgreSQL"
    
    match = re.search(r'PostgreSQL\s+([\d]+\.[\d]+(?:\.[\d]+)*)', banner, re.IGNORECASE)
    if match:
        return f"PostgreSQL {match.group(1)}"
    return "PostgreSQL"

def parse_rdp_banner(banner):
    """Parse RDP banner."""
    return parse_generic_banner(banner, "RDP")

def parse_vnc_banner(banner):
    """Parse VNC banner."""
    if not banner:
        return "VNC"
    
    match = re.search(r'RFB\s+([\d]+\.[\d]+)', banner)
    if match:
        return f"VNC {match.group(1)}"
    return "VNC"

def parse_smb_banner(banner):
    """Parse SMB banner."""
    return parse_generic_banner(banner, "SMB")

def parse_ftp_banner(banner):
    """
    Parse FTP banner.
    """
    if not banner:
        return "FTP"
    
    patterns = [
        (r'FileZilla\s+Server\s+([\d.]+)', 'FileZilla'),
        (r'vsftpd\s+([\d.]+)', 'vsftpd'),
        (r'Pure-FTPd\s+([\d.]+)', 'Pure-FTPd'),
        (r'ProFTPD\s+([\d.]+)', 'ProFTPD'),
        (r'Microsoft\s+FTP\s+Service', 'Microsoft FTP'),
    ]
    
    for pattern, service in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            version = match.group(1) if match.groups() else ""
            year_match = re.search(r'\b(20\d{2})\b', banner)
            year = year_match.group(1) if year_match else ""
            return f"{service} {version}".strip() + (f" ({year})" if year else "")
    
    return parse_generic_banner(banner, "FTP")

def parse_ssh_banner(banner):
    """Parse SSH banner."""
    if not banner:
        return "SSH"
    
    if 'SSH' in banner:
        parts = banner.split()
        if len(parts) >= 2:
            return f"{parts[0]} {parts[1]}"
    
    return parse_generic_banner(banner, "SSH")

def parse_pop3_banner(banner):
    """
    Parse POP3 banner.
    """
    if not banner:
        return "POP3"
    
    if "Dovecot" in banner:
        match = re.search(r'Dovecot\s+([\w.]+)', banner, re.IGNORECASE)
        if match:
            return f"Dovecot {match.group(1)}"
    
    return parse_generic_banner(banner, "POP3")

def parse_imap_banner(banner):
    """
    Parse IMAP banner.
    """
    if not banner:
        return "IMAP"
    
    if "Dovecot" in banner:
        match = re.search(r'Dovecot\s+([\w.]+)', banner, re.IGNORECASE)
        if match:
            return f"Dovecot {match.group(1)}"
    
    return parse_generic_banner(banner, "IMAP")

async def grab_version_async(host, port, timeout=1.0):
    """
    Async version detection.
    """
    try:
        if port in [80, 443]:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f'http{"s" if port == 443 else ""}://{host}'
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    server = resp.headers.get('Server', 'HTTP')
                    return server
        else:

            return grab_version_tcp(host, port, timeout)
    except:
        return None

def grab_version_udp(host, port, timeout=2.0):
    """
    Service version for UDP ports.
    """
    try:
        if port == 53:
            import dns.query
            import dns.message
            query = dns.message.make_query('version.bind', dns.rdns.TXT)
            response = dns.query.udp(query, host, timeout=timeout)
            for answer in response.answer:
                if hasattr(answer, 'strings'):
                    version_info = ' '.join(s.decode() for s in answer.strings)
                    return parse_generic_banner(version_info, 'DNS')
            return 'DNS'
        elif port == 123:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', (host, port))
            data, _ = s.recvfrom(1024)
            s.close()
            if len(data) >= 4:
                version = (data[0] >> 3) & 0x07
                return f'NTP v{version}'
            return 'NTP'
        elif port == 161:
            if HAS_PYSNMP:
                community = 'public'
                oid = '1.3.6.1.2.1.1.1.0' 
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
                        sysdescr = str(varBind[1])
                        return parse_generic_banner(sysdescr, 'SNMP')
            return 'SNMP'
        elif port == 137:

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)

            s.sendto(b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01', (host, port))
            data, _ = s.recvfrom(1024)
            s.close()
            return parse_generic_banner(data.decode(errors='ignore').strip(), 'NetBIOS')
        else:

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b'\x00', (host, port))
            data, _ = s.recvfrom(1024)
            s.close()
            banner = data.decode(errors='ignore').strip()
            try:
                service_name = socket.getservbyport(port, 'udp')
            except:
                service_name = 'unknown'
            return parse_generic_banner(banner, service_name)
    except:
        return None