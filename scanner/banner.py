import socket
import asyncio

def grab_banner_tcp(host, port, timeout=1.0):
    """
    Simple banner grab for TCP ports.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b'\r\n')
        data = s.recv(1024)
        s.close()
        return data.decode(errors='ignore').strip()
    except:
        return None

async def grab_banner_async(host, port, timeout=1.0):
    """
    Async banner grab.
    """
    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(b'\r\n')
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=0.8)
        writer.close()
        await writer.wait_closed()
        return data.decode(errors='ignore').strip()
    except:
        return None

def grab_banner_udp(host, port, timeout=2.0):
    """
    For UDP, send empty packet and see if response.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b'\x00', (host, port))
        data, _ = s.recvfrom(1024)
        s.close()
        return data.decode(errors='ignore').strip()
    except:
        return None