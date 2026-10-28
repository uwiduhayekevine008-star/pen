"""Advanced Network Scanner Module"""
import asyncio
import socket
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    state: str
    service: str = ""
    banner: str = ""
    version: str = ""


class NetworkScanner:
    COMMON_PORTS = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 139: 'netbios', 443: 'https', 445: 'smb',
        1433: 'mssql', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
        6379: 'redis', 8080: 'http-proxy', 27017: 'mongodb'
    }
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    
    async def scan_port(self, host: str, port: int) -> Optional[ServiceInfo]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                info = ServiceInfo(
                    port=port, protocol='tcp', state='open',
                    service=self.COMMON_PORTS.get(port, 'unknown')
                )
                try:
                    sock.settimeout(1.0)
                    sock.send(b'\r\n')
                    info.banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:200]
                except:
                    pass
                sock.close()
                return info
        except:
            pass
        return None
    
    async def scan_ports(self, host: str, ports: List[int] = None) -> Dict[int, ServiceInfo]:
        ports = ports or list(self.COMMON_PORTS.keys())
        tasks = [self.scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        return {r.port: r for r in results if r is not None}
