"""Network Scanner Module with Advanced Service Detection"""
import asyncio
import socket
import struct
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    cpe: str = ""
    os_info: str = ""
    confidence: int = 0


class NetworkScanner:
    """High-performance network scanner with service detection"""
    
    COMMON_PORTS = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 111: 'rpc', 135: 'msrpc', 139: 'netbios',
        143: 'imap', 443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s',
        1433: 'mssql', 1521: 'oracle', 2049: 'nfs', 3306: 'mysql',
        3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
        8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb',
        5984: 'couchdb', 9200: 'elasticsearch', 11211: 'memcached',
        27017: 'mongodb', 6379: 'redis', 11211: 'memcached'
    }
    
    def __init__(self, timeout: float = 2.0, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.executor = None
    
    async def scan_port(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Scan single port with service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                service_info = ServiceInfo(
                    port=port,
                    protocol='tcp',
                    state='open',
                    service=self.COMMON_PORTS.get(port, 'unknown')
                )
                
                # Grab banner
                try:
                    sock.settimeout(1.0)
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        service_info.banner = banner[:200]
                        service_info = self._parse_banner(service_info, banner)
                except:
                    pass
                
                sock.close()
                return service_info
        except:
            pass
        return None
    
    def _parse_banner(self, service: ServiceInfo, banner: str) -> ServiceInfo:
        """Parse banner for service info"""
        lower = banner.lower()
        
        if 'ssh' in lower:
            parts = banner.split('-')
            if len(parts) >= 2:
                service.service = 'ssh'
                service.version = parts[1].split()[0] if len(parts) > 1 else ''
        elif 'ftp' in lower:
            service.service = 'ftp'
            if 'version' in lower:
                service.version = banner.split('version')[-1].strip().split()[0]
        elif 'mysql' in lower:
            service.service = 'mysql'
            if 'mysql' in lower:
                service.product = 'MySQL'
        elif 'postgresql' in lower:
            service.service = 'postgresql'
            service.product = 'PostgreSQL'
        elif 'redis' in lower:
            service.service = 'redis'
            service.product = 'Redis'
        elif 'mongodb' in lower:
            service.service = 'mongodb'
            service.product = 'MongoDB'
        elif 'apache' in lower or 'nginx' in lower:
            service.service = 'http'
            parts = banner.split('/')
            if len(parts) >= 2:
                service.version = parts[1].split()[0]
        
        return service
    
    async def scan_ports(self, host: str, ports: List[int] = None) -> Dict[int, ServiceInfo]:
        """Scan multiple ports concurrently"""
        ports = ports or list(self.COMMON_PORTS.keys())
        tasks = [self.scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        return {r.port: r for r in results if r is not None}
    
    async def scan_range(self, host: str, start: int, end: int) -> Dict[int, ServiceInfo]:
        """Scan port range"""
        ports = list(range(start, end + 1))
        return await self.scan_ports(host, ports)
    
    async def detect_os(self, host: str) -> Dict:
        """Basic OS detection via TCP fingerprinting"""
        result = {'detected': False, 'os': 'unknown', 'confidence': 0}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((host, 80))
            
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            
            if ttl <= 64:
                result = {'detected': True, 'os': 'Linux/Unix', 'confidence': 80}
            elif ttl <= 128:
                result = {'detected': True, 'os': 'Windows', 'confidence': 80}
            elif ttl <= 255:
                result = {'detected': True, 'os': 'Cisco/Network Device', 'confidence': 70}
            
            sock.close()
        except:
            pass
        
        return result
    
    async def get_service_version(self, host: str, port: int) -> Dict:
        """Get detailed service version information"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((host, port))
            
            # Send probe
            if port == 80:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 443:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 22:
                sock.send(b'\r\n')
            elif port == 21:
                sock.send(b'USER anonymous\r\n')
            
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return {
                'port': port,
                'banner': response[:200],
                'detected': True
            }
        except:
            return {'port': port, 'detected': False}


async def quick_scan(host: str) -> Dict[int, ServiceInfo]:
    """Quick scan of common ports"""
    scanner = NetworkScanner(timeout=1.0)
    return await scanner.scan_ports(host)
