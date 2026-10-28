"""Service-Specific Security Checks"""
import asyncio
import socket
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ServiceVuln:
    service: str
    port: int
    vuln_type: str
    severity: str
    cvss: float
    description: str
    evidence: str
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class SSHChecker:
    """SSH security checker"""
    
    @staticmethod
    async def check(host: str, port: int = 22, timeout: int = 5) -> List[ServiceVuln]:
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            
            banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            if 'SSH-1.' in banner_str:
                vulns.append(ServiceVuln(
                    service='SSH', port=port,
                    vuln_type='Weak Protocol',
                    severity='HIGH', cvss=8.0,
                    description='SSHv1 is insecure',
                    evidence=banner_str,
                    remediation='Disable SSHv1, use SSHv2 only'
                ))
            
            if 'OpenSSH' in banner_str:
                try:
                    version = float(banner_str.split('OpenSSH_')[1].split()[0])
                    if version < 7.6:
                        vulns.append(ServiceVuln(
                            service='SSH', port=port,
                            vuln_type='Outdated SSH',
                            severity='MEDIUM', cvss=6.0,
                            description=f'OpenSSH {version} is outdated',
                            evidence=banner_str,
                            remediation='Upgrade OpenSSH to latest version'
                        ))
                except:
                    pass
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            pass
        
        return vulns


class FTPChecker:
    """FTP security checker"""
    
    @staticmethod
    async def check(host: str, port: int = 21, timeout: int = 5) -> List[ServiceVuln]:
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            
            banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            writer.write(b'USER anonymous\r\n')
            await writer.drain()
            user_resp = await reader.readline()
            
            writer.write(b'PASS anonymous@\r\n')
            await writer.drain()
            pass_resp = await reader.readline()
            
            if b'230' in pass_resp or b'Login successful' in pass_resp:
                vulns.append(ServiceVuln(
                    service='FTP', port=port,
                    vuln_type='Anonymous FTP',
                    severity='MEDIUM', cvss=6.0,
                    description='Anonymous FTP access enabled',
                    evidence='Anonymous login successful',
                    remediation='Disable anonymous FTP access'
                ))
            
            writer.write(b'QUIT\r\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            pass
        
        return vulns


class SMBChecker:
    """SMB security checker"""
    
    @staticmethod
    async def check(host: str, port: int = 445, timeout: int = 5) -> List[ServiceVuln]:
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            
            negotiate = bytes.fromhex(
                "00000085ff534d4272000000001853c00000000000000000000000000000fffe0000"
                "00000000000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000000000"
                "000000000000000000000000"
            )
            
            writer.write(negotiate)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            
            if len(response) > 70:
                flags = response[70:72]
                signing_required = bool(flags[1] & 0x80) if len(flags) > 1 else False
                
                if not signing_required:
                    vulns.append(ServiceVuln(
                        service='SMB', port=port,
                        vuln_type='SMB Signing Not Required',
                        severity='MEDIUM', cvss=5.0,
                        description='SMB signing not enforced',
                        evidence='SMB signing is optional',
                        remediation='Enable mandatory SMB signing'
                    ))
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            pass
        
        return vulns


class DatabaseChecker:
    """Database security checker"""
    
    @staticmethod
    async def check_mysql(host: str, port: int = 3306, timeout: int = 5) -> List[ServiceVuln]:
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            
            greeting = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            
            if b'mysql' in greeting.lower() or b'maria' in greeting.lower():
                vulns.append(ServiceVuln(
                    service='MySQL', port=port,
                    vuln_type='MySQL Exposed',
                    severity='MEDIUM', cvss=6.0,
                    description='MySQL service exposed',
                    evidence='MySQL greeting received',
                    remediation='Restrict MySQL access, use firewall rules'
                ))
            
            writer.close()
            await writer.wait_closed()
            
        except:
            pass
        
        return vulns
    
    @staticmethod
    async def check_redis(host: str, port: int = 6379, timeout: int = 5) -> List[ServiceVuln]:
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            
            writer.write(b'INFO\r\n')
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            
            if b'redis_version' in response:
                vulns.append(ServiceVuln(
                    service='Redis', port=port,
                    vuln_type='Unauthenticated Redis',
                    severity='HIGH', cvss=8.0,
                    description='Redis accessible without authentication',
                    evidence='INFO command successful',
                    remediation='Enable Redis authentication'
                ))
            
            writer.close()
            await writer.wait_closed()
            
        except:
            pass
        
        return vulns
    
    @staticmethod
    async def check_mongodb(host: str, port: int = 27017, timeout: int = 5) -> List[ServiceVuln]:
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            
            writer.write(b'\x3f\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xdb\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x24\x69\x6e\x66\x6f\x00\x00\x00\x00\x00')
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            
            if b'mongod' in response.lower() or b'mongodb' in response.lower():
                vulns.append(ServiceVuln(
                    service='MongoDB', port=port,
                    vuln_type='MongoDB Exposed',
                    severity='HIGH', cvss=7.5,
                    description='MongoDB service exposed without authentication',
                    evidence='MongoDB greeting received',
                    remediation='Enable MongoDB authentication'
                ))
            
            writer.close()
            await writer.wait_closed()
            
        except:
            pass
        
        return vulns


class WebServiceChecker:
    """Web service security checker"""
    
    @staticmethod
    async def check_apache(host: str, port: int = 80, timeout: int = 5) -> List[ServiceVuln]:
        vulns = []
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://{host}:{port}/', timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    server_header = resp.headers.get('Server', '')
                    
                    if 'Apache' in server_header:
                        vulns.append(ServiceVuln(
                            service='Apache', port=port,
                            vuln_type='Apache Server Exposed',
                            severity='LOW', cvss=3.0,
                            description='Apache server version exposed',
                            evidence=f'Server: {server_header}',
                            remediation='Hide server version in configuration'
                        ))
        except:
            pass
        
        return vulns
    
    @staticmethod
    async def check_nginx(host: str, port: int = 80, timeout: int = 5) -> List[ServiceVuln]:
        vulns = []
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://{host}:{port}/', timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    server_header = resp.headers.get('Server', '')
                    
                    if 'nginx' in server_header:
                        vulns.append(ServiceVuln(
                            service='Nginx', port=port,
                            vuln_type='Nginx Server Exposed',
                            severity='LOW', cvss=3.0,
                            description='Nginx server version exposed',
                            evidence=f'Server: {server_header}',
                            remediation='Hide server version in configuration'
                        ))
        except:
            pass
        
        return vulns


async def check_service(host: str, port: int, service: str) -> List[ServiceVuln]:
    """Check service based on detected service name"""
    checkers = {
        'ssh': SSHChecker.check,
        'ftp': FTPChecker.check,
        'smb': SMBChecker.check,
        'mysql': DatabaseChecker.check_mysql,
        'redis': DatabaseChecker.check_redis,
        'mongodb': DatabaseChecker.check_mongodb,
        'http': WebServiceChecker.check_apache,
        'https': WebServiceChecker.check_apache
    }
    
    checker = checkers.get(service.lower())
    if checker:
        return await checker(host, port)
    return []
