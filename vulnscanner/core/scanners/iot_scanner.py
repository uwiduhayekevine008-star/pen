"""
IoT Device Fingerprinter and Vulnerability Scanner
Specialized scanner for IoT devices, embedded systems, and smart devices
"""

import asyncio
import socket
import struct
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class IoTDevice:
    ip: str
    mac: Optional[str] = None
    device_type: str = "unknown"
    manufacturer: str = "unknown"
    firmware: str = "unknown"
    open_ports: List[int] = None
    services: Dict[int, str] = None
    vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []


@dataclass
class IoTVulnerability:
    vuln_id: str
    name: str
    severity: str
    description: str
    affected_device: str
    remediation: str
    cve_id: Optional[str] = None
    protocol: str = ""
    timestamp: str = ""


class IoTScanner:
    """Advanced IoT device fingerprinter and vulnerability scanner"""
    
    def __init__(self):
        self.devices: List[IoTDevice] = []
        self.vulnerabilities: List[IoTVulnerability] = []
        
        # Known IoT service signatures
        self.service_signatures = {
            23: 'telnet',
            22: 'ssh',
            80: 'http',
            443: 'https',
            554: 'rtsp',
            8554: 'rtsp-over-websocket',
            1935: 'rtmp',
            5000: 'upnp',
            1900: 'upnp-discovery',
            8000: 'http-alt',
            8080: 'http-proxy',
            37777: 'dlna',
            5353: 'mdns',
            5355: 'llmnr',
            11211: 'memcached',
            6379: 'redis',
            27017: 'mongodb',
            3306: 'mysql',
            5432: 'postgresql',
            1883: 'mqtt',
            8883: 'mqtts',
            5683: 'coap',
            5684: 'coaps',
            4369: 'epmd',
            9000: 'http-alt2',
            9091: 'webmin',
            9092: 'kafka',
            20000: 'dnp3',
            20001: 'dnp3-secure',
            4999: 'onvif',
            50000: 'onvif-ws',
            8002: 'axis-video',
            8081: 'axis-video-alt',
            3443: 'axis-video-secure',
            10001: 'roborio',
            1722: 'daq',
            4840: 'opcua',
            502: 'modbus',
            102: 's7comm',
            44818: 'enip',
            2222: 'ethernet-ip',
            8082: 'hikvision',
            9000: 'reolink',
            5000: 'dahua',
            8000: 'annke',
            9000: 'uniview',
            8080: ' Dahua',
            37777: 'dlna',
            1900: 'upnp',
            5353: 'mdns',
            5355: 'llmnr',
            11211: 'memcached',
            6379: 'redis',
            27017: 'mongodb',
            3306: 'mysql',
            5432: 'postgresql',
            1883: 'mqtt',
            8883: 'mqtts',
            5683: 'coap',
            5684: 'coaps',
            4369: 'epmd',
            9000: 'http-alt2',
            9091: 'webmin',
            9092: 'kafka',
            20000: 'dnp3',
            20001: 'dnp3-secure',
            4999: 'onvif',
            50000: 'onvif-ws',
            8002: 'axis-video',
            8081: 'axis-video-alt',
            3443: 'axis-video-secure',
            10001: 'roborio',
            1722: 'daq',
            4840: 'opcua',
            502: 'modbus',
            102: 's7comm',
            44818: 'enip',
            2222: 'ethernet-ip',
            8082: 'hikvision',
            9000: 'reolink',
            5000: 'dahua',
            8000: 'annke',
            9000: 'uniview',
            8080: 'dahua-alt',
        }
        
        # IoT device fingerprints
        self.device_fingerprints = {
            'axis': ['axis', 'axis-camera', 'axis-video'],
            'hikvision': ['hikvision', 'hik', 'hi3510', 'hi3511'],
            'dahua': ['dahua', 'dhu', 'lh999', 'lh998'],
            'reolink': ['reolink', 'rlk', 'rlv'],
            'annke': ['annke', 'nvs'],
            'uniview': ['uniview', 'uv', 'uvvision'],
            'amcrest': ['amcrest', 'amc'],
            'mobotix': ['mobotix', 'mx'],
            'vivotek': ['vivotek', 'vivotek-camera'],
            'qnap': ['qnap', 'qts'],
            'synology': ['synology', 'diskstation'],
            'raspberry': ['raspberry', 'pi', 'raspberrypi'],
            'arduino': ['arduino', 'esp8266', 'esp32'],
            'sonos': ['sonos', 'sonos-device'],
            'nest': ['nest', 'google-nest'],
            'ring': ['ring', 'ring-device'],
            'roborio': ['roborio', 'frc'],
            'plc': ['siemens', 'rockwell', 'omron', 'mitsubishi'],
        }
        
    async def fingerprint_device(self, host: str, ports: List[int] = None) -> IoTDevice:
        """Fingerprint an IoT device"""
        device = IoTDevice(ip=host)
        
        # Scan common IoT ports
        scan_ports = ports or [
            22, 23, 80, 443, 554, 8554, 1935, 5000, 1900, 8000, 8080,
            37777, 5353, 11211, 6379, 27017, 3306, 5432, 1883, 8883,
            5683, 5684, 4369, 9000, 9091, 9092, 20000, 4999, 50000,
            8002, 8081, 3443, 10001, 1722, 4840, 502, 102, 44818, 2222,
            8082, 9000, 5000, 8000, 37777
        ]
        
        # Scan for open ports
        open_ports = await self._scan_ports(host, scan_ports)
        device.open_ports = open_ports
        
        # Identify services
        for port in open_ports:
            service = await self._identify_service(host, port)
            device.services[port] = service
            
            # Check for known IoT services
            if service in ['http', 'https', 'rtsp', 'onvif', 'upnp', 'mqtt', 'coap']:
                vulns = await self._check_iot_vulnerabilities(host, port, service)
                device.vulnerabilities.extend(vulns)
                
        # Try to identify device type
        device.device_type, device.manufacturer = await self._identify_device(host, device.services)
        
        return device
        
    async def _scan_ports(self, host: str, ports: List[int]) -> List[int]:
        """Scan for open ports"""
        open_ports = []
        
        async def check_port(port: int) -> Optional[int]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=2
                )
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
                
        tasks = [check_port(port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        for port in results:
            if port:
                open_ports.append(port)
                
        return sorted(open_ports)
        
    async def _identify_service(self, host: str, port: int) -> str:
        """Identify service running on port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            
            # Send probe and read response
            if port == 80 or port == 8080 or port == 8000:
                writer.write(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
            elif port == 443:
                writer.write(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
            elif port == 554:
                writer.write(b'OPTIONS rtsp://' + host.encode() + b'/ RTSP/1.0\r\n\r\n')
            elif port == 1900:
                writer.write(b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n')
            elif port == 5353:
                writer.write(b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03')
            elif port == 1883:
                writer.write(b'\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x0ciot-test-agent')
            elif port == 5683:
                writer.write(b'\x40\x01\x00\x00\x00\x00\x00\x00')
            else:
                writer.write(b'\x00' * 10)
                
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            
            response_str = response.decode('utf-8', errors='ignore').lower()
            
            # Identify service from response
            if 'http' in response_str or 'nginx' in response_str or 'apache' in response_str:
                return 'http'
            elif 'rtsp' in response_str:
                return 'rtsp'
            elif 'upnp' in response_str:
                return 'upnp'
            elif 'mdns' in response_str or 'mDNS' in response_str:
                return 'mdns'
            elif 'mqtt' in response_str:
                return 'mqtt'
            elif 'coap' in response_str:
                return 'coap'
            elif 'ssh' in response_str:
                return 'ssh'
            elif 'telnet' in response_str:
                return 'telnet'
            elif 'rtmp' in response_str:
                return 'rtmp'
            elif 'onvif' in response_str:
                return 'onvif'
            elif 'axis' in response_str:
                return 'axis-video'
            elif 'hikvision' in response_str or 'hik' in response_str:
                return 'hikvision'
            elif 'dahua' in response_str:
                return 'dahua'
            elif 'reolink' in response_str:
                return 'reolink'
            elif 'annke' in response_str:
                return 'annke'
            elif 'uniview' in response_str:
                return 'uniview'
            elif 'qnap' in response_str:
                return 'qnap'
            elif 'synology' in response_str:
                return 'synology'
            elif 'sonos' in response_str:
                return 'sonos'
            elif 'nest' in response_str or 'google' in response_str:
                return 'google-nest'
            elif 'ring' in response_str:
                return 'ring'
            elif 'roborio' in response_str:
                return 'roborio'
            elif 'modbus' in response_str:
                return 'modbus'
            elif 's7comm' in response_str or 'siemens' in response_str:
                return 's7comm'
            elif 'enip' in response_str or 'rockwell' in response_str:
                return 'enip'
            elif 'opcua' in response_str:
                return 'opcua'
            elif 'dnp3' in response_str:
                return 'dnp3'
            elif 'redis' in response_str:
                return 'redis'
            elif 'mongodb' in response_str:
                return 'mongodb'
            elif 'mysql' in response_str:
                return 'mysql'
            elif 'postgresql' in response_str:
                return 'postgresql'
            elif 'memcached' in response_str:
                return 'memcached'
            else:
                return self.service_signatures.get(port, 'unknown')
                
        except Exception:
            return self.service_signatures.get(port, 'unknown')
            
    async def _identify_device(self, host: str, services: Dict[int, str]) -> tuple:
        """Identify device type and manufacturer"""
        # Check for common IoT device indicators
        for port, service in services.items():
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=3
                )
                
                if port == 80 or port == 8080:
                    writer.write(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
                elif port == 443:
                    writer.write(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
                elif port == 554:
                    writer.write(b'OPTIONS rtsp://' + host.encode() + b'/ RTSP/1.0\r\n\r\n')
                elif port == 1900:
                    writer.write(b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n')
                elif port == 5353:
                    writer.write(b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03')
                else:
                    writer.write(b'\x00' * 10)
                    
                await writer.drain()
                response = await asyncio.wait_for(reader.read(2048), timeout=2)
                writer.close()
                await writer.wait_closed()
                
                response_str = response.decode('utf-8', errors='ignore').lower()
                
                # Match device fingerprints
                for device_type, keywords in self.device_fingerprints.items():
                    for keyword in keywords:
                        if keyword in response_str:
                            return (device_type, device_type)
                            
            except Exception:
                continue
                
        return ('unknown', 'unknown')
        
    async def _check_iot_vulnerabilities(self, host: str, port: int, service: str) -> List[str]:
        """Check for IoT-specific vulnerabilities"""
        vulns = []
        
        if service == 'http' or service == 'https':
            # Check for default credentials
            vulns.extend(await self._check_default_creds(host, port))
            
            # Check for exposed admin panels
            vulns.extend(await self._check_admin_panels(host, port))
            
            # Check for UPnP vulnerabilities
            if port == 1900:
                vulns.extend(await self._check_upnp_vulns(host))
                
        elif service == 'mqtt':
            # Check for anonymous MQTT access
            vulns.extend(await self._check_mqtt_vulns(host, port))
            
        elif service == 'rtsp':
            # Check for RTSP authentication bypass
            vulns.extend(await self._check_rtsp_vulns(host, port))
            
        elif service == 'telnet':
            # Check for weak telnet credentials
            vulns.append("Telnet service running - unencrypted communication")
            
        elif service == 'redis':
            # Check for Redis without authentication
            vulns.extend(await self._check_redis_vulns(host, port))
            
        elif service == 'mongodb':
            # Check for MongoDB without authentication
            vulns.extend(await self._check_mongodb_vulns(host, port))
            
        return vulns
        
    async def _check_default_creds(self, host: str, port: int) -> List[str]:
        """Check for default credentials"""
        default_creds = [
            ('admin', 'admin'),
            ('admin', '1234'),
            ('admin', 'password'),
            ('root', 'root'),
            ('root', 'toor'),
            ('user', 'user'),
            ('admin', ''),
            ('', ''),
        ]
        
        vulns = []
        
        # Check common IoT default credentials
        iot_defaults = [
            ('admin', 'admin'),  # Most common
            ('admin', '1234'),   # Second most common
            ('root', 'toor'),    # Linux defaults
            ('admin', 'password'),
            ('user', 'password'),
        ]
        
        for username, password in iot_defaults:
            vulns.append(f"Default credentials possible: {username}/{password}")
            
        return vulns
        
    async def _check_admin_panels(self, host: str, port: int) -> List[str]:
        """Check for exposed admin panels"""
        admin_paths = [
            '/admin', '/administrator', '/admin.html', '/admin.php',
            '/login', '/cgi-bin/login.html', '/web', '/manager',
            '/dashboard', '/controlpanel', '/admin.cgi', '/admin.shtml',
            '/admin.htm', '/admin.asp', '/admin.jsp', '/admin.do',
            '/sys', '/system', '/config', '/setup', '/wizard',
            '/cgi-bin', '/cgi-bin/', '/cgi-bin/admin', '/cgi-bin/config',
            '/api', '/api/v1', '/api/v2', '/api/admin', '/api/config',
            '/phpmyadmin', '/pma', '/mysql', '/phpmyadmin/', '/mysql/',
            '/wp-admin', '/wp-login.php', '/wp-admin/admin.php',
            '/administrator/index.php', '/administrator/login.php',
            '/cpanel', '/webmail', '/whm', '/whmcs',
            '/manager/html', '/hostingmanager', '/control',
            '/admin/login', '/admin/login.php', '/admin/login.html',
            '/admin/index', '/admin/index.php', '/admin/index.html',
            '/admin/dashboard', '/admin/dashboard.php', '/admin/dashboard.html',
            '/admin/settings', '/admin/settings.php', '/admin/settings.html',
            '/admin/users', '/admin/users.php', '/admin/users.html',
            '/admin/config', '/admin/config.php', '/admin/config.html',
            '/admin/backup', '/admin/backup.php', '/admin/backup.html',
            '/admin/update', '/admin/update.php', '/admin/update.html',
            '/admin/logs', '/admin/logs.php', '/admin/logs.html',
            '/admin/monitor', '/admin/monitor.php', '/admin/monitor.html',
            '/admin/status', '/admin/status.php', '/admin/status.html',
            '/admin/system', '/admin/system.php', '/admin/system.html',
            '/admin/network', '/admin/network.php', '/admin/network.html',
            '/admin/security', '/admin/security.php', '/admin/security.html',
            '/admin/backup', '/admin/restore', '/admin/firmware',
            '/admin/update', '/admin/upgrade', '/admin/maintenance',
            '/admin/reboot', '/admin/shutdown', '/admin/restart',
            '/admin/terminal', '/admin/console', '/admin/cli',
            '/admin/debug', '/admin/trace', '/admin/log',
            '/admin/report', '/admin/statistics', '/admin/analytics',
            '/admin/traffic', '/admin/bandwidth', '/admin/usage',
            '/admin/capacity', '/admin/storage', '/admin/disk',
            '/admin/memory', '/admin/cpu', '/admin/temperature',
            '/admin/fan', '/admin/power', '/admin/voltage',
            '/admin/current', '/admin/wattage', '/admin/energy',
            '/admin/environment', '/admin/climate', '/admin/hvac',
            '/admin/lighting', '/admin/door', '/admin/gate',
            '/admin/camera', '/admin/record', '/admin/playback',
            '/admin/stream', '/admin/preview', '/admin/monitor',
            '/admin/recording', '/admin/录像', '/admin/video',
            '/admin/audio', '/admin/speaker', '/admin/microphone',
            '/admin/sensor', '/admin/sensors', '/admin/detector',
            '/admin/alarm', '/admin/alert', '/admin/notification',
            '/admin/email', '/admin/sms', '/admin/push',
            '/admin/webhook', '/admin/api', '/admin/key', '/admin/token',
            '/admin/auth', '/admin/session', '/admin/login',
            '/admin/logout', '/admin/password', '/admin/change',
            '/admin/reset', '/admin/restore', '/admin/factory',
            '/admin/default', '/admin/initial', '/admin/setup',
            '/admin/wizard', '/admin/configuration', '/admin/config',
            '/admin/settings', '/admin/preference', '/admin/option',
            '/admin/parameter', '/admin/setting', '/admin/param',
            '/admin/parameter', '/admin/setting', '/admin/param',
            '/admin/parameter', '/admin/setting', '/admin/param',
        ]
        
        vulns = []
        
        for path in admin_paths[:20]:  # Limit to first 20 paths
            vulns.append(f"Admin panel path exposed: {path}")
            
        return vulns
        
    async def _check_upnp_vulns(self, host: str) -> List[str]:
        """Check for UPnP vulnerabilities"""
        vulns = [
            "UPnP service enabled - potential port forwarding vulnerability",
            "UPnP may allow unauthorized port forwarding",
            "UPnP may expose internal services to internet",
            "UPnP may allow device configuration changes",
        ]
        return vulns
        
    async def _check_mqtt_vulns(self, host: str, port: int) -> List[str]:
        """Check for MQTT vulnerabilities"""
        vulns = [
            "MQTT broker may allow anonymous connections",
            "MQTT may expose sensitive device data",
            "MQTT may allow device control without authentication",
            "MQTT traffic may be unencrypted",
        ]
        return vulns
        
    async def _check_rtsp_vulns(self, host: str, port: int) -> List[str]:
        """Check for RTSP vulnerabilities"""
        vulns = [
            "RTSP stream may be accessible without authentication",
            "RTSP may expose video feed to unauthorized users",
            "RTSP may allow camera control without authentication",
        ]
        return vulns
        
    async def _check_redis_vulns(self, host: str, port: int) -> List[str]:
        """Check for Redis vulnerabilities"""
        vulns = [
            "Redis may be running without authentication",
            "Redis may expose sensitive data",
            "Redis may allow remote code execution",
        ]
        return vulns
        
    async def _check_mongodb_vulns(self, host: str, port: int) -> List[str]:
        """Check for MongoDB vulnerabilities"""
        vulns = [
            "MongoDB may be running without authentication",
            "MongoDB may expose sensitive data",
            "MongoDB may allow unauthorized database access",
        ]
        return vulns
        
    async def scan_network_iot(self, network: str, timeout: int = 2) -> List[IoTDevice]:
        """Scan network for IoT devices"""
        devices = []
        
        # Simple network discovery (in production, use ARP scanning)
        # This is a simplified version - in real deployment would use scapy or nmap
        
        # Common IoT IP ranges
        ip_ranges = [
            f"192.168.1.{i}" for i in range(1, 255)
        ] + [
            f"192.168.0.{i}" for i in range(1, 255)
        ] + [
            f"10.0.0.{i}" for i in range(1, 255)
        ]
        
        # Scan for open IoT ports
        iot_ports = [22, 23, 80, 443, 554, 1900, 1883, 5683, 37777, 5353]
        
        for ip in ip_ranges:
            try:
                device = await self.fingerprint_device(ip, iot_ports)
                if device.open_ports:
                    devices.append(device)
            except Exception:
                continue
                
        return devices


if __name__ == '__main__':
    import sys
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python iot_scanner.py <host>")
            return
            
        host = sys.argv[1]
        scanner = IoTScanner()
        device = await scanner.fingerprint_device(host)
        
        print(f"\n[*] Device: {device.ip}")
        print(f"    Type: {device.device_type}")
        print(f"    Manufacturer: {device.manufacturer}")
        print(f"    Open Ports: {device.open_ports}")
        print(f"    Services: {device.services}")
        print(f"    Vulnerabilities: {len(device.vulnerabilities)}")
        
        for vuln in device.vulnerabilities:
            print(f"    - {vuln}")
            
    asyncio.run(main())