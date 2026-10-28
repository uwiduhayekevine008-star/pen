"""
ICS/SCADA Vulnerability Scanner
Specialized scanner for Industrial Control Systems, PLCs, and OT environments
"""

import asyncio
import socket
import struct
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ICSVulnerability:
    vuln_id: str
    name: str
    severity: str
    description: str
    affected_system: str
    remediation: str
    cve_id: Optional[str] = None
    protocol: str = ""
    timestamp: str = ""


class ICSScanner:
    """Advanced ICS/SCADA vulnerability scanner for OT environments"""
    
    def __init__(self):
        self.vulnerabilities: List[ICSVulnerability] = []
        self.protocols = {
            'modbus': {'port': 502, 'type': 'tcp'},
            'bacnet': {'port': 47808, 'type': 'udp'},
            'opcua': {'port': 4840, 'type': 'tcp'},
            's7comm': {'port': 102, 'type': 'tcp'},
            'profinet': {'port': 34980, 'type': 'udp'},
            'ethercat': {'port': 3490, 'type': 'udp'},
            'enip': {'port': 44818, 'type': 'tcp'},
            'mqtt': {'port': 1883, 'type': 'tcp'},
            'coap': {'port': 5683, 'type': 'udp'},
            'knx': {'port': 3671, 'type': 'udp'}
        }
        
    async def scan_modbus(self, host: str, port: int = 502) -> List[ICSVulnerability]:
        """Scan Modbus TCP/UDP vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            
            # Modbus function codes to test
            test_functions = [0x01, 0x02, 0x03, 0x04, 0x06, 0x10, 0x16, 0x17, 0x2B]
            
            for func in test_functions:
                # Modbus ADU: Transaction ID, Protocol ID, Length, Unit ID, Function
                adu = struct.pack('>HHHBB', 
                    0x0001,  # Transaction ID
                    0x0000,  # Protocol ID
                    0x0006,  # Length
                    0xFF,    # Unit ID (broadcast)
                    func     # Function code
                )
                
                writer.write(adu)
                await writer.drain()
                
                try:
                    response = await asyncio.wait_for(reader.read(1024), timeout=2)
                    if response:
                        # Extract function code from response
                        if len(response) >= 9:
                            resp_func = response[8]
                            if resp_func == func or resp_func == func + 0x80:
                                if func == 0x03 or func == 0x04:
                                    vulns.append(ICSVulnerability(
                                        vuln_id=f"MODBUS-{func:02X}",
                                        name=f"Modbus Function {hex(func)} Accessible",
                                        severity="MEDIUM",
                                        description=f"Modbus function {hex(func)} is accessible without authentication",
                                        affected_system=f"{host}:{port}/Modbus",
                                        remediation="Implement Modbus security extensions (Modbus/TCP Security)",
                                        protocol="Modbus"
                                    ))
                except asyncio.TimeoutError:
                    continue
                    
        except Exception as e:
            pass
            
        return vulns
        
    async def scan_s7comm(self, host: str, port: int = 102) -> List[ICSVulnerability]:
        """Scan Siemens S7Comm vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            
            # S7 Protocol - Job Request
            s7_job = bytes.fromhex(
                "0300001611e0000000000000c0a80101000000000000"
            )
            
            writer.write(s7_job)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            if response and len(response) > 10:
                # Check for S7 protocol response
                if response[0] == 0x03 and response[1] == 0x00:
                    vulns.append(ICSVulnerability(
                        vuln_id="S7COMM-001",
                        name="Siemens S7Comm Protocol Detected",
                        severity="LOW",
                        description="Siemens S7Comm protocol is running on the target",
                        affected_system=f"{host}:{port}/S7Comm",
                        remediation="Implement S7Comm security features and access controls",
                        protocol="S7Comm"
                    ))
                    
                    # Try to read PLC information
                    info_request = bytes.fromhex(
                        "0300001d11e0000000000000c0a801010100000000000000000000"
                    )
                    writer.write(info_request)
                    await writer.drain()
                    
                    info_response = await asyncio.wait_for(reader.read(1024), timeout=5)
                    if info_response and len(info_response) > 20:
                        vulns.append(ICSVulnerability(
                            vuln_id="S7COMM-002",
                            name="PLC Information Disclosure",
                            severity="HIGH",
                            description="PLC module information may be accessible",
                            affected_system=f"{host}:{port}/S7Comm",
                            remediation="Restrict S7Comm access and implement authentication",
                            protocol="S7Comm"
                        ))
                        
        except Exception as e:
            pass
            
        return vulns
        
    async def scan_bacnet(self, host: str, port: int = 47808) -> List[ICSVulnerability]:
        """Scan BACnet vulnerabilities"""
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # BACnet WhoIs request
            whois = bytes.fromhex(
                "810a000d01010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
            
            sock.sendto(whois, (host, port))
            
            try:
                response, addr = sock.recvfrom(1024)
                if response:
                    vulns.append(ICSVulnerability(
                        vuln_id="BACNET-001",
                        name="BACnet Service Discovery",
                        severity="LOW",
                        description="BACnet devices are discoverable on the network",
                        affected_system=f"{host}:{port}/BACnet",
                        remediation="Implement BACnet security and network segmentation",
                        protocol="BACnet"
                    ))
            except socket.timeout:
                pass
                
        except Exception as e:
            pass
            
        return vulns
        
    async def scan_opcua(self, host: str, port: int = 4840) -> List[ICSVulnerability]:
        """Scan OPC UA vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            
            # OPC UA Hello message
            hello = b'HELLO/1.0\n'
            writer.write(hello)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            if response and b'OPC UA' in response.upper():
                vulns.append(ICSVulnerability(
                    vuln_id="OPCUA-001",
                    name="OPC UA Service Detected",
                    severity="MEDIUM",
                    description="OPC UA service is running and accessible",
                    affected_system=f"{host}:{port}/OPC UA",
                    remediation="Implement OPC UA security policies and authentication",
                    protocol="OPC UA"
                ))
                
        except Exception as e:
            pass
            
        return vulns
        
    async def scan_enip(self, host: str, port: int = 44818) -> List[ICSVulnerability]:
        """Scan EtherNet/IP vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            
            # CIP Identity Request
            cip_request = bytes.fromhex(
                "650000000000000000000000000000000000000000000000"
            )
            
            writer.write(cip_request)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            if response and len(response) > 20:
                vulns.append(ICSVulnerability(
                    vuln_id="ENIP-001",
                    name="EtherNet/IP Device Discovery",
                    severity="MEDIUM",
                    description="EtherNet/IP devices are discoverable",
                    affected_system=f"{host}:{port}/EtherNet/IP",
                    remediation="Implement EtherNet/IP security and network segmentation",
                    protocol="EtherNet/IP"
                ))
                
        except Exception as e:
            pass
            
        return vulns
        
    async def scan_mqtt(self, host: str, port: int = 1883) -> List[ICSVulnerability]:
        """Scan MQTT vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            
            # MQTT Connect
            connect = bytes.fromhex(
                "103a00044d5154540402003c000c696f742d746573742d6167656e74"
            )
            
            writer.write(connect)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            if response and response[0] == 0x20:
                connack = response[3]
                if connack == 0x00:
                    vulns.append(ICSVulnerability(
                        vuln_id="MQTT-001",
                        name="MQTT Anonymous Access",
                        severity="HIGH",
                        description="MQTT broker allows anonymous connections",
                        affected_system=f"{host}:{port}/MQTT",
                        remediation="Implement MQTT authentication and authorization",
                        protocol="MQTT"
                    ))
                    
        except Exception as e:
            pass
            
        return vulns
        
    async def scan_coap(self, host: str, port: int = 5683) -> List[ICSVulnerability]:
        """Scan CoAP vulnerabilities"""
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # CoAP GET request
            coap_get = bytes.fromhex(
                "4001000000000000"
            )
            
            sock.sendto(coap_get, (host, port))
            
            try:
                response, addr = sock.recvfrom(1024)
                if response and response[0] == 0x60:
                    vulns.append(ICSVulnerability(
                        vuln_id="COAP-001",
                        name="CoAP Service Detected",
                        severity="MEDIUM",
                        description="CoAP service is running and responding",
                        affected_system=f"{host}:{port}/CoAP",
                        remediation="Implement CoAP security (DTLS/TLS)",
                        protocol="CoAP"
                    ))
            except socket.timeout:
                pass
                
        except Exception as e:
            pass
            
        return vulns
        
    async def scan_knx(self, host: str, port: int = 3671) -> List[ICSVulnerability]:
        """Scan KNX vulnerabilities"""
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # KNX Search Request
            search_req = bytes.fromhex(
                "0610020100080000"
            )
            
            sock.sendto(search_req, (host, port))
            
            try:
                response, addr = sock.recvfrom(1024)
                if response and len(response) > 10:
                    vulns.append(ICSVulnerability(
                        vuln_id="KNX-001",
                        name="KNX Device Discovery",
                        severity="LOW",
                        description="KNX devices are discoverable on the network",
                        affected_system=f"{host}:{port}/KNX",
                        remediation="Implement KNX security and network segmentation",
                        protocol="KNX"
                    ))
            except socket.timeout:
                pass
                
        except Exception as e:
            pass
            
        return vulns
        
    async def scan_ics_target(self, host: str, custom_ports: Dict[str, int] = None) -> List[ICSVulnerability]:
        """Scan ICS target for vulnerabilities"""
        all_vulns = []
        
        ports = self.protocols.copy()
        if custom_ports:
            ports.update(custom_ports)
            
        for protocol, info in ports.items():
            port = info['port']
            scan_method = getattr(self, f'scan_{protocol}', None)
            
            if scan_method:
                try:
                    vulns = await scan_method(host, port)
                    all_vulns.extend(vulns)
                except Exception as e:
                    pass
                    
        return all_vulns


if __name__ == '__main__':
    import sys
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python ics_scanner.py <host>")
            return
            
        host = sys.argv[1]
        scanner = ICSScanner()
        vulns = await scanner.scan_ics_target(host)
        
        for vuln in vulns:
            print(f"[{vuln.severity}] {vuln.name} - {vuln.affected_system}")
            
    asyncio.run(main())