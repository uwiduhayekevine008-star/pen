"""Web Application Security Scanner with Advanced Testing"""
import asyncio
import aiohttp
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class WebVuln:
    url: str
    vuln_type: str
    severity: str
    cvss: float
    description: str
    evidence: str
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class WebScanner:
    """Advanced web vulnerability scanner"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session = None
    
    async def init(self):
        self.session = aiohttp.ClientSession(timeout=self.timeout)
    
    async def close(self):
        if self.session:
            await self.session.close()
    
    async def check_security_headers(self, url: str) -> List[WebVuln]:
        """Check for missing security headers"""
        vulns = []
        headers = {
            'X-Frame-Options': ('HIGH', 8.0, 'Clickjacking protection'),
            'X-Content-Type-Options': ('MEDIUM', 5.0, 'MIME sniffing protection'),
            'Strict-Transport-Security': ('HIGH', 7.5, 'HTTPS enforcement'),
            'Content-Security-Policy': ('HIGH', 8.0, 'XSS mitigation'),
            'X-XSS-Protection': ('MEDIUM', 6.0, 'XSS filter'),
            'Referrer-Policy': ('LOW', 3.0, 'Referrer leakage'),
            'Permissions-Policy': ('LOW', 3.0, 'Feature access control'),
            'Cross-Origin-Embedder-Policy': ('MEDIUM', 5.0, 'Cross-origin protection'),
            'Cross-Origin-Opener-Policy': ('MEDIUM', 5.0, 'Cross-origin protection'),
            'Cross-Origin-Resource-Policy': ('MEDIUM', 5.0, 'Cross-origin protection')
        }
        
        try:
            async with self.session.get(url) as resp:
                for header, (sev, cvss, desc) in headers.items():
                    if header not in resp.headers:
                        vulns.append(WebVuln(
                            url=url, vuln_type=f'Missing {header}',
                            severity=sev, cvss=cvss,
                            description=f'Missing {desc}',
                            evidence='Header not present',
                            remediation=f'Add {header} header'
                        ))
        except:
            pass
        return vulns
    
    async def test_sqli(self, url: str, param: str = 'id') -> List[WebVuln]:
        """Test for SQL injection"""
        vulns = []
        payloads = [
            "' OR '1'='1", "' OR '1'='1'--", "' UNION SELECT NULL--",
            "1' ORDER BY 1--", "'; WAITFOR DELAY '0:0:3'--", "1' AND SLEEP(3)--",
            "' AND '1'='1", "' AND '1'='2", "' OR ''='", "' OR 'x'='x"
        ]
        errors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sqlite', 'odbc', 'syntax error']
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url) as resp:
                    text = await resp.text()
                    for err in errors:
                        if err in text.lower():
                            vulns.append(WebVuln(
                                url=test_url, vuln_type='SQL Injection',
                                severity='CRITICAL', cvss=9.8,
                                description='SQL injection vulnerability',
                                evidence=f'Error: {err}',
                                remediation='Use parameterized queries'
                            ))
                            return vulns
            except:
                pass
        return vulns
    
    async def test_xss(self, url: str, param: str = 'input') -> List[WebVuln]:
        """Test for XSS"""
        vulns = []
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "${alert(1)}",
            "<ScRiPt>alert(1)</sCrIpT>",
            "<img/src=x/onerror=alert(1)>"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url) as resp:
                    text = await resp.text()
                    if payload in text or ('alert' in text and '<script>' in payload):
                        vulns.append(WebVuln(
                            url=test_url, vuln_type='Cross-Site Scripting',
                            severity='HIGH', cvss=8.1,
                            description='Reflected XSS vulnerability',
                            evidence='Payload reflected in response',
                            remediation='Encode output and validate input'
                        ))
                        return vulns
            except:
                pass
        return vulns
    
    async def test_lfi(self, url: str, param: str = 'file') -> List[WebVuln]:
        """Test for Local File Inclusion"""
        vulns = []
        payloads = [
            '../../../etc/passwd', '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc/passwd', '/etc/passwd%00',
            '..\\..\\..\\windows\\system32\\config\\sam'
        ]
        indicators = ['root:', '[extensions]', '[fonts]', 'daemon:']
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url) as resp:
                    text = await resp.text()
                    for ind in indicators:
                        if ind in text:
                            vulns.append(WebVuln(
                                url=test_url, vuln_type='Local File Inclusion',
                                severity='HIGH', cvss=8.6,
                                description='LFI vulnerability',
                                evidence=f'Found: {ind}',
                                remediation='Sanitize file path input'
                            ))
                            return vulns
            except:
                pass
        return vulns
    
    async def test_ssrf(self, url: str, param: str = 'url') -> List[WebVuln]:
        """Test for SSRF"""
        vulns = []
        payloads = [
            'http://127.0.0.1:22', 'http://localhost:80/server-status',
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd', 'dict://127.0.0.1:6379/info'
        ]
        indicators = ['SSH-', 'Apache Status', 'ami-id', 'root:', 'redis_version']
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url) as resp:
                    text = await resp.text()
                    for ind in indicators:
                        if ind in text:
                            vulns.append(WebVuln(
                                url=test_url, vuln_type='Server-Side Request Forgery',
                                severity='HIGH', cvss=8.6,
                                description='SSRF vulnerability',
                                evidence=f'Found: {ind}',
                                remediation='Implement URL allowlist'
                            ))
                            return vulns
            except:
                pass
        return vulns
    
    async def test_cmdi(self, url: str, param: str = 'cmd') -> List[WebVuln]:
        """Test for Command Injection"""
        vulns = []
        payloads = [
            "; id", "| id", "&& id", "$(id)", "`id`",
            "; sleep 5", "| sleep 5", "; whoami"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url) as resp:
                    text = await resp.text()
                    if 'uid=' in text or 'root:' in text or 'daemon:' in text:
                        vulns.append(WebVuln(
                            url=test_url, vuln_type='Command Injection',
                            severity='CRITICAL', cvss=9.8,
                            description='Command injection vulnerability',
                            evidence='Command executed successfully',
                            remediation='Sanitize command input'
                        ))
                        return vulns
            except:
                pass
        return vulns
    
    async def test_ssti(self, url: str, param: str = 'template') -> List[WebVuln]:
        """Test for Server-Side Template Injection"""
        vulns = []
        payloads = [
            "{{7*7}}", "${7*7}", "#{7*7}",
            "{{config}}", "{{self}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url) as resp:
                    text = await resp.text()
                    if '49' in text or 'config' in text.lower():
                        vulns.append(WebVuln(
                            url=test_url, vuln_type='Server-Side Template Injection',
                            severity='CRITICAL', cvss=9.8,
                            description='SSTI vulnerability',
                            evidence='Template engine executed',
                            remediation='Use safe template rendering'
                        ))
                        return vulns
            except:
                pass
        return vulns
    
    async def test_open_redirect(self, url: str, param: str = 'redirect') -> List[WebVuln]:
        """Test for Open Redirect"""
        vulns = []
        payloads = [
            "//attacker.com", "https:attacker.com", "https:///attacker.com",
            "///attacker.com", "http://attacker.com", "https://attacker.com"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url, allow_redirects=False) as resp:
                    location = resp.headers.get('Location', '')
                    if payload in location or 'attacker.com' in location:
                        vulns.append(WebVuln(
                            url=test_url, vuln_type='Open Redirect',
                            severity='MEDIUM', cvss=5.0,
                            description='Open redirect vulnerability',
                            evidence=f'Redirect to: {location}',
                            remediation='Validate redirect URLs'
                        ))
                        return vulns
            except:
                pass
        return vulns
    
    async def test_cors(self, url: str) -> List[WebVuln]:
        """Test for CORS misconfiguration"""
        vulns = []
        
        try:
            async with self.session.get(url, headers={'Origin': 'http://attacker.com'}) as resp:
                cors_header = resp.headers.get('Access-Control-Allow-Origin', '')
                if cors_header == '*' or cors_header == 'http://attacker.com':
                    vulns.append(WebVuln(
                        url=url, vuln_type='CORS Misconfiguration',
                        severity='HIGH', cvss=7.5,
                        description='CORS allows any origin',
                        evidence=f'Access-Control-Allow-Origin: {cors_header}',
                        remediation='Restrict Access-Control-Allow-Origin'
                    ))
        except:
            pass
        
        return vulns
    
    async def test_method_override(self, url: str) -> List[WebVuln]:
        """Test for HTTP method override"""
        vulns = []
        
        methods = ['PUT', 'DELETE', 'PATCH', 'CONNECT', 'TRACE', 'DEBUG']
        
        for method in methods:
            try:
                async with self.session.request(
                    method, url, headers={'X-HTTP-Method-Override': method}
                ) as resp:
                    if resp.status in [200, 201, 204]:
                        vulns.append(WebVuln(
                            url=url, vuln_type='HTTP Method Override',
                            severity='MEDIUM', cvss=5.0,
                            description=f'Method {method} allowed via override',
                            evidence=f'Status: {resp.status}',
                            remediation='Restrict HTTP methods'
                        ))
                        return vulns
            except:
                pass
        
        return vulns
    
    async def full_scan(self, url: str) -> List[WebVuln]:
        """Run all web security checks"""
        await self.init()
        tasks = [
            self.check_security_headers(url),
            self.test_sqli(url),
            self.test_xss(url),
            self.test_lfi(url),
            self.test_ssrf(url),
            self.test_cmdi(url),
            self.test_ssti(url),
            self.test_open_redirect(url),
            self.test_cors(url),
            self.test_method_override(url)
        ]
        results = await asyncio.gather(*tasks)
        await self.close()
        
        vulns = []
        for result in results:
            vulns.extend(result)
        return vulns
