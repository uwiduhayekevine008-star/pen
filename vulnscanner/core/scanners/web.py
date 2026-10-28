"""Web Application Security Scanner"""
import asyncio
import aiohttp
from typing import List, Dict, Optional
from dataclasses import dataclass
import re


@dataclass
class WebVuln:
    url: str
    vuln_type: str
    severity: str
    cvss: float
    description: str
    evidence: str
    remediation: str


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
            'Permissions-Policy': ('LOW', 3.0, 'Feature access control')
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
            "1' ORDER BY 1--", "'; WAITFOR DELAY '0:0:3'--", "1' AND SLEEP(3)--"
        ]
        errors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sqlite', 'odbc']
        
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
            "${alert(1)}"
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
    
    async def full_scan(self, url: str) -> List[WebVuln]:
        """Run all web security checks"""
        await self.init()
        tasks = [
            self.check_security_headers(url),
            self.test_sqli(url),
            self.test_xss(url),
            self.test_lfi(url),
            self.test_ssrf(url)
        ]
        results = await asyncio.gather(*tasks)
        await self.close()
        
        vulns = []
        for result in results:
            vulns.extend(result)
        return vulns
