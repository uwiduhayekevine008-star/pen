"""Web Application Security Scanner with Advanced Testing"""
import asyncio
import aiohttp
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlencode

from vulnscanner.security import require_target_in_scope, require_feature_enabled


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
        """Check for missing security headers using a normal GET request."""
        require_target_in_scope(url)
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
            async with self.session.get(url, allow_redirects=False) as resp:
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
        """Low-impact SQL error/boolean probes; active checks require explicit opt-in."""
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_ACTIVE_TESTS', 'Active SQL injection probes')
        vulns = []
        payloads = [
            "'", '"', "' AND '1'='1", "' AND '1'='2", "' OR '1'='1'--"
        ]
        errors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sqlite', 'odbc', 'syntax error']
        
        for payload in payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({param: payload})}"
                async with self.session.get(test_url, allow_redirects=False) as resp:
                    text = await resp.text()
                    for err in errors:
                        if err in text.lower():
                            vulns.append(WebVuln(
                                url=test_url, vuln_type='Potential SQL Injection',
                                severity='HIGH', cvss=7.5,
                                description='Database error correlated with an SQL injection probe; manual validation required',
                                evidence=f'Error: {err}',
                                remediation='Use parameterized queries'
                            ))
                            return vulns
            except:
                pass
        return vulns
    
    async def test_xss(self, url: str, param: str = 'input') -> List[WebVuln]:
        """Check reflection with inert markers; do not send executable scripts."""
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_ACTIVE_TESTS', 'Active XSS reflection probes')
        vulns = []
        payloads = ['<pen-xss-probe>', "\"'><pen-xss-probe>"]
        
        for payload in payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({param: payload})}"
                async with self.session.get(test_url, allow_redirects=False) as resp:
                    text = await resp.text()
                    if payload in text or ('alert' in text and '<script>' in payload):
                        vulns.append(WebVuln(
                            url=test_url, vuln_type='Unencoded HTML Reflection',
                            severity='MEDIUM', cvss=5.3,
                            description='An inert HTML marker was reflected; script execution has not been demonstrated',
                            evidence='Inert marker reflected in response; manual browser validation required',
                            remediation='Encode output and validate input'
                        ))
                        return vulns
            except:
                pass
        return vulns
    
    async def test_lfi(self, url: str, param: str = 'file') -> List[WebVuln]:
        """Test file-read behavior; requires a separate explicit opt-in."""
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_FILE_READ_PROBES', 'File-read probes')
        vulns = []
        payloads = [
            '../../../etc/passwd', '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc/passwd', '/etc/passwd%00',
            '..\\..\\..\\windows\\system32\\config\\sam'
        ]
        indicators = ['root:', '[extensions]', '[fonts]', 'daemon:']
        
        for payload in payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({param: payload})}"
                async with self.session.get(test_url, allow_redirects=False) as resp:
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
        """Test SSRF behavior; requires a separate explicit opt-in."""
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_SSRF_PROBES', 'SSRF probes')
        vulns = []
        payloads = [
            'http://127.0.0.1:22', 'http://localhost:80/server-status',
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd', 'dict://127.0.0.1:6379/info'
        ]
        indicators = ['SSH-', 'Apache Status', 'ami-id', 'root:', 'redis_version']
        
        for payload in payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({param: payload})}"
                async with self.session.get(test_url, allow_redirects=False) as resp:
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
        """Test command injection; requires a separate explicit opt-in."""
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_COMMAND_INJECTION_PROBES', 'Command-injection probes')
        vulns = []
        payloads = [
            "; id", "| id", "&& id", "$(id)", "`id`",
            "; sleep 5", "| sleep 5", "; whoami"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({param: payload})}"
                async with self.session.get(test_url, allow_redirects=False) as resp:
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
        """Test template injection; requires a separate explicit opt-in."""
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_TEMPLATE_INJECTION_PROBES', 'Template-injection probes')
        vulns = []
        payloads = [
            "{{7*7}}", "${7*7}", "#{7*7}",
            "{{config}}", "{{self}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({param: payload})}"
                async with self.session.get(test_url, allow_redirects=False) as resp:
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
        """Test redirects; active checks require explicit opt-in."""
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_ACTIVE_TESTS', 'Active redirect probes')
        vulns = []
        payloads = [
            "//attacker.com", "https:attacker.com", "https:///attacker.com",
            "///attacker.com", "http://attacker.com", "https://attacker.com"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{urlencode({param: payload})}"
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
        """Check CORS behavior with an inert Origin header."""
        require_target_in_scope(url)
        vulns = []
        
        try:
            async with self.session.get(url, headers={'Origin': 'http://attacker.com'}, allow_redirects=False) as resp:
                cors_header = resp.headers.get('Access-Control-Allow-Origin', '')
                allows_credentials = resp.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true'
                reflects_origin = cors_header == 'http://attacker.com'
                if reflects_origin or cors_header == '*':
                    # Wildcard ACAO alone is not equivalent to credentialed data exposure.
                    severity = 'HIGH' if reflects_origin and allows_credentials else 'LOW'
                    cvss = 7.5 if severity == 'HIGH' else 2.0
                    vulns.append(WebVuln(
                        url=url, vuln_type='CORS Misconfiguration',
                        severity=severity, cvss=cvss,
                        description='Untrusted origin reflected' if reflects_origin else 'Wildcard CORS policy observed; impact depends on response sensitivity',
                        evidence=f'Access-Control-Allow-Origin: {cors_header}; Access-Control-Allow-Credentials: {allows_credentials}',
                        remediation='Allow only required trusted origins and enable credentialed access only when necessary'
                    ))
        except:
            pass
        
        return vulns
    
    async def test_method_override(self, url: str) -> List[WebVuln]:
        """Test non-GET methods; requires a separate explicit opt-in."""
        require_target_in_scope(url)
        require_feature_enabled('PEN_ENABLE_METHOD_PROBES', 'HTTP method probes')
        vulns = []
        
        methods = ['PUT', 'DELETE', 'PATCH', 'CONNECT', 'TRACE', 'DEBUG']
        
        for method in methods:
            try:
                async with self.session.request(
                    method, url, headers={'X-HTTP-Method-Override': method}, allow_redirects=False
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
    
    async def full_scan(self, url: str, active: bool = False) -> List[WebVuln]:
        """Run passive checks by default; active checks require explicit opt-in.

        Potentially intrusive SSRF, file-read, command-injection, template-injection,
        and HTTP-method checks are intentionally excluded from this aggregate workflow.
        Each requires its own explicit feature flag if invoked directly.
        """
        require_target_in_scope(url)
        if active:
            require_feature_enabled('PEN_ENABLE_ACTIVE_TESTS', 'Active web checks')
        await self.init()
        try:
            tasks = [self.check_security_headers(url), self.test_cors(url)]
            if active:
                tasks.extend([self.test_sqli(url), self.test_xss(url), self.test_open_redirect(url)])
            results = await asyncio.gather(*tasks)
            return [vuln for result in results for vuln in result]
        finally:
            await self.close()
