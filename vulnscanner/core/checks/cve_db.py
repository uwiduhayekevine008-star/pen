"""CVE Database and Vulnerability Reference System"""
import aiohttp
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CVEInfo:
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    affected_products: List[str]
    exploit_available: bool
    remediation: str
    published: str = ""
    last_modified: str = ""


class CVEDatabase:
    """NVD CVE Database integration"""
    
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, cache_file: str = None):
        self.cache = {}
        self.session = None
    
    async def init(self):
        self.session = aiohttp.ClientSession()
    
    async def close(self):
        if self.session:
            await self.session.close()
    
    async def search_cpe(self, cpe_string: str) -> List[CVEInfo]:
        """Search CVEs by CPE string"""
        results = []
        try:
            async with self.session.get(
                self.NVD_API,
                params={'cpeName': cpe_string},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get('vulnerabilities', [])[:20]:
                        results.append(self._parse_cve(item))
        except:
            pass
        return results
    
    async def search_cve(self, cve_id: str) -> Optional[CVEInfo]:
        """Get specific CVE details"""
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        try:
            async with self.session.get(
                self.NVD_API,
                params={'cveId': cve_id},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    items = data.get('vulnerabilities', [])
                    if items:
                        result = self._parse_cve(items[0])
                        self.cache[cve_id] = result
                        return result
        except:
            pass
        return None
    
    async def search_by_keyword(self, keyword: str) -> List[CVEInfo]:
        """Search CVEs by keyword"""
        results = []
        try:
            async with self.session.get(
                self.NVD_API,
                params={'keywordSearch': keyword},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get('vulnerabilities', [])[:20]:
                        results.append(self._parse_cve(item))
        except:
            pass
        return results
    
    def _parse_cve(self, item: Dict) -> CVEInfo:
        """Parse NVD response into CVEInfo"""
        cve = item['cve']
        
        # Get CVSS score
        metrics = cve.get('metrics', {})
        cvss_data = {}
        
        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
        elif 'cvssMetricV2' in metrics:
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
        
        # Get description
        descriptions = cve.get('descriptions', [])
        desc = descriptions[0]['value'] if descriptions else ''
        
        # Check for exploit references
        references = cve.get('references', [])
        exploit_available = any(
            'exploit' in ref.get('tags', []) or 'Exploit-DB' in ref.get('url', '')
            for ref in references
        )
        
        return CVEInfo(
            cve_id=cve['id'],
            severity=cvss_data.get('baseSeverity', 'UNKNOWN'),
            cvss_score=cvss_data.get('baseScore', 0.0),
            description=desc,
            affected_products=[],
            exploit_available=exploit_available,
            remediation='Apply vendor patches',
            published=cve.get('published', ''),
            last_modified=cve.get('lastModified', '')
        )


class ExploitDatabase:
    """Known exploits database with modern CVEs"""
    
    EXPLOITS = {
        # Critical vulnerabilities
        'CVE-2017-0144': {  # EternalBlue
            'name': 'EternalBlue',
            'service': 'SMB',
            'ports': [445],
            'description': 'SMBv1 RCE vulnerability (MS17-010)',
            'severity': 'CRITICAL',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2019-0708': {  # BlueKeep
            'name': 'BlueKeep',
            'service': 'RDP',
            'ports': [3389],
            'description': 'RDP RCE vulnerability',
            'severity': 'CRITICAL',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2014-0160': {  # Heartbleed
            'name': 'Heartbleed',
            'service': 'OpenSSL',
            'ports': [443],
            'description': 'OpenSSL heartbeat info disclosure',
            'severity': 'CRITICAL',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2021-44228': {  # Log4Shell
            'name': 'Log4Shell',
            'service': 'Log4j',
            'ports': [80, 443, 8080, 8443],
            'description': 'Apache Log4j RCE',
            'severity': 'CRITICAL',
            'cvss': 10.0,
            'exploitable': True
        },
        'CVE-2022-22965': {  # Spring4Shell
            'name': 'Spring4Shell',
            'service': 'Spring',
            'ports': [8080],
            'description': 'Spring Framework RCE',
            'severity': 'CRITICAL',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2021-34473': {  # ProxyShell
            'name': 'ProxyShell',
            'service': 'Exchange',
            'ports': [443],
            'description': 'Exchange Server RCE via Proxy',
            'severity': 'CRITICAL',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2021-34527': {  # PrintNightmare
            'name': 'PrintNightmare',
            'service': 'Print Spooler',
            'ports': [445],
            'description': 'Print Spooler RCE',
            'severity': 'CRITICAL',
            'cvss': 8.8,
            'exploitable': True
        },
        'CVE-2022-41040': {  # ProxyToken
            'name': 'ProxyToken',
            'service': 'Exchange',
            'ports': [443],
            'description': 'Exchange OAB Virtual Directory RCE',
            'severity': 'CRITICAL',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2023-28253': {  # Foxit PDF
            'name': 'Foxit PDF RCE',
            'service': 'Foxit',
            'ports': [80, 443],
            'description': 'Foxit PDF Reader RCE',
            'severity': 'CRITICAL',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2023-46604': {  # ActiveMQ
            'name': 'ActiveMQ RCE',
            'service': 'ActiveMQ',
            'ports': [61616],
            'description': 'Apache ActiveMQ RCE',
            'severity': 'CRITICAL',
            'cvss': 9.8,
            'exploitable': True
        },
        # High severity
        'CVE-2014-6271': {  # Shellshock
            'name': 'Shellshock',
            'service': 'Bash',
            'ports': [80, 443, 22],
            'description': 'Bash environment variable injection',
            'severity': 'HIGH',
            'cvss': 10.0,
            'exploitable': True
        },
        'CVE-2018-7600': {  # Drupalgeddon
            'name': 'Drupalgeddon',
            'service': 'Drupal',
            'ports': [80, 443],
            'description': 'Drupal core RCE',
            'severity': 'HIGH',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2017-5638': {  # Apache Struts
            'name': 'Apache Struts RCE',
            'service': 'Struts',
            'ports': [80, 443],
            'description': 'Apache Struts OGNL injection',
            'severity': 'HIGH',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2019-11043': {  # PHP-FPM
            'name': 'PHP-FPM RCE',
            'service': 'PHP-FPM',
            'ports': [9000, 9001],
            'description': 'PHP-FPM fastcgi header injection',
            'severity': 'HIGH',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2020-5902': {  # F5 BIG-IP
            'name': 'F5 BIG-IP RCE',
            'service': 'F5 BIG-IP',
            'ports': [443],
            'description': 'F5 BIG-IP TMUI RCE',
            'severity': 'HIGH',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2021-21972': {  # vCenter
            'name': 'vCenter RCE',
            'service': 'vCenter',
            'ports': [443],
            'description': 'VMware vCenter RCE',
            'severity': 'HIGH',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2022-26134': {  # Confluence
            'name': 'Confluence RCE',
            'service': 'Confluence',
            'ports': [80, 443],
            'description': 'Atlassian Confluence OGNL injection',
            'severity': 'HIGH',
            'cvss': 9.8,
            'exploitable': True
        },
        'CVE-2022-42894': {  # Spring Cloud
            'name': 'Spring Cloud RCE',
            'service': 'Spring Cloud',
            'ports': [80, 443],
            'description': 'Spring Cloud Function SpEL injection',
            'severity': 'HIGH',
            'cvss': 9.8,
            'exploitable': True
        },
        # Medium severity
        'CVE-2020-11710': {  # WordPress
            'name': 'WordPress REST API',
            'service': 'WordPress',
            'ports': [80, 443],
            'description': 'WordPress REST API data exposure',
            'severity': 'MEDIUM',
            'cvss': 6.1,
            'exploitable': False
        },
        'CVE-2021-22122': {  # Fortinet
            'name': 'Fortinet SSL VPN',
            'service': 'Fortinet',
            'ports': [443],
            'description': 'Fortinet SSL VPN file disclosure',
            'severity': 'MEDIUM',
            'cvss': 6.5,
            'exploitable': True
        },
    }
    
    @classmethod
    def get_exploit(cls, cve_id: str) -> Optional[Dict]:
        return cls.EXPLOITS.get(cve_id)
    
    @classmethod
    def get_by_service(cls, service: str) -> List[Dict]:
        return [
            {'cve': cve, **data}
            for cve, data in cls.EXPLOITS.items()
            if data['service'].lower() == service.lower()
        ]
    
    @classmethod
    def get_by_port(cls, port: int) -> List[Dict]:
        return [
            {'cve': cve, **data}
            for cve, data in cls.EXPLOITS.items()
            if port in data['ports']
        ]
    
    @classmethod
    def get_critical_exploits(cls) -> List[Dict]:
        return [
            {'cve': cve, **data}
            for cve, data in cls.EXPLOITS.items()
            if data['severity'] == 'CRITICAL'
        ]
    
    @classmethod
    def get_exploitable(cls) -> List[Dict]:
        return [
            {'cve': cve, **data}
            for cve, data in cls.EXPLOITS.items()
            if data.get('exploitable', False)
        ]
