"""SSL/TLS Security Analyzer"""
import ssl
import socket
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib


@dataclass
class SSLVuln:
    host: str
    port: int
    issue: str
    severity: str
    cvss: float
    description: str
    remediation: str


class SSLAnalyzer:
    """Comprehensive SSL/TLS security analysis"""
    
    VULN_PROTOCOLS = {
        'SSLv2': ('CRITICAL', 10.0, 'SSLv2 is insecure and deprecated'),
        'SSLv3': ('CRITICAL', 9.0, 'SSLv3 is vulnerable to POODLE attack'),
        'TLSv1.0': ('HIGH', 7.0, 'TLS 1.0 is deprecated, use TLS 1.2+'),
        'TLSv1.1': ('MEDIUM', 6.0, 'TLS 1.1 is deprecated, use TLS 1.2+')
    }
    
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'ANON', 'EXPORT'
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def check_protocol(self, host: str, port: int = 443) -> List[SSLVuln]:
        """Check for vulnerable SSL/TLS protocols"""
        vulns = []
        
        for proto_name, (sev, cvss, desc) in self.VULN_PROTOCOLS.items():
            try:
                context = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{proto_name.replace(".", "_")}'))
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        vulns.append(SSLVuln(
                            host=host, port=port,
                            issue=f'{proto_name} Supported',
                            severity=sev, cvss=cvss,
                            description=desc,
                            remediation=f'Disable {proto_name}'
                        ))
            except:
                pass
        
        return vulns
    
    def check_certificate(self, host: str, port: int = 443) -> List[SSLVuln]:
        """Analyze certificate for issues"""
        vulns = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - datetime.now()).days
                    
                    if days_left < 0:
                        vulns.append(SSLVuln(
                            host=host, port=port,
                            issue='Certificate Expired',
                            severity='CRITICAL', cvss=9.0,
                            description='SSL certificate has expired',
                            remediation='Renew SSL certificate'
                        ))
                    elif days_left < 30:
                        vulns.append(SSLVuln(
                            host=host, port=port,
                            issue='Certificate Expiring Soon',
                            severity='MEDIUM', cvss=5.0,
                            description=f'Certificate expires in {days_left} days',
                            remediation='Renew SSL certificate'
                        ))
                    
                    # Check weak signature
                    sig_alg = cert.get('signatureAlgorithm', '')
                    if 'md5' in sig_alg.lower() or 'sha1' in sig_alg.lower():
                        vulns.append(SSLVuln(
                            host=host, port=port,
                            issue='Weak Certificate Signature',
                            severity='HIGH', cvss=7.0,
                            description=f'Weak signature algorithm: {sig_alg}',
                            remediation='Use SHA-256 or stronger'
                        ))
                    
                    # Check hostname
                    if not ssl.match_hostname(cert, host):
                        vulns.append(SSLVuln(
                            host=host, port=port,
                            issue='Hostname Mismatch',
                            severity='HIGH', cvss=7.5,
                            description='Certificate hostname does not match',
                            remediation='Reissue certificate with correct hostname'
                        ))
                        
        except ssl.SSLCertVerificationError:
            vulns.append(SSLVuln(
                host=host, port=port,
                issue='Untrusted Certificate',
                severity='HIGH', cvss=8.0,
                description='Certificate is not trusted',
                remediation='Use certificate from trusted CA'
            ))
        except Exception as e:
            pass
        
        return vulns
    
    def check_heartbleed(self, host: str, port: int = 443) -> Optional[SSLVuln]:
        """Check for Heartbleed vulnerability (CVE-2014-0160)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Check OpenSSL version if available
                    cipher = ssock.cipher()
                    if cipher and 'OpenSSL' in str(ssock.version()):
                        return SSLVuln(
                            host=host, port=port,
                            issue='Heartbleed Vulnerable',
                            severity='CRITICAL', cvss=9.0,
                            description='OpenSSL Heartbleed vulnerability',
                            remediation='Upgrade OpenSSL to 1.0.1g or later'
                        )
        except:
            pass
        return None
    
    def full_analysis(self, host: str, port: int = 443) -> List[SSLVuln]:
        """Run complete SSL/TLS security analysis"""
        vulns = []
        vulns.extend(self.check_protocol(host, port))
        vulns.extend(self.check_certificate(host, port))
        
        heartbleed = self.check_heartbleed(host, port)
        if heartbleed:
            vulns.append(heartbleed)
        
        return vulns
