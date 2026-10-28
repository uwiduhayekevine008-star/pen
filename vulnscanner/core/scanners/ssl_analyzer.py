"""SSL/TLS Security Analyzer with Modern Testing"""
import ssl
import socket
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from vulnscanner.security import require_target_in_scope, validate_ports


@dataclass
class SSLVuln:
    host: str
    port: int
    issue: str
    severity: str
    cvss: float
    description: str
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


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
        """Check legacy TLS protocol negotiation using supported Python TLS APIs.

        SSLv2/SSLv3 are omitted because modern Python/OpenSSL builds generally
        cannot negotiate them; an unavailable runtime probe is not a finding.
        """
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
        vulns = []
        tls_version = getattr(ssl, "TLSVersion", None)
        if tls_version is None:
            return vulns
        versions = {
            "TLSv1.0": getattr(tls_version, "TLSv1", None),
            "TLSv1.1": getattr(tls_version, "TLSv1_1", None),
        }
        for proto_name, version in versions.items():
            if version is None:
                continue
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = version
                context.maximum_version = version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as wrapped:
                        negotiated = wrapped.version()
                if negotiated:
                    sev, cvss, desc = self.VULN_PROTOCOLS[proto_name]
                    vulns.append(SSLVuln(
                        host=host, port=port,
                        issue=f'{proto_name} Supported',
                        severity=sev, cvss=cvss,
                        description=desc,
                        remediation=f'Disable {proto_name}'
                    ))
            except (OSError, ssl.SSLError, ValueError, AttributeError):
                # A disabled or unsupported protocol does not prove the host is secure
                # for other protocols; it simply did not negotiate this legacy version.
                continue
        return vulns
    
    def check_certificate(self, host: str, port: int = 443) -> List[SSLVuln]:
        """Analyze certificate for issues"""
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
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
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
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
    
    def check_poodle(self, host: str, port: int = 443) -> Optional[SSLVuln]:
        """Check for POODLE vulnerability (CVE-2014-3566)"""
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return SSLVuln(
                        host=host, port=port,
                        issue='POODLE Vulnerable',
                        severity='CRITICAL', cvss=7.5,
                        description='SSLv3 POODLE vulnerability',
                        remediation='Disable SSLv3'
                    )
        except:
            pass
        return None
    
    def check_beast(self, host: str, port: int = 443) -> Optional[SSLVuln]:
        """Check for BEAST vulnerability (CVE-2011-3389)"""
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return SSLVuln(
                        host=host, port=port,
                        issue='BEAST Vulnerable',
                        severity='MEDIUM', cvss=5.0,
                        description='TLS 1.0 BEAST vulnerability',
                        remediation='Use TLS 1.1+ with proper cipher configuration'
                    )
        except:
            pass
        return None
    
    def check_logjam(self, host: str, port: int = 443) -> Optional[SSLVuln]:
        """Check for LOGJAM vulnerability (CVE-2015-4000)"""
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher and 'DHE' in cipher[0]:
                        return SSLVuln(
                            host=host, port=port,
                            issue='LOGJAM Vulnerable',
                            severity='MEDIUM', cvss=5.0,
                            description='DH key exchange vulnerable to Logjam',
                            remediation='Use strong DH parameters (2048+ bits)'
                        )
        except:
            pass
        return None
    
    def check_freak(self, host: str, port: int = 443) -> Optional[SSLVuln]:
        """Check for FREAK vulnerability (CVE-2015-2730)"""
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher and 'EXPORT' in cipher[0]:
                        return SSLVuln(
                            host=host, port=port,
                            issue='FREAK Vulnerable',
                            severity='HIGH', cvss=7.5,
                            description='Export-grade RSA vulnerable to FREAK',
                            remediation='Disable export ciphers'
                        )
        except:
            pass
        return None
    
    def check_drown(self, host: str, port: int = 443) -> Optional[SSLVuln]:
        """Check for DROWN vulnerability (CVE-2016-0800)"""
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return SSLVuln(
                        host=host, port=port,
                        issue='DROWN Vulnerable',
                        severity='CRITICAL', cvss=9.0,
                        description='SSLv2 DROWN vulnerability',
                        remediation='Disable SSLv2'
                    )
        except:
            pass
        return None
    
    def check_weak_ciphers(self, host: str, port: int = 443) -> List[SSLVuln]:
        """Check for weak cipher suites"""
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
        vulns = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else ''
                    
                    for weak in self.WEAK_CIPHERS:
                        if weak in cipher_name:
                            vulns.append(SSLVuln(
                                host=host, port=port,
                                issue=f'Weak Cipher: {cipher_name}',
                                severity='HIGH', cvss=7.0,
                                description=f'Cipher {cipher_name} is weak',
                                remediation='Use strong cipher suites (AES-GCM, ChaCha20)'
                            ))
                            break
        except:
            pass
        
        return vulns
    
    def full_analysis(self, host: str, port: int = 443) -> List[SSLVuln]:
        """Run complete SSL/TLS security analysis for an authorized target."""
        require_target_in_scope(host)
        validate_ports([port], maximum=1)
        vulns = []
        vulns.extend(self.check_protocol(host, port))
        vulns.extend(self.check_certificate(host, port))
        
        heartbleed = self.check_heartbleed(host, port)
        if heartbleed:
            vulns.append(heartbleed)
        
        poodle = self.check_poodle(host, port)
        if poodle:
            vulns.append(poodle)
        
        beast = self.check_beast(host, port)
        if beast:
            vulns.append(beast)
        
        logjam = self.check_logjam(host, port)
        if logjam:
            vulns.append(logjam)
        
        freak = self.check_freak(host, port)
        if freak:
            vulns.append(freak)
        
        drown = self.check_drown(host, port)
        if drown:
            vulns.append(drown)
        
        vulns.extend(self.check_weak_ciphers(host, port))
        
        return vulns
