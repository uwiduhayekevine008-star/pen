"""Main Scanner Orchestrator - Unified Interface"""
import asyncio
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import os

from vulnscanner.security import (
    ScopeError, require_target_in_scope, validate_targets, validate_ports,
    require_feature_enabled,
)


@dataclass
class ScanResult:
    target: str
    ports: Dict
    vulnerabilities: List
    exploits: List
    scan_time: str
    risk_score: float = 0.0


class VulnerabilityScanner:
    """Main vulnerability scanner orchestrator"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.verbose = self.config.get('verbose', False)
    
    async def scan_host(self, host: str, ports: List[int] = None) -> ScanResult:
        """Run a scoped scan of a single host using passive checks by default."""
        validate_targets([host])
        if '://' in host or '/' in host:
            raise ScopeError('This scanner entry point expects a hostname or IP, not a URL or CIDR')
        require_target_in_scope(host)
        ports = validate_ports(ports)
        start_time = datetime.now()
        
        # 1. Port scan
        if self.verbose:
            print(f"[*] Scanning ports on {host}")
        
        from vulnscanner.core.scanners.network import NetworkScanner
        port_scanner = NetworkScanner(timeout=self.timeout)
        open_ports = await port_scanner.scan_ports(host, ports)
        
        # Service-specific protocol commands (e.g. FTP anonymous login or Redis INFO)
        # are opt-in. The default scan uses banner/service detection only.
        service_vulns = []
        if self.config.get('enable_service_probes'):
            require_feature_enabled('PEN_ENABLE_SERVICE_PROBES', 'Service-specific probes')
            if self.verbose:
                print(f"[*] Running explicitly enabled service probes on {host}")
            from vulnscanner.core.checks.services import check_service
            for port, service_info in open_ports.items():
                vulns = await check_service(host, port, service_info.service)
                service_vulns.extend(vulns)
        
        # 3. Web application scanning
        web_vulns = []
        for port, service_info in open_ports.items():
            if service_info.service in ['http', 'https', 'http-proxy']:
                if self.verbose:
                    print(f"[*] Web scanning {host}:{port}")
                
                from vulnscanner.core.scanners.web import WebScanner
                web_scanner = WebScanner(timeout=self.timeout)
                protocol = 'https' if 'https' in service_info.service or port == 443 else 'http'
                url = f"{protocol}://{host}:{port}"
                
                vulns = await web_scanner.full_scan(url, active=bool(self.config.get('enable_active_tests')))
                web_vulns.extend(vulns)
        
        # 4. SSL/TLS analysis
        ssl_vulns = []
        if 443 in open_ports or any('https' in open_ports[p].service for p in open_ports):
            if self.verbose:
                print(f"[*] SSL/TLS analysis on {host}")
            
            from vulnscanner.core.scanners.ssl_analyzer import SSLAnalyzer
            ssl_analyzer = SSLAnalyzer(timeout=self.timeout)
            ssl_vulns = ssl_analyzer.full_analysis(host, 443)
        
        # 5. Directory scanning for web services
        dir_vulns = []
        if self.config.get('full_scan'):
            require_feature_enabled('PEN_ENABLE_DIRECTORY_DISCOVERY', 'Directory discovery')
            for port in [80, 443, 8080]:
                if port in open_ports:
                    from vulnscanner.core.scanners.directory import DirectoryScanner
                    dir_scanner = DirectoryScanner(timeout=5, threads=10)
                    protocol = 'https' if port == 443 else 'http'
                    url = f"{protocol}://{host}:{port}"
                    
                    files = await dir_scanner.scan_files(url)
                    for f in files:
                        if f.is_sensitive:
                            dir_vulns.append({
                                'type': 'Sensitive File Exposed',
                                'severity': f.risk,
                                'url': f.url,
                                'description': f'Sensitive file accessible: {f.url}'
                            })
        
        # 6. Active exploit checks are never part of the default scan.
        exploit_results = []
        if self.config.get('enable_exploit_checks'):
            require_feature_enabled('PEN_ENABLE_EXPLOIT_CHECKS', 'Exploit checks')
            if self.verbose:
                print(f"[*] Running explicitly enabled exploit checks on {host}")
            from vulnscanner.core.checks.exploits import ExploitScanner
            exploit_scanner = ExploitScanner(timeout=self.timeout)
            try:
                exploit_results = await exploit_scanner.full_scan(host, open_ports)
            finally:
                await exploit_scanner.close()
        
        # Compile results
        all_vulns = []
        all_vulns.extend([v.__dict__ for v in service_vulns])
        all_vulns.extend([v.__dict__ for v in web_vulns])
        all_vulns.extend([v.__dict__ for v in ssl_vulns])
        all_vulns.extend(dir_vulns)
        
        exploits = [e.__dict__ for e in exploit_results if e.vulnerable]
        
        # Calculate risk score
        risk_score = self._calculate_risk(all_vulns, exploits)
        
        return ScanResult(
            target=host,
            ports={p: {'service': s.service, 'state': s.state} for p, s in open_ports.items()},
            vulnerabilities=all_vulns,
            exploits=exploits,
            scan_time=datetime.now().isoformat(),
            risk_score=risk_score
        )
    
    def _calculate_risk(self, vulns: List, exploits: List) -> float:
        """Calculate overall risk score"""
        severity_weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        
        vuln_score = sum(
            severity_weights.get(v.get('severity', 'LOW'), 1)
            for v in vulns
        )
        
        exploit_score = len(exploits) * 10
        
        return min(100, vuln_score + exploit_score)
    
    async def scan_multiple(self, targets: List[str], ports: List[int] = None) -> List[ScanResult]:
        """Scan a bounded, in-scope target batch with limited concurrency."""
        targets = validate_targets(targets)
        ports = validate_ports(ports)
        try:
            limit = int(os.getenv('PEN_MAX_CONCURRENT_TARGETS', '2'))
        except ValueError:
            limit = 2
        limit = min(max(1, limit), 10)
        semaphore = asyncio.Semaphore(limit)

        async def limited_scan(target: str) -> ScanResult:
            async with semaphore:
                return await self.scan_host(target, ports)

        return list(await asyncio.gather(*(limited_scan(target) for target in targets)))
    
    def generate_report(self, results: List[ScanResult], output_format: str = 'json') -> str:
        """Generate scan report"""
        if output_format == 'json':
            return json.dumps([{
                'target': r.target,
                'ports': r.ports,
                'vulnerabilities': r.vulnerabilities,
                'exploits': r.exploits,
                'risk_score': r.risk_score,
                'scan_time': r.scan_time
            } for r in results], indent=2, default=str)
        
        elif output_format == 'summary':
            lines = ["=" * 60, "VULNERABILITY SCAN REPORT", "=" * 60]
            
            for r in results:
                lines.append(f"\nTarget: {r.target}")
                lines.append(f"Open Ports: {len(r.ports)}")
                lines.append(f"Vulnerabilities: {len(r.vulnerabilities)}")
                lines.append(f"Exploits Found: {len(r.exploits)}")
                lines.append(f"Risk Score: {r.risk_score}/100")
                
                if r.vulnerabilities:
                    lines.append("\n  Vulnerabilities:")
                    for v in r.vulnerabilities:
                        lines.append(f"    - [{v.get('severity', 'INFO')}] {v.get('vuln_type', v.get('issue', 'Unknown'))}")
            
            return "\n".join(lines)
        
        return ""


async def quick_scan(target: str) -> ScanResult:
    """Quick vulnerability scan"""
    scanner = VulnerabilityScanner({'timeout': 5, 'verbose': True})
    return await scanner.scan_host(target)


async def full_scan(target: str) -> ScanResult:
    """Full vulnerability scan with all modules"""
    scanner = VulnerabilityScanner({'timeout': 10, 'verbose': True, 'full_scan': True})
    return await scanner.scan_host(target)
