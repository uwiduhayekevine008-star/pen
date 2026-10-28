#!/usr/bin/env python3
"""
Advanced Vulnerability Scanner v2.0
Enterprise Security Assessment Platform
Usage:
    python main.py scan -t 192.168.1.1
    python main.py scan -t targets.txt -o reports/
    python main.py api --port 8000
    python main.py agent --controller 192.168.1.100
"""

import asyncio
import argparse
import os
from datetime import datetime, timezone
from pathlib import Path
from vulnscanner.core import VulnerabilityScanner
from vulnscanner.core.attack_modules.remote_agent import run_agent, run_controller
from vulnscanner.security import (
    ScopeError, require_feature_enabled, validate_ports, validate_targets,
)


async def run_scan(args):
    """Execute vulnerability scan"""
    print("\n" + "="*60)
    print("  ADVANCED VULNERABILITY SCANNER v2.0")
    print("  Enterprise Security Assessment Platform")
    print("="*60 + "\n")
    
    # Load and validate targets before any network activity.
    target_path = Path(args.target)
    if target_path.is_file():
        with target_path.open(encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip() and not line.lstrip().startswith('#')]
    else:
        targets = [args.target]
    targets = validate_targets(targets)
    if any('://' in target or '/' in target for target in targets):
        raise ScopeError('CLI scanner expects hostnames or IP addresses, not URLs or CIDR ranges')
    
    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Scan Type: {'Full' if args.full else 'Quick'}")
    print(f"[*] Starting scan...\n")
    
    # Configure scanner
    config = {
        'timeout': args.timeout,
        'verbose': True,
        'full_scan': args.full,
        'enable_active_tests': args.active_tests,
        'enable_exploit_checks': args.exploits,
        'enable_service_probes': args.service_probes,
    }
    if args.timeout < 1 or args.timeout > 60:
        raise ScopeError('Timeout must be between 1 and 60 seconds')
    if args.active_tests:
        require_feature_enabled('PEN_ENABLE_ACTIVE_TESTS', 'Active web checks')
    if args.exploits:
        require_feature_enabled('PEN_ENABLE_EXPLOIT_CHECKS', 'Exploit checks')
    if args.service_probes:
        require_feature_enabled('PEN_ENABLE_SERVICE_PROBES', 'Service-specific probes')
    if args.full:
        require_feature_enabled('PEN_ENABLE_DIRECTORY_DISCOVERY', 'Directory discovery')
    
    scanner = VulnerabilityScanner(config)
    
    # Parse ports
    ports = None
    if args.ports:
        if '-' in args.ports:
            parts = args.ports.split('-')
            if len(parts) != 2:
                raise ScopeError('Use a port range such as 80-443')
            s, e = map(int, parts)
            if s < 1 or e > 65535 or s > e or e - s + 1 > 100:
                raise ScopeError('Port ranges must be ordered and contain at most 100 ports')
            ports = list(range(s, e + 1))
        else:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        ports = validate_ports(ports, maximum=100)
    
    # Run scan
    results = await scanner.scan_multiple(targets, ports)
    
    # Generate reports
    print("\n[*] Generating reports...")
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save JSON report
    report = scanner.generate_report(results, 'json')
    report_path = output_dir / f"scan_results_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    with report_path.open('w', encoding='utf-8') as f:
        f.write(report)
    
    # Print summary
    summary = scanner.generate_report(results, 'summary')
    print(summary)
    
    print(f"\n[+] Results saved to: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="Advanced Vulnerability Scanner v2.0")
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run vulnerability scan')
    scan_parser.add_argument('-t', '--target', required=True, help='Target IP/host/file')
    scan_parser.add_argument('-p', '--ports', help='Ports (80,443 or 1-1000)')
    scan_parser.add_argument('-o', '--output', default='reports', help='Output directory')
    scan_parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (1-60 seconds)')
    scan_parser.add_argument('--full', action='store_true', help='Include directory discovery (requires PEN_ENABLE_DIRECTORY_DISCOVERY=1)')
    scan_parser.add_argument('--active-tests', action='store_true', help='Enable limited active web probes (requires PEN_ENABLE_ACTIVE_TESTS=1)')
    scan_parser.add_argument('--exploits', action='store_true', help='Enable exploit checks (requires PEN_ENABLE_EXPLOIT_CHECKS=1)')
    scan_parser.add_argument('--service-probes', action='store_true', help='Enable protocol-level checks such as anonymous FTP (requires PEN_ENABLE_SERVICE_PROBES=1)')

    # API command
    api_parser = subparsers.add_parser('api', help='Start REST API server')
    api_parser.add_argument('--host', default='127.0.0.1', help='API host (loopback by default)')
    api_parser.add_argument('--port', type=int, default=8000, help='API port')

    # Agent command
    agent_parser = subparsers.add_parser('agent', help='Run remote scanning agent')
    agent_parser.add_argument('--controller', required=True, help='Controller host')
    agent_parser.add_argument('--port', type=int, default=9999, help='Controller port')

    # Controller command
    controller_parser = subparsers.add_parser('controller', help='Run agent controller')
    controller_parser.add_argument('--port', type=int, default=9999, help='Listen port')

    # Payloads command
    payload_parser = subparsers.add_parser('payloads', help='List payloads')
    payload_parser.add_argument('category', nargs='?', help='Payload category')

    args = parser.parse_args()

    if args.command == 'scan':
        try:
            asyncio.run(run_scan(args))
        except ScopeError as exc:
            parser.error(str(exc))
    elif args.command == 'api':
        from vulnscanner.api.server import run_server
        print(f"[*] Starting API server on {args.host}:{args.port}")
        run_server(args.host, args.port)
    elif args.command == 'agent':
        require_feature_enabled('PEN_ENABLE_REMOTE_AGENTS', 'Remote scanning agents')
        print(f"[*] Starting remote agent, connecting to {args.controller}:{args.port}")
        asyncio.run(run_agent(args.controller, args.port))
    elif args.command == 'controller':
        require_feature_enabled('PEN_ENABLE_REMOTE_AGENTS', 'Remote scanning agents')
        print(f"[*] Starting agent controller on port {args.port}")
        asyncio.run(run_controller(args.port))
    elif args.command == 'payloads':
        from vulnscanner.core.checks.payloads import AdvancedPayloads
        pm = AdvancedPayloads()
        if args.category:
            payloads = pm.get_all_categories().get(args.category, [])
            print(f"\n[*] {args.category.upper()} Payloads ({len(payloads)}):")
            for p in payloads[:20]:
                print(f"    {p[:80]}")
        else:
            print("\n[*] Available Categories:")
            for cat, pls in pm.get_all_categories().items():
                print(f"    {cat}: {len(pls)} payloads")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
