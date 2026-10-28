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
import sys
from pathlib import Path
from vulnscanner.core import VulnerabilityScanner, quick_scan, full_scan
from vulnscanner.core.attack_modules.remote_agent import run_agent, run_controller


async def run_scan(args):
    """Execute vulnerability scan"""
    print("\n" + "="*60)
    print("  ADVANCED VULNERABILITY SCANNER v2.0")
    print("  Enterprise Security Assessment Platform")
    print("="*60 + "\n")
    
    # Load targets
    targets = []
    target_path = Path(args.target)
    if target_path.exists():
        with open(target_path) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    else:
        targets = [args.target]
    
    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Scan Type: {'Full' if args.full else 'Quick'}")
    print(f"[*] Starting scan...\n")
    
    # Configure scanner
    config = {
        'timeout': args.timeout,
        'verbose': True,
        'full_scan': args.full
    }
    
    scanner = VulnerabilityScanner(config)
    
    # Parse ports
    ports = None
    if args.ports:
        if '-' in args.ports:
            s, e = map(int, args.ports.split('-'))
            ports = list(range(s, e + 1))
        else:
            ports = [int(p) for p in args.ports.split(',')]
    
    # Run scan
    results = await scanner.scan_multiple(targets, ports)
    
    # Generate reports
    print("\n[*] Generating reports...")
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    # Save JSON report
    report = scanner.generate_report(results, 'json')
    with open(output_dir / 'scan_results.json', 'w') as f:
        f.write(report)
    
    # Print summary
    summary = scanner.generate_report(results, 'summary')
    print(summary)
    
    print(f"\n[+] Results saved to: {output_dir}/")


def main():
    parser = argparse.ArgumentParser(description="Advanced Vulnerability Scanner v2.0")
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run vulnerability scan')
    scan_parser.add_argument('-t', '--target', required=True, help='Target IP/host/file')
    scan_parser.add_argument('-p', '--ports', help='Ports (80,443 or 1-1000)')
    scan_parser.add_argument('-o', '--output', default='reports', help='Output directory')
    scan_parser.add_argument('--timeout', type=int, default=10, help='Connection timeout')
    scan_parser.add_argument('--full', action='store_true', help='Full scan with all modules')

    # API command
    api_parser = subparsers.add_parser('api', help='Start REST API server')
    api_parser.add_argument('--host', default='0.0.0.0', help='API host')
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
        asyncio.run(run_scan(args))
    elif args.command == 'api':
        from vulnscanner.api.server import run_server
        print(f"[*] Starting API server on {args.host}:{args.port}")
        run_server(args.host, args.port)
    elif args.command == 'agent':
        print(f"[*] Starting remote agent, connecting to {args.controller}:{args.port}")
        asyncio.run(run_agent(args.controller, args.port))
    elif args.command == 'controller':
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
