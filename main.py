#!/usr/bin/env python3
"""
Advanced Vulnerability Scanner - Security Assessment Tool
Usage Examples:
    python main.py scan -t 192.168.1.1
    python main.py scan -t targets.txt -o reports/
    python main.py api --port 8000
"""

import asyncio
import argparse
import sys
from pathlib import Path

from vulnscanner.core import ScannerEngine, ReportGenerator, ExploitModule


async def run_scan(args):
    """Execute vulnerability scan"""
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║       ADVANCED VULNERABILITY SCANNER v1.0               ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    engine = ScannerEngine(config={'threads': args.workers})
    
    # Load targets
    targets = []
    target_path = Path(args.target)
    if target_path.exists():
        with open(target_path) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    else:
        targets = [args.target]

    # Parse ports
    ports = None
    if args.ports:
        if '-' in args.ports:
            s, e = map(int, args.ports.split('-'))
            ports = list(range(s, e + 1))
        else:
            ports = [int(p) for p in args.ports.split(',')]

    for t in targets:
        engine.add_target(t, ports)

    print(f"[*] Targets: {len(engine.targets)}")
    print(f"[*] Starting scan...\n")

    results = await engine.run_full_scan()
    
    all_vulns = []
    for host, vulns in results.items():
        all_vulns.extend(vulns)

    # Run exploits if requested
    exploits = []
    if args.exploits:
        print("\n[*] Running exploit checks...")
        exp_module = ExploitModule()
        for target in engine.targets:
            exp_results = await exp_module.scan_target(target.host)
            exploits.extend(exp_results)

    # Generate reports
    print("\n[*] Generating reports...")
    reporter = ReportGenerator(all_vulns, exploits)
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    reporter.export_all(str(output_dir))
    print(reporter.generate_executive_summary())

    await engine.close()


def main():
    parser = argparse.ArgumentParser(description="Advanced Vulnerability Scanner")
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run vulnerability scan')
    scan_parser.add_argument('-t', '--target', required=True, help='Target IP/host/file')
    scan_parser.add_argument('-p', '--ports', help='Ports (80,443 or 1-1000)')
    scan_parser.add_argument('-o', '--output', default='reports', help='Output directory')
    scan_parser.add_argument('-w', '--workers', type=int, default=50, help='Workers')
    scan_parser.add_argument('--exploits', action='store_true', help='Run exploits')

    # API command
    api_parser = subparsers.add_parser('api', help='Start REST API server')
    api_parser.add_argument('--host', default='0.0.0.0', help='API host')
    api_parser.add_argument('--port', type=int, default=8000, help='API port')

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
    elif args.command == 'payloads':
        from vulnscanner.core.payloads import PayloadManager
        pm = PayloadManager()
        if args.category:
            payloads = pm.get_payloads(args.category)
            print(f"\n[*] {args.category.upper()} Payloads ({len(payloads)}):")
            for p in payloads[:20]:
                print(f"    {p[:80]}...")
        else:
            print("\n[*] Available Categories:")
            for cat, pls in pm.get_all_payloads().items():
                print(f"    {cat}: {len(pls)} payloads")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
