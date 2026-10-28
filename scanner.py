import asyncio
import argparse
from datetime import datetime
from pathlib import Path

from vulnscanner.core.engine import ScannerEngine
from vulnscanner.core.exploits import ExploitModule
from vulnscanner.core.reporter import ReportGenerator
from vulnscanner.security import ScopeError, require_feature_enabled, validate_ports, validate_targets


async def main():
    parser = argparse.ArgumentParser(
        description='Advanced Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python scanner.py -t 192.168.1.1
  python scanner.py -t 192.168.1.1 -p 80,443,8080
  python scanner.py -t targets.txt -o reports/
  python scanner.py -t 192.168.1.0/24 --exploits
        '''
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP, hostname, CIDR, or file with targets')
    parser.add_argument('-p', '--ports', default=None, help='Ports to scan (comma-separated or range)')
    parser.add_argument('-o', '--output', default='reports', help='Output directory for reports')
    parser.add_argument('-w', '--workers', type=int, default=50, help='Number of concurrent workers')
    parser.add_argument('--exploits', action='store_true', help='Run exploit checks (requires PEN_ENABLE_EXPLOIT_CHECKS=1)')
    parser.add_argument('--active-tests', action='store_true', help='Enable limited active web probes (requires PEN_ENABLE_ACTIVE_TESTS=1)')
    parser.add_argument('--web', action='store_true', help='Focus on web application checks (uses passive checks unless --active-tests is set)')
    parser.add_argument('--full', action='store_true', help='Full comprehensive scan')
    parser.add_argument('--format', choices=['json', 'csv', 'html', 'all'], default='all', help='Report format')
    
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║          ADVANCED VULNERABILITY SCANNER v1.0                 ║
║              Security Assessment Tool                        ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if args.workers < 1 or args.workers > 100:
        parser.error('--workers must be between 1 and 100')
    if args.active_tests:
        require_feature_enabled('PEN_ENABLE_ACTIVE_TESTS', 'Active web checks')
    if args.exploits:
        require_feature_enabled('PEN_ENABLE_EXPLOIT_CHECKS', 'Exploit checks')

    # Parse targets and enforce the authorization allowlist before connecting.
    target_path = Path(args.target)
    if target_path.is_file():
        with target_path.open('r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip() and not line.lstrip().startswith('#')]
    else:
        targets = [args.target]
    targets = validate_targets(targets)
    if args.exploits and any('/' in target or '://' in target for target in targets):
        parser.error('Exploit checks require individual hostnames or IP addresses, not CIDR ranges or URLs')

    engine = ScannerEngine(config={'threads': args.workers, 'enable_active_tests': args.active_tests})
    exploit_module = ExploitModule() if args.exploits else None
    
    # Parse ports
    ports = None
    if args.ports:
        if '-' in args.ports:
            parts = args.ports.split('-')
            if len(parts) != 2:
                parser.error('Use a port range such as 80-443')
            start, end = map(int, parts)
            if start < 1 or end > 65535 or start > end or end - start + 1 > 100:
                parser.error('Port ranges must be ordered and contain at most 100 ports')
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        ports = validate_ports(ports, maximum=100)
    
    # Add the target batch once, then execute a single scan pass.
    for target in targets:
        engine.add_target(target, ports)
    
    print(f"[*] Targets loaded: {len(engine.targets)}")
    print(f"[*] Starting scan at {datetime.now().isoformat()}")
    print("-" * 60)
    
    # Run scans
    all_vulns = []
    all_exploits = []
    
    try:
        results = await engine.run_full_scan()
        for host_vulns in results.values():
            all_vulns.extend(host_vulns)

        if exploit_module:
            for target in targets:
                print(f"\n[*] Running explicitly enabled exploit checks for {target}...")
                exploit_results = await exploit_module.scan_target(target, ports)
                all_exploits.extend(exploit_results)
                for result in exploit_results:
                    status = "[!]" if result.success else "[-]"
                    print(f"  {status} {result.exploit_name}: {result.output[:50]}")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    finally:
        await engine.close()
    
    # Generate reports
    print("\n" + "=" * 60)
    print("[*] Generating reports...")
    
    reporter = ReportGenerator(all_vulns, all_exploits)
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    report_stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if args.format == 'all':
        reporter.export_all(str(output_dir))
    elif args.format == 'json':
        reporter.export_json(str(output_dir / f"report_{report_stamp}.json"))
    elif args.format == 'csv':
        reporter.export_csv(str(output_dir / f"report_{report_stamp}.csv"))
    elif args.format == 'html':
        reporter.export_html(str(output_dir / f"report_{report_stamp}.html"))
    
    # Print summary
    print("\n" + reporter.generate_executive_summary())
    
    print("[+] Scan completed successfully")


if __name__ == '__main__':
    asyncio.run(main())
