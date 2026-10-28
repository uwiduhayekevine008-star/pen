import sys
import asyncio
import argparse
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnscanner.core.engine import ScannerEngine, Target, Vulnerability
from vulnscanner.core.exploits import ExploitModule
from vulnscanner.core.reporter import ReportGenerator


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
    parser.add_argument('--exploits', action='store_true', help='Run exploit checks')
    parser.add_argument('--web', action='store_true', help='Focus on web application scanning')
    parser.add_argument('--full', action='store_true', help='Full comprehensive scan')
    parser.add_argument('--format', choices=['json', 'csv', 'html', 'all'], default='all', help='Report format')
    
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║          ADVANCED VULNERABILITY SCANNER v1.0                 ║
║              Security Assessment Tool                        ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    engine = ScannerEngine(config={'threads': args.workers})
    exploit_module = ExploitModule() if args.exploits else None
    
    # Parse targets
    targets = []
    if Path(args.target).exists():
        with open(args.target, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        targets = [args.target]
    
    # Parse ports
    ports = None
    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in args.ports.split(',')]
    
    # Add targets to engine
    for target in targets:
        engine.add_target(target, ports)
    
    print(f"[*] Targets loaded: {len(engine.targets)}")
    print(f"[*] Starting scan at {datetime.now().isoformat()}")
    print("-" * 60)
    
    # Run scans
    all_vulns = []
    all_exploits = []
    
    for target in engine.targets:
        print(f"\n[*] Scanning: {target.host}")
        
        try:
            # Main vulnerability scan
            results = await engine.run_full_scan()
            for host, vulns in results.items():
                all_vulns.extend(vulns)
            
            # Exploit checks
            if exploit_module and args.exploits:
                print(f"[*] Running exploit checks for {target.host}...")
                exploit_results = await exploit_module.scan_target(target.host, ports)
                all_exploits.extend(exploit_results)
                
                for result in exploit_results:
                    status = "[!]" if result.success else "[-]"
                    print(f"  {status} {result.exploit_name}: {result.output[:50]}")
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            break
        except Exception as e:
            print(f"[-] Error scanning {target.host}: {e}")
    
    # Generate reports
    print("\n" + "=" * 60)
    print("[*] Generating reports...")
    
    reporter = ReportGenerator(all_vulns, all_exploits)
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    if args.format == 'all':
        reporter.export_all(str(output_dir))
    elif args.format == 'json':
        reporter.export_json(str(output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"))
    elif args.format == 'csv':
        reporter.export_csv(str(output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"))
    elif args.format == 'html':
        reporter.export_html(str(output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"))
    
    # Print summary
    print("\n" + reporter.generate_executive_summary())
    
    # Close resources
    await engine.close()
    
    print("[+] Scan completed successfully")


if __name__ == '__main__':
    asyncio.run(main())
