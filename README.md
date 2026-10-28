# Vulnerability Scanner

Python-based security assessment tooling for authorized systems only.

## Install

    python -m pip install -r requirements.txt

Install Nmap separately if you want the Nmap-backed scanner engine.

## Configure authorized scope first

All scan entry points fail closed unless PEN_ALLOWED_TARGETS is configured. Use only assets covered by written authorization. Scope entries may be exact IP addresses, CIDR ranges, exact hostnames, or DNS wildcards.

    # Examples use documentation-only TEST-NET addresses. Replace with approved assets.
    export PEN_ALLOWED_TARGETS="192.0.2.10,192.0.2.0/24,app.example.org,*.internal.example.org"

The default limits are 25 targets per batch, 256 addresses per CIDR, and 100 explicit ports. Adjust PEN_MAX_TARGETS or PEN_MAX_CIDR_ADDRESSES only as needed for an approved engagement. A universal wildcard is rejected. Targets outside the allowlist are rejected before network activity. Hostname entries are matched by name; ensure approved DNS records resolve only to assets covered by the authorization.

## CLI

Safe default scan: scoped TCP port/service discovery and passive web checks.

    python main.py scan -t 192.0.2.10
    python main.py scan -t 192.0.2.10 -p 80,443,8080
    python main.py scan -t targets.txt -o reports/

Target files contain one host or IP per line. Blank lines and comment lines are ignored. Target batches, CIDR sizes, port values, and timeouts are bounded. Reports are timestamped so a new run does not silently overwrite the most recent JSON report.

### Active checks are opt-in

The default scan does not run exploit checks or active web payload tests.

    # Limited active web probes
    export PEN_ENABLE_ACTIVE_TESTS=1
    python main.py scan -t 192.0.2.10 --active-tests

    # Limited exploit-check workflow; unverified high-impact payload probes are disabled
    export PEN_ENABLE_EXPLOIT_CHECKS=1
    python main.py scan -t 192.0.2.10 --exploits

    # Directory/file discovery (issues multiple HTTP GET requests)
    export PEN_ENABLE_DIRECTORY_DISCOVERY=1
    python main.py scan -t 192.0.2.10 --full

    # Protocol-specific service checks (e.g. FTP anonymous login or Redis INFO)
    export PEN_ENABLE_SERVICE_PROBES=1
    python main.py scan -t 192.0.2.10 --service-probes

The lower-level web scanner keeps file-read, SSRF, command-injection, template-injection, and method probes behind separate flags: PEN_ENABLE_FILE_READ_PROBES, PEN_ENABLE_SSRF_PROBES, PEN_ENABLE_COMMAND_INJECTION_PROBES, PEN_ENABLE_TEMPLATE_INJECTION_PROBES, and PEN_ENABLE_METHOD_PROBES. These checks are excluded from the aggregate scan. Protocol-level service checks are also excluded by default; enable them separately with PEN_ENABLE_SERVICE_PROBES=1. Set these flags only for specifically approved tests on controlled targets.

## API

The REST API binds to loopback by default. When binding directly to a remote interface, PEN_ALLOW_REMOTE_API=1 plus existing certificate and private-key files configured by PEN_API_TLS_CERTFILE and PEN_API_TLS_KEYFILE are required, and network-layer access controls are still necessary. If TLS terminates at a reverse proxy, keep this API bound to loopback behind that proxy rather than exposing its plain HTTP port.

    export PEN_ALLOWED_TARGETS="192.0.2.10"
    export PEN_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    python main.py api --host 127.0.0.1 --port 8000

Include the token in the X-API-Key header for all scan, results, payload and exploit-list endpoints.

    curl -H "X-API-Key: $PEN_API_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"targets":["192.0.2.10"],"ports":[80,443],"scan_type":"safe"}' \
      http://127.0.0.1:8000/scan

The API rejects requests until PEN_API_TOKEN is configured. Interactive API docs are disabled unless PEN_ENABLE_API_DOCS=1. CORS origins are disabled by default; set PEN_CORS_ORIGINS to a comma-separated list of exact trusted origins when browser access is required. Do not use wildcard CORS for a credentialed scanner interface.

API requests are bounded to 25 targets and 100 explicit ports; a default maximum of two scans can run at once. Scan type must be safe or active; active mode additionally requires PEN_ENABLE_ACTIVE_TESTS=1. Setting run_exploits to true additionally requires PEN_ENABLE_EXPLOIT_CHECKS=1.

## Remote agents and dashboard

Both services are disabled by default and restricted to loopback because their transport does not provide a production TLS channel.

For local-only use, configure a random shared secret first:

    export PEN_ENABLE_REMOTE_AGENTS=1
    export PEN_AGENT_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

Remote agent task execution validates targets against PEN_ALLOWED_TARGETS. Exploit tasks need PEN_ENABLE_EXPLOIT_CHECKS=1. The legacy dashboard may perform network discovery only when PEN_ENABLE_NETWORK_DISCOVERY=1. To connect agents across machines, use a properly authenticated SSH tunnel or implement and review a TLS/mutual-auth transport; do not expose the TCP services directly to an untrusted network.

The WebSocket dashboard is local-only and disabled by default:

    export PEN_ENABLE_DASHBOARD=1

## Python library

    import asyncio
    from vulnscanner.core.engine import ScannerEngine

    async def scan():
        engine = ScannerEngine()
        try:
            engine.add_target("192.0.2.10", [80, 443])
            return await engine.run_full_scan()
        finally:
            await engine.close()

    asyncio.run(scan())

The PEN_ALLOWED_TARGETS environment variable is required for the library as well as the CLI and API.

## Current capabilities and limitations

- TCP port and service discovery, with bounded concurrency.
- Security-header checks and basic CORS checks.
- CVE reference lookup through NVD where service fingerprint data is available.
- SSL/TLS configuration checks and JSON/CSV/HTML report support.
- Limited active probes behind explicit environment flags. Service-specific commands and exploit modules remain disabled unless explicitly enabled.
- Built-in Heartbleed, Spring4Shell and Log4Shell probes that did not verify vulnerability safely are disabled and report an inconclusive/not-tested status rather than sending their former payloads.
- No persistence database, organization/tenant model, audit-log store, or user/role management is included yet.
- Findings from heuristic banner/protocol checks require manual validation. A check result is not proof of exploitability.
- The remote agent transport is designed for loopback/tunnel use only; it is not a standalone, production-ready distributed-control protocol.

## Safe operation

1. Obtain written authorization and record the approved target list and time window.
2. Start with the safe scan type and review the expected request volume.
3. Enable active checks individually only where approved.
4. Retain scan reports securely; they may contain hostnames, service banners and vulnerability evidence.
