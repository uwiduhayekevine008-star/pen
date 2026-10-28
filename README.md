# Vulnerability Scanner

Enterprise-grade security vulnerability assessment tool.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### CLI Scanner

```bash
# Basic scan
python main.py scan -t 192.168.1.1

# Scan with custom ports
python main.py scan -t 192.168.1.1 -p 80,443,8080

# Scan from file
python main.py scan -t targets.txt -o reports/

# Full scan with exploits
python main.py scan -t 192.168.1.1 --exploits
```

### API Server

```bash
python main.py api --port 8000
```

API Endpoints:
- `GET /` - API info
- `POST /scan` - Start scan
- `GET /scan/{id}` - Scan status
- `GET /scan/{id}/results` - Get results
- `GET /exploits` - List exploits
- `GET /payloads` - List payloads

### Python Library

```python
from vulnscanner import ScannerEngine, ReportGenerator

async def scan():
    engine = ScannerEngine()
    engine.add_target("192.168.1.1")
    results = await engine.run_full_scan()
    
    reporter = ReportGenerator()
    reporter.export_all("reports/")
    
asyncio.run(scan())
```

## Features

- Port scanning with service detection
- CVE database lookup
- SQL Injection testing
- XSS testing
- SSRF testing
- Command injection testing
- Security headers analysis
- SSL/TLS configuration check
- Exploit modules (EternalBlue, BlueKeep, Heartbleed, etc.)
- JSON/CSV/HTML reports
