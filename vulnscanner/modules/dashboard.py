"""
WebSocket Dashboard Server
Real-time monitoring and control interface for the vulnerability scanner
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Set
import websockets
from websockets.server import serve


class DashboardServer:
    """Real-time dashboard with WebSocket communication"""
    
    def __init__(self, scanner_engine=None):
        self.scanner = scanner_engine
        self.clients: Set[websockets.WebSocketServerProtocol] = set()
        self.scan_status = {}
        
    async def register(self, websocket):
        """Register new client"""
        self.clients.add(websocket)
        print(f"[+] Client connected. Total clients: {len(self.clients)}")
        
        # Send current status
        await self.send_status(websocket)
        
    async def unregister(self, websocket):
        """Unregister client"""
        self.clients.discard(websocket)
        print(f"[-] Client disconnected. Total clients: {len(self.clients)}")
        
    async def send_status(self, websocket):
        """Send current status to client"""
        status = {
            'type': 'status',
            'timestamp': datetime.now().isoformat(),
            'clients': len(self.clients),
            'scan_active': getattr(self.scanner, 'scan_active', False),
            'targets': len(getattr(self.scanner, 'targets', [])),
            'results': len(getattr(self.scanner, 'results', []))
        }
        await websocket.send(json.dumps(status))
        
    async def broadcast(self, message: Dict):
        """Broadcast message to all clients"""
        if self.clients:
            await asyncio.gather(
                *[client.send(json.dumps(message)) for client in self.clients]
            )
            
    async def handle_message(self, websocket, message: str):
        """Handle incoming message from client"""
        try:
            data = json.loads(message)
            command = data.get('command')
            
            if command == 'start_scan':
                target = data.get('target')
                response = {
                    'type': 'response',
                    'command': 'start_scan',
                    'status': 'initiated',
                    'target': target
                }
                await websocket.send(json.dumps(response))
                
            elif command == 'get_results':
                if self.scanner:
                    results = [{
                        'vuln_id': v.vuln_id,
                        'name': v.name,
                        'severity': v.severity,
                        'cvss': v.cvss_score
                    } for v in self.scanner.results[:50]]
                else:
                    results = []
                    
                response = {
                    'type': 'results',
                    'count': len(results),
                    'results': results
                }
                await websocket.send(json.dumps(response))
                
            elif command == 'get_payloads':
                from vulnscanner.core.payloads import PayloadManager
                pm = PayloadManager()
                response = {
                    'type': 'payloads',
                    'categories': {k: len(v) for k, v in pm.get_all_payloads().items()}
                }
                await websocket.send(json.dumps(response))
                
            elif command == 'get_exploits':
                from vulnscanner.core.exploits import ExploitModule
                em = ExploitModule()
                response = {
                    'type': 'exploits',
                    'exploits': em.get_exploit_list()
                }
                await websocket.send(json.dumps(response))
                
            else:
                response = {'type': 'error', 'message': f'Unknown command: {command}'}
                await websocket.send(json.dumps(response))
                
        except json.JSONDecodeError:
            await websocket.send(json.dumps({'type': 'error', 'message': 'Invalid JSON'}))
            
    async def handler(self, websocket):
        """Main handler for WebSocket connections"""
        await self.register(websocket)
        try:
            async for message in websocket:
                await self.handle_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister(websocket)
            
    async def notify_scan_progress(self, progress: float, target: str, vulns_found: int):
        """Notify clients of scan progress"""
        await self.broadcast({
            'type': 'progress',
            'progress': progress,
            'current_target': target,
            'vulnerabilities_found': vulns_found,
            'timestamp': datetime.now().isoformat()
        })
        
    async def notify_vulnerability(self, vuln: Dict):
        """Notify clients of new vulnerability"""
        await self.broadcast({
            'type': 'vulnerability',
            'vuln_id': vuln.get('vuln_id'),
            'name': vuln.get('name'),
            'severity': vuln.get('severity'),
            'cvss': vuln.get('cvss_score'),
            'timestamp': datetime.now().isoformat()
        })
        
    async def start(self, host: str = "0.0.0.0", port: int = 8765):
        """Start the WebSocket server"""
        print(f"[*] Dashboard WebSocket server starting on {host}:{port}")
        async with serve(self.handler, host, port):
            print(f"[+] Dashboard ready - ws://{host}:{port}")
            await asyncio.Future()  # Run forever


# Dashboard HTML interface
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scanner Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        h1 { color: #58a6ff; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
        .card h3 { color: #8b949e; margin-bottom: 10px; font-size: 0.9em; }
        .card .value { font-size: 2.5em; font-weight: bold; color: #58a6ff; }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 8px; }
        .status-online { background: #3fb950; }
        .status-scanning { background: #f0883e; animation: pulse 1s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        #log { height: 300px; overflow-y: auto; font-family: monospace; font-size: 0.85em; padding: 15px; background: #0d1117; }
        .log-entry { padding: 4px 0; border-bottom: 1px solid #21262d; }
        .severity-critical { color: #f85149; }
        .severity-high { color: #f0883e; }
        .severity-medium { color: #d29922; }
        .severity-low { color: #3fb950; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; font-weight: 500; }
        .badge { padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 500; }
        .badge-critical { background: #f85149; color: white; }
        .badge-high { background: #f0883e; color: white; }
        .badge-medium { background: #d29922; color: black; }
        .badge-low { background: #3fb950; color: black; }
        input, button { padding: 10px 15px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; }
        button { cursor: pointer; background: #238636; border-color: #238636; }
        button:hover { background: #2ea043; }
        .controls { display: flex; gap: 10px; margin-bottom: 20px; }
        input { flex: 1; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Vulnerability Scanner Dashboard</h1>
        
        <div class="controls">
            <input type="text" id="target" placeholder="Enter target IP or hostname">
            <button onclick="startScan()">Start Scan</button>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>STATUS</h3>
                <div class="value"><span class="status-dot status-online" id="status-dot"></span><span id="status">Ready</span></div>
            </div>
            <div class="card">
                <h3>VULNERABILITIES</h3>
                <div class="value" id="vuln-count">0</div>
            </div>
            <div class="card">
                <h3>PROGRESS</h3>
                <div class="value" id="progress">0%</div>
            </div>
        </div>
        
        <div class="card">
            <h3>SCANNER LOG</h3>
            <div id="log"></div>
        </div>
        
        <div class="card">
            <h3>VULNERABILITIES FOUND</h3>
            <table id="vulns-table">
                <thead>
                    <tr><th>ID</th><th>Name</th><th>Severity</th><th>CVSS</th><th>Component</th></tr>
                </thead>
                <tbody id="vulns-body"></tbody>
            </table>
        </div>
    </div>
    
    <script>
        const ws = new WebSocket('ws://localhost:8765');
        let vulns = [];
        
        ws.onopen = () => {
            log('Connected to scanner', 'info');
        };
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            handleMessage(data);
        };
        
        function handleMessage(data) {
            switch(data.type) {
                case 'status':
                    document.getElementById('status-dot').className = 'status-dot status-' + 
                        (data.scan_active ? 'scanning' : 'online');
                    document.getElementById('status').textContent = 
                        data.scan_active ? 'Scanning...' : 'Ready';
                    break;
                case 'progress':
                    document.getElementById('progress').textContent = Math.round(data.progress) + '%';
                    log(`Progress: ${Math.round(data.progress)}% - ${data.current_target}`, 'info');
                    break;
                case 'vulnerability':
                    vulns.push(data);
                    document.getElementById('vuln-count').textContent = vulns.length;
                    log(`Found: ${data.name} (${data.severity})`, data.severity.toLowerCase());
                    addVulnRow(data);
                    break;
                case 'results':
                    vulns = data.results;
                    document.getElementById('vuln-count').textContent = vulns.length;
                    renderVulns();
                    break;
            }
        }
        
        function log(msg, level) {
            const logDiv = document.getElementById('log');
            const entry = document.createElement('div');
            entry.className = 'log-entry severity-' + level;
            entry.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
            logDiv.appendChild(entry);
            logDiv.scrollTop = logDiv.scrollHeight;
        }
        
        function addVulnRow(vuln) {
            const tbody = document.getElementById('vulns-body');
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${vuln.vuln_id || '-'}</td>
                <td>${vuln.name}</td>
                <td><span class="badge badge-${vuln.severity.toLowerCase()}">${vuln.severity}</span></td>
                <td>${vuln.cvss || '-'}</td>
                <td>${vuln.affected_component || '-'}</td>
            `;
            tbody.insertBefore(row, tbody.firstChild);
        }
        
        function renderVulns() {
            const tbody = document.getElementById('vulns-body');
            tbody.innerHTML = '';
            vulns.forEach(v => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${v.vuln_id || '-'}</td>
                    <td>${v.name}</td>
                    <td><span class="badge badge-${v.severity.toLowerCase()}">${v.severity}</span></td>
                    <td>${v.cvss || '-'}</td>
                    <td>${v.affected_component || '-'}</td>
                `;
                tbody.appendChild(row);
            });
        }
        
        function startScan() {
            const target = document.getElementById('target').value;
            if (!target) {
                alert('Please enter a target');
                return;
            }
            ws.send(JSON.stringify({command: 'start_scan', target: target}));
            log('Starting scan of ' + target, 'info');
        }
    </script>
</body>
</html>
'''


if __name__ == '__main__':
    server = DashboardServer()
    asyncio.run(server.start())
