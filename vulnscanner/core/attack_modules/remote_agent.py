"""Remote Agent for Distributed Scanning"""
import asyncio
import json
import socket
import platform
import os
from typing import Dict, Optional
from dataclasses import dataclass
import uuid

from vulnscanner.security import (
    ScopeError, agent_token_is_valid, require_target_in_scope,
    require_feature_enabled, validate_ports,
)



@dataclass
class ScanTask:
    task_id: str
    task_type: str
    target: str
    params: Dict


class RemoteAgent:
    """Lightweight remote scanning agent"""
    
    def __init__(self, controller_host: str, controller_port: int = 9999):
        self.controller_host = controller_host
        self.controller_port = controller_port
        self.agent_id = str(uuid.uuid4())[:8]
        self.running = False
        self.socket = None
    
    async def connect(self):
        """Connect to an explicitly enabled local controller using a shared secret."""
        try:
            require_feature_enabled('PEN_ENABLE_REMOTE_AGENTS', 'Remote scanning agents')
            agent_token = os.getenv('PEN_AGENT_TOKEN', '')
            if not agent_token:
                raise ScopeError('PEN_AGENT_TOKEN must be configured before starting an agent')
            self.socket = await asyncio.wait_for(
                asyncio.open_connection(self.controller_host, self.controller_port),
                timeout=10
            )
            reader, writer = self.socket
            
            # Register
            reg = {
                'type': 'register',
                'agent_id': self.agent_id,
                'hostname': platform.node(),
                'platform': platform.system(),
                'token': agent_token,
                'capabilities': ['port_scan', 'web_scan']
            }
            writer.write(json.dumps(reg).encode() + b'\n')
            await writer.drain()
            
            self.running = True
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    async def listen(self):
        """Listen for tasks from controller"""
        if not self.socket:
            return
        
        reader, writer = self.socket
        
        while self.running:
            try:
                data = await asyncio.wait_for(reader.readline(), timeout=30)
                if not data:
                    break
                
                message = json.loads(data.decode())
                result = await self.execute(message)
                
                response = {
                    'type': 'result',
                    'task_id': message.get('task_id'),
                    'result': result
                }
                writer.write(json.dumps(response).encode() + b'\n')
                await writer.drain()
                
            except asyncio.TimeoutError:
                # Send heartbeat
                heartbeat = {'type': 'heartbeat', 'agent_id': self.agent_id}
                writer.write(json.dumps(heartbeat).encode() + b'\n')
                await writer.drain()
            except Exception as e:
                break
        
        self.running = False
    
    async def execute(self, task: Dict) -> Dict:
        """Execute assigned task"""
        task_type = task.get('task_type')
        target = task.get('target')
        params = task.get('params', {})
        
        try:
            require_feature_enabled('PEN_ENABLE_REMOTE_AGENTS', 'Remote scanning agents')
            if task_type in {'port_scan', 'web_scan', 'exploit_check'}:
                if not isinstance(target, str) or not target:
                    raise ScopeError('A target is required for this task')
                require_target_in_scope(target)
            if task_type == 'exploit_check':
                require_feature_enabled('PEN_ENABLE_EXPLOIT_CHECKS', 'Exploit checks')
                validate_ports(params.get('ports'), maximum=100)
            if task_type == 'port_scan':
                from vulnscanner.core.scanners.network import NetworkScanner
                scanner = NetworkScanner()
                results = await scanner.scan_ports(target, params.get('ports'))
                return {
                    'status': 'success',
                    'open_ports': len(results),
                    'services': {p: {'service': s.service, 'banner': s.banner} for p, s in results.items()}
                }
            
            elif task_type == 'web_scan':
                from vulnscanner.core.scanners.web import WebScanner
                scanner = WebScanner()
                results = await scanner.full_scan(target)
                return {
                    'status': 'success',
                    'vulnerabilities': len(results),
                    'details': [{'type': v.vuln_type, 'severity': v.severity} for v in results]
                }
            
            elif task_type == 'exploit_check':
                from vulnscanner.core.checks.exploits import ExploitScanner
                scanner = ExploitScanner()
                results = await scanner.full_scan(target, params.get('ports', {}))
                return {
                    'status': 'success',
                    'vulnerabilities': [r.__dict__ for r in results if r.vulnerable]
                }
            
            else:
                return {'status': 'error', 'message': f'Unknown task: {task_type}'}
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    async def run(self):
        """Main agent loop"""
        while True:
            if await self.connect():
                await self.listen()
            
            # Reconnect delay
            await asyncio.sleep(10)


class AgentController:
    """Controller for managing remote agents"""
    
    def __init__(self, port: int = 9999):
        self.port = port
        self.agents = {}
        self.tasks = {}
        self.server = None
    
    async def start(self):
        """Start a local-only controller; remote transport requires a reviewed TLS design."""
        require_feature_enabled('PEN_ENABLE_REMOTE_AGENTS', 'Remote scanning agents')
        if not os.getenv('PEN_AGENT_TOKEN'):
            raise RuntimeError('PEN_AGENT_TOKEN must be configured before starting the controller')
        if not 1 <= int(self.port) <= 65535:
            raise ValueError('Port must be between 1 and 65535')
        self.server = await asyncio.start_server(
            self.handle_agent, '127.0.0.1', self.port, limit=65536
        )
        print(f"[*] Local-only controller listening on 127.0.0.1:{self.port}")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def handle_agent(self, reader, writer):
        """Handle agent connection"""
        addr = writer.get_extra_info('peername')
        agent_id = None
        
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                
                message = json.loads(data.decode())
                
                if message.get('type') == 'register':
                    if not agent_token_is_valid(message.get('token')):
                        break
                    agent_id = str(message.get('agent_id', ''))[:64]
                    if not agent_id:
                        break
                    safe_info = {key: value for key, value in message.items() if key != 'token'}
                    self.agents[agent_id] = {
                        'info': safe_info,
                        'writer': writer,
                        'status': 'online'
                    }
                    print(f"[+] Agent connected: {agent_id} from {addr}")
                
                elif message.get('type') == 'result':
                    if not agent_id:
                        continue
                    task_id = message.get('task_id')
                    if task_id in self.tasks and self.tasks[task_id].get('agent_id') == agent_id:
                        self.tasks[task_id]['result'] = message['result']
                        self.tasks[task_id]['status'] = 'completed'
                
                elif message.get('type') == 'heartbeat':
                    if agent_id:
                        self.agents[agent_id]['status'] = 'online'
        
        except (ValueError, json.JSONDecodeError, ConnectionError, asyncio.IncompleteReadError):
            pass
        
        finally:
            if agent_id and agent_id in self.agents:
                self.agents[agent_id]['status'] = 'offline'
                print(f"[-] Agent disconnected: {agent_id}")
            writer.close()
    
    async def send_task(self, agent_id: str, task: Dict) -> str:
        """Send only recognized, in-scope tasks to a registered local agent."""
        if agent_id not in self.agents:
            return None
        if not isinstance(task, dict) or task.get('task_type') not in {'port_scan', 'web_scan', 'exploit_check'}:
            raise ScopeError('Unsupported remote task type')
        target = task.get('target')
        require_target_in_scope(target)
        if task.get('task_type') == 'exploit_check':
            require_feature_enabled('PEN_ENABLE_EXPLOIT_CHECKS', 'Exploit checks')
        params = task.get('params') or {}
        if not isinstance(params, dict):
            raise ScopeError('Task params must be an object')
        validate_ports(params.get('ports'), maximum=100)
        task_id = str(uuid.uuid4())
        message = dict(task)
        message['task_id'] = task_id
        self.tasks[task_id] = {'status': 'pending', 'result': None, 'agent_id': agent_id}
        writer = self.agents[agent_id]['writer']
        writer.write(json.dumps(message).encode() + b'\n')
        await writer.drain()
        self.tasks[task_id]['status'] = 'sent'
        return task_id
    
    def get_agents(self) -> Dict:
        """Get all agents"""
        return {
            aid: {'status': a['status'], 'info': a['info']}
            for aid, a in self.agents.items()
        }
    
    def get_task_result(self, task_id: str) -> Optional[Dict]:
        """Get task result"""
        return self.tasks.get(task_id)


async def run_agent(controller_host: str, controller_port: int = 9999):
    """Run a local agent after explicit enablement and token configuration."""
    require_feature_enabled('PEN_ENABLE_REMOTE_AGENTS', 'Remote scanning agents')
    if not os.getenv('PEN_AGENT_TOKEN'):
        raise RuntimeError('PEN_AGENT_TOKEN must be configured before starting an agent')
    if controller_host not in {'127.0.0.1', 'localhost', '::1'}:
        raise RuntimeError('Remote agents are restricted to loopback until TLS transport is implemented')
    agent = RemoteAgent(controller_host, controller_port)
    await agent.run()


async def run_controller(port: int = 9999):
    """Run controller process"""
    controller = AgentController(port)
    await controller.start()
