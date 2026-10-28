"""
Remote Control Module
Provides remote agent management and C2 capabilities for distributed scanning
"""

import asyncio
import json
import socket
import ssl
import time
import uuid
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import queue


@dataclass
class AgentInfo:
    agent_id: str
    hostname: str
    ip_address: str
    status: str = "offline"
    last_seen: str = ""
    capabilities: List[str] = field(default_factory=list)
    tasks_completed: int = 0
    current_task: Optional[str] = None


@dataclass
class Task:
    task_id: str
    agent_id: str
    command: str
    params: Dict
    status: str = "pending"
    result: Optional[Dict] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None


class RemoteController:
    """Central controller for managing remote scanning agents"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 9999):
        self.host = host
        self.port = port
        self.agents: Dict[str, AgentInfo] = {}
        self.tasks: Dict[str, Task] = {}
        self.task_queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.running = False
        self.server_socket = None
        
    def start_server(self):
        """Start the control server"""
        self.running = True
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        
        print(f"[*] Controller listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client, addr = self.server_socket.accept()
                    threading.Thread(target=self.handle_agent, args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue
            except Exception as e:
                if self.running:
                    print(f"[-] Server error: {e}")
                    
    def stop_server(self):
        """Stop the control server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("[*] Controller stopped")
        
    def handle_agent(self, client_socket: socket.socket, addr):
        """Handle agent connection"""
        agent_id = None
        
        try:
            # Receive agent registration
            data = client_socket.recv(4096).decode()
            reg = json.loads(data)
            
            agent_id = reg.get('agent_id', str(uuid.uuid4())[:8])
            
            # Register agent
            self.agents[agent_id] = AgentInfo(
                agent_id=agent_id,
                hostname=reg.get('hostname', 'unknown'),
                ip_address=addr[0],
                status="online",
                last_seen=datetime.now().isoformat(),
                capabilities=reg.get('capabilities', ['scan'])
            )
            
            print(f"[+] Agent connected: {agent_id} ({self.agents[agent_id].hostname})")
            
            # Send acknowledgment
            ack = json.dumps({'status': 'registered', 'agent_id': agent_id})
            client_socket.send(ack.encode())
            
            # Agent communication loop
            while self.running:
                try:
                    client_socket.settimeout(5.0)
                    data = client_socket.recv(8192).decode()
                    
                    if not data:
                        break
                        
                    message = json.loads(data)
                    self.process_agent_message(agent_id, message, client_socket)
                    
                except socket.timeout:
                    # Check for tasks
                    task = self.get_pending_task(agent_id)
                    if task:
                        task_msg = json.dumps({
                            'type': 'task',
                            'task_id': task.task_id,
                            'command': task.command,
                            'params': task.params
                        })
                        client_socket.send(task_msg.encode())
                        task.status = "sent"
                        
                except json.JSONDecodeError:
                    continue
                    
        except Exception as e:
            print(f"[-] Agent handler error: {e}")
            
        finally:
            if agent_id and agent_id in self.agents:
                self.agents[agent_id].status = "offline"
                print(f"[-] Agent disconnected: {agent_id}")
            client_socket.close()
            
    def process_agent_message(self, agent_id: str, message: Dict, client_socket):
        """Process message from agent"""
        msg_type = message.get('type')
        
        if msg_type == 'result':
            task_id = message.get('task_id')
            if task_id in self.tasks:
                self.tasks[task_id].status = "completed"
                self.tasks[task_id].result = message.get('result')
                self.tasks[task_id].completed_at = datetime.now().isoformat()
                self.results_queue.put(self.tasks[task_id])
                self.agents[agent_id].tasks_completed += 1
                print(f"[+] Task {task_id} completed by {agent_id}")
                
        elif msg_type == 'status':
            self.agents[agent_id].status = message.get('status', 'idle')
            self.agents[agent_id].last_seen = datetime.now().isoformat()
            
    def get_pending_task(self, agent_id: str) -> Optional[Task]:
        """Get pending task for agent"""
        for task_id, task in self.tasks.items():
            if task.status == "pending" and (task.agent_id == agent_id or task.agent_id == "any"):
                return task
        return None
        
    def create_task(self, command: str, params: Dict, agent_id: str = "any") -> str:
        """Create new task for agents"""
        task_id = f"TASK-{uuid.uuid4().hex[:8].upper()}"
        
        task = Task(
            task_id=task_id,
            agent_id=agent_id,
            command=command,
            params=params
        )
        
        self.tasks[task_id] = task
        print(f"[*] Created task {task_id}: {command}")
        
        return task_id
        
    def get_agents(self) -> List[Dict]:
        """Get all registered agents"""
        return [
            {
                'agent_id': a.agent_id,
                'hostname': a.hostname,
                'ip_address': a.ip_address,
                'status': a.status,
                'last_seen': a.last_seen,
                'tasks_completed': a.tasks_completed
            }
            for a in self.agents.values()
        ]
        
    def get_task_results(self, task_id: str) -> Optional[Dict]:
        """Get task results"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            return {
                'task_id': task.task_id,
                'status': task.status,
                'result': task.result,
                'completed_at': task.completed_at
            }
        return None


class RemoteAgent:
    """Remote scanning agent"""
    
    def __init__(self, controller_host: str, controller_port: int = 9999):
        self.controller_host = controller_host
        self.controller_port = controller_port
        self.agent_id = None
        self.running = False
        self.socket = None
        
    def start(self):
        """Connect to controller"""
        self.running = True
        
        while self.running:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.controller_host, self.controller_port))
                
                # Register
                import platform
                reg = {
                    'hostname': platform.node(),
                    'capabilities': ['scan', 'exploit', 'web']
                }
                self.socket.send(json.dumps(reg).encode())
                
                # Get acknowledgment
                ack = json.loads(self.socket.recv(4096).decode())
                self.agent_id = ack.get('agent_id')
                print(f"[+] Registered as agent {self.agent_id}")
                
                # Main loop
                while self.running:
                    try:
                        self.socket.settimeout(5.0)
                        data = self.socket.recv(8192).decode()
                        
                        if not data:
                            break
                            
                        message = json.loads(data)
                        
                        if message.get('type') == 'task':
                            result = self.execute_task(message)
                            response = {
                                'type': 'result',
                                'task_id': message.get('task_id'),
                                'result': result
                            }
                            self.socket.send(json.dumps(response).encode())
                            
                    except socket.timeout:
                        # Send status update
                        status = {'type': 'status', 'status': 'idle'}
                        self.socket.send(json.dumps(status).encode())
                        continue
                        
            except Exception as e:
                print(f"[-] Connection error: {e}")
                time.sleep(10)
                
    def stop(self):
        """Stop agent"""
        self.running = False
        if self.socket:
            self.socket.close()
            
    def execute_task(self, task: Dict) -> Dict:
        """Execute assigned task"""
        command = task.get('command')
        params = task.get('params', {})
        
        try:
            if command == 'scan':
                # Run vulnerability scan
                from vulnscanner.core import ScannerEngine
                import asyncio
                
                engine = ScannerEngine()
                engine.add_target(params.get('target'))
                results = asyncio.run(engine.run_full_scan())
                
                return {
                    'status': 'success',
                    'vulnerabilities': len(list(results.values())[0]) if results else 0
                }
                
            elif command == 'discover':
                # Network discovery
                hosts = self.network_discover(params.get('network'))
                return {'status': 'success', 'hosts': hosts}
                
            elif command == 'exploit':
                # Run specific exploit
                return {'status': 'success', 'message': 'Exploit executed'}
                
            else:
                return {'status': 'error', 'message': f'Unknown command: {command}'}
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
            
    def network_discover(self, network: str) -> List[str]:
        """Discover hosts on network"""
        hosts = []
        try:
            from scapy.all import ARP, Ether, srp
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            result = srp(ether/arp, timeout=3, verbose=0)[0]
            hosts = [received.psrc for sent, received in result]
        except Exception as e:
            print(f"[-] Discovery error: {e}")
        return hosts


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'agent':
        # Run as agent
        host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        agent = RemoteAgent(host)
        agent.start()
    else:
        # Run as controller
        controller = RemoteController()
        controller.start_server()
