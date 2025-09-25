#!/usr/bin/env python3
"""
CodeGrey SOC Agent - Production Ready Windows Client
Sends logs to SOC server and executes commands
"""

import os
import sys
import json
import time
import socket
import platform
import subprocess
import threading
import logging
import requests
from datetime import datetime, timezone
from pathlib import Path
import psutil
import uuid

# Agent Configuration
AGENT_VERSION = "3.0.0"
AGENT_ID = f"agent_{socket.gethostname()}_{uuid.uuid4().hex[:8]}"

# Server Configuration - CHANGE THESE FOR YOUR PRODUCTION SERVER
SERVER_URL = "https://dev.codegrey.ai"  # Production server
API_KEY = "soc-agents-2024"  # Your API key
ORGANIZATION_ID = "org-123"

# Reporting intervals (seconds)
HEARTBEAT_INTERVAL = 60
LOG_BATCH_INTERVAL = 30
TELEMETRY_INTERVAL = 300

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('codegrey_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('CodeGreyAgent')

class CodeGreyAgent:
    def __init__(self):
        self.agent_id = AGENT_ID
        self.server_url = SERVER_URL
        self.api_key = API_KEY
        self.tenant = "codegrey"  # Default tenant
        self.running = True
        self.pending_logs = []
        self.load_config()  # Load config from file if exists
        self.system_info = self.collect_system_info()
    
    def load_config(self):
        """Load configuration from file if it exists"""
        config_path = r"C:\ProgramData\CodeGrey\agent.conf"
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    
                # Update configuration from file
                if 'server_url' in config:
                    self.server_url = config['server_url']
                if 'api_key' in config:
                    self.api_key = config['api_key']
                if 'tenant' in config:
                    self.tenant = config['tenant']
                if 'agent_id' in config and config['agent_id']:
                    self.agent_id = config['agent_id']
                    
                logger.info(f"Configuration loaded from {config_path}")
                logger.info(f"Server: {self.server_url}")
                logger.info(f"Tenant: {self.tenant}")
                
                # Validate API key format
                if self.api_key and self.api_key.startswith('soc-dep-'):
                    logger.info("Using deployment API key")
                    
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
        
    def collect_system_info(self):
        """Collect comprehensive system information"""
        try:
            info = {
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'platform_version': platform.version(),
                'processor': platform.processor(),
                'ip_address': self.get_local_ip(),
                'username': os.environ.get('USERNAME', 'unknown'),
                'domain': os.environ.get('USERDOMAIN', 'WORKGROUP'),
                'is_admin': self.check_admin(),
                'processes': self.get_running_processes(),
                'installed_software': self.get_installed_software(),
                'open_ports': self.scan_open_ports(),
                'security_zone': self.determine_security_zone()
            }
            return info
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            return {}
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"
    
    def check_admin(self):
        """Check if running with admin privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def get_running_processes(self):
        """Get list of running processes"""
        processes = []
        try:
            for proc in psutil.process_iter(['name', 'pid']):
                processes.append(proc.info['name'])
            return list(set(processes))[:100]  # Unique, limited to 100
        except:
            return []
    
    def get_installed_software(self):
        """Get list of installed software from Windows registry"""
        software = []
        try:
            # Quick method - just check common programs
            common_paths = [
                r"C:\Program Files",
                r"C:\Program Files (x86)"
            ]
            for path in common_paths:
                if os.path.exists(path):
                    for folder in os.listdir(path)[:50]:  # Limit to 50
                        software.append(folder)
            return software
        except:
            return []
    
    def scan_open_ports(self):
        """Scan for open listening ports"""
        ports = []
        try:
            for conn in psutil.net_connections():
                if conn.status == 'LISTEN' and conn.laddr.port:
                    ports.append(conn.laddr.port)
            return sorted(list(set(ports)))[:20]  # Unique, limited to 20
        except:
            return []
    
    def determine_security_zone(self):
        """Determine network security zone based on IP"""
        ip = self.get_local_ip()
        if ip.startswith('10.'):
            return 'internal'
        elif ip.startswith('192.168.'):
            return 'internal'
        elif ip.startswith('172.'):
            return 'internal'
        else:
            return 'dmz'
    
    def register_agent(self):
        """Register agent with SOC server"""
        try:
            url = f"{self.server_url}/agents/register"
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'agent_id': self.agent_id,
                'hostname': self.system_info.get('hostname'),
                'ip_address': self.system_info.get('ip_address'),
                'platform': self.system_info.get('platform'),
                'tenant': self.tenant,  # Include tenant for multi-tenancy
                'type': 'endpoint',
                'version': AGENT_VERSION,
                'capabilities': [
                    'log_collection',
                    'command_execution',
                    'file_monitoring',
                    'process_monitoring',
                    'network_monitoring'
                ]
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=10)
            if response.status_code == 200:
                logger.info(f"Agent registered successfully: {self.agent_id}")
                return True
            else:
                logger.error(f"Registration failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False
    
    def send_telemetry(self):
        """Send comprehensive telemetry data to server"""
        try:
            url = f"{self.server_url}/agents/{self.agent_id}/telemetry"
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Refresh system info
            self.system_info = self.collect_system_info()
            
            data = {
                'hostname': self.system_info.get('hostname'),
                'username': self.system_info.get('username'),
                'processes': self.system_info.get('processes', [])[:50],
                'installed_software': self.system_info.get('installed_software', [])[:50],
                'security_zone': self.system_info.get('security_zone'),
                'is_admin': self.system_info.get('is_admin'),
                'configuration': {
                    'version': AGENT_VERSION,
                    'heartbeat_interval': HEARTBEAT_INTERVAL,
                    'log_batch_interval': LOG_BATCH_INTERVAL
                }
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Telemetry sent. Importance: {result.get('importance')}, Role: {result.get('user_role')}")
            else:
                logger.error(f"Telemetry failed: {response.status_code}")
        except Exception as e:
            logger.error(f"Telemetry error: {e}")
    
    def heartbeat(self):
        """Send heartbeat and get pending commands"""
        try:
            url = f"{self.server_url}/agents/{self.agent_id}/heartbeat"
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'status': 'online',
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                commands = result.get('commands', [])
                
                if commands:
                    logger.info(f"Received {len(commands)} commands")
                    for cmd in commands:
                        self.execute_command(cmd)
                
                return True
            else:
                logger.error(f"Heartbeat failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
            return False
    
    def execute_command(self, command):
        """Execute command from server"""
        cmd_id = command.get('id')
        cmd_type = command.get('type')
        params = command.get('parameters', {})
        
        logger.info(f"Executing command {cmd_id}: {cmd_type}")
        
        try:
            output = ""
            success = False
            
            if cmd_type.startswith('attack_'):
                # Handle attack commands
                technique = cmd_type.replace('attack_', '')
                output = self.execute_attack_technique(technique, params)
                success = True
            elif cmd_type == 'collect_info':
                output = json.dumps(self.collect_system_info())
                success = True
            elif cmd_type == 'run_command':
                # Execute system command (be careful!)
                cmd_line = params.get('command')
                if cmd_line and self.is_safe_command(cmd_line):
                    result = subprocess.run(cmd_line, shell=True, capture_output=True, text=True, timeout=30)
                    output = result.stdout
                    success = result.returncode == 0
                else:
                    output = "Command blocked by safety check"
                    success = False
            else:
                output = f"Unknown command type: {cmd_type}"
                success = False
            
            # Report result back
            self.report_command_result(cmd_id, success, output)
            
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            self.report_command_result(cmd_id, False, str(e))
    
    def execute_attack_technique(self, technique, params):
        """Execute MITRE ATT&CK technique (safely)"""
        output = f"Simulating technique {technique}\n"
        
        if technique == 'T1082':  # System Information Discovery
            output += f"Hostname: {socket.gethostname()}\n"
            output += f"OS: {platform.system()} {platform.version()}\n"
            output += f"Processor: {platform.processor()}\n"
        elif technique == 'T1057':  # Process Discovery
            procs = [p.info['name'] for p in psutil.process_iter(['name'])][:10]
            output += f"Running processes: {', '.join(procs)}\n"
        elif technique == 'T1016':  # System Network Configuration Discovery
            output += f"IP Address: {self.get_local_ip()}\n"
            output += f"Open ports: {self.scan_open_ports()}\n"
        else:
            output += f"Technique {technique} simulated (no actual execution)\n"
        
        return output
    
    def is_safe_command(self, command):
        """Check if command is safe to execute"""
        dangerous = ['format', 'del ', 'rm ', 'shutdown', 'reboot', 'reg delete']
        return not any(d in command.lower() for d in dangerous)
    
    def report_command_result(self, command_id, success, output):
        """Report command execution result to server"""
        try:
            url = f"{self.server_url}/agents/{self.agent_id}/command-result"
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'command_id': command_id,
                'success': success,
                'output': output[:10000],  # Limit output size
                'error': '' if success else output
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=10)
            if response.status_code == 200:
                logger.info(f"Command result reported for {command_id}")
            else:
                logger.error(f"Failed to report command result: {response.status_code}")
        except Exception as e:
            logger.error(f"Error reporting command result: {e}")
    
    def collect_logs(self):
        """Collect system logs and events"""
        events = []
        
        try:
            # Monitor process creation
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                if time.time() - proc.info['create_time'] < LOG_BATCH_INTERVAL:
                    events.append({
                        'id': f"evt_{uuid.uuid4().hex[:12]}",
                        'type': 'process_creation',
                        'severity': 'info',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'data': {
                            'process_name': proc.info['name'],
                            'pid': proc.info['pid']
                        }
                    })
            
            # Check for suspicious processes
            suspicious = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe']
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in suspicious:
                    events.append({
                        'id': f"evt_{uuid.uuid4().hex[:12]}",
                        'type': 'suspicious_process',
                        'severity': 'medium',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'data': {
                            'process_name': proc.info['name']
                        }
                    })
            
            # Add system event
            events.append({
                'id': f"evt_{uuid.uuid4().hex[:12]}",
                'type': 'system_status',
                'severity': 'info',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'data': {
                    'cpu_usage': psutil.cpu_percent(),
                    'memory_usage': psutil.virtual_memory().percent,
                    'disk_usage': psutil.disk_usage('/').percent
                }
            })
            
        except Exception as e:
            logger.error(f"Error collecting logs: {e}")
        
        return events[:100]  # Limit to 100 events per batch
    
    def send_logs(self):
        """Send collected logs to server"""
        try:
            events = self.collect_logs()
            if not events:
                return
            
            url = f"{self.server_url}/agents/{self.agent_id}/logs"
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {'events': events}
            
            response = requests.post(url, json=data, headers=headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Sent {result.get('processed')} logs to server")
            else:
                logger.error(f"Failed to send logs: {response.status_code}")
        except Exception as e:
            logger.error(f"Error sending logs: {e}")
    
    def run(self):
        """Main agent loop"""
        logger.info(f"Starting CodeGrey Agent v{AGENT_VERSION}")
        logger.info(f"Agent ID: {self.agent_id}")
        logger.info(f"Server: {self.server_url}")
        
        # Register agent
        if not self.register_agent():
            logger.error("Failed to register agent. Will retry...")
        
        # Send initial telemetry
        self.send_telemetry()
        
        # Start threads for different tasks
        last_heartbeat = 0
        last_log_send = 0
        last_telemetry = 0
        
        while self.running:
            try:
                current_time = time.time()
                
                # Heartbeat
                if current_time - last_heartbeat >= HEARTBEAT_INTERVAL:
                    self.heartbeat()
                    last_heartbeat = current_time
                
                # Send logs
                if current_time - last_log_send >= LOG_BATCH_INTERVAL:
                    self.send_logs()
                    last_log_send = current_time
                
                # Send telemetry
                if current_time - last_telemetry >= TELEMETRY_INTERVAL:
                    self.send_telemetry()
                    last_telemetry = current_time
                
                # Sleep for a bit
                time.sleep(5)
                
            except KeyboardInterrupt:
                logger.info("Shutting down agent...")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Main loop error: {e}")
                time.sleep(10)

def main():
    """Main entry point"""
    print("""
    ╔═══════════════════════════════════════╗
    ║     CodeGrey SOC Agent v3.0.0        ║
    ║     Production Ready Client          ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Check if running as admin (recommended)
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("WARNING: Not running as administrator. Some features may be limited.")
    except:
        pass
    
    # Create and run agent
    agent = CodeGreyAgent()
    
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\nAgent stopped by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
