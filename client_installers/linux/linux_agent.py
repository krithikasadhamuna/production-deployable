#!/usr/bin/env python3
"""
CodeGrey SOC Linux Agent
Endpoint monitoring and command execution agent for Linux systems
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
from datetime import datetime
import requests
import psutil
from pathlib import Path

# Configuration
CONFIG = {
    "server_url": "https://dev.codegrey.ai",
    "agent_id": None,
    "api_key": None,
    "heartbeat_interval": 30,
    "log_batch_size": 100,
    "log_send_interval": 10,
    "tenant": "codegrey"
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/codegrey-agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('CodeGreyAgent')

class LinuxAgent:
    def __init__(self):
        self.running = True
        self.log_buffer = []
        self.config = CONFIG.copy()
        self.load_config()
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.config["api_key"]}',
            'Content-Type': 'application/json'
        })
        
    def load_config(self):
        """Load configuration from file"""
        config_path = Path('/etc/codegrey/agent.conf')
        if config_path.exists():
            with open(config_path) as f:
                stored_config = json.load(f)
                self.config.update(stored_config)
        
        # Generate agent ID if not exists
        if not self.config["agent_id"]:
            self.config["agent_id"] = f"linux-{socket.gethostname()}-{os.getpid()}"
            self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        config_path = Path('/etc/codegrey/agent.conf')
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def register(self):
        """Register agent with server"""
        try:
            data = {
                "agent_id": self.config["agent_id"],
                "hostname": socket.gethostname(),
                "platform": "Linux",
                "os_version": platform.release(),
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "tenant": self.config["tenant"]
            }
            
            response = self.session.post(
                f"{self.config['server_url']}/agents/register",
                json=data
            )
            
            if response.status_code == 200:
                logger.info(f"Agent registered successfully: {self.config['agent_id']}")
                return True
            else:
                logger.error(f"Registration failed: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False
    
    def send_heartbeat(self):
        """Send heartbeat to server"""
        while self.running:
            try:
                data = {
                    "agent_id": self.config["agent_id"],
                    "status": "online",
                    "cpu_usage": psutil.cpu_percent(),
                    "memory_usage": psutil.virtual_memory().percent,
                    "disk_usage": psutil.disk_usage('/').percent,
                    "processes": len(psutil.pids()),
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                response = self.session.post(
                    f"{self.config['server_url']}/agents/{self.config['agent_id']}/heartbeat",
                    json=data
                )
                
                if response.status_code == 200:
                    # Check for pending commands
                    result = response.json()
                    if result.get('commands'):
                        for cmd in result['commands']:
                            self.execute_command(cmd)
                
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
            
            time.sleep(self.config["heartbeat_interval"])
    
    def collect_logs(self):
        """Collect system logs"""
        while self.running:
            try:
                # Collect auth logs
                auth_log_path = '/var/log/auth.log'
                if os.path.exists(auth_log_path):
                    with open(auth_log_path, 'r') as f:
                        # Read last 100 lines
                        lines = f.readlines()[-100:]
                        for line in lines:
                            if line.strip():
                                self.log_buffer.append({
                                    "type": "auth",
                                    "message": line.strip(),
                                    "timestamp": datetime.utcnow().isoformat()
                                })
                
                # Collect system logs
                syslog_path = '/var/log/syslog'
                if os.path.exists(syslog_path):
                    with open(syslog_path, 'r') as f:
                        lines = f.readlines()[-100:]
                        for line in lines:
                            if line.strip():
                                self.log_buffer.append({
                                    "type": "system",
                                    "message": line.strip(),
                                    "timestamp": datetime.utcnow().isoformat()
                                })
                
                # Collect process information
                for proc in psutil.process_iter(['pid', 'name', 'username']):
                    try:
                        pinfo = proc.info
                        self.log_buffer.append({
                            "type": "process",
                            "pid": pinfo['pid'],
                            "name": pinfo['name'],
                            "user": pinfo['username'],
                            "timestamp": datetime.utcnow().isoformat()
                        })
                    except:
                        pass
                
                # Collect network connections
                connections = psutil.net_connections()
                for conn in connections[:50]:  # Limit to 50 connections
                    if conn.status == 'ESTABLISHED':
                        self.log_buffer.append({
                            "type": "network",
                            "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            "status": conn.status,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                
                # Send logs if buffer is full
                if len(self.log_buffer) >= self.config["log_batch_size"]:
                    self.send_logs()
                
            except Exception as e:
                logger.error(f"Log collection error: {e}")
            
            time.sleep(self.config["log_send_interval"])
    
    def send_logs(self):
        """Send collected logs to server"""
        if not self.log_buffer:
            return
        
        try:
            data = {
                "agent_id": self.config["agent_id"],
                "logs": self.log_buffer[:self.config["log_batch_size"]],
                "timestamp": datetime.utcnow().isoformat()
            }
            
            response = self.session.post(
                f"{self.config['server_url']}/agents/{self.config['agent_id']}/logs",
                json=data
            )
            
            if response.status_code == 200:
                # Clear sent logs
                self.log_buffer = self.log_buffer[self.config["log_batch_size"]:]
                logger.info(f"Sent {len(data['logs'])} logs to server")
            else:
                logger.error(f"Failed to send logs: {response.text}")
                
        except Exception as e:
            logger.error(f"Log send error: {e}")
    
    def execute_command(self, command):
        """Execute command from server"""
        try:
            logger.info(f"Executing command: {command['type']}")
            
            result = {
                "command_id": command.get('id'),
                "success": False,
                "output": "",
                "error": ""
            }
            
            if command['type'] == 'shell':
                # Execute shell command
                proc = subprocess.run(
                    command['command'],
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                result['success'] = proc.returncode == 0
                result['output'] = proc.stdout
                result['error'] = proc.stderr
                
            elif command['type'] == 'file_read':
                # Read file
                with open(command['path'], 'r') as f:
                    result['output'] = f.read()
                result['success'] = True
                
            elif command['type'] == 'file_write':
                # Write file
                with open(command['path'], 'w') as f:
                    f.write(command['content'])
                result['success'] = True
                
            elif command['type'] == 'process_kill':
                # Kill process
                os.kill(command['pid'], 9)
                result['success'] = True
                
            # Send result back
            self.session.post(
                f"{self.config['server_url']}/agents/{self.config['agent_id']}/command-result",
                json=result
            )
            
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            result['error'] = str(e)
            self.session.post(
                f"{self.config['server_url']}/agents/{self.config['agent_id']}/command-result",
                json=result
            )
    
    def start(self):
        """Start the agent"""
        logger.info("Starting CodeGrey Linux Agent...")
        
        # Register with server
        if not self.register():
            logger.error("Failed to register with server")
            return
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self.send_heartbeat)
        heartbeat_thread.daemon = True
        heartbeat_thread.start()
        
        # Start log collection thread
        log_thread = threading.Thread(target=self.collect_logs)
        log_thread.daemon = True
        log_thread.start()
        
        logger.info("Agent started successfully")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down agent...")
            self.running = False
            self.send_logs()  # Send remaining logs

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("This agent must be run as root for full functionality")
        print("Run: sudo python3 linux_agent.py")
        sys.exit(1)
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--config':
            # Configure agent
            server = input("Server URL [https://dev.codegrey.ai]: ") or "https://dev.codegrey.ai"
            api_key = input("API Key: ")
            tenant = input("Tenant [codegrey]: ") or "codegrey"
            
            CONFIG["server_url"] = server
            CONFIG["api_key"] = api_key
            CONFIG["tenant"] = tenant
            
            # Save configuration
            config_path = Path('/etc/codegrey/agent.conf')
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(CONFIG, f, indent=2)
            
            print("Configuration saved to /etc/codegrey/agent.conf")
            return
        
        elif sys.argv[1] == '--install':
            # Install as systemd service
            service_content = """[Unit]
Description=CodeGrey SOC Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/codegrey/linux_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
            
            # Copy agent to /opt
            os.makedirs('/opt/codegrey', exist_ok=True)
            subprocess.run(['cp', __file__, '/opt/codegrey/linux_agent.py'])
            
            # Create systemd service
            with open('/etc/systemd/system/codegrey-agent.service', 'w') as f:
                f.write(service_content)
            
            # Enable and start service
            subprocess.run(['systemctl', 'daemon-reload'])
            subprocess.run(['systemctl', 'enable', 'codegrey-agent'])
            subprocess.run(['systemctl', 'start', 'codegrey-agent'])
            
            print("Agent installed and started as systemd service")
            return
    
    # Start agent
    agent = LinuxAgent()
    agent.start()

if __name__ == "__main__":
    main()
