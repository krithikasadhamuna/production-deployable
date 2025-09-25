#!/usr/bin/env python3
"""
CodeGrey SOC macOS Agent
Endpoint monitoring and command execution agent for macOS systems
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
log_dir = Path.home() / 'Library' / 'Logs' / 'CodeGrey'
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('CodeGreyAgent')

class MacOSAgent:
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
        config_path = Path.home() / 'Library' / 'Application Support' / 'CodeGrey' / 'agent.conf'
        if config_path.exists():
            with open(config_path) as f:
                stored_config = json.load(f)
                self.config.update(stored_config)
        
        # Generate agent ID if not exists
        if not self.config["agent_id"]:
            self.config["agent_id"] = f"macos-{socket.gethostname()}-{os.getpid()}"
            self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        config_path = Path.home() / 'Library' / 'Application Support' / 'CodeGrey' / 'agent.conf'
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def register(self):
        """Register agent with server"""
        try:
            # Get macOS version
            mac_ver = platform.mac_ver()[0]
            
            data = {
                "agent_id": self.config["agent_id"],
                "hostname": socket.gethostname(),
                "platform": "macOS",
                "os_version": mac_ver,
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "tenant": self.config["tenant"],
                "metadata": {
                    "arch": platform.machine(),
                    "processor": platform.processor()
                }
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
                    "timestamp": datetime.utcnow().isoformat(),
                    "tenant": self.config["tenant"]
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
                # Collect system logs using log show
                try:
                    # Get last 5 minutes of logs
                    result = subprocess.run(
                        ['log', 'show', '--last', '5m', '--style', 'json'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0 and result.stdout:
                        logs = json.loads(result.stdout)
                        for log_entry in logs[:50]:  # Limit to 50 entries
                            self.log_buffer.append({
                                "type": "system",
                                "message": log_entry.get('eventMessage', ''),
                                "process": log_entry.get('processImagePath', ''),
                                "timestamp": log_entry.get('timestamp', datetime.utcnow().isoformat())
                            })
                except Exception as e:
                    logger.debug(f"System log collection error: {e}")
                
                # Collect process information
                for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']):
                    try:
                        pinfo = proc.info
                        if pinfo['cpu_percent'] > 10:  # Only log high CPU processes
                            self.log_buffer.append({
                                "type": "process",
                                "pid": pinfo['pid'],
                                "name": pinfo['name'],
                                "user": pinfo['username'],
                                "cpu_percent": pinfo['cpu_percent'],
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
                            "pid": conn.pid,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                
                # Collect security events (login/logout)
                try:
                    result = subprocess.run(
                        ['last', '-10'],  # Last 10 login events
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        for line in lines[:10]:
                            if line and not line.startswith('wtmp'):
                                self.log_buffer.append({
                                    "type": "security",
                                    "event": "login",
                                    "message": line.strip(),
                                    "timestamp": datetime.utcnow().isoformat()
                                })
                except Exception as e:
                    logger.debug(f"Security event collection error: {e}")
                
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
                "timestamp": datetime.utcnow().isoformat(),
                "tenant": self.config["tenant"]
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
                "agent_id": self.config["agent_id"],
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
                
            elif command['type'] == 'osascript':
                # Execute AppleScript
                proc = subprocess.run(
                    ['osascript', '-e', command['script']],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                result['success'] = proc.returncode == 0
                result['output'] = proc.stdout
                result['error'] = proc.stderr
                
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
        logger.info("Starting CodeGrey macOS Agent...")
        
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

def create_launchd_plist():
    """Create LaunchDaemon plist for auto-start"""
    plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.codegrey.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Library/Application Support/CodeGrey/macos_agent.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/CodeGrey/agent.err</string>
    <key>StandardOutPath</key>
    <string>/Library/Logs/CodeGrey/agent.out</string>
</dict>
</plist>"""
    
    plist_path = '/Library/LaunchDaemons/ai.codegrey.agent.plist'
    with open(plist_path, 'w') as f:
        f.write(plist_content)
    
    # Set permissions
    os.chmod(plist_path, 0o644)
    
    return plist_path

def main():
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
            config_path = Path.home() / 'Library' / 'Application Support' / 'CodeGrey' / 'agent.conf'
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(CONFIG, f, indent=2)
            
            print(f"Configuration saved to {config_path}")
            return
        
        elif sys.argv[1] == '--install':
            # Check if running as root
            if os.geteuid() != 0:
                print("Installation requires root privileges")
                print("Run: sudo python3 macos_agent.py --install")
                sys.exit(1)
            
            # Copy agent to system location
            agent_dir = Path('/Library/Application Support/CodeGrey')
            agent_dir.mkdir(parents=True, exist_ok=True)
            
            import shutil
            shutil.copy(__file__, agent_dir / 'macos_agent.py')
            
            # Create LaunchDaemon
            plist_path = create_launchd_plist()
            
            # Load the daemon
            subprocess.run(['launchctl', 'load', plist_path])
            
            print("Agent installed successfully")
            print(f"LaunchDaemon created: {plist_path}")
            print("Agent will start automatically on boot")
            print("\nCommands:")
            print("  Start:   sudo launchctl start ai.codegrey.agent")
            print("  Stop:    sudo launchctl stop ai.codegrey.agent")
            print("  Status:  sudo launchctl list | grep codegrey")
            print("  Logs:    tail -f /Library/Logs/CodeGrey/agent.log")
            return
        
        elif sys.argv[1] == '--uninstall':
            if os.geteuid() != 0:
                print("Uninstallation requires root privileges")
                sys.exit(1)
            
            # Stop and unload daemon
            subprocess.run(['launchctl', 'stop', 'ai.codegrey.agent'])
            subprocess.run(['launchctl', 'unload', '/Library/LaunchDaemons/ai.codegrey.agent.plist'])
            
            # Remove files
            os.remove('/Library/LaunchDaemons/ai.codegrey.agent.plist')
            import shutil
            shutil.rmtree('/Library/Application Support/CodeGrey', ignore_errors=True)
            
            print("Agent uninstalled successfully")
            return
    
    # Start agent
    agent = MacOSAgent()
    agent.start()

if __name__ == "__main__":
    main()
