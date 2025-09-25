#!/usr/bin/env python3
"""
CodeGrey Simple Windows Agent
Minimal configuration required - just needs API key
"""

import os
import json
import time
import socket
import platform
import requests
import psutil
from datetime import datetime

class SimpleAgent:
    def __init__(self):
        self.config_file = r"C:\ProgramData\CodeGrey\agent.conf"
        self.server_url = "https://dev.codegrey.ai"
        self.api_key = None
        self.agent_key = None
        self.agent_id = None
        self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.api_key = config.get('api_key')
                self.server_url = config.get('server_url', self.server_url)
                self.agent_key = config.get('agent_key')
                self.agent_id = config.get('agent_id')
    
    def save_config(self):
        """Save configuration to file"""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        config = {
            'api_key': self.api_key,
            'server_url': self.server_url,
            'agent_key': self.agent_key,
            'agent_id': self.agent_id
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def register(self):
        """Register agent with server"""
        if not self.api_key:
            print("ERROR: No API key found in configuration")
            return False
        
        print(f"Registering with {self.server_url}...")
        
        try:
            response = requests.post(
                f"{self.server_url}/api/agent/simple-register",
                json={
                    'api_key': self.api_key,
                    'hostname': socket.gethostname(),
                    'platform': 'Windows'
                },
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.agent_id = data['agent_id']
                self.agent_key = data['agent_key']
                self.save_config()
                print(f"✓ Registered successfully as {self.agent_id}")
                return True
            else:
                print(f"Registration failed: {response.text}")
                return False
                
        except Exception as e:
            print(f"Registration error: {e}")
            return False
    
    def send_heartbeat(self):
        """Send heartbeat to server"""
        if not self.agent_key:
            return False
        
        try:
            response = requests.post(
                f"{self.server_url}/api/agent/heartbeat",
                json={
                    'agent_key': self.agent_key,
                    'agent_id': self.agent_id,
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_percent': psutil.disk_usage('/').percent,
                    'timestamp': datetime.now().isoformat()
                },
                verify=False,
                timeout=5
            )
            return response.status_code == 200
        except:
            return False
    
    def run(self):
        """Main agent loop"""
        # Register if needed
        if not self.agent_key:
            if not self.register():
                print("Failed to register. Exiting.")
                return
        
        print(f"Agent {self.agent_id} is running...")
        print("Press Ctrl+C to stop")
        
        # Main loop
        while True:
            try:
                # Send heartbeat
                if self.send_heartbeat():
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Heartbeat sent")
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Heartbeat failed")
                
                # Wait 60 seconds
                time.sleep(60)
                
            except KeyboardInterrupt:
                print("\nStopping agent...")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(60)

if __name__ == "__main__":
    agent = SimpleAgent()
    agent.run()
