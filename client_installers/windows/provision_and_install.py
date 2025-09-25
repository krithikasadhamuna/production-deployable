#!/usr/bin/env python3
"""
CodeGrey Agent - Provision and Install
This script provisions the agent with the organization and installs it
"""

import os
import sys
import json
import socket
import platform
import uuid
import requests
import subprocess
from pathlib import Path
import getpass

class AgentProvisioner:
    def __init__(self):
        self.server_url = "https://dev.codegrey.ai"
        self.config_path = r"C:\ProgramData\CodeGrey\agent.conf"
        
    def get_system_info(self):
        """Collect system information for provisioning"""
        try:
            # Get MAC address
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                          for elements in range(0,2*6,2)][::-1])
            
            # Get IP address
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            
            # Get domain info
            try:
                import win32api
                import win32con
                domain = win32api.GetComputerNameEx(win32con.ComputerNameDnsDomain)
            except:
                domain = os.environ.get('USERDOMAIN', 'WORKGROUP')
            
            return {
                'hostname': hostname,
                'platform': 'Windows',
                'ip_address': ip_address,
                'mac_address': mac,
                'username': os.environ.get('USERNAME', getpass.getuser()),
                'domain': domain,
                'department': input("Enter department (e.g., finance, IT, sales): "),
                'location': input("Enter location (e.g., Building A, Floor 3): ")
            }
        except Exception as e:
            print(f"Error collecting system info: {e}")
            return None
    
    def provision_agent(self, user_api_key, system_info):
        """Provision agent with the organization"""
        try:
            headers = {
                'Authorization': f'Bearer {user_api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f'{self.server_url}/api/agent/provision',
                json=system_info,
                headers=headers,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Provisioning failed: {response.text}")
                return None
                
        except Exception as e:
            print(f"Error during provisioning: {e}")
            return None
    
    def save_config(self, provision_data):
        """Save agent configuration"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            config = {
                'server_url': provision_data.get('server_url', self.server_url),
                'api_key': provision_data['api_key'],
                'agent_id': provision_data['agent_id'],
                'tenant': provision_data['tenant'],
                'organization': provision_data.get('organization', ''),
                'config': provision_data.get('config', {})
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"Configuration saved to {self.config_path}")
            return True
            
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def install_agent(self):
        """Install the agent as a service"""
        try:
            # Copy agent to Program Files
            install_path = r"C:\Program Files\CodeGrey"
            os.makedirs(install_path, exist_ok=True)
            
            # Copy windows_agent.py to install location
            import shutil
            agent_file = Path(__file__).parent / "windows_agent.py"
            if agent_file.exists():
                shutil.copy(agent_file, Path(install_path) / "windows_agent.py")
            
            # Create startup batch file
            startup_script = Path(install_path) / "start_agent.bat"
            with open(startup_script, 'w') as f:
                f.write('@echo off\n')
                f.write(f'cd /d "{install_path}"\n')
                f.write('python windows_agent.py\n')
            
            print(f"Agent installed to {install_path}")
            print(f"To start: {startup_script}")
            return True
            
        except Exception as e:
            print(f"Installation error: {e}")
            return False

def main():
    print("=" * 60)
    print("CodeGrey Agent - Provisioning and Installation")
    print("=" * 60)
    print()
    
    # Check for admin privileges
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("ERROR: Administrator privileges required!")
            print("Please run as Administrator.")
            sys.exit(1)
    
    # Get user API key
    print("To provision this agent, you need your user API key.")
    print("You can get this from your SOC administrator or the SOC platform.")
    print()
    
    user_api_key = input("Enter your User API Key (usr-api-xxxxx): ").strip()
    
    if not user_api_key.startswith('usr-api-'):
        print("ERROR: Invalid API key format. User API keys start with 'usr-api-'")
        sys.exit(1)
    
    provisioner = AgentProvisioner()
    
    # Collect system information
    print("\nCollecting system information...")
    system_info = provisioner.get_system_info()
    if not system_info:
        print("ERROR: Failed to collect system information")
        sys.exit(1)
    
    # Provision agent
    print("\nProvisioning agent with organization...")
    provision_data = provisioner.provision_agent(user_api_key, system_info)
    if not provision_data:
        print("ERROR: Provisioning failed")
        sys.exit(1)
    
    print(f"\n✓ Agent provisioned successfully!")
    print(f"  Organization: {provision_data.get('organization', 'N/A')}")
    print(f"  Tenant: {provision_data['tenant']}")
    print(f"  Agent ID: {provision_data['agent_id']}")
    
    # Save configuration
    if not provisioner.save_config(provision_data):
        print("ERROR: Failed to save configuration")
        sys.exit(1)
    
    # Install agent
    print("\nInstalling agent...")
    if not provisioner.install_agent():
        print("ERROR: Installation failed")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("Installation Complete!")
    print("=" * 60)
    print("\nThe agent has been provisioned and installed.")
    print("It will automatically connect to your organization's SOC platform.")
    print("\nAgent ID:", provision_data['agent_id'])
    print("Organization:", provision_data.get('organization', 'N/A'))
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
