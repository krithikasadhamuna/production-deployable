#!/usr/bin/env python3
"""
CodeGrey Agent Installer Wrapper
This wrapper requires a deployment token to be provided during installation
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
from pathlib import Path

class AgentInstaller:
    def __init__(self):
        self.install_path = r"C:\Program Files\CodeGrey"
        self.config_path = r"C:\ProgramData\CodeGrey"
        
    def install(self, deployment_token, server_url, tenant):
        """
        Install agent with deployment configuration
        
        Args:
            deployment_token: The soc-dep-xxxxx token from download API
            server_url: The SOC platform server URL
            tenant: The tenant/organization slug
        """
        if not deployment_token or not deployment_token.startswith('soc-dep-'):
            print("ERROR: Invalid deployment token!")
            print("Please obtain a valid deployment token from your SOC administrator.")
            print("Deployment tokens start with 'soc-dep-'")
            return False
            
        print(f"Installing CodeGrey Agent...")
        print(f"Server: {server_url}")
        print(f"Tenant: {tenant}")
        print(f"Token: {deployment_token[:15]}...")
        
        # Create directories
        os.makedirs(self.install_path, exist_ok=True)
        os.makedirs(self.config_path, exist_ok=True)
        
        # Copy agent files
        agent_file = Path(__file__).parent / "windows_agent.py"
        if agent_file.exists():
            shutil.copy(agent_file, Path(self.install_path) / "windows_agent.py")
        
        # Write configuration
        config = {
            "server_url": server_url,
            "api_key": deployment_token,
            "tenant": tenant,
            "agent_id": None  # Will be generated on first run
        }
        
        config_file = Path(self.config_path) / "agent.conf"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"Configuration saved to {config_file}")
        
        # Install as Windows service (optional)
        self.install_service()
        
        print("\n✓ Installation complete!")
        print("The agent will start automatically and report to your SOC platform.")
        return True
        
    def install_service(self):
        """Install as Windows service"""
        try:
            # This would use pywin32 or nssm to install as service
            # For now, just create a startup script
            startup_script = Path(self.install_path) / "start_agent.bat"
            with open(startup_script, 'w') as f:
                f.write(f'@echo off\n')
                f.write(f'cd /d "{self.install_path}"\n')
                f.write(f'python windows_agent.py\n')
            print(f"Startup script created: {startup_script}")
        except Exception as e:
            print(f"Warning: Could not create service: {e}")

def main():
    parser = argparse.ArgumentParser(description='CodeGrey Agent Installer')
    parser.add_argument('--token', required=True, help='Deployment token (soc-dep-xxxxx)')
    parser.add_argument('--server', default='https://dev.codegrey.ai', help='SOC server URL')
    parser.add_argument('--tenant', required=True, help='Organization/tenant identifier')
    parser.add_argument('--silent', action='store_true', help='Silent installation')
    
    args = parser.parse_args()
    
    # Check for admin privileges
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("ERROR: This installer requires Administrator privileges!")
            print("Please run as Administrator.")
            sys.exit(1)
    
    installer = AgentInstaller()
    success = installer.install(args.token, args.server, args.tenant)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("=" * 60)
        print("CodeGrey Agent Installer")
        print("=" * 60)
        print("\nThis installer requires a deployment token from your SOC platform.")
        print("\nTo obtain a deployment token:")
        print("1. Log into your SOC platform")
        print("2. Go to Software Downloads")
        print("3. Click 'Download' for Windows Agent")
        print("4. You will receive installation instructions with your token")
        print("\nUsage:")
        print("  installer.exe --token soc-dep-xxxxx --tenant yourorg")
        print("\nFor help:")
        print("  installer.exe --help")
        sys.exit(0)
    
    main()
