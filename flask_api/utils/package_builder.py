"""
Dynamic Package Builder for Client Agents
Creates customized agent packages with embedded deployment tokens
"""

import os
import json
import zipfile
import tempfile
import shutil
from pathlib import Path
import uuid

class AgentPackageBuilder:
    def __init__(self, base_path="/app/client_installers"):
        self.base_path = Path(base_path)
        self.temp_dir = Path(tempfile.gettempdir()) / "agent_packages"
        self.temp_dir.mkdir(exist_ok=True)
        
    def build_package(self, platform, deployment_token, tenant, server_url="https://dev.codegrey.ai"):
        """
        Build a customized agent package with embedded configuration
        
        Args:
            platform: 'windows', 'linux', or 'macos'
            deployment_token: The soc-dep-xxxxx token
            tenant: The tenant/organization slug
            server_url: The SOC platform URL
            
        Returns:
            Path to the created ZIP file
        """
        # Create unique package directory
        package_id = uuid.uuid4().hex[:8]
        package_dir = self.temp_dir / f"{platform}_{package_id}"
        package_dir.mkdir(exist_ok=True)
        
        try:
            # Copy agent files
            source_dir = self.base_path / platform
            if platform == 'windows':
                agent_file = 'windows_agent.py'
                installer_file = 'installer_wrapper.py'
            elif platform == 'linux':
                agent_file = 'linux_agent.py'
                installer_file = 'install.sh'
            elif platform == 'macos':
                agent_file = 'macos_agent.py'
                installer_file = 'install.sh'
            else:
                raise ValueError(f"Unsupported platform: {platform}")
            
            # Copy main agent file
            shutil.copy(source_dir / agent_file, package_dir / agent_file)
            
            # Create configuration file with deployment token
            config = {
                "server_url": server_url,
                "api_key": deployment_token,
                "tenant": tenant,
                "agent_id": None,
                "deployment_info": {
                    "package_id": package_id,
                    "platform": platform,
                    "created_at": str(uuid.uuid4())
                }
            }
            
            config_file = package_dir / "agent.conf"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Create platform-specific installer
            if platform == 'windows':
                self._create_windows_installer(package_dir, deployment_token, tenant, server_url)
            elif platform == 'linux':
                self._create_linux_installer(package_dir, deployment_token, tenant, server_url)
            elif platform == 'macos':
                self._create_macos_installer(package_dir, deployment_token, tenant, server_url)
            
            # Create README
            readme_content = f"""
# CodeGrey Agent - {platform.title()}

## Pre-configured for: {tenant}

This agent package has been pre-configured with your deployment credentials.

## Installation

### Windows:
1. Run as Administrator: install.bat
2. Or manually: python windows_agent.py --install

### Linux/macOS:
1. chmod +x install.sh
2. sudo ./install.sh

## Configuration

Your deployment token has been embedded in agent.conf
No additional configuration is required.

## Support

Contact your SOC administrator for assistance.
"""
            
            with open(package_dir / "README.md", 'w') as f:
                f.write(readme_content)
            
            # Create ZIP package
            zip_path = self.temp_dir / f"codegrey_agent_{platform}_{package_id}.zip"
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file in package_dir.rglob('*'):
                    if file.is_file():
                        arcname = file.relative_to(package_dir)
                        zipf.write(file, arcname)
            
            # Clean up package directory
            shutil.rmtree(package_dir)
            
            return zip_path
            
        except Exception as e:
            # Clean up on error
            if package_dir.exists():
                shutil.rmtree(package_dir)
            raise e
    
    def _create_windows_installer(self, package_dir, token, tenant, server):
        """Create Windows batch installer"""
        installer_content = f"""@echo off
echo ========================================
echo CodeGrey Agent Installer for Windows
echo ========================================
echo.
echo Organization: {tenant}
echo Server: {server}
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Administrator privileges required!
    echo Please run as Administrator.
    pause
    exit /b 1
)

:: Create directories
mkdir "C:\\Program Files\\CodeGrey" 2>nul
mkdir "C:\\ProgramData\\CodeGrey" 2>nul

:: Copy files
echo Installing agent files...
copy /Y "windows_agent.py" "C:\\Program Files\\CodeGrey\\"
copy /Y "agent.conf" "C:\\ProgramData\\CodeGrey\\"

:: Install Python dependencies
echo Installing dependencies...
pip install requests psutil pyyaml

:: Create startup script
echo Creating startup script...
echo @echo off > "C:\\Program Files\\CodeGrey\\start_agent.bat"
echo cd /d "C:\\Program Files\\CodeGrey" >> "C:\\Program Files\\CodeGrey\\start_agent.bat"
echo python windows_agent.py >> "C:\\Program Files\\CodeGrey\\start_agent.bat"

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo To start the agent:
echo   "C:\\Program Files\\CodeGrey\\start_agent.bat"
echo.
pause
"""
        with open(package_dir / "install.bat", 'w') as f:
            f.write(installer_content)
    
    def _create_linux_installer(self, package_dir, token, tenant, server):
        """Create Linux shell installer"""
        installer_content = f"""#!/bin/bash

echo "========================================"
echo "CodeGrey Agent Installer for Linux"
echo "========================================"
echo ""
echo "Organization: {tenant}"
echo "Server: {server}"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run as root (use sudo)"
    exit 1
fi

# Create directories
mkdir -p /opt/codegrey
mkdir -p /etc/codegrey

# Copy files
echo "Installing agent files..."
cp linux_agent.py /opt/codegrey/
cp agent.conf /etc/codegrey/
chmod +x /opt/codegrey/linux_agent.py

# Install dependencies
echo "Installing dependencies..."
pip3 install requests psutil pyyaml

# Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/codegrey-agent.service << EOF
[Unit]
Description=CodeGrey Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/codegrey
ExecStart=/usr/bin/python3 /opt/codegrey/linux_agent.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable codegrey-agent
systemctl start codegrey-agent

echo ""
echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "Agent status: systemctl status codegrey-agent"
echo "Agent logs: journalctl -u codegrey-agent -f"
echo ""
"""
        with open(package_dir / "install.sh", 'w') as f:
            f.write(installer_content)
        os.chmod(package_dir / "install.sh", 0o755)
    
    def _create_macos_installer(self, package_dir, token, tenant, server):
        """Create macOS shell installer"""
        installer_content = f"""#!/bin/bash

echo "========================================"
echo "CodeGrey Agent Installer for macOS"
echo "========================================"
echo ""
echo "Organization: {tenant}"
echo "Server: {server}"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run with sudo"
    exit 1
fi

# Create directories
mkdir -p /usr/local/codegrey
mkdir -p /etc/codegrey

# Copy files
echo "Installing agent files..."
cp macos_agent.py /usr/local/codegrey/
cp agent.conf /etc/codegrey/
chmod +x /usr/local/codegrey/macos_agent.py

# Install dependencies
echo "Installing dependencies..."
pip3 install requests psutil pyyaml

# Create LaunchDaemon
echo "Creating LaunchDaemon..."
cat > /Library/LaunchDaemons/com.codegrey.agent.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.codegrey.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/usr/local/codegrey/macos_agent.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/codegrey-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/codegrey-agent.error.log</string>
</dict>
</plist>
EOF

# Load the LaunchDaemon
launchctl load /Library/LaunchDaemons/com.codegrey.agent.plist

echo ""
echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "Agent status: launchctl list | grep codegrey"
echo "Agent logs: tail -f /var/log/codegrey-agent.log"
echo ""
"""
        with open(package_dir / "install.sh", 'w') as f:
            f.write(installer_content)
        os.chmod(package_dir / "install.sh", 0o755)
    
    def cleanup_old_packages(self, max_age_hours=24):
        """Clean up old temporary packages"""
        import time
        current_time = time.time()
        for package_file in self.temp_dir.glob("*.zip"):
            file_age = current_time - package_file.stat().st_mtime
            if file_age > (max_age_hours * 3600):
                package_file.unlink()
