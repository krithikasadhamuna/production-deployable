#!/bin/bash

# Simple Linux installer
clear
echo "========================================="
echo "   CodeGrey SOC Agent - Linux Setup"
echo "========================================="
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run with sudo"
    echo "Usage: sudo ./install.sh"
    exit 1
fi

# Get API key
read -p "Enter your API Key: " API_KEY
echo ""

echo "Installing agent..."

# Install dependencies
pip3 install requests psutil pyyaml -q 2>/dev/null

# Create directories
mkdir -p /opt/codegrey
mkdir -p /etc/codegrey

# Copy agent
cp linux_agent.py /opt/codegrey/agent.py
chmod +x /opt/codegrey/agent.py

# Create config
cat > /etc/codegrey/agent.conf <<EOF
{
  "api_key": "$API_KEY",
  "server_url": "https://dev.codegrey.ai"
}
EOF

# Create service
cat > /etc/systemd/system/codegrey.service <<EOF
[Unit]
Description=CodeGrey Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/codegrey/agent.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl daemon-reload
systemctl enable codegrey
systemctl start codegrey

echo ""
echo "========================================="
echo "   Installation Complete!"
echo "========================================="
echo ""
echo "Agent is running. Check status with:"
echo "  systemctl status codegrey"
echo ""