#!/bin/bash

# Simple macOS installer (double-click to run)
clear
echo "========================================="
echo "   CodeGrey SOC Agent - macOS Setup"
echo "========================================="
echo ""

# Get API key
echo "Enter your API Key:"
read API_KEY
echo ""

echo "Installing agent (password required)..."

# Install dependencies
sudo pip3 install requests psutil pyyaml -q 2>/dev/null

# Create directories
sudo mkdir -p /usr/local/codegrey
sudo mkdir -p /etc/codegrey

# Copy agent
sudo cp macos_agent.py /usr/local/codegrey/agent.py
sudo chmod +x /usr/local/codegrey/agent.py

# Create config
sudo bash -c "cat > /etc/codegrey/agent.conf" <<EOF
{
  "api_key": "$API_KEY",
  "server_url": "https://dev.codegrey.ai"
}
EOF

# Create LaunchDaemon
sudo bash -c "cat > /Library/LaunchDaemons/com.codegrey.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.codegrey</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/usr/local/codegrey/agent.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Load agent
sudo launchctl load /Library/LaunchDaemons/com.codegrey.plist

echo ""
echo "========================================="
echo "   Installation Complete!"
echo "========================================="
echo ""
echo "Agent is now running and connected."
echo ""
echo "Press any key to close..."
read -n 1
