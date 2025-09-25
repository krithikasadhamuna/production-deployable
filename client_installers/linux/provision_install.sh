#!/bin/bash

# CodeGrey SOC Agent - Linux Provisioning and Installation Script

set -e

echo "========================================"
echo "CodeGrey SOC Agent - Linux Installation"
echo "========================================"
echo ""

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run with sudo or as root"
    exit 1
fi

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is required but not installed"
    echo "Install with: apt-get install python3 python3-pip (Ubuntu/Debian)"
    echo "          or: yum install python3 python3-pip (CentOS/RHEL)"
    exit 1
fi

# Function to get system info
get_system_info() {
    HOSTNAME=$(hostname)
    PLATFORM="Linux"
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    MAC_ADDRESS=$(ip link show | awk '/ether/ {print $2}' | head -1)
    USERNAME=$(who am i | awk '{print $1}')
    DOMAIN=$(hostname -d)
    
    if [ -z "$DOMAIN" ]; then
        DOMAIN="WORKGROUP"
    fi
}

# Function to provision agent
provision_agent() {
    local api_key=$1
    local department=$2
    local location=$3
    
    echo "Provisioning agent with organization..."
    
    # Create JSON payload
    JSON_DATA=$(cat <<EOF
{
    "hostname": "$HOSTNAME",
    "platform": "$PLATFORM",
    "ip_address": "$IP_ADDRESS",
    "mac_address": "$MAC_ADDRESS",
    "username": "$USERNAME",
    "domain": "$DOMAIN",
    "department": "$department",
    "location": "$location"
}
EOF
)
    
    # Make provisioning request
    RESPONSE=$(curl -s -X POST \
        -H "Authorization: Bearer $api_key" \
        -H "Content-Type: application/json" \
        -d "$JSON_DATA" \
        https://dev.codegrey.ai/api/agent/provision)
    
    # Check if successful
    if echo "$RESPONSE" | grep -q "success.*true"; then
        echo "✓ Agent provisioned successfully"
        
        # Extract values from response
        AGENT_ID=$(echo "$RESPONSE" | grep -o '"agent_id":"[^"]*' | cut -d'"' -f4)
        AGENT_API_KEY=$(echo "$RESPONSE" | grep -o '"api_key":"[^"]*' | cut -d'"' -f4)
        TENANT=$(echo "$RESPONSE" | grep -o '"tenant":"[^"]*' | cut -d'"' -f4)
        ORGANIZATION=$(echo "$RESPONSE" | grep -o '"organization":"[^"]*' | cut -d'"' -f4)
        
        echo "  Organization: $ORGANIZATION"
        echo "  Tenant: $TENANT"
        echo "  Agent ID: $AGENT_ID"
        
        return 0
    else
        echo "ERROR: Provisioning failed"
        echo "Response: $RESPONSE"
        return 1
    fi
}

# Main installation flow
main() {
    echo "This installation requires a User API Key from your SOC platform."
    echo ""
    read -p "Enter your User API Key (usr-api-xxxxx): " USER_API_KEY
    
    # Validate API key format
    if [[ ! "$USER_API_KEY" =~ ^usr-api- ]]; then
        echo "ERROR: Invalid API key format. User API keys start with 'usr-api-'"
        exit 1
    fi
    
    read -p "Enter department (e.g., IT, finance, sales): " DEPARTMENT
    read -p "Enter location (e.g., Building A, Floor 3): " LOCATION
    
    # Get system information
    echo ""
    echo "Collecting system information..."
    get_system_info
    
    # Provision agent
    if ! provision_agent "$USER_API_KEY" "$DEPARTMENT" "$LOCATION"; then
        exit 1
    fi
    
    # Install dependencies
    echo ""
    echo "Installing Python dependencies..."
    pip3 install requests psutil pyyaml || {
        echo "WARNING: Failed to install some dependencies"
        echo "You may need to install them manually"
    }
    
    # Create directories
    echo "Creating directories..."
    mkdir -p /opt/codegrey
    mkdir -p /etc/codegrey
    
    # Copy agent file
    echo "Installing agent..."
    cp linux_agent.py /opt/codegrey/
    chmod +x /opt/codegrey/linux_agent.py
    
    # Create configuration
    echo "Saving configuration..."
    cat > /etc/codegrey/agent.conf <<EOF
{
    "server_url": "https://dev.codegrey.ai",
    "api_key": "$AGENT_API_KEY",
    "agent_id": "$AGENT_ID",
    "tenant": "$TENANT",
    "organization": "$ORGANIZATION"
}
EOF
    chmod 600 /etc/codegrey/agent.conf
    
    # Install systemd service
    echo "Installing systemd service..."
    cat > /etc/systemd/system/codegrey-agent.service <<EOF
[Unit]
Description=CodeGrey Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/codegrey
ExecStart=/usr/bin/python3 /opt/codegrey/linux_agent.py
Restart=always
RestartSec=10

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
    echo "Agent has been installed and started."
    echo ""
    echo "Useful commands:"
    echo "  Check status:  systemctl status codegrey-agent"
    echo "  View logs:     journalctl -u codegrey-agent -f"
    echo "  Stop agent:    systemctl stop codegrey-agent"
    echo "  Start agent:   systemctl start codegrey-agent"
    echo ""
    echo "Agent ID: $AGENT_ID"
    echo "Organization: $ORGANIZATION"
    echo ""
}

# Run main function
main
