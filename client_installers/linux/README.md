# CodeGrey SOC Agent - Linux Installation Guide

## Package Contents
- `linux_agent.py` - Main agent program
- `provision_install.sh` - Automated provisioning and installation script
- `requirements.txt` - Python dependencies
- `codegrey-agent.service` - Systemd service file
- `README.md` - This file

## Prerequisites
- Linux (Ubuntu 18.04+, CentOS 7+, RHEL 8+, Debian 10+)
- Python 3.6 or higher
- Root or sudo access
- Network connectivity to SOC platform (https://dev.codegrey.ai)

## Installation Methods

### Method 1: Automated Provisioning (Recommended)

1. **Get your User API Key**:
   - Log into the SOC platform
   - Go to Profile > API Keys
   - Copy your User API Key (starts with `usr-api-`)

2. **Make script executable**:
   ```bash
   chmod +x provision_install.sh
   ```

3. **Run with sudo**:
   ```bash
   sudo ./provision_install.sh
   ```

4. **Follow the prompts**:
   - Enter your User API Key
   - Enter department
   - Enter location

### Method 2: Manual Installation

1. **Install Python dependencies**:
   ```bash
   sudo pip3 install -r requirements.txt
   ```

2. **Create directories**:
   ```bash
   sudo mkdir -p /opt/codegrey
   sudo mkdir -p /etc/codegrey
   ```

3. **Copy agent files**:
   ```bash
   sudo cp linux_agent.py /opt/codegrey/
   sudo chmod +x /opt/codegrey/linux_agent.py
   ```

4. **Create configuration** at `/etc/codegrey/agent.conf`:
   ```json
   {
     "server_url": "https://dev.codegrey.ai",
     "api_key": "your-agent-api-key",
     "tenant": "your-tenant-slug",
     "agent_id": null
   }
   ```

5. **Install as systemd service**:
   ```bash
   sudo cp codegrey-agent.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable codegrey-agent
   sudo systemctl start codegrey-agent
   ```

## Service Management

### Start the agent:
```bash
sudo systemctl start codegrey-agent
```

### Stop the agent:
```bash
sudo systemctl stop codegrey-agent
```

### Check status:
```bash
sudo systemctl status codegrey-agent
```

### View logs:
```bash
sudo journalctl -u codegrey-agent -f
```

## Configuration Files

- **Agent Config**: `/etc/codegrey/agent.conf`
- **Agent Program**: `/opt/codegrey/linux_agent.py`
- **Service File**: `/etc/systemd/system/codegrey-agent.service`
- **Log Output**: Use `journalctl` to view

## Verifying Installation

1. Check service status:
   ```bash
   sudo systemctl status codegrey-agent
   ```
   Should show "active (running)"

2. Check recent logs:
   ```bash
   sudo journalctl -u codegrey-agent --since "5 minutes ago"
   ```

3. Verify in SOC dashboard:
   - Agent should appear within 60 seconds
   - Status should show as "Active"

## Troubleshooting

### Permission denied errors
- Ensure running with sudo
- Check file permissions: `ls -la /opt/codegrey/`

### Service fails to start
```bash
# Check for errors
sudo journalctl -u codegrey-agent -n 50

# Verify Python path
which python3

# Test agent directly
sudo python3 /opt/codegrey/linux_agent.py
```

### Connection issues
- Check firewall: `sudo ufw status` (Ubuntu) or `sudo firewall-cmd --list-all` (CentOS/RHEL)
- Test connectivity: `curl -I https://dev.codegrey.ai`
- Check DNS: `nslookup dev.codegrey.ai`

### Agent not appearing in dashboard
- Verify API key is correct
- Check tenant assignment
- Review logs for registration errors

## Security Notes

- Agent runs as root to monitor system activities
- All communication uses HTTPS encryption
- API keys stored with 600 permissions
- Agent only reads system information, no modifications

## Firewall Configuration

If needed, allow outbound HTTPS:

### UFW (Ubuntu/Debian):
```bash
sudo ufw allow out 443/tcp
```

### Firewalld (CentOS/RHEL):
```bash
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## Uninstallation

To completely remove the agent:

```bash
# Stop and disable service
sudo systemctl stop codegrey-agent
sudo systemctl disable codegrey-agent

# Remove files
sudo rm -rf /opt/codegrey
sudo rm -rf /etc/codegrey
sudo rm /etc/systemd/system/codegrey-agent.service

# Reload systemd
sudo systemctl daemon-reload
```

## Support

For assistance, contact your SOC administrator or support team.
