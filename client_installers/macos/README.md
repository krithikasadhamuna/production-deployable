# CodeGrey SOC Agent - macOS Installation Guide

## Package Contents
- `macos_agent.py` - Main agent program  
- `provision_install.sh` - Automated provisioning and installation script
- `requirements.txt` - Python dependencies
- `com.codegrey.agent.plist` - LaunchDaemon configuration
- `README.md` - This file

## Prerequisites
- macOS 11.0 (Big Sur) or later
- Python 3.8 or higher (usually pre-installed)
- Administrator privileges
- Network connectivity to SOC platform (https://dev.codegrey.ai)

## Installation Methods

### Method 1: Automated Provisioning (Recommended)

1. **Get your User API Key**:
   - Log into the SOC platform
   - Go to Profile > API Keys
   - Copy your User API Key (starts with `usr-api-`)

2. **Open Terminal** (Applications > Utilities > Terminal)

3. **Navigate to the agent directory**:
   ```bash
   cd ~/Downloads/codegrey-agent-macos
   ```

4. **Make script executable**:
   ```bash
   chmod +x provision_install.sh
   ```

5. **Run with sudo**:
   ```bash
   sudo ./provision_install.sh
   ```

6. **Follow the prompts**:
   - Enter your User API Key
   - Enter department
   - Enter location

### Method 2: Manual Installation

1. **Install Python dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Create directories**:
   ```bash
   sudo mkdir -p /usr/local/codegrey
   sudo mkdir -p /etc/codegrey
   ```

3. **Copy agent files**:
   ```bash
   sudo cp macos_agent.py /usr/local/codegrey/
   sudo chmod +x /usr/local/codegrey/macos_agent.py
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

5. **Install LaunchDaemon**:
   ```bash
   sudo cp com.codegrey.agent.plist /Library/LaunchDaemons/
   sudo launchctl load /Library/LaunchDaemons/com.codegrey.agent.plist
   ```

## Service Management

### Start the agent:
```bash
sudo launchctl load /Library/LaunchDaemons/com.codegrey.agent.plist
```

### Stop the agent:
```bash
sudo launchctl unload /Library/LaunchDaemons/com.codegrey.agent.plist
```

### Check if running:
```bash
sudo launchctl list | grep codegrey
```

### View logs:
```bash
tail -f /var/log/codegrey-agent.log
```

## Configuration Files

- **Agent Config**: `/etc/codegrey/agent.conf`
- **Agent Program**: `/usr/local/codegrey/macos_agent.py`
- **LaunchDaemon**: `/Library/LaunchDaemons/com.codegrey.agent.plist`
- **Log Files**: `/var/log/codegrey-agent.log`

## Verifying Installation

1. Check if service is running:
   ```bash
   sudo launchctl list | grep codegrey
   ```
   Should show the service with a PID

2. Check recent logs:
   ```bash
   tail -n 50 /var/log/codegrey-agent.log
   ```

3. Verify in SOC dashboard:
   - Agent should appear within 60 seconds
   - Status should show as "Active"

## macOS Security & Privacy

### Granting Permissions

The agent may require additional permissions on macOS:

1. **Full Disk Access** (for comprehensive monitoring):
   - System Preferences > Security & Privacy > Privacy
   - Select "Full Disk Access"
   - Click the lock to make changes
   - Add `/usr/bin/python3` or the agent

2. **Network Monitoring**:
   - Usually granted automatically
   - Check if firewall is blocking connections

### Code Signing (Future Versions)
Future versions will be properly code-signed to avoid Gatekeeper warnings.

## Troubleshooting

### "Operation not permitted" errors
- Ensure running with sudo
- Check System Integrity Protection (SIP) status: `csrutil status`
- Grant Full Disk Access if needed

### LaunchDaemon not loading
```bash
# Check for errors
sudo launchctl list | grep codegrey

# View system log
log show --predicate 'subsystem == "com.apple.launchd"' --last 5m

# Try loading with verbose output
sudo launchctl load -w /Library/LaunchDaemons/com.codegrey.agent.plist
```

### Connection issues
- Check firewall settings in System Preferences
- Test connectivity: `curl -I https://dev.codegrey.ai`
- Check DNS: `nslookup dev.codegrey.ai`

### Python issues
```bash
# Check Python version
python3 --version

# Install/update Python if needed
brew install python3
```

### Agent not appearing in dashboard
- Verify API key format and validity
- Check tenant assignment
- Review logs for registration errors

## Security Notes

- Agent requires root privileges for system monitoring
- All communication uses HTTPS encryption
- API keys stored with restricted permissions
- Agent operates read-only, no system modifications

## Firewall Configuration

If needed, allow outbound HTTPS:

1. System Preferences > Security & Privacy > Firewall
2. Click "Firewall Options"
3. Ensure "Block all incoming connections" is unchecked
4. Add `/usr/local/codegrey/macos_agent.py` if needed

## Uninstallation

To completely remove the agent:

```bash
# Stop and unload LaunchDaemon
sudo launchctl unload /Library/LaunchDaemons/com.codegrey.agent.plist
sudo rm /Library/LaunchDaemons/com.codegrey.agent.plist

# Remove files
sudo rm -rf /usr/local/codegrey
sudo rm -rf /etc/codegrey
sudo rm -f /var/log/codegrey-agent*

# Remove from Full Disk Access if granted
# (Manual step in System Preferences)
```

## Support

For assistance, contact your SOC administrator or support team.

## Known Issues

- On Apple Silicon Macs, ensure using native Python3, not x86 emulation
- Some security tools may flag the agent; add to exclusions if needed
- VPN connections may affect agent connectivity
