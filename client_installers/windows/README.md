# CodeGrey SOC Agent - Windows Installation Guide

## Package Contents
- `windows_agent.py` - Main agent program
- `provision_and_install.py` - Automated provisioning and installation script
- `installer_wrapper.py` - Alternative installer for pre-configured deployments
- `requirements.txt` - Python dependencies
- `README.md` - This file

## Prerequisites
- Windows 10/11 (64-bit)
- Python 3.8 or higher installed
- Administrator privileges
- Network connectivity to SOC platform (https://dev.codegrey.ai)

## Installation Methods

### Method 1: User API Key Provisioning (Recommended)
This method automatically registers the agent with your organization.

1. **Get your User API Key**:
   - Log into the SOC platform
   - Go to Profile > API Keys
   - Copy your User API Key (starts with `usr-api-`)

2. **Run as Administrator**:
   ```cmd
   python provision_and_install.py
   ```

3. **Follow the prompts**:
   - Enter your User API Key
   - Enter department (e.g., finance, IT, sales)
   - Enter location (e.g., Building A, Floor 3)

4. **Agent will automatically**:
   - Register with your organization
   - Save configuration
   - Install to C:\Program Files\CodeGrey

### Method 2: Pre-configured Deployment Token
If your SOC administrator provided a deployment token:

1. **Run as Administrator**:
   ```cmd
   python installer_wrapper.py --token soc-dep-xxxxx --tenant yourorg
   ```

### Method 3: Manual Installation
For advanced users or troubleshooting:

1. **Install dependencies**:
   ```cmd
   pip install -r requirements.txt
   ```

2. **Create configuration** at `C:\ProgramData\CodeGrey\agent.conf`:
   ```json
   {
     "server_url": "https://dev.codegrey.ai",
     "api_key": "your-agent-api-key",
     "tenant": "your-tenant-slug",
     "agent_id": null
   }
   ```

3. **Run the agent**:
   ```cmd
   python windows_agent.py
   ```

## Starting the Agent

### Option 1: Run directly
```cmd
cd "C:\Program Files\CodeGrey"
python windows_agent.py
```

### Option 2: Use startup script
```cmd
"C:\Program Files\CodeGrey\start_agent.bat"
```

### Option 3: Install as Windows Service (Coming Soon)
The agent will be configured to run as a Windows service in future versions.

## Verifying Installation

1. Check agent logs:
   ```cmd
   type C:\Program Files\CodeGrey\codegrey_agent.log
   ```

2. Verify connectivity:
   - Agent should report "Registration successful" in logs
   - Check SOC platform dashboard for agent status

## Configuration Files

- **Agent Config**: `C:\ProgramData\CodeGrey\agent.conf`
- **Log File**: `C:\Program Files\CodeGrey\codegrey_agent.log`
- **Agent Program**: `C:\Program Files\CodeGrey\windows_agent.py`

## Troubleshooting

### "Administrator privileges required"
- Right-click Command Prompt and select "Run as Administrator"

### "Connection refused" or timeout errors
- Check firewall settings
- Verify network connectivity to https://dev.codegrey.ai
- Check proxy settings if applicable

### "Invalid API key"
- Ensure your User API Key starts with `usr-api-`
- Verify the key is active in SOC platform
- Check you're using the correct tenant

### Agent not appearing in dashboard
- Wait 60 seconds for first heartbeat
- Check agent.log for errors
- Verify tenant assignment is correct

## Security Notes

- The agent requires Administrator privileges to monitor system activities
- All communication with SOC platform is encrypted (HTTPS)
- API keys are stored locally in protected directory
- Agent does not modify system files or settings

## Support

For assistance, contact your SOC administrator or support team.

## Uninstallation

To remove the agent:

1. Stop the agent process
2. Delete `C:\Program Files\CodeGrey`
3. Delete `C:\ProgramData\CodeGrey`
4. Remove from startup if configured
