# CodeGrey SOC Platform - Client Agents

## Available Packages

### 1. Windows Agent (codegrey-agent-windows.zip)
- For: Windows 10/11 (64-bit)
- Requires: Python 3.8+, Administrator privileges
- Installation: Extract and run provision_and_install.py as Administrator

### 2. Linux Agent (codegrey-agent-linux.zip)
- For: Ubuntu 18.04+, CentOS 7+, RHEL 8+, Debian 10+
- Requires: Python 3.6+, sudo access
- Installation: Extract and run sudo ./provision_install.sh

### 3. macOS Agent (codegrey-agent-macos.zip)
- For: macOS 11.0+ (Big Sur or later)
- Requires: Python 3.8+, Administrator privileges
- Installation: Extract and run sudo ./provision_install.sh

## Installation Overview

All agents support two installation methods:

### Method 1: User API Key Provisioning (Recommended)
1. SOC analyst obtains User API Key from platform
2. Run the provisioning script on target endpoint
3. Enter User API Key when prompted
4. Agent automatically registers with correct organization

### Method 2: Pre-configured Deployment
1. SOC platform generates deployment token
2. Token embedded in installation command
3. Agent uses token for authentication

## Key Features

- **Multi-tenant Support**: Agents automatically associate with correct organization
- **Auto-discovery**: Detects endpoint type (executive, SOC, server, employee)
- **Secure Communication**: All traffic encrypted via HTTPS
- **Minimal Footprint**: Lightweight monitoring with low resource usage
- **Cross-platform**: Consistent functionality across Windows, Linux, macOS

## Security Considerations

- User API Keys are tied to specific organizations
- Each agent gets unique credentials upon provisioning
- Endpoint fingerprinting prevents duplicate registrations
- All API keys can be revoked from SOC platform

## Deployment Best Practices

1. **Test First**: Deploy to test endpoints before production
2. **Staged Rollout**: Deploy in phases to monitor impact
3. **Document Assignments**: Track which analyst deployed which agents
4. **Regular Updates**: Keep agents updated with latest versions
5. **Monitor Status**: Check SOC dashboard for agent health

## Troubleshooting

Common issues and solutions are documented in each platform's README.md file.

## Support

For technical assistance, contact your SOC platform administrator.

---
Package Version: 2024.1.3
Build Date: 2025-09-25
