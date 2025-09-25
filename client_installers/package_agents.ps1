# PowerShell script to create ZIP packages for each platform's agent

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Creating Client Agent Installation Packages" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get current directory
$baseDir = Get-Location
$outputDir = Join-Path $baseDir "packaged_agents"

# Create output directory
if (Test-Path $outputDir) {
    Remove-Item $outputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $outputDir | Out-Null

# Function to create ZIP package
function Create-AgentPackage {
    param(
        [string]$Platform,
        [string]$SourceDir,
        [string]$OutputFile
    )
    
    Write-Host "Packaging $Platform agent..." -ForegroundColor Yellow
    
    # Check if source directory exists
    if (-not (Test-Path $SourceDir)) {
        Write-Host "  ERROR: Source directory not found: $SourceDir" -ForegroundColor Red
        return
    }
    
    # Create ZIP file
    try {
        Compress-Archive -Path "$SourceDir\*" -DestinationPath $OutputFile -Force
        $size = [math]::Round((Get-Item $OutputFile).Length / 1MB, 2)
        Write-Host "  Created: $(Split-Path $OutputFile -Leaf) (${size}MB)" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Failed to create package: $_" -ForegroundColor Red
    }
}

# Package Windows agent
$windowsSource = Join-Path $baseDir "windows"
$windowsOutput = Join-Path $outputDir "codegrey-agent-windows.zip"
Create-AgentPackage -Platform "Windows" -SourceDir $windowsSource -OutputFile $windowsOutput

# Package Linux agent
$linuxSource = Join-Path $baseDir "linux"
$linuxOutput = Join-Path $outputDir "codegrey-agent-linux.zip"
Create-AgentPackage -Platform "Linux" -SourceDir $linuxSource -OutputFile $linuxOutput

# Package macOS agent
$macosSource = Join-Path $baseDir "macos"
$macosOutput = Join-Path $outputDir "codegrey-agent-macos.zip"
Create-AgentPackage -Platform "macOS" -SourceDir $macosSource -OutputFile $macosOutput

# Create master README
$masterReadme = @"
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
Build Date: $(Get-Date -Format "yyyy-MM-dd")
"@

$masterReadme | Out-File -FilePath (Join-Path $outputDir "README.md") -Encoding UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Package Creation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Packages created in: $outputDir" -ForegroundColor Yellow
Write-Host ""
Write-Host "Files created:" -ForegroundColor Cyan
Get-ChildItem $outputDir | ForEach-Object {
    $size = [math]::Round($_.Length / 1MB, 2)
    Write-Host "  - $($_.Name) (${size}MB)"
}
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Upload these ZIP files to your S3 bucket or file server"
Write-Host "2. Update the frontend download URLs to point to these packages"
Write-Host "3. Provide User API Keys to SOC analysts for agent deployment"
Write-Host ""
