# Frontend API Structure

## 1. Software Downloads API
**Endpoint:** `GET /api/software-download`

**Response Structure:**
```json
[
    {
        "id": 1,
        "name": "windows",
        "version": "2024.1.3",
        "description": "Windows endpoint agent with real-time monitoring, behavioral analysis, and AI-powered threat detection.",
        "fileName": "CodeGrey AI Endpoint Agent",
        "downloadUrl": "https://dev-codegrey.s3.ap-south-1.amazonaws.com/windows.zip",
        "os": "Windows",
        "architecture": "x64",
        "minRamGB": 4,
        "minDiskMB": 500,
        "configurationCmd": "codegrey-agent.exe --configure --server=https://dev.codegrey.ai --token=YOUR_API_TOKEN",
        "systemRequirements": [
            "Windows 10/11 (64-bit)",
            "Administrator privileges",
            "4 GB RAM",
            "500 MB disk space"
        ]
    },
    // Linux and macOS agents follow same structure
]
```

## 2. AI Agents API
**Endpoint:** `GET /api/agents`

**Response Structure:**
```json
[
    {
        "id": "1",
        "name": "PhantomStrike AI",
        "type": "attack",
        "status": "idle",
        "location": "External Network",
        "lastActivity": "2 mins ago",
        "capabilities": [...],
        "enabled": true
    },
    {
        "id": "2",
        "name": "GuardianAlpha AI",
        "type": "detection",
        "status": "active",
        "location": "SOC Infrastructure",
        "lastActivity": "Now",
        "capabilities": [...],
        "enabled": true
    },
    {
        "id": "3",
        "name": "SentinalDeploy AI",
        "type": "enforcement",
        "status": "disabled",
        "location": "Enforcement Layer",
        "lastActivity": "Not Active",
        "capabilities": [...],
        "enabled": false
    },
    {
        "id": "4",
        "name": "ThreatMind AI",
        "type": "intelligence",
        "status": "disabled",
        "location": "Intelligence Hub",
        "lastActivity": "Not Active",
        "capabilities": [...],
        "enabled": false
    }
]
```

**Note:** Last 2 agents (SentinalDeploy AI and ThreatMind AI) will always have `enabled: false` and `status: "disabled"` for UI to disable them by default.

## 3. Software Download Tracking
**Endpoint:** `POST /api/software-download/{id}`

**Request Body:**
```json
{
    "user_email": "user@codegrey.ai",
    "tenant": "codegrey",
    "endpoint_type": "employee",
    "department": "finance",
    "num_licenses": 1
}
```

**Response:**
```json
{
    "success": true,
    "deployment": {
        "id": "dep_abc123",
        "api_key": "soc-dep-xxxxx",
        "platform": "Windows"
    },
    "installation_command": "...",
    "download_url": "https://dev.codegrey.ai/downloads/dep_abc123/agent-windows.zip"
}
```
