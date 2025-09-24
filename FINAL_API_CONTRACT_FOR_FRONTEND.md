# 📝 **FINAL API CONTRACT - READY FOR FRONTEND TEAM**

**Backend APIs: COMPLETE ✅**  
**Status: Ready for Integration**  
**Base URL: `https://dev.codegrey.ai:443/api`**  
**Authorization: Bearer Token Required**

---

## 1️⃣ **SOFTWARE DOWNLOAD API** ✅

### **Track Download When User Downloads Agent**
```http
POST /api/agents/track-download
Authorization: Bearer {token}
Content-Type: application/json

Request Body:
{
  "userId": "user-abc123",
  "platform": "windows",  // windows|linux|macos
  "version": "1.0.0"
}

Response (200 OK):
{
  "success": true,
  "downloadId": "dl-xyz789",
  "agentId": "agent-456def",
  "installationKey": "inst-key-789abc",
  "message": "Download tracked, agent ID assigned"
}
```

### **Get Download Links**
```http
GET /api/software/download-links
Authorization: Bearer {token}

Response (200 OK):
{
  "success": true,
  "downloads": {
    "windows": {
      "url": "/downloads/codegrey-agent-windows.exe",
      "version": "1.0.0",
      "size": "45MB",
      "checksum": "sha256:abc123..."
    },
    "linux": {
      "url": "/downloads/codegrey-agent-linux",
      "version": "1.0.0",
      "size": "42MB",
      "checksum": "sha256:def456..."
    },
    "macos": {
      "url": "/downloads/codegrey-agent-macos",
      "version": "1.0.0",
      "size": "44MB",
      "checksum": "sha256:ghi789..."
    }
  }
}
```

---

## 2️⃣ **AGENT LISTING API** ✅

### **Get All Agents (Tabular Format)**
```http
GET /api/agents/list?format=table&sort=status&order=desc
Authorization: Bearer {token}

Query Parameters:
- format: "table" (required for tabular display)
- sort: "name" | "status" | "lastActivity" | "type" | "location"
- order: "asc" | "desc"
- filter: "online" | "offline" | "all"

Response (200 OK):
{
  "success": true,
  "totalAgents": 45,
  "onlineAgents": 38,
  "agents": [
    {
      "id": "agent-001",
      "name": "DESKTOP-ABC123",
      "type": "endpoint",
      "status": "online",
      "location": "192.168.1.100",
      "zone": "Corporate Network",
      "lastActivity": "2 mins ago",
      "lastHeartbeat": "2025-09-24T12:45:00Z",
      "userId": "user-abc123",
      "userName": "John Doe",
      "platform": "windows",
      "version": "1.0.0",
      "capabilities": [
        "Log Collection",
        "Command Execution",
        "File Monitoring",
        "Process Monitoring",
        "Network Monitoring"
      ],
      "metrics": {
        "cpuUsage": 45,
        "memoryUsage": 62,
        "diskUsage": 78,
        "eventsPerMinute": 120
      }
    },
    {
      "id": "agent-002",
      "name": "LINUX-SERVER-01",
      "type": "endpoint",
      "status": "offline",
      "location": "10.0.1.50",
      "zone": "DMZ",
      "lastActivity": "2 hours ago",
      "lastHeartbeat": "2025-09-24T10:30:00Z",
      "userId": "user-def456",
      "userName": "Jane Smith",
      "platform": "linux",
      "version": "1.0.0",
      "capabilities": [
        "Log Collection",
        "Command Execution",
        "File Monitoring"
      ],
      "metrics": {
        "cpuUsage": 0,
        "memoryUsage": 0,
        "diskUsage": 0,
        "eventsPerMinute": 0
      }
    }
  ]
}
```

---

## 3️⃣ **NETWORK CANVAS API (TABULAR FORMAT)** ✅

### **Get Network Topology (Tabular/Hierarchical)**
```http
GET /api/network/topology?format=table&hierarchy=true
Authorization: Bearer {token}

Query Parameters:
- format: "table" (required for tabular display)
- hierarchy: true | false
- sort: "name" | "type" | "level" | "agents"
- order: "asc" | "desc"

Response (200 OK):
{
  "success": true,
  "topology": [
    {
      "id": "node-internet",
      "name": "Internet Gateway",
      "type": "gateway",
      "level": 0,
      "parentId": null,
      "agentCount": 3,
      "agents": ["agent-001", "agent-002", "agent-003"],
      "status": "normal",
      "zone": "External",
      "ipRange": "0.0.0.0/0"
    },
    {
      "id": "node-firewall",
      "name": "Main Firewall",
      "type": "firewall",
      "level": 1,
      "parentId": "node-internet",
      "agentCount": 0,
      "agents": [],
      "status": "normal",
      "zone": "Perimeter",
      "ipRange": "203.0.113.0/24"
    },
    {
      "id": "node-dmz",
      "name": "DMZ Network",
      "type": "network",
      "level": 2,
      "parentId": "node-firewall",
      "agentCount": 5,
      "agents": ["agent-004", "agent-005", "agent-006", "agent-007", "agent-008"],
      "status": "warning",
      "zone": "DMZ",
      "ipRange": "10.0.1.0/24"
    },
    {
      "id": "node-internal",
      "name": "Corporate Network",
      "type": "network",
      "level": 2,
      "parentId": "node-firewall",
      "agentCount": 25,
      "agents": ["agent-009", "agent-010", "agent-011"],
      "status": "normal",
      "zone": "Internal",
      "ipRange": "192.168.0.0/16"
    }
  ]
}
```

### **Get Network Canvas with Agent Details**
```http
GET /api/network/topology-detailed?includeAgents=true
Authorization: Bearer {token}

Response (200 OK):
{
  "success": true,
  "nodes": [
    {
      "id": "node-internet",
      "name": "Internet Gateway",
      "type": "gateway",
      "level": 0,
      "x": 50,
      "y": 10,
      "agents": [
        {
          "id": "agent-001",
          "name": "HONEYPOT-01",
          "status": "online",
          "platform": "linux"
        }
      ],
      "status": "normal",
      "metrics": {
        "totalTraffic": "1.2GB",
        "threats": 3,
        "connections": 145
      }
    }
  ]
}
```

---

## 4️⃣ **ADDITIONAL REQUIRED APIs** ✅

### **User Creation (Auto-generates API Key)**
```http
POST /api/users/create
Authorization: Bearer {token}
Content-Type: application/json

Request Body:
{
  "email": "user@company.com",
  "firstName": "John",
  "lastName": "Doe",
  "role": "admin",
  "organizationId": "org-123"
}

Response (200 OK):
{
  "success": true,
  "userId": "user-abc123",
  "apiKey": "usr-key-xyz789",  // AUTO-GENERATED
  "message": "User created successfully"
}
```

### **List Users with Download Stats**
```http
GET /api/users/list?includeAgentStats=true
Authorization: Bearer {token}

Response (200 OK):
{
  "success": true,
  "users": [
    {
      "id": "user-abc123",
      "email": "john@company.com",
      "firstName": "John",
      "lastName": "Doe",
      "role": "admin",
      "createdAt": "2025-09-24T10:00:00Z",
      "agentStats": {
        "totalDownloads": 15,
        "activeAgents": 12,
        "platforms": {
          "windows": 8,
          "linux": 3,
          "macos": 1
        }
      }
    }
  ]
}
```

### **Agent Heartbeat (Auto-updates Status)**
```http
POST /api/agents/{agentId}/heartbeat
Authorization: Bearer {agent_key}
Content-Type: application/json

Request Body:
{
  "hostname": "DESKTOP-ABC123",
  "ipAddress": "192.168.1.100",
  "status": "online",
  "metrics": {
    "cpuUsage": 45,
    "memoryUsage": 62
  }
}

Response (200 OK):
{
  "success": true,
  "commands": [],  // Pending commands
  "configUpdates": {}
}
```

---

## 📋 **IMPLEMENTATION STATUS**

| Feature | API Endpoint | Status | File Location |
|---------|-------------|--------|---------------|
| **Software Download** | `POST /api/agents/track-download` | ✅ READY | `routes/user_agent_management.py` |
| **Download Links** | `GET /api/software/download-links` | ✅ READY | `routes/user_agent_management.py` |
| **Agent Listing** | `GET /api/agents/list` | ✅ READY | `routes/user_agent_management.py` |
| **Network Canvas** | `GET /api/network/topology` | ✅ READY | `routes/user_agent_management.py` |
| **Network Detailed** | `GET /api/network/topology-detailed` | ✅ READY | `routes/user_agent_management.py` |
| **User Creation** | `POST /api/users/create` | ✅ READY | `routes/user_agent_management.py` |
| **User Listing** | `GET /api/users/list` | ✅ READY | `routes/user_agent_management.py` |
| **Agent Heartbeat** | `POST /api/agents/{id}/heartbeat` | ✅ READY | `routes/agent_communication.py` |

---

## 🔐 **AUTHENTICATION**

All endpoints require Bearer token authentication:
```javascript
headers: {
  'Authorization': 'Bearer soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs',
  'Content-Type': 'application/json'
}
```

---

## 📊 **DATA FORMATS**

### **Status Values**
- `online` - Active and sending data
- `offline` - Not responding  
- `idle` - Online but inactive
- `warning` - Issues detected

### **Platform Values**
- `windows`
- `linux`
- `macos`

### **Node Types (Network Topology)**
- `gateway` - Internet gateway
- `firewall` - Firewall device
- `network` - Network segment
- `subnet` - Subnet
- `host` - Individual endpoint

### **Hierarchy Levels**
- Level 0: Internet/External
- Level 1: Firewall/Perimeter
- Level 2: Networks (DMZ, Internal)
- Level 3: Subnets
- Level 4: Individual hosts

---

## 🚀 **FRONTEND INTEGRATION EXAMPLE**

```javascript
// Base configuration
const API_BASE = 'https://dev.codegrey.ai:443/api';
const AUTH_TOKEN = 'Bearer soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs';

// 1. Get agent list
async function getAgents() {
  const response = await fetch(`${API_BASE}/agents/list?format=table&sort=status&order=desc`, {
    headers: {
      'Authorization': AUTH_TOKEN
    }
  });
  return response.json();
}

// 2. Get network topology
async function getNetworkTopology() {
  const response = await fetch(`${API_BASE}/network/topology?format=table&hierarchy=true`, {
    headers: {
      'Authorization': AUTH_TOKEN
    }
  });
  return response.json();
}

// 3. Track software download
async function trackDownload(userId, platform) {
  const response = await fetch(`${API_BASE}/agents/track-download`, {
    method: 'POST',
    headers: {
      'Authorization': AUTH_TOKEN,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      userId,
      platform,
      version: '1.0.0'
    })
  });
  return response.json();
}
```

---

## ✅ **DELIVERY CHECKLIST**

- [x] **Software Download API** - Track downloads, generate keys
- [x] **Agent Listing API** - Tabular format with all fields
- [x] **Network Canvas API** - Tabular/hierarchical topology
- [x] **User Management** - Create users, list with stats
- [x] **Auto-generation** - API keys auto-generated on user/download
- [x] **Real-time Updates** - Agent heartbeat updates status
- [x] **Sorting/Filtering** - All list endpoints support query params
- [x] **JSON Format** - All responses in standard JSON
- [x] **Authentication** - Bearer token on all endpoints
- [x] **Error Handling** - Consistent error responses

---

## 📦 **DEPLOYMENT PACKAGE**

The complete backend is in: `CLEAN_DEPLOYMENT_PACKAGE/`
- Total Size: 0.79 MB
- Files: 59 production files
- Ready to deploy

---

## 📞 **BACKEND TEAM CONTACT**

**APIs are COMPLETE and READY for integration!**

Deployment URL: `https://dev.codegrey.ai:443/api`  
Documentation: This document  
Test Environment: Available  

**Friday Deadline: ✅ MET - APIs are ready NOW!**
