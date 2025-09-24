# 📊 USER MANAGEMENT & CLIENT AGENT TRACKING APIs

## 🔑 **CLARIFICATION**
- **Client Agents** = Software installed on endpoints (Windows/Linux/Mac) that send logs & execute commands
- **NOT** AI Attack/Detection agents (those are SOC components)

---

## 1️⃣ **USER MANAGEMENT APIs**

### **Create User**
```http
POST /api/users/create
Authorization: Bearer {api_key}

Request:
{
  "email": "john.doe@company.com",
  "firstName": "John",
  "lastName": "Doe",
  "role": "admin|analyst|viewer",
  "organizationId": "org-123",
  "department": "Security",
  "permissions": ["view_agents", "manage_agents", "execute_commands"]
}

Response:
{
  "success": true,
  "userId": "user-abc123",
  "apiKey": "usr-key-xyz789",  // Auto-generated for this user
  "message": "User created successfully"
}
```

### **List Users with Agent Stats**
```http
GET /api/users/list?includeAgentStats=true
Authorization: Bearer {api_key}

Response:
{
  "success": true,
  "users": [
    {
      "id": "user-abc123",
      "email": "john.doe@company.com",
      "firstName": "John",
      "lastName": "Doe",
      "role": "admin",
      "createdAt": "2025-09-24T10:00:00Z",
      "lastLogin": "2025-09-24T12:30:00Z",
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

---

## 2️⃣ **CLIENT AGENT DOWNLOAD TRACKING**

### **Track Agent Download**
```http
POST /api/agents/track-download
Authorization: Bearer {api_key}

Request:
{
  "userId": "user-abc123",
  "agentType": "endpoint",
  "platform": "windows|linux|macos",
  "version": "1.0.0",
  "downloadUrl": "/downloads/agent-win-x64.exe"
}

Response:
{
  "success": true,
  "downloadId": "dl-xyz789",
  "agentId": "agent-456def",  // Pre-assigned agent ID
  "installationKey": "inst-key-789",  // Unique key for this installation
  "message": "Download tracked, agent ID assigned"
}
```

### **Get User's Downloaded Agents**
```http
GET /api/users/{userId}/agents
Authorization: Bearer {api_key}

Response:
{
  "success": true,
  "userId": "user-abc123",
  "agents": [
    {
      "id": "agent-456def",
      "downloadId": "dl-xyz789",
      "platform": "windows",
      "version": "1.0.0",
      "downloadedAt": "2025-09-24T10:15:00Z",
      "status": "online",  // online|offline|inactive
      "lastHeartbeat": "2025-09-24T12:45:00Z",
      "hostname": "DESKTOP-ABC123",
      "ipAddress": "192.168.1.100"
    }
  ]
}
```

---

## 3️⃣ **CLIENT AGENT LISTING (TABULAR)**

### **List All Client Agents (Tabular Format)**
```http
GET /api/agents/list?format=table&sort=status&order=desc
Authorization: Bearer {api_key}

Query Parameters:
- format: "table" (for tabular display)
- sort: "name|status|lastActivity|type|location"
- order: "asc|desc"
- filter: "online|offline|all"
- userId: "user-abc123" (optional, filter by user)

Response:
{
  "success": true,
  "totalAgents": 45,
  "onlineAgents": 38,
  "agents": [
    {
      "id": "agent-001",
      "name": "DESKTOP-ABC123",
      "type": "endpoint",
      "platform": "windows",
      "status": "online",  // online|offline|idle|warning
      "location": "192.168.1.100",
      "zone": "Corporate Network",
      "lastActivity": "2 mins ago",
      "lastHeartbeat": "2025-09-24T12:45:00Z",
      "userId": "user-abc123",
      "userName": "John Doe",
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
      "platform": "linux",
      "status": "online",
      "location": "10.0.1.50",
      "zone": "DMZ",
      "lastActivity": "5 mins ago",
      "lastHeartbeat": "2025-09-24T12:42:00Z",
      "userId": "user-def456",
      "userName": "Jane Smith",
      "version": "1.0.0",
      "capabilities": [
        "Log Collection",
        "Command Execution",
        "File Monitoring",
        "Process Monitoring"
      ],
      "metrics": {
        "cpuUsage": 20,
        "memoryUsage": 35,
        "diskUsage": 45,
        "eventsPerMinute": 80
      }
    }
  ]
}
```

---

## 4️⃣ **NETWORK TOPOLOGY (TABULAR)**

### **Get Network Topology (Tabular Format)**
```http
GET /api/network/topology?format=table&hierarchy=true
Authorization: Bearer {api_key}

Query Parameters:
- format: "table" (tabular view)
- hierarchy: true|false (show hierarchical structure)
- sort: "name|type|agents|status"
- order: "asc|desc"

Response:
{
  "success": true,
  "topology": [
    {
      "id": "node-internet",
      "name": "Internet Gateway",
      "type": "gateway",
      "level": 0,  // Hierarchy level (0 = top)
      "parentId": null,
      "agentCount": 3,
      "agents": ["agent-001", "agent-002", "agent-003"],
      "status": "normal",  // normal|warning|critical
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
      "agents": ["agent-009", "agent-010", "..."],
      "status": "normal",
      "zone": "Internal",
      "ipRange": "192.168.0.0/16"
    },
    {
      "id": "node-servers",
      "name": "Server Farm",
      "type": "subnet",
      "level": 3,
      "parentId": "node-internal",
      "agentCount": 10,
      "agents": ["agent-020", "agent-021", "..."],
      "status": "normal",
      "zone": "Internal",
      "ipRange": "192.168.10.0/24"
    }
  ]
}
```

### **Get Network Topology with Agent Details**
```http
GET /api/network/topology-detailed?includeAgents=true
Authorization: Bearer {api_key}

Response:
{
  "success": true,
  "nodes": [
    {
      "id": "node-internet",
      "name": "Internet Gateway",
      "type": "gateway",
      "level": 0,
      "x": 50,  // For visual positioning if needed
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

## 5️⃣ **AGENT STATUS UPDATES**

### **Update Agent Status (Automatic via Heartbeat)**
```http
POST /api/agents/{agentId}/heartbeat
Authorization: Bearer {agent_key}

Request:
{
  "hostname": "DESKTOP-ABC123",
  "ipAddress": "192.168.1.100",
  "status": "online",
  "metrics": {
    "cpuUsage": 45,
    "memoryUsage": 62,
    "diskUsage": 78
  },
  "timestamp": "2025-09-24T12:45:00Z"
}

Response:
{
  "success": true,
  "commands": [],  // Any pending commands for this agent
  "configUpdates": {}  // Any config changes
}
```

---

## 6️⃣ **API KEY GENERATION**

### **When is API Key Generated?**

1. **User Creation**: User gets personal API key
   ```json
   {
     "userId": "user-123",
     "apiKey": "usr-key-abc123"  // Auto-generated
   }
   ```

2. **Agent Download**: Installation key generated
   ```json
   {
     "agentId": "agent-456",
     "installationKey": "inst-key-xyz789"  // For agent auth
   }
   ```

3. **Organization Level**: Shared org key
   ```json
   {
     "organizationId": "org-123",
     "organizationKey": "org-key-def456"
   }
   ```

---

## 📊 **DATABASE SCHEMA**

### **users** Table
```sql
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  first_name TEXT,
  last_name TEXT,
  api_key TEXT UNIQUE,  -- Auto-generated
  organization_id TEXT,
  role TEXT,
  created_at TIMESTAMP,
  last_login TIMESTAMP
);
```

### **agent_downloads** Table
```sql
CREATE TABLE agent_downloads (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  agent_id TEXT,  -- Pre-assigned
  platform TEXT,
  version TEXT,
  download_timestamp TIMESTAMP,
  installation_key TEXT,  -- Auto-generated
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### **agents** Table (Client Agents)
```sql
CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  name TEXT,  -- Hostname
  type TEXT DEFAULT 'endpoint',
  platform TEXT,  -- windows|linux|macos
  status TEXT,  -- online|offline|idle
  ip_address TEXT,
  location TEXT,
  zone TEXT,
  user_id TEXT,  -- Who downloaded it
  installation_key TEXT,
  last_heartbeat TIMESTAMP,
  version TEXT,
  metrics TEXT,  -- JSON
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### **network_topology** Table
```sql
CREATE TABLE network_topology (
  id TEXT PRIMARY KEY,
  name TEXT,
  type TEXT,  -- gateway|firewall|network|subnet
  level INTEGER,  -- Hierarchy level
  parent_id TEXT,
  agents TEXT,  -- JSON array of agent IDs
  status TEXT,
  zone TEXT,
  ip_range TEXT,
  x INTEGER,  -- Position if needed
  y INTEGER
);
```

---

## 🔄 **AUTOMATIC WORKFLOWS**

### **User Creates Account → Downloads Agent**
1. User created → API key generated
2. User downloads agent → Download tracked
3. Agent ID pre-assigned → Installation key created
4. Agent installs → Uses installation key
5. Agent starts → Sends heartbeat
6. Agent appears in topology → Auto-mapped by IP

### **Agent Lifecycle**
```
Download → Install → Register → Heartbeat → Online
                                    ↓
                              Execute Commands
                                    ↓
                              Submit Logs
                                    ↓
                              Status Updates
```

---

## ✅ **KEY POINTS**

1. **API keys are auto-generated** when:
   - User is created
   - Agent is downloaded

2. **Client agents** (not AI agents) are tracked:
   - By user who downloaded
   - By installation location
   - By network zone

3. **Tabular format** for easy display:
   - Sortable columns
   - Hierarchical levels
   - Status indicators

4. **Real-time updates** via:
   - Agent heartbeats
   - Status changes
   - Metric updates
