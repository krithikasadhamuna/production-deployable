# 📊 **FRONTEND API INTEGRATION GUIDE**

## 🎯 **QUICK CLARIFICATION**
- **Client Agents** = Software on endpoints (Windows/Linux/Mac) that send logs
- **AI Agents** = SOC components (Attack/Detection) - NOT what you're listing
- **Users** = People who download and manage client agents

---

## 🔑 **API KEY GENERATION FLOW**

### **Automatic Generation Points:**
1. **User Creation** → Personal API key generated
2. **Agent Download** → Installation key generated  
3. **Agent Registration** → Agent appears in topology

```javascript
// When user is created
POST /api/users/create
Response: {
  "userId": "user-abc123",
  "apiKey": "usr-xyz789"  // AUTO-GENERATED
}

// When agent is downloaded
POST /api/agents/track-download
Response: {
  "agentId": "agent-456",
  "installationKey": "inst-key-789"  // AUTO-GENERATED
}
```

---

## 📋 **1. USER MANAGEMENT APIS**

### **Create User**
```javascript
// REQUEST
POST /api/users/create
{
  "email": "john@company.com",
  "firstName": "John",
  "lastName": "Doe",
  "role": "admin",
  "organizationId": "org-123",
  "password": "optional"
}

// RESPONSE
{
  "success": true,
  "userId": "user-abc123",
  "apiKey": "usr-key-xyz789"  // ✅ AUTO-GENERATED
}
```

### **List Users with Stats**
```javascript
// REQUEST
GET /api/users/list?includeAgentStats=true

// RESPONSE
{
  "users": [{
    "id": "user-abc123",
    "email": "john@company.com",
    "firstName": "John",
    "lastName": "Doe",
    "agentStats": {
      "totalDownloads": 15,
      "activeAgents": 12,
      "platforms": {
        "windows": 8,
        "linux": 3,
        "macos": 1
      }
    }
  }]
}
```

---

## 🖥️ **2. CLIENT AGENT LISTING (TABULAR)**

### **List Agents - Your Required Structure**
```javascript
// REQUEST
GET /api/agents/list?format=table&sort=status&order=desc

// RESPONSE - EXACT STRUCTURE YOU REQUESTED
{
  "agents": [
    {
      "id": "agent-001",
      "name": "DESKTOP-ABC123",  // Hostname
      "type": "endpoint",         // Always "endpoint" for client agents
      "status": "online",         // online|offline|idle|warning
      "location": "192.168.1.100", // IP Address
      "lastActivity": "2 mins ago",
      "capabilities": [
        "Log Collection",
        "Command Execution", 
        "File Monitoring",
        "Process Monitoring",
        "Network Monitoring"
      ]
    },
    {
      "id": "agent-002",
      "name": "LINUX-SERVER-01",
      "type": "endpoint",
      "status": "idle",
      "location": "10.0.1.50",
      "lastActivity": "5 mins ago",
      "capabilities": [
        "Log Collection",
        "Command Execution",
        "File Monitoring"
      ]
    }
  ]
}
```

### **Status Values:**
- `online` - Active and sending data
- `offline` - Not responding
- `idle` - Online but inactive
- `warning` - Issues detected

---

## 🌐 **3. NETWORK TOPOLOGY (TABULAR)**

### **Get Topology - Hierarchical Table**
```javascript
// REQUEST
GET /api/network/topology?format=table&hierarchy=true&order=asc

// RESPONSE - TABULAR FORMAT
{
  "topology": [
    {
      "id": "node-internet",
      "name": "Internet Gateway",
      "type": "gateway",
      "level": 0,              // Hierarchy level (0=top)
      "parentId": null,
      "agentCount": 3,
      "agents": ["agent-001", "agent-002", "agent-003"],
      "status": "normal",
      "zone": "External"
    },
    {
      "id": "node-firewall",
      "name": "Main Firewall", 
      "type": "firewall",
      "level": 1,              // Child of gateway
      "parentId": "node-internet",
      "agentCount": 0,
      "agents": [],
      "status": "normal",
      "zone": "Perimeter"
    },
    {
      "id": "node-internal",
      "name": "Corporate Network",
      "type": "network",
      "level": 2,              // Child of firewall
      "parentId": "node-firewall",
      "agentCount": 25,
      "agents": ["agent-004", "agent-005", "..."],
      "status": "normal",
      "zone": "Internal"
    }
  ]
}
```

### **Hierarchy Levels:**
- **Level 0**: Internet/External
- **Level 1**: Firewall/Perimeter
- **Level 2**: Networks (DMZ, Internal)
- **Level 3**: Subnets
- **Level 4**: Individual hosts

---

## 📥 **4. AGENT DOWNLOAD TRACKING**

### **Track When User Downloads Agent**
```javascript
// Called when user clicks "Download Windows Agent"
POST /api/agents/track-download
{
  "userId": "user-abc123",
  "platform": "windows",
  "version": "1.0.0"
}

// RESPONSE
{
  "agentId": "agent-456",           // Pre-assigned
  "installationKey": "inst-key-789"  // For agent auth
}
```

### **Get User's Downloaded Agents**
```javascript
GET /api/users/{userId}/agents

// RESPONSE
{
  "agents": [{
    "id": "agent-456",
    "platform": "windows",
    "downloadedAt": "2025-09-24T10:15:00Z",
    "status": "online",      // Current status
    "hostname": "DESKTOP-ABC",
    "ipAddress": "192.168.1.100"
  }]
}
```

---

## 🔄 **5. AGENT STATUS UPDATES**

### **Automatic via Heartbeat**
```javascript
// Agent sends this every 30 seconds
POST /api/agents/{agentId}/heartbeat
{
  "hostname": "DESKTOP-ABC123",
  "ipAddress": "192.168.1.100",
  "status": "online",
  "metrics": {
    "cpuUsage": 45,
    "memoryUsage": 62
  }
}
```

---

## 📊 **6. SORTING & FILTERING**

### **Query Parameters:**
```javascript
// Sorting
?sort=name|status|lastActivity|type|location
?order=asc|desc

// Filtering
?filter=online|offline|all
?userId=user-123  // Filter by user

// Hierarchy
?hierarchy=true|false  // For topology

// Examples
GET /api/agents/list?sort=status&order=desc&filter=online
GET /api/network/topology?hierarchy=true&order=asc
```

---

## 🎨 **7. FRONTEND DISPLAY SUGGESTIONS**

### **Agent List Table**
```html
| Name            | Status  | Location      | Last Activity | User      |
|-----------------|---------|---------------|---------------|-----------|
| DESKTOP-ABC123  | 🟢 Online | 192.168.1.100 | 2 mins ago   | John Doe  |
| LINUX-SERVER-01 | 🟡 Idle  | 10.0.1.50     | 5 mins ago   | Jane Smith|
| MAC-DESIGN-02   | 🔴 Offline| 192.168.1.105 | 2 hours ago  | Bob Jones |
```

### **Network Topology Table**
```html
| Level | Name               | Type     | Agents | Status |
|-------|-------------------|----------|--------|---------|
| 0     | Internet Gateway   | Gateway  | 3      | Normal  |
| 1     | └─ Main Firewall  | Firewall | 0      | Normal  |
| 2     |    ├─ DMZ Network | Network  | 5      | Warning |
| 2     |    └─ Corporate   | Network  | 25     | Normal  |
```

---

## 💡 **IMPORTANT NOTES**

1. **API Keys are AUTO-GENERATED**
   - User creation → User API key
   - Agent download → Installation key
   - No manual generation needed

2. **Agent Registration Flow**
   ```
   Download → Install → Auto-Register → Appear in Topology
   ```

3. **Real-time Updates**
   - Agents send heartbeat every 30 seconds
   - Status updates automatically
   - No polling needed from frontend

4. **Tabular Format Benefits**
   - Easy to sort
   - Easy to filter
   - No complex canvas rendering
   - Mobile-friendly

---

## 🚀 **QUICK START CODE**

```javascript
// 1. Create user
const createUser = async (userData) => {
  const response = await fetch('/api/users/create', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer soc-prod-...',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(userData)
  });
  const data = await response.json();
  // Save data.apiKey for user
  return data;
};

// 2. List agents
const listAgents = async () => {
  const response = await fetch('/api/agents/list?format=table&sort=status&order=desc', {
    headers: {
      'Authorization': 'Bearer soc-prod-...'
    }
  });
  return response.json();
};

// 3. Get topology
const getTopology = async () => {
  const response = await fetch('/api/network/topology?hierarchy=true', {
    headers: {
      'Authorization': 'Bearer soc-prod-...'
    }
  });
  return response.json();
};
```

---

## ✅ **DELIVERABLES**

You now have:
1. ✅ User management with auto API keys
2. ✅ Agent listing in your exact format
3. ✅ Network topology in tabular format
4. ✅ Download tracking
5. ✅ Sorting/filtering options
6. ✅ Real-time status updates

All APIs are ready and match your requirements! 🎯
