# 🚀 CodeGrey SOC - Complete API Reference for Frontend

**Base URL:** `https://your-server:8443`  
**Authentication:** `Authorization: Bearer <your-api-token>`  
**Content-Type:** `application/json`


---

## 📊 **Agent Management APIs**

### **1. Get All Agents**
```http
GET /api/agents
GET /api/agents?type=attack
GET /api/agents?type=detection  
GET /api/agents?type=reasoning
GET /api/agents?status=online
```
**Response:**
```json
{
  "success": true,
  "agents": [
    {
      "id": "phantom-ai-01",
      "name": "PhantomStrike AI", 
      "type": "attack",
      "status": "idle",
      "location": "External Network",
      "lastActivity": "2 mins ago",
      "capabilities": ["Email Simulation", "Web Exploitation", "Social Engineering"]
    }
  ],
  "total": 5
}
```

### **2. Get Specific Agent**
```http
GET /api/agents/{agent_id}
```

### **3. Get Agents by Status**
```http
GET /api/agents/status/{status}
# status: online, offline, idle, active
```

### **4. Get Agents by Type** 
```http
GET /api/agents/type/{type}
# type: attack, detection, reasoning, windows, linux, macos
```

### **5. Get Agent Statistics**
```http
GET /api/agents/statistics
```
**Response:**
```json
{
  "success": true,
  "statistics": {
    "total": 5,
    "online": 4,
    "offline": 1,
    "by_type": {
      "attack": 1,
      "detection": 1, 
      "reasoning": 1,
      "windows": 1,
      "linux": 1
    },
    "by_status": {
      "online": 4,
      "idle": 1,
      "offline": 0
    }
  }
}
```

### **6. Get Agent Capabilities**
```http
GET /api/agents/{agent_id}/capabilities
```
**Response:**
```json
{
  "success": true,
  "agent_id": "phantom-ai-01",
  "capabilities": {
    "primary": ["Email Simulation", "Web Exploitation"],
    "attack_vectors": ["Spear Phishing Campaigns", "Web Application Exploitation"],
    "supported_frameworks": ["MITRE ATT&CK", "Cyber Kill Chain"],
    "automation_level": "Fully Automated"
  }
}
```

---

## ⚔️ **Attack Agent APIs**

### **1. List Attack Scenarios**
```http
GET /api/attack_scenarios
```
**Response:**
```json
{
  "success": true,
  "scenarios": [
    {
      "id": "apt28_spear_phishing",
      "name": "Fancy Bear Email Campaign",
      "description": "Sophisticated spear-phishing campaign targeting government and military organizations",
      "apt_group": "APT28 (Fancy Bear)",
      "country": "Russia",
      "difficulty": "advanced",
      "duration_minutes": 45,
      "impact": "Critical Impact",
      "techniques": ["T1566.001", "T1071.001", "T1027", "T1055"],
      "target_sectors": ["Government", "Military", "Defense Contractors"],
      "motivation": "Espionage, Intelligence Gathering"
    }
  ],
  "total": 6
}
```

### **2. Execute Attack Scenario**
```http
POST /api/attack_scenarios/execute
```
**Request:**
```json
{
  "scenario_id": "apt28_spear_phishing",
  "agent_id": "phantom-ai-01"
}
```
**Response:**
```json
{
  "success": true,
  "command_id": "cmd_abc123",
  "scenario_id": "apt28_spear_phishing", 
  "agent_id": "phantom-ai-01",
  "message": "Attack scenario queued for execution"
}
```

### **3. Get Attack Timeline**
```http
GET /api/attack_timeline
```
**Response:**
```json
{
  "success": true,
  "timeline": [
    {
      "id": "attack_001",
      "scenario_id": "apt28_spear_phishing",
      "scenario_name": "Fancy Bear Email Campaign",
      "agent_id": "phantom-ai-01",
      "agent_name": "PhantomStrike AI",
      "status": "completed",
      "started_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T11:15:00Z",
      "duration_minutes": 45,
      "techniques_executed": ["T1566.001", "T1071.001", "T1027"],
      "targets_affected": 12,
      "success_rate": 85.5
    }
  ],
  "total": 2
}
```

### **4. Get Attack Scenario Details**
```http
GET /api/attack_scenarios/{scenario_id}
```
**Response:**
```json
{
  "success": true,
  "scenario": {
    "id": "apt28_spear_phishing",
    "name": "Fancy Bear Email Campaign",
    "description": "Sophisticated spear-phishing campaign targeting government and military organizations",
    "playbook_steps": [
      "1. Reconnaissance and target identification",
      "2. Craft spear-phishing emails with malicious attachments",
      "3. Deploy Zebrocy malware payload",
      "4. Establish command and control channel",
      "5. Lateral movement and privilege escalation",
      "6. Data exfiltration"
    ],
    "required_capabilities": ["Email Simulation", "Web Exploitation", "Social Engineering"],
    "estimated_duration": 45,
    "difficulty": "advanced"
  }
}
```

---

## 🛡️ **Detection Agent APIs**

### **1. Get Agent Detections**
```http
GET /api/agents/{agent_id}/detections
```
**Response:**
```json
{
  "success": true,
  "detections": [
    {
      "id": "det_001",
      "timestamp": "2024-01-15T10:45:00Z",
      "threat_type": "malware",
      "severity": "high",
      "confidence": 0.92,
      "source_ip": "192.168.1.100",
      "target_ip": "10.0.1.50", 
      "technique": "T1566.001",
      "description": "Suspicious email attachment detected",
      "status": "confirmed"
    }
  ],
  "agent_id": "guardian-ai-01",
  "total": 2
}
```

### **2. Get Live Detections**
```http
GET /api/detections/live
```
**Response:**
```json
{
  "success": true,
  "detections": [
    {
      "id": "live_001",
      "agent_id": "guardian-ai-01",
      "agent_name": "GuardianAlpha AI",
      "timestamp": "2024-01-15T15:30:00Z",
      "threat_type": "command_and_control",
      "severity": "critical",
      "confidence": 0.95,
      "source": "192.168.1.150",
      "technique": "T1071.001",
      "description": "Suspicious C2 communication detected",
      "status": "active"
    }
  ],
  "total": 1
}
```

### **3. Get Missed Detections**
```http
GET /api/detections/missed
```
**Response:**
```json
{
  "success": true,
  "missed_detections": [
    {
      "id": "missed_001",
      "timestamp": "2024-01-15T12:15:00Z",
      "threat_type": "data_exfiltration",
      "severity": "high",
      "source": "10.0.1.100",
      "technique": "T1041",
      "description": "Data exfiltration attempt not detected in real-time",
      "discovered_at": "2024-01-15T14:30:00Z",
      "delay_minutes": 135
    }
  ],
  "total": 1
}
```

---

## 🧠 **AI Reasoning Agent APIs**

### **1. AI Chat Interface**
```http
POST /api/v1/chat
```
**Request:**
```json
{
  "message": "What is the current threat level?",
  "agent_id": "threatmind-ai-01"
}
```
**Response:**
```json
{
  "success": true,
  "response": "SOC AI Assistant: I understand you're asking about 'What is the current threat level?'. I'm analyzing the current security posture and will provide recommendations based on our threat intelligence and active monitoring data.",
  "command_id": "cmd_def456",
  "agent_id": "threatmind-ai-01",
  "timestamp": "2024-01-15T16:00:00Z"
}
```

---

## 🌐 **Network Topology APIs**

### **1. Get Network Topology**
```http
GET /api/network/topology
```
**Response:**
```json
{
  "success": true,
  "topology": [
    {
      "id": "internet",
      "name": "Internet",
      "type": "gateway",
      "agents": ["agent-001", "agent-002"],
      "status": "normal",
      "risk_level": "medium"
    },
    {
      "id": "dmz",
      "name": "DMZ",
      "type": "network_segment", 
      "agents": ["agent-003"],
      "status": "normal",
      "risk_level": "high"
    }
  ],
  "total_nodes": 8,
  "hierarchy_enabled": true
}
```

### **2. Get Network Node Details**
```http
GET /api/network/node/{node_id}
```

### **3. Get Agents by Network Node**
```http
GET /api/network/agents/{node_id}
```

### **4. Get Network Summary**
```http
GET /api/network/summary
```

---

## 🎛️ **Command & Control APIs**

### **1. Send Command to Agent**
```http
POST /api/agents/{agent_id}/command
```
**Request:**
```json
{
  "type": "system_info",
  "priority": "normal"
}
```
**Response:**
```json
{
  "success": true,
  "command_id": "cmd_789xyz",
  "message": "Command queued for execution"
}
```

### **2. Get Agent Commands**
```http
GET /api/agents/{agent_id}/commands
```

### **3. Get Command Result**
```http
GET /api/commands/{command_id}/result
```
**Response:**
```json
{
  "success": true,
  "result": {
    "command_id": "cmd_789xyz",
    "status": "completed",
    "output": "Command executed successfully",
    "stderr": "",
    "exit_code": 0,
    "execution_time": "2024-01-15T16:05:00Z"
  }
}
```

### **4. Update Command Result**
```http
POST /api/commands/{command_id}/result
```

---

## 📊 **System & Monitoring APIs**

### **1. Get System Status**
```http
GET /api/system/status
```
**Response:**
```json
{
  "success": true,
  "status": {
    "server_version": "2.1.0",
    "uptime": "5 days, 12 hours",
    "connected_agents": 4,
    "total_agents": 5,
    "active_campaigns": 2,
    "database_status": "healthy",
    "memory_usage": 45.2,
    "cpu_usage": 12.8,
    "ai_agents": {
      "attack_orchestrator": "active",
      "detection_pipeline": "active", 
      "reasoning_engine": "active"
    }
  }
}
```

### **2. Get Threat Metrics**
```http
GET /api/threats/metrics
```
**Response:**
```json
{
  "success": true,
  "metrics": {
    "threatLevel": "medium",
    "activeCampaigns": 2,
    "detectionRate": 94.5,
    "meanTimeToDetection": 45,
    "falsePositiveRate": 2.1,
    "complianceScore": 98.7
  }
}
```

---

## 🏢 **Organization Management APIs**

### **1. Create Organization**
```http
POST /api/organizations
```
**Request:**
```json
{
  "name": "Acme Corporation",
  "contact_email": "admin@acme.com"
}
```

---

## 🧪 **Testing & Development APIs**

### **1. Create Sample Agents**
```http
POST /api/test/create-sample-agents
```
**Response:**
```json
{
  "success": true,
  "created": 5,
  "agents": [
    {
      "id": "phantom-ai-01",
      "name": "PhantomStrike AI",
      "type": "attack"
    },
    {
      "id": "guardian-ai-01", 
      "name": "GuardianAlpha AI",
      "type": "detection"
    },
    {
      "id": "threatmind-ai-01",
      "name": "ThreatMind AI",
      "type": "reasoning"
    }
  ]
}
```

---

## 🔐 **Authentication**

All API calls require Bearer token authentication:

```javascript
const headers = {
  'Authorization': 'Bearer your-api-token-here',
  'Content-Type': 'application/json'
};
```

---

## ⚡ **Real-time Polling Recommendations**

For real-time updates, poll these endpoints:

| Endpoint | Frequency | Purpose |
|----------|-----------|---------|
| `/api/agents` | 30 seconds | Agent status changes |
| `/api/detections/live` | 10 seconds | New threat detections |
| `/api/attack_timeline` | 60 seconds | Attack progress updates |
| `/api/system/status` | 5 minutes | System health monitoring |
| `/api/agents/statistics` | 30 seconds | Dashboard statistics |

---

## 🚨 **Error Handling**

All APIs return consistent error responses:

```json
{
  "success": false,
  "error": "Error description here"
}
```

**HTTP Status Codes:**
- `200` - Success
- `400` - Bad Request (missing parameters)
- `401` - Unauthorized (missing/invalid token)
- `404` - Not Found (resource not found)
- `500` - Internal Server Error
- `503` - Service Unavailable (agents offline)

---

## 📝 **Frontend Integration Example**

```javascript
// Example React component
const fetchAgents = async (type = null) => {
  const url = type ? `/api/agents?type=${type}` : '/api/agents';
  const response = await fetch(`https://your-server:8443${url}`, {
    headers: {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json'
    }
  });
  return await response.json();
};

// Usage
const attackAgents = await fetchAgents('attack');
const detectionAgents = await fetchAgents('detection'); 
const reasoningAgents = await fetchAgents('reasoning');
```

---

## 🎯 **Summary: 28 API Endpoints Available**

✅ **Agent Management** - 6 endpoints  
✅ **Attack Operations** - 4 endpoints  
✅ **Detection Results** - 3 endpoints  
✅ **AI Reasoning** - 1 endpoint  
✅ **Network Topology** - 4 endpoints  
✅ **Command & Control** - 4 endpoints  
✅ **System Monitoring** - 2 endpoints  
✅ **Organization Management** - 1 endpoint  
✅ **Testing/Development** - 1 endpoint  
✅ **Agent Capabilities** - 1 endpoint  
✅ **Agent Registration/Heartbeat** - 2 endpoints  

**Your frontend team now has complete API access to the entire AI SOC platform!**



