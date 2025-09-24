# 🗂️ CodeGrey SOC - Tabular API Structures

**Purpose:** Optimized API responses for tabular display (no canvas UI needed)  
**Features:** Hierarchy support, sorting flags, simplified data structures

---

## 📊 **Network Topology - Tabular Format**

### **API: GET /api/network/topology**
**Query Parameters:**
```
?hierarchy=true|false     # Enable hierarchical ordering
?sort_order=asc|desc     # Sorting order
?sort_by=name|type|risk_level|agent_count
```

**Response Structure:**
```json
{
  "success": true,
  "network_nodes": [
    {
      "id": "internet",
      "name": "Internet", 
      "type": "gateway",
      "level": 0,
      "parent_id": null,
      "agents": [
        {
          "id": "phantom-ai-01",
          "name": "PhantomStrike AI",
          "type": "attack",
          "status": "idle"
        }
      ],
      "agent_count": 1,
      "status": "normal",
      "risk_level": "medium",
      "security_zone": "untrusted",
      "ip_ranges": ["0.0.0.0/0"],
      "last_updated": "2024-01-15T16:00:00Z"
    },
    {
      "id": "firewall",
      "name": "Corporate Firewall",
      "type": "security_device", 
      "level": 1,
      "parent_id": "internet",
      "agents": [
        {
          "id": "fw-agent-01",
          "name": "Firewall Monitor",
          "type": "detection",
          "status": "active"
        }
      ],
      "agent_count": 1,
      "status": "normal",
      "risk_level": "low",
      "security_zone": "perimeter",
      "ip_ranges": ["192.168.1.1/32"],
      "last_updated": "2024-01-15T16:00:00Z"
    },
    {
      "id": "dmz",
      "name": "DMZ Segment",
      "type": "network_segment",
      "level": 2, 
      "parent_id": "firewall",
      "agents": [
        {
          "id": "dmz-agent-01",
          "name": "DMZ Monitor",
          "type": "detection", 
          "status": "active"
        }
      ],
      "agent_count": 1,
      "status": "normal",
      "risk_level": "high",
      "security_zone": "dmz",
      "ip_ranges": ["192.168.100.0/24"],
      "last_updated": "2024-01-15T16:00:00Z"
    }
  ],
  "hierarchy_enabled": true,
  "sort_order": "asc",
  "sort_by": "level",
  "total_nodes": 8,
  "total_agents": 15
}
```

### **Frontend Table Display:**
```
Level | Network Element    | Type           | Agents | Status | Risk   | Security Zone
------|-------------------|----------------|--------|--------|--------|---------------
0     | Internet          | gateway        | 1      | normal | medium | untrusted
1     | ├─ Corporate FW   | security_device| 1      | normal | low    | perimeter  
2     | ├─ DMZ Segment    | network_segment| 1      | normal | high   | dmz
2     | ├─ Internal Net   | network_segment| 8      | normal | low    | trusted
3     | │  ├─ Data Center | datacenter     | 2      | normal | medium | secure
3     | │  └─ Endpoints   | endpoint_group | 6      | normal | medium | trusted
1     | └─ SOC Platform   | soc_platform   | 2      | active | low    | secure
```

---

## 👥 **Agents List - Tabular Format**

### **API: GET /api/agents**
**Query Parameters:**
```
?sort_by=name|type|status|lastActivity|location
?sort_order=asc|desc
?filter_type=attack|detection|reasoning|windows|linux|macos
?filter_status=online|offline|idle|active
```

**Response Structure:**
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
      "lastActivityTimestamp": "2024-01-15T15:58:00Z",
      "capabilities": [
        "Email Simulation",
        "Web Exploitation", 
        "Social Engineering",
        "Lateral Movement",
        "Persistence Testing"
      ],
      "capabilities_summary": "Email Simulation, Web Exploitation, +3 more",
      "hostname": "phantom-ai-01",
      "ip_address": "10.0.1.100",
      "version": "2.1.0",
      "network_element": "internet",
      "security_zone": "untrusted",
      "risk_level": "medium",
      "health_score": 95.2,
      "commands_executed": 127,
      "success_rate": 89.5
    },
    {
      "id": "guardian-ai-01", 
      "name": "GuardianAlpha AI",
      "type": "detection",
      "status": "active",
      "location": "SOC Infrastructure",
      "lastActivity": "Now",
      "lastActivityTimestamp": "2024-01-15T16:00:00Z",
      "capabilities": [
        "Behavioral Analysis",
        "Signature Detection",
        "Threat Hunting",
        "ML-based Detection",
        "Anomaly Correlation"
      ],
      "capabilities_summary": "Behavioral Analysis, Signature Detection, +3 more",
      "hostname": "guardian-ai-01",
      "ip_address": "10.0.2.100", 
      "version": "2.1.0",
      "network_element": "soc_platform",
      "security_zone": "secure",
      "risk_level": "low",
      "health_score": 98.7,
      "threats_detected": 23,
      "detection_accuracy": 94.2
    },
    {
      "id": "threatmind-ai-01",
      "name": "ThreatMind AI", 
      "type": "reasoning",
      "status": "active",
      "location": "Threat Intelligence Platform",
      "lastActivity": "30 secs ago",
      "lastActivityTimestamp": "2024-01-15T15:59:30Z",
      "capabilities": [
        "Threat Analysis",
        "Risk Assessment", 
        "Incident Response Planning",
        "Natural Language Processing",
        "Decision Support",
        "Automated Reporting"
      ],
      "capabilities_summary": "Threat Analysis, Risk Assessment, +4 more",
      "hostname": "threatmind-ai-01",
      "ip_address": "10.0.2.101",
      "version": "2.1.0", 
      "network_element": "soc_platform",
      "security_zone": "secure",
      "risk_level": "low",
      "health_score": 97.1,
      "queries_processed": 156,
      "analysis_accuracy": 96.8
    }
  ],
  "sort_by": "name",
  "sort_order": "asc", 
  "total": 15,
  "filters_applied": {
    "type": null,
    "status": null
  },
  "summary": {
    "online": 12,
    "offline": 3,
    "by_type": {
      "attack": 3,
      "detection": 4,
      "reasoning": 2,
      "endpoint": 6
    }
  }
}
```

### **Frontend Table Display:**
```
Name              | Type      | Status | Location                    | Last Activity | Capabilities              | Health
------------------|-----------|--------|-----------------------------|---------------|---------------------------|--------
GuardianAlpha AI  | detection | active | SOC Infrastructure          | Now           | Behavioral Analysis, +3   | 98.7%
PhantomStrike AI  | attack    | idle   | External Network            | 2 mins ago    | Email Simulation, +3      | 95.2%  
ThreatMind AI     | reasoning | active | Threat Intelligence Platform| 30 secs ago   | Threat Analysis, +4       | 97.1%
Windows-WS-001    | windows   | online | Internal Network            | 5 mins ago    | Log Collection, +2        | 92.3%
Linux-SRV-01      | linux     | online | Data Center                 | 1 min ago     | Process Monitoring, +3    | 96.8%
```

---

## ⚔️ **Attack Timeline - Tabular Format**

### **API: GET /api/attack_timeline**
**Query Parameters:**
```
?sort_by=started_at|duration|success_rate|status
?sort_order=asc|desc
?filter_status=completed|in_progress|failed|queued
?limit=50
```

**Response Structure:**
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
      "techniques_summary": "T1566.001, T1071.001, +1 more",
      "targets_affected": 12,
      "success_rate": 85.5,
      "severity": "high",
      "apt_group": "APT28 (Fancy Bear)",
      "results_summary": "12 targets affected, 8 payloads executed"
    },
    {
      "id": "attack_002",
      "scenario_id": "lazarus_financial_heist", 
      "scenario_name": "Lazarus Financial Heist",
      "agent_id": "phantom-ai-01",
      "agent_name": "PhantomStrike AI",
      "status": "in_progress",
      "started_at": "2024-01-15T14:00:00Z",
      "completed_at": null,
      "duration_minutes": 35,
      "techniques_executed": ["T1190", "T1078"],
      "techniques_summary": "T1190, T1078",
      "targets_affected": 3,
      "success_rate": 67.0,
      "severity": "critical",
      "apt_group": "Lazarus Group",
      "results_summary": "3 targets affected, ongoing..."
    }
  ],
  "sort_by": "started_at",
  "sort_order": "desc",
  "total": 47,
  "summary": {
    "completed": 42,
    "in_progress": 2,
    "failed": 3,
    "avg_success_rate": 78.4
  }
}
```

### **Frontend Table Display:**
```
Scenario Name              | Agent           | Status      | Started    | Duration | Success Rate | Techniques      | Targets
---------------------------|-----------------|-------------|------------|----------|--------------|-----------------|--------
Lazarus Financial Heist   | PhantomStrike AI| in_progress | 14:00      | 35 min   | 67.0%        | T1190, T1078    | 3
Fancy Bear Email Campaign | PhantomStrike AI| completed   | 10:30      | 45 min   | 85.5%        | T1566.001, +2   | 12
Comment Crew IP Theft     | PhantomStrike AI| completed   | 09:15      | 25 min   | 92.1%        | T1566.001, +2   | 8
```

---

## 🛡️ **Live Detections - Tabular Format**

### **API: GET /api/detections/live**
**Query Parameters:**
```
?sort_by=timestamp|severity|confidence|threat_type
?sort_order=asc|desc
?filter_severity=critical|high|medium|low
?limit=100
```

**Response Structure:**
```json
{
  "success": true,
  "detections": [
    {
      "id": "live_001",
      "agent_id": "guardian-ai-01",
      "agent_name": "GuardianAlpha AI",
      "timestamp": "2024-01-15T15:30:00Z",
      "time_ago": "30 mins ago",
      "threat_type": "command_and_control",
      "threat_name": "Suspicious C2 Communication",
      "severity": "critical",
      "confidence": 95.2,
      "source": "192.168.1.150",
      "target": "malicious-c2.com",
      "technique": "T1071.001",
      "technique_name": "Web Protocols",
      "description": "Suspicious C2 communication detected via HTTPS",
      "status": "active",
      "risk_score": 8.7,
      "recommended_action": "Block communication, isolate host",
      "network_element": "internal_network",
      "affected_systems": 1
    },
    {
      "id": "live_002",
      "agent_id": "guardian-ai-01", 
      "agent_name": "GuardianAlpha AI",
      "timestamp": "2024-01-15T15:25:00Z",
      "time_ago": "35 mins ago",
      "threat_type": "malware",
      "threat_name": "Suspicious Email Attachment",
      "severity": "high",
      "confidence": 92.1,
      "source": "finance@suspicious-domain.com",
      "target": "user@company.com",
      "technique": "T1566.001",
      "technique_name": "Spearphishing Attachment", 
      "description": "Malicious PDF attachment detected",
      "status": "confirmed",
      "risk_score": 7.2,
      "recommended_action": "Quarantine email, scan endpoint",
      "network_element": "dmz",
      "affected_systems": 1
    }
  ],
  "sort_by": "timestamp",
  "sort_order": "desc",
  "total": 23,
  "summary": {
    "critical": 2,
    "high": 8,
    "medium": 11,
    "low": 2,
    "avg_confidence": 87.3
  }
}
```

### **Frontend Table Display:**
```
Time     | Threat Type      | Severity | Confidence | Source            | Technique    | Status    | Action Required
---------|------------------|----------|------------|-------------------|--------------|-----------|------------------
15:30    | C2 Communication | critical | 95.2%      | 192.168.1.150     | T1071.001    | active    | Block & isolate
15:25    | Malware          | high     | 92.1%      | suspicious-domain | T1566.001    | confirmed | Quarantine email
15:20    | Lateral Movement | medium   | 78.5%      | 192.168.1.100     | T1021.001    | investigating | Monitor activity
```

---

## 🎛️ **API Usage Examples for Frontend**

### **React/Vue Component Examples:**

```javascript
// 1. Fetch Network Topology with Hierarchy
const fetchNetworkTopology = async () => {
  const response = await fetch('/api/network/topology?hierarchy=true&sort_order=asc', {
    headers: {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json'
    }
  });
  const data = await response.json();
  
  // Display in hierarchical table
  setNetworkNodes(data.network_nodes);
};

// 2. Fetch Agents with Sorting
const fetchAgents = async (sortBy = 'name', sortOrder = 'asc') => {
  const response = await fetch(`/api/agents?sort_by=${sortBy}&sort_order=${sortOrder}`, {
    headers: {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json'
    }
  });
  const data = await response.json();
  
  // Display in sortable table
  setAgents(data.agents);
};

// 3. Real-time Live Detections (Poll every 10 seconds)
const fetchLiveDetections = async () => {
  const response = await fetch('/api/detections/live?sort_by=timestamp&sort_order=desc&limit=50', {
    headers: {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json'
    }
  });
  const data = await response.json();
  
  // Update detection table
  setDetections(data.detections);
};

// Set up polling
useEffect(() => {
  const interval = setInterval(fetchLiveDetections, 10000); // Every 10 seconds
  return () => clearInterval(interval);
}, []);
```

---

## 🎯 **Why APIs Work This Way**

### **1. Frontend Simplicity**
```
Frontend Developer thinks:
"I need agent data" → calls /api/agents → gets clean JSON → displays in table
```

### **2. Backend Complexity Hidden**
```
Backend does the hard work:
- Query database
- Process AI agent data  
- Apply security filtering
- Format response
- Handle errors
```

### **3. Real-time Updates**
```
Frontend polls APIs every few seconds:
- /api/agents (30s) → Update agent status
- /api/detections/live (10s) → Show new threats  
- /api/attack_timeline (60s) → Update attack progress
```

### **4. Scalability**
```
Multiple frontends can use same APIs:
- Web dashboard
- Mobile app  
- Desktop application
- Third-party integrations
```

---

## 🎉 **Summary**

✅ **Tabular Format Ready** - All APIs optimized for table display  
✅ **Hierarchy Support** - Network topology with level-based ordering  
✅ **Sorting & Filtering** - Frontend can sort by any field  
✅ **Real-time Polling** - Live updates every 10-60 seconds  
✅ **Simplified Data** - No complex canvas coordinates needed  
✅ **Performance Optimized** - Summary fields for quick display  

**Your frontend team can now build beautiful, functional tables without complex canvas implementation!** 🚀



