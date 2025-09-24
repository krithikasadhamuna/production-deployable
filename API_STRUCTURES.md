# 🏗️ CodeGrey SOC - Complete API Structures

**Base URL:** `https://your-server:8443`  
**Authentication:** `Authorization: Bearer <token>` (required for all endpoints)  
**Content-Type:** `application/json`

---

## 📊 **Agent Management APIs**

### **1. GET /api/agents**
**Query Parameters:**
```
?status=online|offline|idle|active
?type=attack|detection|reasoning|windows|linux|macos
?hostname=hostname-filter
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
      "hostname": "phantom-ai-01",
      "ip_address": "10.0.1.100",
      "location": "External Network",
      "lastActivity": "2 mins ago",
      "capabilities": ["Email Simulation", "Web Exploitation", "Social Engineering"],
      "version": "2.1.0",
      "first_seen": "2024-01-15T08:00:00Z",
      "last_heartbeat": "2024-01-15T16:00:00Z",
      "network_element_type": "endpoint",
      "network_role": "attack_platform",
      "security_zone": "external",
      "user_role_info": {
        "username": "admin",
        "is_admin": true,
        "classified_roles": ["privileged_user"]
      }
    }
  ],
  "total": 5,
  "organization_id": "org-123"
}
```

### **2. GET /api/agents/{agent_id}**
**Response Structure:**
```json
{
  "success": true,
  "agent": {
    "id": "phantom-ai-01",
    "name": "PhantomStrike AI",
    "type": "attack",
    "status": "idle",
    "hostname": "phantom-ai-01",
    "ip_address": "10.0.1.100",
    "capabilities": ["Email Simulation", "Web Exploitation"],
    "version": "2.1.0",
    "first_seen": "2024-01-15T08:00:00Z",
    "last_heartbeat": "2024-01-15T16:00:00Z",
    "network_characteristics": {
      "open_ports": [80, 443, 8080],
      "detected_services": ["nginx", "ssh"],
      "subnet": "10.0.1.0/24"
    },
    "user_role_info": {
      "username": "admin",
      "user_groups": ["administrators", "domain_admins"],
      "is_admin": true,
      "domain_info": "CORP.LOCAL",
      "classified_roles": ["privileged_user", "system_admin"],
      "role_confidence": 0.95
    }
  }
}
```

### **3. GET /api/agents/statistics**
**Response Structure:**
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
    },
    "by_network_element": {
      "endpoint": 3,
      "firewall": 1,
      "soc": 1
    }
  },
  "organization_id": "org-123"
}
```

### **4. GET /api/agents/{agent_id}/capabilities**
**Response Structure:**
```json
{
  "success": true,
  "agent_id": "phantom-ai-01",
  "capabilities": {
    "primary": ["Email Simulation", "Web Exploitation", "Social Engineering"],
    "attack_vectors": [
      "Spear Phishing Campaigns",
      "Web Application Exploitation",
      "Social Engineering",
      "Lateral Movement Techniques",
      "Persistence Mechanisms",
      "Command & Control Channels"
    ],
    "supported_frameworks": ["MITRE ATT&CK", "Cyber Kill Chain"],
    "automation_level": "Fully Automated"
  }
}
```

---

## ⚔️ **Attack Agent APIs**

### **1. GET /api/attack_scenarios**
**Response Structure:**
```json
{
  "success": true,
  "scenarios": [
    {
      "id": "apt28_spear_phishing",
      "name": "Fancy Bear Email Campaign",
      "description": "Sophisticated spear-phishing campaign targeting government and military organizations using Zebrocy malware and domain fronting techniques",
      "apt_group": "APT28 (Fancy Bear)",
      "country": "Russia",
      "difficulty": "advanced",
      "duration_minutes": 45,
      "impact": "Critical Impact",
      "techniques": ["T1566.001", "T1071.001", "T1027", "T1055"],
      "target_sectors": ["Government", "Military", "Defense Contractors", "Think Tanks"],
      "motivation": "Espionage, Intelligence Gathering"
    }
  ],
  "total": 6
}
```

### **2. POST /api/attack_scenarios/execute**
**Request Structure:**
```json
{
  "scenario_id": "apt28_spear_phishing",
  "agent_id": "phantom-ai-01",
  "priority": "high",
  "parameters": {
    "target_count": 50,
    "duration_override": 30
  }
}
```

**Response Structure:**
```json
{
  "success": true,
  "command_id": "cmd_abc123def456",
  "scenario_id": "apt28_spear_phishing",
  "agent_id": "phantom-ai-01",
  "message": "Attack scenario queued for execution",
  "estimated_duration": 45,
  "scheduled_at": "2024-01-15T16:05:00Z"
}
```

### **3. GET /api/attack_timeline**
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
      "targets_affected": 12,
      "success_rate": 85.5,
      "results": {
        "emails_sent": 50,
        "clicks_received": 12,
        "payloads_executed": 8,
        "lateral_moves": 3
      }
    }
  ],
  "total": 2
}
```

### **4. GET /api/attack_scenarios/{scenario_id}**
**Response Structure:**
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
    "difficulty": "advanced",
    "mitre_techniques": [
      {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access"
      },
      {
        "id": "T1071.001", 
        "name": "Web Protocols",
        "tactic": "Command and Control"
      }
    ]
  }
}
```

---

## 🛡️ **Detection Agent APIs**

### **1. GET /api/agents/{agent_id}/detections**
**Response Structure:**
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
      "technique_name": "Spearphishing Attachment",
      "description": "Suspicious email attachment detected",
      "status": "confirmed",
      "indicators": {
        "file_hash": "a1b2c3d4e5f6...",
        "file_name": "invoice.pdf.exe",
        "email_sender": "finance@suspicious-domain.com"
      },
      "risk_score": 8.5,
      "false_positive_probability": 0.08
    }
  ],
  "agent_id": "guardian-ai-01",
  "total": 2
}
```

### **2. GET /api/detections/live**
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
      "threat_type": "command_and_control",
      "severity": "critical",
      "confidence": 0.95,
      "source": "192.168.1.150",
      "technique": "T1071.001",
      "technique_name": "Web Protocols",
      "description": "Suspicious C2 communication detected",
      "status": "active",
      "network_indicators": {
        "destination_domain": "malicious-c2.com",
        "protocol": "HTTPS",
        "frequency": "every_60_seconds",
        "data_volume": "1.2MB"
      },
      "recommended_actions": [
        "Block communication to malicious-c2.com",
        "Isolate source host 192.168.1.150",
        "Investigate lateral movement"
      ]
    }
  ],
  "total": 1
}
```

### **3. GET /api/detections/missed**
**Response Structure:**
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
      "technique_name": "Exfiltration Over C2 Channel",
      "description": "Data exfiltration attempt not detected in real-time",
      "discovered_at": "2024-01-15T14:30:00Z",
      "delay_minutes": 135,
      "reason_missed": "New attack pattern not in ML model",
      "data_indicators": {
        "volume_exfiltrated": "500MB",
        "destination": "external_server_xyz",
        "file_types": ["pdf", "docx", "xlsx"]
      },
      "lessons_learned": [
        "Update ML model with new pattern",
        "Add behavioral rule for large file transfers",
        "Enhance monitoring for off-hours activity"
      ]
    }
  ],
  "total": 1
}
```

---

## 🧠 **AI Reasoning Agent APIs**

### **1. POST /api/v1/chat**
**Request Structure:**
```json
{
  "message": "What is the current threat level in our network?",
  "agent_id": "threatmind-ai-01",
  "context": {
    "include_recent_detections": true,
    "time_range": "last_24_hours"
  },
  "priority": "normal"
}
```

**Response Structure:**
```json
{
  "success": true,
  "response": "Based on my analysis of the last 24 hours, the current threat level is MEDIUM. I've identified 3 active threats: 1 confirmed malware detection, 1 suspicious C2 communication, and 1 potential data exfiltration attempt. The attack surface shows increased activity in the DMZ segment. I recommend immediate isolation of host 192.168.1.150 and enhanced monitoring of external communications.",
  "command_id": "cmd_def456ghi789",
  "agent_id": "threatmind-ai-01",
  "timestamp": "2024-01-15T16:00:00Z",
  "analysis_data": {
    "threat_level": "MEDIUM",
    "active_threats": 3,
    "risk_score": 6.8,
    "confidence": 0.87,
    "recommendations": [
      "Isolate host 192.168.1.150",
      "Block communication to malicious-c2.com", 
      "Investigate potential data exfiltration"
    ]
  },
  "sources_analyzed": [
    "recent_detections",
    "network_topology",
    "attack_timeline",
    "threat_intelligence"
  ]
}
```

---

## 🌐 **Network Topology APIs**

### **1. GET /api/network/topology**
**Query Parameters:**
```
?hierarchy=true|false
?include_agents=true|false
```

**Response Structure:**
```json
{
  "success": true,
  "topology": [
    {
      "id": "internet",
      "name": "Internet",
      "type": "gateway",
      "level": 0,
      "agents": ["agent-001", "agent-002"],
      "agent_count": 2,
      "status": "normal",
      "risk_level": "medium",
      "confidence": 0.95,
      "characteristics": {
        "ip_ranges": ["0.0.0.0/0"],
        "services": ["external_access"],
        "security_zone": "untrusted"
      },
      "children": ["dmz", "firewall"]
    },
    {
      "id": "dmz",
      "name": "DMZ",
      "type": "network_segment",
      "level": 1,
      "agents": ["agent-003"],
      "agent_count": 1,
      "status": "normal",
      "risk_level": "high",
      "confidence": 0.88,
      "characteristics": {
        "ip_ranges": ["192.168.100.0/24"],
        "services": ["web_server", "mail_server"],
        "security_zone": "dmz"
      },
      "parent": "firewall",
      "children": []
    }
  ],
  "total_nodes": 8,
  "hierarchy_enabled": true,
  "last_updated": "2024-01-15T16:00:00Z"
}
```

### **2. GET /api/network/summary**
**Response Structure:**
```json
{
  "success": true,
  "summary": {
    "total_network_elements": 8,
    "element_breakdown": {
      "internet": 1,
      "firewall": 1,
      "dmz": 1,
      "internal_network": 2,
      "endpoints": 2,
      "soc": 1
    },
    "security_zones": {
      "untrusted": 1,
      "dmz": 1,
      "trusted": 4,
      "secure": 2
    },
    "risk_distribution": {
      "critical": 0,
      "high": 2,
      "medium": 4,
      "low": 2
    },
    "agent_distribution": {
      "total_agents": 15,
      "by_element": {
        "endpoints": 8,
        "firewall": 2,
        "dmz": 2,
        "soc": 3
      }
    }
  }
}
```

---

## 🎛️ **Command & Control APIs**

### **1. POST /api/agents/{agent_id}/command**
**Request Structure:**
```json
{
  "type": "system_info",
  "priority": "normal",
  "parameters": {
    "include_processes": true,
    "include_network": true,
    "timeout": 30
  },
  "schedule_at": "2024-01-15T16:30:00Z"
}
```

**Response Structure:**
```json
{
  "success": true,
  "command_id": "cmd_789xyz123abc",
  "agent_id": "agent-001",
  "message": "Command queued for execution",
  "status": "queued",
  "created_at": "2024-01-15T16:00:00Z",
  "scheduled_at": "2024-01-15T16:30:00Z"
}
```

### **2. GET /api/commands/{command_id}/result**
**Response Structure:**
```json
{
  "success": true,
  "result": {
    "command_id": "cmd_789xyz123abc",
    "agent_id": "agent-001",
    "status": "completed",
    "output": {
      "system_info": {
        "os": "Windows 10 Pro",
        "cpu": "Intel Core i7-8700K",
        "memory": "16 GB",
        "disk": "500 GB SSD"
      },
      "processes": [
        {"name": "chrome.exe", "pid": 1234, "cpu": 15.2},
        {"name": "notepad.exe", "pid": 5678, "cpu": 0.1}
      ],
      "network": {
        "active_connections": 23,
        "listening_ports": [80, 443, 3389]
      }
    },
    "stderr": "",
    "exit_code": 0,
    "execution_time": "2024-01-15T16:05:00Z",
    "duration_seconds": 3.2
  }
}
```

---

## 📊 **System Monitoring APIs**

### **1. GET /api/system/status**
**Response Structure:**
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
    "disk_usage": 23.4,
    "ai_agents": {
      "attack_orchestrator": {
        "status": "active",
        "last_activity": "2024-01-15T15:58:00Z",
        "scenarios_executed": 12,
        "success_rate": 89.5
      },
      "detection_pipeline": {
        "status": "active", 
        "last_activity": "2024-01-15T15:59:45Z",
        "logs_processed": 15420,
        "threats_detected": 3
      },
      "reasoning_engine": {
        "status": "active",
        "last_activity": "2024-01-15T15:59:30Z",
        "queries_processed": 47,
        "analysis_accuracy": 94.2
      }
    },
    "database": {
      "size_mb": 127.3,
      "total_records": 45230,
      "last_backup": "2024-01-15T02:00:00Z"
    }
  }
}
```

### **2. GET /api/threats/metrics**
**Response Structure:**
```json
{
  "success": true,
  "metrics": {
    "threatLevel": "medium",
    "activeCampaigns": 2,
    "detectionRate": 94.5,
    "meanTimeToDetection": 45,
    "falsePositiveRate": 2.1,
    "complianceScore": 98.7,
    "threat_breakdown": {
      "malware": 12,
      "phishing": 8,
      "lateral_movement": 3,
      "data_exfiltration": 2,
      "command_control": 1
    },
    "severity_distribution": {
      "critical": 2,
      "high": 8,
      "medium": 12,
      "low": 4
    },
    "time_metrics": {
      "avg_detection_time_minutes": 45,
      "avg_response_time_minutes": 12,
      "avg_containment_time_minutes": 23
    }
  },
  "organization_id": "org-123"
}
```

---

## 🏢 **Organization Management APIs**

### **1. POST /api/organizations**
**Request Structure:**
```json
{
  "name": "Acme Corporation",
  "contact_email": "admin@acme.com",
  "industry": "Technology",
  "size": "medium",
  "settings": {
    "max_agents": 100,
    "retention_days": 90,
    "alert_threshold": "medium"
  }
}
```

**Response Structure:**
```json
{
  "success": true,
  "organization": {
    "id": "org-456def789ghi",
    "name": "Acme Corporation",
    "contact_email": "admin@acme.com",
    "api_key": "ak_abc123def456ghi789",
    "created_at": "2024-01-15T16:00:00Z",
    "settings": {
      "max_agents": 100,
      "retention_days": 90,
      "alert_threshold": "medium"
    },
    "status": "active"
  },
  "message": "Organization created successfully"
}
```

---

## 🚨 **Error Response Structure**

All APIs return consistent error responses:

```json
{
  "success": false,
  "error": "Detailed error message here",
  "error_code": "AGENT_NOT_FOUND",
  "timestamp": "2024-01-15T16:00:00Z",
  "request_id": "req_abc123def456"
}
```

**Common Error Codes:**
- `UNAUTHORIZED` - Invalid or missing API token
- `AGENT_NOT_FOUND` - Requested agent doesn't exist
- `SCENARIO_NOT_FOUND` - Attack scenario doesn't exist
- `COMMAND_FAILED` - Command execution failed
- `INVALID_PARAMETERS` - Invalid request parameters
- `RATE_LIMITED` - Too many requests
- `INTERNAL_ERROR` - Server error

---

## 🔐 **Authentication Structure**

**Header Required:**
```http
Authorization: Bearer your-api-token-here
Content-Type: application/json
```

**Token Format:**
- Prefix: `ak_` (API Key)
- Length: 32-64 characters
- Example: `ak_abc123def456ghi789jkl012mno345pqr678`

---

## 🎯 **Summary**

**Total API Endpoints:** 28  
**Request Methods:** GET (20), POST (8)  
**Authentication:** Bearer token required for all  
**Response Format:** JSON with consistent structure  
**Error Handling:** Standardized error responses  
**Multi-tenant:** All endpoints are tenant-scoped  

**Your frontend team now has the complete API structure documentation for seamless integration!** 🚀



