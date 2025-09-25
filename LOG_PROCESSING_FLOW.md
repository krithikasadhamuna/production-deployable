# 📊 Log Processing Flow - Complete Documentation

## ✅ **YES, Logs Are Received and Parsed Correctly!**

The SOC platform has a comprehensive log processing system that handles all agent formats.

## **1. Log Collection (Client Agents)**

### **Windows Agent** sends:
```json
{
  "events": [
    {
      "id": "evt_123",
      "type": "process_creation",
      "severity": "medium",
      "timestamp": "2024-09-25T10:00:00Z",
      "data": {
        "process": "powershell.exe",
        "command": "-enc ...",
        "user": "admin"
      }
    }
  ]
}
```

### **Linux Agent** sends:
```json
{
  "logs": [
    {
      "timestamp": "2024-09-25T10:00:00Z",
      "level": "error",
      "source": "/var/log/auth.log",
      "message": "Failed password for root from 192.168.1.100"
    }
  ]
}
```

### **macOS Agent** sends:
```json
{
  "logs": [
    {
      "timestamp": "2024-09-25T10:00:00Z",
      "type": "system",
      "message": "Unauthorized access attempt detected"
    }
  ]
}
```

## **2. Log Reception (Server)**

**Endpoint:** `POST /agents/{agent_id}/logs`

The server automatically:
- ✅ Accepts both `events` and `logs` formats
- ✅ Handles Windows, Linux, and macOS formats
- ✅ Validates agent authentication
- ✅ Routes to correct tenant database

## **3. Log Processing Pipeline**

### **Step 1: Format Detection**
```python
if 'events' in data:
    # Windows format
elif 'logs' in data:
    # Linux/macOS format
else:
    # Raw format
```

### **Step 2: Parsing**
The `LogProcessor` class:
- Extracts timestamp, severity, type, source
- Parses Windows event logs
- Parses Linux syslog format
- Parses Apache/Nginx logs
- Handles plain text logs

### **Step 3: Threat Scoring**
Each log gets a threat score (0.0 - 1.0) based on:
- Severity level (critical=0.9, high=0.7, medium=0.5)
- Suspicious patterns (mimikatz=0.9, powershell -enc=0.8)
- IOC indicators (malicious IPs, domains, hashes)

### **Step 4: IOC Extraction**
Automatically extracts:
- IP addresses
- Domain names
- File hashes (MD5, SHA1, SHA256)
- File paths
- Registry keys

### **Step 5: Storage**
Logs are stored in two tables:
- `agent_logs` - All logs with parsed data
- `detections` - High/critical severity for AI analysis

## **4. AI Analysis (Background)**

### **Continuous Monitoring Loop**
```python
Every 30 seconds:
  1. Fetch unprocessed logs with threat_score > 0.3
  2. Send to Detection Agent
  3. ML models analyze for anomalies
  4. LLM checks for malicious patterns
  5. AI Reasoning Agent makes final verdict
```

### **Detection Flow**
```
Logs → ML Models → LLM Analysis → AI Reasoning → Alert
         ↓             ↓              ↓
     Anomalies    Behaviors      Final Verdict
```

## **5. Database Schema**

### **agent_logs table:**
```sql
CREATE TABLE agent_logs (
    id TEXT PRIMARY KEY,
    agent_id TEXT,
    timestamp TIMESTAMP,
    log_type TEXT,        -- process_event, network_event, system_log
    severity TEXT,        -- critical, high, medium, low, info
    source TEXT,          -- windows_agent, linux_agent, etc.
    message TEXT,         -- Parsed message
    raw_data TEXT,        -- Original JSON
    parsed_data TEXT,     -- Parsed JSON with indicators
    processed INTEGER,    -- 0=pending, 1=processed
    threat_score REAL,    -- 0.0 to 1.0
    created_at TIMESTAMP
)
```

### **detections table:**
```sql
CREATE TABLE detections (
    id TEXT PRIMARY KEY,
    agent_id TEXT,
    type TEXT,
    severity TEXT,
    timestamp TIMESTAMP,
    data TEXT,
    status TEXT,          -- pending, analyzing, detected, false_positive
    ai_analysis TEXT,     -- AI findings
    threat_verdict TEXT,  -- Final decision
    created_at TIMESTAMP
)
```

## **6. Real Examples**

### **Example 1: Ransomware Detection**
```
Windows Agent → Sends process creation event
→ Server parses: powershell.exe with encoded command
→ Threat score: 0.8 (high)
→ Stored in detections table
→ AI Detection Agent analyzes
→ Alert: "Potential ransomware activity detected"
```

### **Example 2: Brute Force Attack**
```
Linux Agent → Sends auth.log entries
→ Server parses: Multiple failed SSH attempts
→ Threat score: 0.7 (high)
→ Pattern detected: 50 failures in 5 minutes
→ AI correlates with source IP reputation
→ Alert: "Brute force attack from 192.168.1.100"
```

### **Example 3: Data Exfiltration**
```
macOS Agent → Sends network logs
→ Server parses: Large outbound transfer
→ Threat score: 0.6 (medium)
→ IOC extraction: Suspicious domain detected
→ AI analyzes: Unusual volume to unknown host
→ Alert: "Possible data exfiltration to evil.com"
```

## **7. API Testing**

### **Send Test Logs:**
```bash
curl -X POST https://dev.codegrey.ai/agents/agt-123/logs \
  -H "Authorization: Bearer agt-key-xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "type": "suspicious_process",
        "severity": "high",
        "timestamp": "2024-09-25T10:00:00Z",
        "data": {
          "process": "mimikatz.exe",
          "user": "admin"
        }
      }
    ]
  }'
```

### **Check Processed Logs:**
```bash
# On server
sqlite3 tenant_databases/codegrey.db \
  "SELECT * FROM agent_logs ORDER BY created_at DESC LIMIT 5;"
```

## **8. Verification Checklist**

✅ **Log Reception Working:**
- Windows events format supported
- Linux logs format supported  
- macOS logs format supported
- Plain text logs supported

✅ **Parsing Working:**
- Timestamps extracted correctly
- Severity levels identified
- Event types categorized
- IOCs extracted automatically

✅ **Storage Working:**
- Logs saved to agent_logs table
- High severity saved to detections
- Threat scores calculated
- Indexes for fast queries

✅ **AI Analysis Working:**
- Background monitoring active
- ML models processing logs
- LLM analyzing patterns
- Alerts generated for threats

## **Summary**

**YES**, the log processing system is fully functional and handles:
- Multiple agent formats (Windows/Linux/macOS)
- Automatic parsing and categorization
- Threat scoring and IOC extraction
- Real-time AI analysis
- Persistent storage with indexing
- Background continuous monitoring

The system is production-ready and will correctly receive, parse, store, and analyze all logs from your client agents!
