# 🚀 CodeGrey SOC - Complete Production Setup Guide

## 📋 **Quick Setup Checklist**

- [ ] Upload PRODUCTION_DEPLOYMENT folder to server
- [ ] Run setup script
- [ ] Verify all AI agents are running
- [ ] Test API endpoints
- [ ] Set up data extraction for LLM training

---

## 🖥️ **Step 1: Server Upload & Setup**

### **Upload to Server**
```bash
# Upload the entire PRODUCTION_DEPLOYMENT folder
scp -r PRODUCTION_DEPLOYMENT/ user@your-server:/opt/codegrey-soc/

# Or using rsync for better performance
rsync -avz PRODUCTION_DEPLOYMENT/ user@your-server:/opt/codegrey-soc/
```

### **SSH into Server & Start**
```bash
ssh user@your-server
cd /opt/codegrey-soc/

# Quick start (recommended)
chmod +x start.sh
./start.sh

# Or manual Docker setup
cp env.example .env
# Edit .env with your settings
docker-compose up -d
```

---

## 🗄️ **Step 2: Database Setup (Automatic)**

**✅ The database is created automatically when the server starts!**

### **How it works:**
1. **SQLite database** is created at `database/soc_production.db`
2. **Schema is applied** from `database/multi_tenant_schema.sql`
3. **All tables created** for agents, logs, commands, organizations
4. **Multi-tenant isolation** is configured

### **Database includes these tables:**
- `organizations` - Tenant management
- `agents` - Agent registration and status
- `agent_logs` - **All client logs stored here** ⭐
- `agent_commands` - Commands sent to agents
- `network_topology` - Network mapping data

---

## 📊 **Step 3: Verify AI Agents Are Running**

### **Check Server Startup Logs**
```bash
# Docker logs
docker-compose logs -f soc-server

# Direct logs
tail -f logs/soc_server.log
```

### **You should see:**
```
🚀 Initializing Core AI Agent Engines...
  📊 Starting Multi-Tenant Agent Manager...
  ⚔️  Starting Attack Orchestrator...
  🛡️  Starting Detection Pipeline...
  🧠 Starting AI Reasoning Engine...
✅ All AI Agent Engines initialized successfully!
🔍 Detection monitoring thread started
🤖 AI reasoning analysis thread started
🔄 Background agent processes started

🎯 Core SOC Components Active:
  ⚔️  Attack Orchestrator - Ready for scenario execution
  🛡️  Detection Pipeline - Monitoring for threats
  🧠 AI Reasoning Engine - Analyzing security posture
  📊 Multi-Tenant Manager - Managing agent fleet
```

---

## 🧪 **Step 4: Test Your SOC Platform**

### **Health Check**
```bash
curl http://your-server:8443/api/system/status
```

### **Create Sample Agents**
```bash
curl -X POST http://your-server:8443/api/test/create-sample-agents \
     -H "Authorization: Bearer your-api-key" \
     -H "Content-Type: application/json"
```

### **Test Attack Scenarios**
```bash
# List available scenarios
curl http://your-server:8443/api/attack_scenarios \
     -H "Authorization: Bearer your-api-key"

# Execute an attack scenario
curl -X POST http://your-server:8443/api/attack_scenarios/execute \
     -H "Authorization: Bearer your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"scenario_id": "apt28_spear_phishing", "agent_id": "phantom-ai-01"}'
```

### **Test AI Chat**
```bash
curl -X POST http://your-server:8443/api/v1/chat \
     -H "Authorization: Bearer your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"message": "What is the current threat level?"}'
```

---

## 📥 **Step 5: Client Logs Storage & Flow**

### **✅ YES - All client logs are stored in the database!**

**Here's how the data flows:**

1. **Client agents** (Windows/Linux/macOS) collect logs
2. **Logs are sent** to server via `/api/agents/register` and heartbeat
3. **Server stores logs** in `agent_logs` table in SQLite database
4. **AI agents process** the logs:
   - **Detection Pipeline** analyzes for threats every 10 seconds
   - **AI Reasoning Engine** correlates data every minute
   - **Attack Orchestrator** uses data for scenario planning

### **Log Storage Schema:**
```sql
CREATE TABLE agent_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    log_type TEXT NOT NULL,          -- 'system', 'security', 'network', etc.
    log_data TEXT NOT NULL,          -- JSON log content
    timestamp DATETIME NOT NULL,
    severity TEXT DEFAULT 'info',    -- 'low', 'medium', 'high', 'critical'
    processed BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);
```

### **What logs are stored:**
- **System logs** - Process, service, startup events
- **Security logs** - Authentication, privilege changes
- **Network logs** - Connections, traffic, DNS queries
- **Application logs** - Software events, crashes
- **User activity** - Login/logout, file access
- **Detection results** - Threat analysis, ML predictions

---

## 🤖 **Step 6: Extract Data for LLM Training**

### **Run Data Extraction**
```bash
# Extract last 30 days of sanitized data
python extract_training_data.py

# Or specify custom time range
python extract_training_data.py --days 60
```

### **What gets extracted & sanitized:**
```
training_data/
├── agent_logs_20240923_143022.json      # System/security logs
├── attack_scenarios_20240923_143022.json # Attack execution data
├── detection_results_20240923_143022.json # Threat detection data
├── ai_reasoning_20240923_143022.json    # Chat/reasoning interactions
└── extraction_summary_20240923_143022.json # Summary report
```

### **🔒 Automatic Data Sanitization:**
- **IP addresses** → `IP_a1b2c3d4`
- **Email addresses** → `EMAIL_e5f6g7h8`
- **Domain names** → `DOMAIN_d9e0f1a2`
- **File paths** → `PATH_b3c4d5e6`
- **Usernames** → `USER_f7g8h9i0`
- **Passwords** → `PASS_[REDACTED]`
- **API keys/tokens** → `TOKEN_[REDACTED]`

### **Use for LLM Training:**
```python
# Example: Load training data
import json

with open('training_data/agent_logs_20240923_143022.json', 'r') as f:
    training_logs = json.load(f)

# Use for fine-tuning your SOC AI models
# - Attack pattern recognition
# - Threat detection improvement
# - Natural language SOC queries
# - Automated incident response
```

---

## 🔧 **Step 7: Production Configuration**

### **Environment Variables (.env)**
```bash
# Server Configuration
SOC_HOST=0.0.0.0
SOC_PORT=8443
SOC_DEBUG=false

# Database
SOC_DATABASE_PATH=database/soc_production.db

# Security (CHANGE THIS!)
SOC_SECRET_KEY=your-super-secret-production-key-here

# Multi-tenant Limits
SOC_MAX_AGENTS_PER_TENANT=1000
SOC_MAX_COMMANDS_PER_MINUTE=100

# AI Agent Settings
SOC_DETECTION_INTERVAL=10    # seconds
SOC_REASONING_INTERVAL=60    # seconds
```

### **Resource Monitoring**
```bash
# Check resource usage
docker stats codegrey-soc-server

# Check database size
ls -lh database/soc_production.db

# Check log storage
du -sh logs/
du -sh training_data/
```

---

## 🚨 **Step 8: Security & Maintenance**

### **Backup Strategy**
```bash
# Daily database backup
cp database/soc_production.db backups/soc_backup_$(date +%Y%m%d).db

# Weekly training data backup
tar -czf backups/training_data_$(date +%Y%m%d).tar.gz training_data/
```

### **Log Rotation**
```bash
# Rotate server logs (add to crontab)
0 0 * * * /usr/sbin/logrotate /opt/codegrey-soc/logrotate.conf
```

### **Security Checklist**
- [ ] Change default `SOC_SECRET_KEY`
- [ ] Use HTTPS in production (add SSL certificates)
- [ ] Configure firewall (only port 8443 open)
- [ ] Regular database backups
- [ ] Monitor disk space for logs
- [ ] Rotate API tokens regularly

---

## 📊 **Step 9: Monitoring & Health Checks**

### **Automated Health Monitoring**
```bash
# Add to crontab for continuous monitoring
*/5 * * * * curl -f http://localhost:8443/api/system/status || echo "SOC Server Down" | mail admin@company.com
```

### **Performance Monitoring**
```bash
# Check AI agent performance
curl http://localhost:8443/api/agents/statistics

# Check database performance
sqlite3 database/soc_production.db ".schema" | wc -l
sqlite3 database/soc_production.db "SELECT COUNT(*) FROM agent_logs;"
```

---

## 🎯 **Summary: What You Get**

✅ **Complete AI SOC Platform** running on single server  
✅ **Attack, Detection, and Reasoning AI agents** active  
✅ **All client logs stored** in database automatically  
✅ **Data extraction tool** for LLM training with sanitization  
✅ **Multi-tenant architecture** for multiple organizations  
✅ **RESTful APIs** ready for frontend integration  
✅ **Production monitoring** and health checks  
✅ **Docker containerization** for easy deployment  

**Your AI-driven SOC product is now fully operational!**

---

## 🆘 **Troubleshooting**

### **Server won't start**
```bash
# Check Docker logs
docker-compose logs soc-server

# Check port availability
netstat -tlnp | grep 8443

# Check permissions
chown -R www-data:www-data /opt/codegrey-soc/
```

### **Database issues**
```bash
# Reset database (will lose data!)
rm database/soc_production.db
# Restart server to recreate

# Check database integrity
sqlite3 database/soc_production.db "PRAGMA integrity_check;"
```

### **AI agents not responding**
```bash
# Check if background threads are running
curl http://localhost:8443/api/system/status

# Restart server
docker-compose restart soc-server
```

**🎉 Your complete AI SOC platform is ready for production!**