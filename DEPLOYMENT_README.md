# CodeGrey SOC Server - Production Deployment

## 📦 **What's Included**

This production deployment package contains **all essential files** needed to run the complete CodeGrey SOC Server with integrated AI agents:

```
PRODUCTION_DEPLOYMENT/
├── app.py                          # Main application entry point with AI agents
├── requirements.txt                # Python dependencies (including AI/ML)
├── Dockerfile                      # Container configuration
├── docker-compose.yml             # Multi-container setup
├── env.example                     # Environment variables template
├── DEPLOYMENT_README.md            # This file
├── start.sh / start.bat            # Quick start scripts
├── api/
│   ├── multi_tenant_api.py         # Main API endpoints
│   └── network_topology_api.py     # Network topology APIs
├── agents/
│   ├── multi_tenant_agent_manager.py  # Agent management
│   ├── network_element_detector.py    # Network detection
│   ├── attack_agent/               # 🚀 ATTACK AI AGENT
│   │   ├── attack_orchestrator.py  # Main attack engine
│   │   ├── playbook_engine.py      # Attack playbook execution
│   │   ├── dynamic_attack_generator.py # Dynamic attack scenarios
│   │   ├── comprehensive_attack_ttps.py # MITRE ATT&CK techniques
│   │   └── [4 more attack modules]
│   ├── detection_agent/            # 🛡️ DETECTION AI AGENT
│   │   ├── detection_pipeline.py   # Main detection engine
│   │   ├── adaptive_detection_engine.py # ML-based detection
│   │   ├── mitre_attack_engine.py  # MITRE ATT&CK correlation
│   │   ├── sigma_detection_engine.py # Sigma rule processing
│   │   └── [3 more detection modules]
│   └── ai_reasoning_agent/         # 🧠 AI REASONING AGENT
│       ├── reasoning_engine.py     # Main AI reasoning engine
│       └── [AI analysis modules]
├── config/
│   └── production.py               # Production configuration
└── database/
    └── multi_tenant_schema.sql     # Database schema
```

## 🚀 **Quick Start**

### **Option 1: Docker (Recommended)**

1. **Copy files to your server:**
   ```bash
   scp -r PRODUCTION_DEPLOYMENT/ user@your-server:/opt/codegrey-soc/
   ```

2. **Setup environment:**
   ```bash
   cd /opt/codegrey-soc/
   cp env.example .env
   # Edit .env with your settings
   ```

3. **Run with Docker:**
   ```bash
   docker-compose up -d
   ```

4. **Verify deployment:**
   ```bash
   curl http://your-server:8443/api/system/status
   ```

### **Option 2: Direct Python**

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Setup environment:**
   ```bash
   cp env.example .env
   # Edit .env with your settings
   ```

3. **Run the server:**
   ```bash
   python app.py
   ```

## 🗄️ **Database Decision**

### **Single Server Setup (Recommended for most cases)**

**✅ You can keep everything on one server because:**

- **SQLite is embedded** - No separate database server needed
- **Small footprint** - Entire database is a single file
- **High performance** - Perfect for SOC operations (< 100 agents)
- **Automatic backups** - Easy to backup single database file
- **Zero maintenance** - No database server to manage

### **When to use separate database server:**

- **>1000 agents** across multiple tenants
- **High write volume** (>10,000 commands/hour)
- **Multiple SOC servers** (horizontal scaling)
- **Enterprise compliance** requirements

## 📊 **Resource Requirements**

### **Minimum (Single Server)**
- **CPU:** 2 cores
- **RAM:** 4 GB
- **Storage:** 20 GB
- **Network:** 10 Mbps

### **Recommended (Production)**
- **CPU:** 4 cores
- **RAM:** 8 GB
- **Storage:** 100 GB SSD
- **Network:** 100 Mbps

## 🔒 **Security Checklist**

- [ ] Change `SOC_SECRET_KEY` in `.env`
- [ ] Use HTTPS in production (add SSL certificates)
- [ ] Configure firewall (only port 8443 open)
- [ ] Regular database backups
- [ ] Monitor log files

## 🔧 **Configuration**

### **Environment Variables**
```bash
# Server
SOC_HOST=0.0.0.0              # Listen on all interfaces
SOC_PORT=8443                 # API port
SOC_DEBUG=false               # Production mode

# Database
SOC_DATABASE_PATH=database/soc_production.db

# Security
SOC_SECRET_KEY=your-random-secret-key-here
```

## 📈 **Monitoring**

### **Health Check**
```bash
curl http://localhost:8443/api/system/status
```

### **AI Agent Status**
```bash
# Check if all AI agents are running
curl http://localhost:8443/api/agents/statistics
```

### **Logs**
```bash
tail -f logs/soc_server.log
```

### **Docker Logs**
```bash
docker-compose logs -f soc-server
```

### **AI Agent Monitoring**
The production server now runs these core AI agents:
- **🚀 Attack Orchestrator** - Executes attack scenarios in background
- **🛡️ Detection Pipeline** - Processes logs every 10 seconds for threats
- **🧠 AI Reasoning Engine** - Analyzes security posture every minute
- **📊 Multi-Tenant Manager** - Manages agent fleet and commands

## 🔄 **Updates**

1. **Stop server:**
   ```bash
   docker-compose down
   ```

2. **Replace files:**
   ```bash
   # Copy new PRODUCTION_DEPLOYMENT files
   ```

3. **Restart:**
   ```bash
   docker-compose up -d
   ```

## 📋 **API Endpoints Available**

- **Agent Management:** `/api/agents`
- **Attack Scenarios:** `/api/attack_scenarios`
- **Detection Results:** `/api/detections/live`
- **AI Chat:** `/api/v1/chat`
- **Network Topology:** `/api/network/hierarchy`
- **System Status:** `/api/system/status`

## 🆘 **Troubleshooting**

### **Server won't start:**
```bash
# Check logs
docker-compose logs soc-server

# Check port availability
netstat -tlnp | grep 8443
```

### **Database issues:**
```bash
# Reset database
rm database/soc_production.db
# Server will recreate on next start
```

### **Permission issues:**
```bash
# Fix file permissions
chmod +x app.py
chown -R www-data:www-data /opt/codegrey-soc/
```

## 🎯 **What You DON'T Need to Upload**

The following files/folders are **NOT needed** for production:

- `CLIENT_DEPLOYABLES/` (agents run on endpoints, not server)
- `test_*.py` files
- `*.md` documentation files (except this one)
- `__pycache__/` folders
- `.git/` version control
- Development databases (`*.db` in SOC_SERVER/)
- Jupyter notebooks
- Example/sample files

## 📞 **Support**

Your production server is now ready with:
- ✅ Multi-tenant architecture
- ✅ All API endpoints for frontend
- ✅ Network topology detection  
- ✅ Agent management
- ✅ Attack scenario execution
- ✅ Detection results
- ✅ AI reasoning chat

**Total deployment size: ~50MB** (instead of several GB with unnecessary files)
