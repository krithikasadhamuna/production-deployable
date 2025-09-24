# 🚀 CODEGREY SOC PLATFORM - CLEAN DEPLOYMENT

## ✅ WHAT'S INCLUDED

### Core Components
- ✅ Flask API Server with all routes
- ✅ AI Attack Agent (LangGraph)
- ✅ AI Detection Agent (LangGraph)
- ✅ AI Reasoning Agent (LangGraph)
- ✅ Incident Response System
- ✅ Network Discovery Scanner
- ✅ Real-time SIEM
- ✅ User Management
- ✅ Agent Communication

### AI Features
- ✅ LangGraph workflows for all AI agents
- ✅ Human-in-the-loop approval
- ✅ Dynamic attack generation
- ✅ Intelligent threat detection
- ✅ Automated incident response

## 📦 DEPLOYMENT STEPS

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp production.env .env
# Edit .env with your settings
```

### 3. Initialize Database
```bash
python start_server.py --init-db
```

### 4. Start Server
```bash
# Production (HTTPS on port 443)
sudo python start_server.py

# Development (HTTP on port 5000)
SOC_PORT=5000 python start_server.py
```

## 🔑 API AUTHENTICATION

All API endpoints require Bearer token:
```
Authorization: Bearer soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs
```

## 📡 KEY ENDPOINTS

### AI Attack Agent
- POST `/api/ai-attack/start` - Start AI attack workflow
- GET `/api/ai-attack/scenarios/{id}` - Get attack scenarios
- POST `/api/ai-attack/approve/{id}` - Approve scenario

### Agent Management
- POST `/api/agents/register` - Register new agent
- POST `/api/agents/{id}/heartbeat` - Agent heartbeat
- POST `/api/agents/{id}/logs` - Submit logs

### AI Chat
- POST `/api/v1/chat` - AI reasoning chat
- POST `/api/v2/chat` - LangGraph stateful chat

## 🔧 CONFIGURATION

Edit `production.env`:
```env
SOC_HOST=0.0.0.0
SOC_PORT=443
SOC_API_KEY=soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs
DATABASE_PATH=soc_database.db
OLLAMA_URL=http://localhost:11434
```

## 🚨 PRODUCTION CHECKLIST

- [ ] Change default API key
- [ ] Configure proper SSL certificates
- [ ] Set up firewall rules
- [ ] Configure Ollama with cybersec-ai model
- [ ] Set up log rotation
- [ ] Configure backup strategy
- [ ] Set up monitoring

## 📊 SYSTEM REQUIREMENTS

- Python 3.9+
- 8GB RAM minimum
- 50GB disk space
- Ollama installed with cybersec-ai model
- SSL certificates for HTTPS

## 🆘 TROUBLESHOOTING

### Port 443 Permission Denied
```bash
# Use sudo or change to port 8443
sudo python start_server.py
# OR
SOC_PORT=8443 python start_server.py
```

### Ollama Not Found
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh
# Pull cybersec-ai model
ollama pull cybersec-ai
```

### Database Issues
```bash
# Recreate database
rm soc_database.db
python start_server.py --init-db
```

## 📞 SUPPORT

For issues, check:
- Logs in `logs/` directory
- Database integrity
- Network connectivity
- Ollama service status

---
**Version**: 1.0.0
**Last Updated**: September 2025
