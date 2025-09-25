# CodeGrey AI-Driven SOC Platform

## Overview
Complete AI-driven Security Operations Center (SOC) platform with multitenancy support, featuring PhantomStrike AI (Attack Agent) and GuardianAlpha AI (Detection Agent).

## Architecture

### Core Components

1. **PhantomStrike AI** (Attack Agent)
   - Analyzes network topology
   - Generates dynamic attack scenarios
   - Creates golden images before attacks
   - Executes attacks with user approval
   - Restores systems after testing

2. **GuardianAlpha AI** (Detection Agent)
   - Continuous log monitoring
   - ML-based threat detection
   - LLM analysis pipeline
   - AI reasoning for final verdict
   - Real-time threat alerts

3. **Client Agents**
   - Deployed on endpoints
   - Send logs to server
   - Execute commands from server
   - Support Windows/Linux/macOS

4. **Multitenancy**
   - Isolated databases per organization
   - Separate AI agent instances
   - API key based authentication
   - Complete data isolation

## Quick Start

```bash
# Deploy the platform
chmod +x deploy.sh
./deploy.sh

# Test the deployment
curl http://localhost:8080/api/backend/health
```

## API Endpoints

### Core Endpoints
- `GET /api/backend/health` - Platform health
- `GET /api/backend/agents` - List AI agents
- `GET /api/backend/network-topology` - Network topology

### Attack Operations (PhantomStrike)
- `POST /api/backend/langgraph/attack/start` - Start attack workflow
- `POST /api/backend/langgraph/attack/{id}/approve` - Approve attack
- `POST /api/backend/langgraph/attack/{id}/restore` - Restore from golden images

### Detection Operations (GuardianAlpha)
- `GET /api/backend/langgraph/detection/status` - Detection status
- `GET /api/backend/langgraph/detection/recent` - Recent detections
- `POST /api/backend/langgraph/detection/continuous/start` - Start continuous monitoring

### Client Agent APIs
- `POST /api/backend/agent/register` - Register endpoint
- `POST /api/backend/agent/logs` - Send logs
- `POST /api/backend/agent/heartbeat` - Heartbeat

## Files Structure

```
soc-platform-production/
├── agents/                      # AI Agents
│   ├── attack_agent/            # PhantomStrike AI
│   ├── detection_agent/         # GuardianAlpha AI
│   ├── langgraph/              # LangGraph workflows
│   └── network_discovery/       # Network scanner
├── flask_api/                   # API implementation
├── client_installers/           # Client agents
├── ml_models/                   # ML models
├── nginx_config/                # NGINX configuration
├── COMPLETE_SOC_PLATFORM.py     # Main server
├── start_complete_platform.py   # Alternative starter
├── deploy.sh                    # Deployment script
└── requirements.txt            # Dependencies
```

## Default Credentials

- Organization: CodeGrey
- Admin Email: sagar@codegrey.ai
- API Key: api_codegrey_2024

## Support

For issues or questions, contact the SOC team.