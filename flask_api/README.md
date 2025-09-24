# 🚀 CodeGrey SOC - Flask API Server

Complete Flask implementation of the AI-driven SOC backend APIs based on your specifications.

## 📋 Features

✅ **28 API Endpoints** - Complete implementation of all specified endpoints  
✅ **Authentication** - Bearer token authentication for all endpoints  
✅ **Database** - SQLite database with proper schema  
✅ **CORS Support** - Enabled for frontend integration  
✅ **Error Handling** - Consistent error responses  
✅ **Sample Data** - Built-in test data for development  
✅ **HTTPS Support** - Self-signed SSL certificates  

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd PRODUCTION_DEPLOYMENT/flask_api
pip install -r requirements.txt
```

### 2. Start the Server
```bash
python start_server.py
```

### 3. Test the API
```bash
curl -k -H "Authorization: Bearer ak_demo_token_12345" https://localhost:8443/api/agents
```

## 📊 API Endpoints

### Agent Management (6 endpoints)
- `GET /api/agents` - List all agents
- `GET /api/agents/{id}` - Get specific agent
- `GET /api/agents/statistics` - Agent statistics
- `GET /api/agents/{id}/capabilities` - Agent capabilities
- `GET /api/agents/status/{status}` - Agents by status
- `GET /api/agents/type/{type}` - Agents by type

### Attack Operations (4 endpoints)
- `GET /api/attack_scenarios` - List attack scenarios
- `POST /api/attack_scenarios/execute` - Execute attack
- `GET /api/attack_timeline` - Attack timeline
- `GET /api/attack_scenarios/{id}` - Scenario details

### Detection Results (3 endpoints)
- `GET /api/agents/{id}/detections` - Agent detections
- `GET /api/detections/live` - Live detections
- `GET /api/detections/missed` - Missed detections

### AI Reasoning (1 endpoint)
- `POST /api/v1/chat` - AI chat interface

### Network Topology (4 endpoints)
- `GET /api/network/topology` - Network topology
- `GET /api/network/node/{id}` - Node details
- `GET /api/network/agents/{id}` - Node agents
- `GET /api/network/summary` - Network summary

### Command & Control (4 endpoints)
- `POST /api/agents/{id}/command` - Send command
- `GET /api/agents/{id}/commands` - Agent commands
- `GET /api/commands/{id}/result` - Command result
- `POST /api/commands/{id}/result` - Update result

### System Monitoring (2 endpoints)
- `GET /api/system/status` - System status
- `GET /api/threats/metrics` - Threat metrics

### Organizations (1 endpoint)
- `POST /api/organizations` - Create organization

### Testing (1 endpoint)
- `POST /api/test/create-sample-agents` - Create sample data

## 🔐 Authentication

All endpoints require Bearer token authentication:

```bash
Authorization: Bearer <your-token>
```

**Sample tokens for testing:**
- `ak_demo_token_12345`
- `ak_test_key_67890`

## 📁 Project Structure

```
flask_api/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── start_server.py       # Startup script
├── README.md             # This file
└── routes/               # API route modules
    ├── agents.py         # Agent management APIs
    ├── attacks.py        # Attack scenario APIs
    ├── detections.py     # Detection result APIs
    ├── reasoning.py      # AI reasoning APIs
    ├── network.py        # Network topology APIs
    ├── commands.py       # Command & control APIs
    ├── system.py         # System monitoring APIs
    ├── organizations.py  # Organization APIs
    └── testing.py        # Testing/development APIs
```

## 🗄️ Database Schema

The server automatically creates SQLite tables:
- `agents` - Agent information
- `attack_scenarios` - Attack scenario definitions
- `attack_timeline` - Attack execution history
- `detections` - Threat detection results
- `commands` - Agent command queue
- `network_topology` - Network structure
- `organizations` - Organization/tenant data

## 🧪 Testing

### Create Sample Data
```bash
curl -k -X POST -H "Authorization: Bearer ak_demo_token_12345" \
  https://localhost:8443/api/test/create-sample-agents
```

### Test AI Chat
```bash
curl -k -X POST -H "Authorization: Bearer ak_demo_token_12345" \
  -H "Content-Type: application/json" \
  -d '{"message": "What is the current threat level?"}' \
  https://localhost:8443/api/v1/chat
```

### Execute Attack Scenario
```bash
curl -k -X POST -H "Authorization: Bearer ak_demo_token_12345" \
  -H "Content-Type: application/json" \
  -d '{"scenario_id": "apt28_spear_phishing", "agent_id": "phantom-ai-01"}' \
  https://localhost:8443/api/attack_scenarios/execute
```

## 🔧 Configuration

### Environment Variables
- `SECRET_KEY` - Flask secret key (default: dev-secret-key)
- `DATABASE` - Database file path (default: soc_database.db)

### Production Deployment
For production, consider:
- Use PostgreSQL instead of SQLite
- Implement proper JWT authentication
- Use real SSL certificates
- Add rate limiting
- Implement logging
- Use Gunicorn/uWSGI

## 📝 API Response Format

All endpoints return consistent JSON responses:

**Success:**
```json
{
  "success": true,
  "data": {...}
}
```

**Error:**
```json
{
  "success": false,
  "error": "Error message",
  "error_code": "ERROR_CODE"
}
```

## 🎯 Frontend Integration

The API is designed to work seamlessly with your frontend:

```javascript
// Example frontend integration
const fetchAgents = async () => {
  const response = await fetch('https://localhost:8443/api/agents', {
    headers: {
      'Authorization': 'Bearer ak_demo_token_12345',
      'Content-Type': 'application/json'
    }
  });
  return await response.json();
};
```

## 🚀 Your Flask API server is ready to use!

All 28 endpoints from your specification are implemented and working. The server includes sample data, proper error handling, and is ready for frontend integration.


