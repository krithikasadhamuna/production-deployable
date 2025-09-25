#!/bin/bash

echo "=========================================="
echo " DEPLOYING COMPLETE AI-DRIVEN SOC PLATFORM"
echo " PhantomStrike AI + GuardianAlpha AI"
echo "=========================================="

# 1. Stop any existing processes
echo "Stopping existing processes..."
pkill -f python
pkill -f "port 8080"

# 2. Install dependencies
echo "Installing dependencies..."
pip3 install --user flask flask-cors

# Try to install agent dependencies
pip3 install --user scikit-learn numpy pandas 2>/dev/null || echo "ML libraries not available"

# 3. Create necessary directories
echo "Creating directories..."
mkdir -p golden_images
mkdir -p logs
mkdir -p client_agents

# 4. Initialize sample endpoints in database
echo "Initializing sample network topology..."
python3 << 'EOF'
import sqlite3
import json
from datetime import datetime

# Create topology database with sample endpoints
conn = sqlite3.connect('network_topology.db')
c = conn.cursor()

# Create tables
c.execute('''CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    ip_address TEXT,
    mac_address TEXT,
    os_type TEXT,
    os_version TEXT,
    agent_version TEXT,
    status TEXT,
    last_seen TIMESTAMP,
    capabilities TEXT,
    network_zone TEXT,
    importance TEXT,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')

# Insert sample endpoints to simulate real network
endpoints = [
    ('ep-001', 'WIN-DC-01', '10.0.0.10', '00:11:22:33:44:55', 'Windows', 'Server 2019', '2.0', 
     'online', datetime.now(), '["logs", "execute", "backup"]', 'internal', 'critical'),
    ('ep-002', 'WIN-EXEC-01', '10.0.0.20', '00:11:22:33:44:56', 'Windows', '11', '2.0',
     'online', datetime.now(), '["logs", "execute"]', 'internal', 'high'),
    ('ep-003', 'LNX-WEB-01', '10.0.0.30', '00:11:22:33:44:57', 'Linux', 'Ubuntu 22.04', '2.0',
     'online', datetime.now(), '["logs", "execute"]', 'dmz', 'high'),
    ('ep-004', 'LNX-DB-01', '10.0.0.40', '00:11:22:33:44:58', 'Linux', 'CentOS 8', '2.0',
     'online', datetime.now(), '["logs", "execute", "backup"]', 'internal', 'critical'),
    ('ep-005', 'WIN-WS-01', '10.0.0.50', '00:11:22:33:44:59', 'Windows', '10', '2.0',
     'online', datetime.now(), '["logs"]', 'internal', 'medium')
]

for endpoint in endpoints:
    c.execute('''INSERT OR REPLACE INTO endpoints 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''', endpoint)

# Create topology connections
c.execute('''CREATE TABLE IF NOT EXISTS topology (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id TEXT,
    connected_to TEXT,
    connection_type TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')

# Map network connections
connections = [
    ('ep-001', 'ep-002', 'domain'),
    ('ep-001', 'ep-005', 'domain'),
    ('ep-003', 'ep-004', 'database'),
    ('ep-002', 'ep-001', 'auth'),
    ('ep-005', 'ep-001', 'auth')
]

for conn_data in connections:
    c.execute('INSERT INTO topology (endpoint_id, connected_to, connection_type) VALUES (?, ?, ?)', conn_data)

conn.commit()
conn.close()

print("Network topology initialized with 5 endpoints")
EOF

# 5. Start the COMPLETE platform
echo ""
echo "Starting COMPLETE SOC Platform..."
nohup python3 COMPLETE_SOC_PLATFORM.py > complete_platform.log 2>&1 &
PID=$!

# 6. Wait for startup
sleep 5

# 7. Test the platform
echo ""
echo "=========================================="
echo " TESTING PLATFORM"
echo "=========================================="

echo "1. Health Check:"
curl -s http://localhost:8080/api/backend/health | python3 -m json.tool

echo ""
echo "2. Network Topology:"
curl -s http://localhost:8080/api/backend/network-topology | python3 -m json.tool | head -20

echo ""
echo "3. Testing PhantomStrike AI (Attack):"
curl -X POST http://localhost:8080/api/backend/langgraph/attack/start \
  -H "Content-Type: application/json" \
  -d '{"user_request":"Execute APT simulation on critical infrastructure","attack_type":"apt","complexity":"advanced"}' \
  | python3 -m json.tool | head -20

echo ""
echo "4. Detection Status:"
curl -s http://localhost:8080/api/backend/langgraph/detection/status | python3 -m json.tool

echo ""
echo "=========================================="
echo " DEPLOYMENT COMPLETE!"
echo "=========================================="
echo ""
echo "Platform Details:"
echo "  PID: $PID"
echo "  Port: 8080"
echo "  Log: tail -f complete_platform.log"
echo ""
echo "AI Agents:"
echo "  PhantomStrike AI - Attack scenarios based on network topology"
echo "  GuardianAlpha AI - Continuous threat detection from logs"
echo "  AI Reasoning Engine - Final verdict with explanations"
echo ""
echo "Features:"
echo "  Network topology awareness (5 endpoints registered)"
echo "  Golden image backup before attacks"
echo "  Continuous log monitoring and detection"
echo "  ML + LLM analysis pipeline"
echo "  Client agent management"
echo "  Attack scenario generation based on actual topology"
echo ""
echo "API Endpoints:"
echo "  Attack: http://localhost:8080/api/backend/langgraph/attack/start"
echo "  Detection: http://localhost:8080/api/backend/langgraph/detection/status"
echo "  Topology: http://localhost:8080/api/backend/network-topology"
echo "  Endpoints: http://localhost:8080/api/backend/endpoints"
echo ""
echo "Client Agent APIs:"
echo "  Register: POST /api/backend/agent/register"
echo "  Logs: POST /api/backend/agent/logs"
echo "  Heartbeat: POST /api/backend/agent/heartbeat"
echo ""
echo "=========================================="