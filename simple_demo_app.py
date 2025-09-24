#!/usr/bin/env python3
"""
CodeGrey SOC - Simple Demo Server
A simplified version of the SOC backend for demo purposes
"""

import os
import sqlite3
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/demo_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Database setup
DB_PATH = 'database/demo_soc.db'

def init_database():
    """Initialize SQLite database with schema"""
    try:
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Read and execute schema
        with open('database/sqlite_schema.sql', 'r') as f:
            schema = f.read()
            cursor.executescript(schema)
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Authentication middleware (simplified)
def require_auth():
    """Simple authentication check"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return False
    
    # For demo, accept any token that contains 'demo' or the default key
    token = auth_header.replace('Bearer ', '')
    return 'demo' in token or token == 'ak_default_key_change_in_production'

# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "CodeGrey SOC Demo",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    })

@app.route('/api/system/status', methods=['GET'])
def system_status():
    """System status endpoint"""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get agent counts
        cursor.execute("SELECT type, COUNT(*) as count FROM agents GROUP BY type")
        agent_counts = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Get active detections
        cursor.execute("SELECT COUNT(*) FROM threat_detections WHERE status = 'active'")
        active_threats = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            "status": "operational",
            "agents": {
                "total": sum(agent_counts.values()),
                "by_type": agent_counts,
                "online": sum(agent_counts.values())  # Simplified for demo
            },
            "threats": {
                "active": active_threats,
                "resolved_today": 5  # Mock data
            },
            "system": {
                "cpu_usage": "23%",
                "memory_usage": "45%",
                "disk_usage": "67%"
            },
            "uptime": "2 days, 14 hours",
            "last_updated": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"System status error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/agents', methods=['GET'])
def list_agents():
    """List all agents"""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, name, type, hostname, ip_address, status, capabilities, 
                   network_element_type, security_zone, last_heartbeat
            FROM agents 
            ORDER BY last_heartbeat DESC
        """)
        
        agents = []
        for row in cursor.fetchall():
            capabilities = json.loads(row[6]) if row[6] else []
            agent = {
                "id": row[0],
                "name": row[1],
                "type": row[2],
                "hostname": row[3],
                "ip_address": row[4],
                "status": row[5],
                "capabilities": capabilities,
                "location": f"{row[7]} ({row[8]})" if row[7] else "Unknown",
                "lastActivity": row[9] or "Never",
                "network_element_type": row[7],
                "security_zone": row[8]
            }
            agents.append(agent)
        
        conn.close()
        return jsonify(agents)
        
    except Exception as e:
        logger.error(f"List agents error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/attack_scenarios', methods=['GET'])
def list_attack_scenarios():
    """List attack scenarios"""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, name, description, apt_group, difficulty, 
                   duration_minutes, mitre_techniques, status
            FROM attack_scenarios 
            WHERE status = 'active'
            ORDER BY difficulty, name
        """)
        
        scenarios = []
        for row in cursor.fetchall():
            techniques = json.loads(row[6]) if row[6] else []
            scenario = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "apt_group": row[3],
                "difficulty": row[4],
                "duration_minutes": row[5],
                "mitre_techniques": techniques,
                "status": row[7],
                "last_executed": "Never",  # Mock data
                "success_rate": "85%"  # Mock data
            }
            scenarios.append(scenario)
        
        conn.close()
        return jsonify(scenarios)
        
    except Exception as e:
        logger.error(f"List attack scenarios error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/detections/live', methods=['GET'])
def live_detections():
    """Get live threat detections"""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT td.id, td.threat_type, td.severity, td.confidence, 
                   td.description, td.status, td.detection_timestamp,
                   a.name as agent_name, a.hostname
            FROM threat_detections td
            JOIN agents a ON td.agent_id = a.id
            WHERE td.status IN ('active', 'investigating')
            ORDER BY td.detection_timestamp DESC
            LIMIT 50
        """)
        
        detections = []
        for row in cursor.fetchall():
            detection = {
                "id": row[0],
                "threat_type": row[1],
                "severity": row[2],
                "confidence": row[3],
                "description": row[4],
                "status": row[5],
                "timestamp": row[6],
                "agent_name": row[7],
                "hostname": row[8],
                "source_ip": "192.168.1.50",  # Mock data
                "target_ip": "192.168.1.100"  # Mock data
            }
            detections.append(detection)
        
        conn.close()
        return jsonify(detections)
        
    except Exception as e:
        logger.error(f"Live detections error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/network/topology', methods=['GET'])
def network_topology():
    """Get network topology data"""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    hierarchy = request.args.get('hierarchy', 'false').lower() == 'true'
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get agents grouped by network element type
        cursor.execute("""
            SELECT network_element_type, security_zone, COUNT(*) as agent_count,
                   AVG(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as health_ratio
            FROM agents 
            WHERE network_element_type IS NOT NULL
            GROUP BY network_element_type, security_zone
            ORDER BY network_element_type
        """)
        
        topology_data = []
        for row in cursor.fetchall():
            element_type = row[0] or 'unknown'
            zone = row[1] or 'unclassified'
            
            node = {
                "id": f"{element_type}_{zone}",
                "name": f"{element_type.title()} ({zone})",
                "type": element_type,
                "security_zone": zone,
                "agent_count": row[2],
                "status": "healthy" if row[3] > 0.8 else "warning" if row[3] > 0.5 else "critical",
                "risk_level": "low" if zone in ['secure', 'trusted'] else "medium" if zone == 'dmz' else "high",
                "hierarchy_level": 1 if element_type == 'firewall' else 2 if element_type in ['dmz', 'internal'] else 3
            }
            topology_data.append(node)
        
        conn.close()
        
        if hierarchy:
            # Sort by hierarchy level for hierarchical display
            topology_data.sort(key=lambda x: x['hierarchy_level'])
        
        return jsonify({
            "nodes": topology_data,
            "hierarchy": hierarchy,
            "total_nodes": len(topology_data),
            "last_updated": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Network topology error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/v1/chat', methods=['POST'])
def ai_chat():
    """AI chat endpoint (mock for demo)"""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        message = data.get('message', '')
        
        # Mock AI responses for demo
        responses = {
            'threat': "Based on current analysis, we have 3 active threats requiring attention. The highest priority is a potential privilege escalation on agent-001.",
            'status': "All systems are operational. 3 agents online, 2 active threats detected in the last hour.",
            'attack': "Latest attack simulation completed successfully with 85% success rate. Detected vulnerabilities in network segmentation.",
            'default': f"I understand you're asking about: '{message}'. Our AI reasoning engine is analyzing current threat landscape and system status."
        }
        
        # Simple keyword matching for demo
        response_key = 'default'
        if any(word in message.lower() for word in ['threat', 'detection', 'malware']):
            response_key = 'threat'
        elif any(word in message.lower() for word in ['status', 'health', 'system']):
            response_key = 'status'
        elif any(word in message.lower() for word in ['attack', 'simulation', 'test']):
            response_key = 'attack'
        
        return jsonify({
            "response": responses[response_key],
            "timestamp": datetime.utcnow().isoformat(),
            "confidence": 0.85,
            "sources": ["threat_detections", "agent_logs", "ml_models"]
        })
        
    except Exception as e:
        logger.error(f"AI chat error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/test/create-sample-agents', methods=['POST'])
def create_sample_agents():
    """Create sample agents for demo (already in schema)"""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    return jsonify({
        "message": "Sample agents already exist in database",
        "agents_created": 3,
        "scenarios_created": 3,
        "detections_created": 3
    })

# ============================================================================
# MAIN APPLICATION
# ============================================================================

if __name__ == '__main__':
    # Initialize database
    if not init_database():
        logger.error("Failed to initialize database. Exiting.")
        exit(1)
    
    # Start the server
    logger.info("Starting CodeGrey SOC Demo Server...")
    logger.info("Demo API Key: ak_default_key_change_in_production")
    logger.info("Or use any token containing 'demo'")
    
    app.run(
        host='0.0.0.0',
        port=8443,
        debug=True,
        ssl_context=None  # Simplified for demo
    )


