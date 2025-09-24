"""
Testing & Development APIs
Implements testing endpoints for development and demo purposes
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone, timedelta
import sqlite3
import json
import uuid
from functools import wraps

testing_bp = Blueprint('testing', __name__)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'Missing or invalid Authorization header',
                'error_code': 'UNAUTHORIZED'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

@testing_bp.route('/test/create-sample-agents', methods=['POST'])
@require_auth
def create_sample_agents():
    """
    POST /api/test/create-sample-agents
    Create sample agents for testing and demo
    """
    try:
        conn = get_db_connection()
        now = datetime.now(timezone.utc).isoformat()
        
        # Sample agents data
        sample_agents = [
            {
                "id": "phantom-ai-01",
                "name": "PhantomStrike AI",
                "type": "attack",
                "status": "idle",
                "hostname": "phantom-ai-01",
                "ip_address": "10.0.1.100",
                "location": "External Network",
                "capabilities": ["Email Simulation", "Web Exploitation", "Social Engineering"],
                "version": "2.1.0",
                "network_element_type": "endpoint",
                "security_zone": "untrusted"
            },
            {
                "id": "guardian-ai-01",
                "name": "GuardianAlpha AI", 
                "type": "detection",
                "status": "active",
                "hostname": "guardian-ai-01",
                "ip_address": "10.0.2.100",
                "location": "SOC Infrastructure",
                "capabilities": ["Behavioral Analysis", "Signature Detection", "Threat Hunting"],
                "version": "2.1.0",
                "network_element_type": "soc",
                "security_zone": "secure"
            },
            {
                "id": "threatmind-ai-01",
                "name": "ThreatMind AI",
                "type": "reasoning", 
                "status": "active",
                "hostname": "threatmind-ai-01",
                "ip_address": "10.0.2.101",
                "location": "Threat Intelligence Platform",
                "capabilities": ["Threat Analysis", "Risk Assessment", "Incident Response Planning"],
                "version": "2.1.0",
                "network_element_type": "soc",
                "security_zone": "secure"
            },
            {
                "id": "windows-ws-001",
                "name": "Windows Workstation 001",
                "type": "windows",
                "status": "online",
                "hostname": "WS-001",
                "ip_address": "192.168.1.101",
                "location": "Internal Network",
                "capabilities": ["Log Collection", "Process Monitoring", "File Integrity"],
                "version": "3.0.0-AI",
                "network_element_type": "endpoint",
                "security_zone": "trusted"
            },
            {
                "id": "linux-srv-01",
                "name": "Linux Server 01",
                "type": "linux",
                "status": "online",
                "hostname": "linux-srv-01",
                "ip_address": "192.168.1.201",
                "location": "Data Center",
                "capabilities": ["System Monitoring", "Network Analysis", "Log Aggregation"],
                "version": "3.0.0-AI", 
                "network_element_type": "server",
                "security_zone": "trusted"
            }
        ]
        
        created_agents = []
        
        for agent_data in sample_agents:
            # Check if agent already exists
            cursor = conn.execute("SELECT id FROM agents WHERE id = ?", (agent_data['id'],))
            if cursor.fetchone():
                continue  # Skip if already exists
            
            # Insert agent
            cursor.execute("""
                INSERT INTO agents 
                (id, name, type, status, hostname, ip_address, location, capabilities, 
                 version, first_seen, last_heartbeat, network_element_type, security_zone, organization_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent_data['id'], agent_data['name'], agent_data['type'], agent_data['status'],
                agent_data['hostname'], agent_data['ip_address'], agent_data['location'],
                json.dumps(agent_data['capabilities']), agent_data['version'], now, now,
                agent_data['network_element_type'], agent_data['security_zone'], 'org-123'
            ))
            
            created_agents.append({
                "id": agent_data['id'],
                "name": agent_data['name'],
                "type": agent_data['type']
            })
        
        # Create sample attack scenarios
        sample_scenarios = [
            {
                "id": "apt28_spear_phishing",
                "name": "Fancy Bear Email Campaign",
                "description": "Sophisticated spear-phishing campaign targeting government and military organizations",
                "apt_group": "APT28 (Fancy Bear)",
                "country": "Russia",
                "difficulty": "advanced",
                "duration_minutes": 45,
                "impact": "Critical Impact",
                "techniques": ["T1566.001", "T1071.001", "T1027", "T1055"],
                "target_sectors": ["Government", "Military", "Defense Contractors"],
                "motivation": "Espionage, Intelligence Gathering",
                "playbook_steps": [
                    "1. Reconnaissance and target identification",
                    "2. Craft spear-phishing emails with malicious attachments", 
                    "3. Deploy Zebrocy malware payload",
                    "4. Establish command and control channel",
                    "5. Lateral movement and privilege escalation",
                    "6. Data exfiltration"
                ]
            }
        ]
        
        for scenario in sample_scenarios:
            cursor.execute("SELECT id FROM attack_scenarios WHERE id = ?", (scenario['id'],))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO attack_scenarios 
                    (id, name, description, apt_group, country, difficulty, duration_minutes, 
                     impact, techniques, target_sectors, motivation, playbook_steps)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scenario['id'], scenario['name'], scenario['description'], scenario['apt_group'],
                    scenario['country'], scenario['difficulty'], scenario['duration_minutes'],
                    scenario['impact'], json.dumps(scenario['techniques']), 
                    json.dumps(scenario['target_sectors']), scenario['motivation'],
                    json.dumps(scenario['playbook_steps'])
                ))
        
        # Create sample detections
        sample_detections = [
            {
                "id": f"det_{uuid.uuid4().hex[:6]}",
                "agent_id": "guardian-ai-01",
                "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(),
                "threat_type": "command_and_control",
                "severity": "critical",
                "confidence": 0.95,
                "source_ip": "192.168.1.150",
                "target_ip": "malicious-c2.com",
                "technique": "T1071.001",
                "technique_name": "Web Protocols",
                "description": "Suspicious C2 communication detected",
                "status": "active",
                "indicators": {"destination_domain": "malicious-c2.com", "protocol": "HTTPS"},
                "risk_score": 8.7,
                "false_positive_probability": 0.05
            }
        ]
        
        for detection in sample_detections:
            cursor.execute("""
                INSERT INTO detections 
                (id, agent_id, timestamp, threat_type, severity, confidence, source_ip, target_ip,
                 technique, technique_name, description, status, indicators, risk_score, false_positive_probability)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                detection['id'], detection['agent_id'], detection['timestamp'], detection['threat_type'],
                detection['severity'], detection['confidence'], detection['source_ip'], detection['target_ip'],
                detection['technique'], detection['technique_name'], detection['description'], detection['status'],
                json.dumps(detection['indicators']), detection['risk_score'], detection['false_positive_probability']
            ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "created": len(created_agents),
            "agents": created_agents,
            "message": f"Successfully created {len(created_agents)} sample agents with supporting data"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500


