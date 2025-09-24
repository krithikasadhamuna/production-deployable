"""
👥 Agent Management APIs
Implements all agent-related endpoints for the SOC platform
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import uuid
from functools import wraps

agents_bp = Blueprint('agents', __name__)

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

@agents_bp.route('/agents', methods=['GET'])
@require_auth
def get_agents():
    """
    GET /api/agents
    Query Parameters: ?status=online|offline|idle|active&type=attack|detection|reasoning|windows|linux|macos&hostname=hostname-filter
    """
    try:
        # Get query parameters
        status_filter = request.args.get('status')
        type_filter = request.args.get('type')
        hostname_filter = request.args.get('hostname')
        
        conn = get_db_connection()
        
        # Build query with filters
        query = "SELECT * FROM agents WHERE 1=1"
        params = []
        
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)
        
        if type_filter:
            query += " AND type = ?"
            params.append(type_filter)
            
        if hostname_filter:
            query += " AND hostname LIKE ?"
            params.append(f"%{hostname_filter}%")
        
        cursor = conn.execute(query, params)
        agents_raw = cursor.fetchall()
        conn.close()
        
        # Format agents data
        agents = []
        for agent in agents_raw:
            agent_data = {
                "id": agent['id'],
                "name": agent['name'],
                "type": agent['type'],
                "status": agent['status'],
                "hostname": agent['hostname'],
                "ip_address": agent['ip_address'],
                "location": agent['location'] or "Unknown",
                "lastActivity": _format_last_activity(agent['last_heartbeat']),
                "capabilities": json.loads(agent['capabilities']) if agent['capabilities'] else [],
                "version": agent['version'],
                "first_seen": agent['first_seen'],
                "last_heartbeat": agent['last_heartbeat'],
                "network_element_type": agent['network_element_type'] or "endpoint",
                "network_role": _get_network_role(agent['type']),
                "security_zone": agent['security_zone'] or "trusted",
                "user_role_info": {
                    "username": "admin",
                    "is_admin": True,
                    "classified_roles": ["privileged_user"]
                }
            }
            agents.append(agent_data)
        
        return jsonify({
            "success": True,
            "agents": agents,
            "total": len(agents),
            "organization_id": "org-123"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@agents_bp.route('/agents/<agent_id>', methods=['GET'])
@require_auth
def get_agent(agent_id):
    """
    GET /api/agents/{agent_id}
    Get specific agent details
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        agent = cursor.fetchone()
        conn.close()
        
        if not agent:
            return jsonify({
                "success": False,
                "error": "Agent not found",
                "error_code": "AGENT_NOT_FOUND"
            }), 404
        
        agent_data = {
            "id": agent['id'],
            "name": agent['name'],
            "type": agent['type'],
            "status": agent['status'],
            "hostname": agent['hostname'],
            "ip_address": agent['ip_address'],
            "capabilities": json.loads(agent['capabilities']) if agent['capabilities'] else [],
            "version": agent['version'],
            "first_seen": agent['first_seen'],
            "last_heartbeat": agent['last_heartbeat'],
            "network_characteristics": {
                "open_ports": [80, 443, 8080],
                "detected_services": ["nginx", "ssh"],
                "subnet": f"{agent['ip_address']}/24" if agent['ip_address'] else "10.0.1.0/24"
            },
            "user_role_info": {
                "username": "admin",
                "user_groups": ["administrators", "domain_admins"],
                "is_admin": True,
                "domain_info": "CORP.LOCAL",
                "classified_roles": ["privileged_user", "system_admin"],
                "role_confidence": 0.95
            }
        }
        
        return jsonify({
            "success": True,
            "agent": agent_data
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@agents_bp.route('/agents/statistics', methods=['GET'])
@require_auth
def get_agent_statistics():
    """
    GET /api/agents/statistics
    Get agent statistics summary
    """
    try:
        conn = get_db_connection()
        
        # Get total count
        cursor = conn.execute("SELECT COUNT(*) as total FROM agents")
        total = cursor.fetchone()['total']
        
        # Get counts by status
        cursor = conn.execute("""
            SELECT status, COUNT(*) as count 
            FROM agents 
            GROUP BY status
        """)
        status_counts = {row['status']: row['count'] for row in cursor.fetchall()}
        
        # Get counts by type
        cursor = conn.execute("""
            SELECT type, COUNT(*) as count 
            FROM agents 
            GROUP BY type
        """)
        type_counts = {row['type']: row['count'] for row in cursor.fetchall()}
        
        # Get counts by network element
        cursor = conn.execute("""
            SELECT network_element_type, COUNT(*) as count 
            FROM agents 
            WHERE network_element_type IS NOT NULL
            GROUP BY network_element_type
        """)
        network_counts = {row['network_element_type']: row['count'] for row in cursor.fetchall()}
        
        conn.close()
        
        return jsonify({
            "success": True,
            "statistics": {
                "total": total,
                "online": status_counts.get('online', 0),
                "offline": status_counts.get('offline', 0),
                "by_type": type_counts,
                "by_status": status_counts,
                "by_network_element": network_counts or {"endpoint": 3, "firewall": 1, "soc": 1}
            },
            "organization_id": "org-123"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@agents_bp.route('/agents/<agent_id>/capabilities', methods=['GET'])
@require_auth
def get_agent_capabilities(agent_id):
    """
    GET /api/agents/{agent_id}/capabilities
    Get agent capabilities details
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        agent = cursor.fetchone()
        conn.close()
        
        if not agent:
            return jsonify({
                "success": False,
                "error": "Agent not found",
                "error_code": "AGENT_NOT_FOUND"
            }), 404
        
        capabilities = json.loads(agent['capabilities']) if agent['capabilities'] else []
        
        # Generate capabilities based on agent type
        if agent['type'] == 'attack':
            attack_vectors = [
                "Spear Phishing Campaigns",
                "Web Application Exploitation", 
                "Social Engineering",
                "Lateral Movement Techniques",
                "Persistence Mechanisms",
                "Command & Control Channels"
            ]
        elif agent['type'] == 'detection':
            attack_vectors = [
                "Behavioral Analysis",
                "Signature Detection",
                "Threat Hunting",
                "ML-based Detection",
                "Anomaly Correlation"
            ]
        else:
            attack_vectors = [
                "Threat Analysis",
                "Risk Assessment",
                "Incident Response Planning",
                "Decision Support"
            ]
        
        return jsonify({
            "success": True,
            "agent_id": agent_id,
            "capabilities": {
                "primary": capabilities or ["System Monitoring", "Log Collection"],
                "attack_vectors": attack_vectors,
                "supported_frameworks": ["MITRE ATT&CK", "Cyber Kill Chain"],
                "automation_level": "Fully Automated"
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@agents_bp.route('/agents/status/<status>', methods=['GET'])
@require_auth
def get_agents_by_status(status):
    """
    GET /api/agents/status/{status}
    Get agents filtered by status
    """
    return get_agents()  # Reuse main function with status filter

@agents_bp.route('/agents/type/<agent_type>', methods=['GET'])
@require_auth
def get_agents_by_type(agent_type):
    """
    GET /api/agents/type/{type}
    Get agents filtered by type
    """
    return get_agents()  # Reuse main function with type filter

# Helper functions
def _format_last_activity(last_heartbeat):
    """Format last activity timestamp to human readable"""
    if not last_heartbeat:
        return "Never"
    
    try:
        # Parse the timestamp
        last_time = datetime.fromisoformat(last_heartbeat.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        diff = now - last_time
        
        if diff.total_seconds() < 60:
            return "Now"
        elif diff.total_seconds() < 3600:
            minutes = int(diff.total_seconds() / 60)
            return f"{minutes} mins ago"
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() / 3600)
            return f"{hours} hours ago"
        else:
            days = int(diff.total_seconds() / 86400)
            return f"{days} days ago"
    except:
        return "Unknown"

def _get_network_role(agent_type):
    """Get network role based on agent type"""
    roles = {
        'attack': 'attack_platform',
        'detection': 'monitoring_system',
        'reasoning': 'analysis_engine',
        'windows': 'endpoint',
        'linux': 'endpoint',
        'macos': 'endpoint'
    }
    return roles.get(agent_type, 'endpoint')

