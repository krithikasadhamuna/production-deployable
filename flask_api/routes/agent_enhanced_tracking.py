"""
Enhanced Agent Tracking with Role Detection
Tracks endpoint importance, user roles, and agent configurations
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import uuid
import logging
from functools import wraps

logger = logging.getLogger(__name__)
agent_tracking_bp = Blueprint('agent_tracking', __name__)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'Missing or invalid Authorization header'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(current_app.config.get('DATABASE', 'soc_database.db'))
    conn.row_factory = sqlite3.Row
    return conn

def determine_endpoint_importance(data):
    """
    Determine endpoint importance based on various factors
    Returns: 'critical', 'high', 'medium', 'low'
    """
    importance_score = 0
    
    # Check hostname patterns
    hostname = data.get('hostname', '').lower()
    if any(exec_term in hostname for exec_term in ['exec', 'ceo', 'cfo', 'cto', 'director', 'vp']):
        importance_score += 10
    elif any(soc_term in hostname for soc_term in ['soc', 'security', 'analyst', 'incident']):
        importance_score += 8
    elif any(it_term in hostname for it_term in ['admin', 'server', 'dc', 'domain']):
        importance_score += 7
    elif any(dev_term in hostname for dev_term in ['dev', 'test', 'staging']):
        importance_score += 3
    
    # Check installed software for executive/sensitive tools
    software = data.get('installed_software', [])
    sensitive_software = ['outlook', 'teams', 'slack', 'zoom', 'vpn', 'citrix', 'rdp']
    for sw in software:
        if any(s in str(sw).lower() for s in sensitive_software):
            importance_score += 2
    
    # Check running processes
    processes = data.get('processes', [])
    executive_processes = ['outlook', 'teams', 'zoom', 'chrome', 'firefox', 'edge']
    soc_processes = ['wireshark', 'tcpdump', 'nmap', 'metasploit', 'burp', 'nessus']
    
    for proc in processes:
        proc_name = str(proc).lower()
        if any(s in proc_name for s in soc_processes):
            importance_score += 8
        elif any(e in proc_name for e in executive_processes):
            importance_score += 3
    
    # Check network location/security zone
    security_zone = data.get('security_zone', 'internal')
    if security_zone == 'dmz':
        importance_score += 5
    elif security_zone == 'management':
        importance_score += 8
    elif security_zone == 'executive':
        importance_score += 10
    
    # Check user privileges
    is_admin = data.get('is_admin', False)
    if is_admin:
        importance_score += 5
    
    # Determine final importance level
    if importance_score >= 15:
        return 'critical'
    elif importance_score >= 10:
        return 'high'
    elif importance_score >= 5:
        return 'medium'
    else:
        return 'low'

def detect_user_role(data):
    """
    Detect the role of the user based on endpoint data
    Returns: role type and confidence score
    """
    indicators = {
        'executive': 0,
        'soc_analyst': 0,
        'it_admin': 0,
        'developer': 0,
        'employee': 0
    }
    
    hostname = data.get('hostname', '').lower()
    username = data.get('username', '').lower()
    processes = [str(p).lower() for p in data.get('processes', [])]
    software = [str(s).lower() for s in data.get('installed_software', [])]
    
    # Executive indicators
    if any(term in hostname + username for term in ['exec', 'ceo', 'cfo', 'cto', 'president', 'vp']):
        indicators['executive'] += 10
    if any(app in ' '.join(processes + software) for app in ['boardroom', 'investor', 'financial']):
        indicators['executive'] += 5
        
    # SOC Analyst indicators
    if any(term in hostname + username for term in ['soc', 'security', 'analyst', 'incident', 'csirt']):
        indicators['soc_analyst'] += 10
    soc_tools = ['wireshark', 'tcpdump', 'splunk', 'qradar', 'sentinel', 'metasploit', 'nmap', 'burp']
    for tool in soc_tools:
        if tool in ' '.join(processes + software):
            indicators['soc_analyst'] += 3
    
    # IT Admin indicators
    if any(term in hostname + username for term in ['admin', 'it', 'helpdesk', 'support']):
        indicators['it_admin'] += 8
    admin_tools = ['mmc', 'dsa.msc', 'gpmc', 'powershell', 'putty', 'rdp', 'vmware', 'hyperv']
    for tool in admin_tools:
        if tool in ' '.join(processes + software):
            indicators['it_admin'] += 2
    
    # Developer indicators
    if any(term in hostname + username for term in ['dev', 'developer', 'engineer', 'programmer']):
        indicators['developer'] += 8
    dev_tools = ['vscode', 'visual studio', 'intellij', 'eclipse', 'git', 'docker', 'python', 'node']
    for tool in dev_tools:
        if tool in ' '.join(processes + software):
            indicators['developer'] += 2
    
    # Determine most likely role
    max_score = max(indicators.values())
    if max_score < 5:
        return 'employee', 0.5
    
    role = max(indicators, key=indicators.get)
    confidence = min(max_score / 20.0, 1.0)  # Normalize to 0-1
    
    return role, confidence

@agent_tracking_bp.route('/agents/<agent_id>/telemetry', methods=['POST'])
@require_auth
def receive_telemetry(agent_id):
    """
    POST /api/agents/{agent_id}/telemetry
    Receive comprehensive telemetry data from agent including system info, processes, etc.
    This endpoint processes logs and determines endpoint importance
    """
    try:
        data = request.get_json()
        
        # Determine endpoint importance and user role
        importance = determine_endpoint_importance(data)
        user_role, role_confidence = detect_user_role(data)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update agent with enriched information
        cursor.execute("""
            UPDATE agents 
            SET endpoint_importance = ?, 
                user_role = ?, 
                role_confidence = ?,
                configuration = ?,
                last_telemetry = ?
            WHERE id = ?
        """, (
            importance,
            user_role,
            role_confidence,
            json.dumps(data.get('configuration', {})),
            datetime.now(timezone.utc).isoformat(),
            agent_id
        ))
        
        # Store telemetry data for analysis
        telemetry_id = f"tel_{uuid.uuid4().hex[:12]}"
        cursor.execute("""
            INSERT INTO agent_telemetry 
            (id, agent_id, timestamp, importance, user_role, role_confidence, data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            telemetry_id,
            agent_id,
            datetime.now(timezone.utc).isoformat(),
            importance,
            user_role,
            role_confidence,
            json.dumps(data)
        ))
        
        # Process logs if included
        if 'logs' in data:
            for log_entry in data['logs']:
                log_id = f"log_{uuid.uuid4().hex[:12]}"
                cursor.execute("""
                    INSERT INTO agent_logs 
                    (id, agent_id, timestamp, level, source, message, importance)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    log_id,
                    agent_id,
                    log_entry.get('timestamp', datetime.now(timezone.utc).isoformat()),
                    log_entry.get('level', 'info'),
                    log_entry.get('source', 'unknown'),
                    log_entry.get('message', ''),
                    importance
                ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Telemetry processed for agent {agent_id}: importance={importance}, role={user_role}")
        
        return jsonify({
            "success": True,
            "agent_id": agent_id,
            "importance": importance,
            "user_role": user_role,
            "role_confidence": role_confidence,
            "message": "Telemetry processed successfully"
        })
        
    except Exception as e:
        logger.error(f"Telemetry processing error for agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@agent_tracking_bp.route('/agents/by-importance', methods=['GET'])
@require_auth
def get_agents_by_importance():
    """
    GET /api/agents/by-importance
    Get agents grouped by their endpoint importance
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                id, hostname, endpoint_importance, user_role, 
                role_confidence, status, last_heartbeat
            FROM agents
            WHERE endpoint_importance IS NOT NULL
            ORDER BY 
                CASE endpoint_importance
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                last_heartbeat DESC
        """)
        
        agents_by_importance = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for agent in cursor.fetchall():
            importance = agent['endpoint_importance'] or 'low'
            agents_by_importance[importance].append({
                'id': agent['id'],
                'hostname': agent['hostname'],
                'user_role': agent['user_role'],
                'role_confidence': agent['role_confidence'],
                'status': agent['status'],
                'last_heartbeat': agent['last_heartbeat']
            })
        
        conn.close()
        
        return jsonify({
            "success": True,
            "agents": agents_by_importance,
            "summary": {
                "critical": len(agents_by_importance['critical']),
                "high": len(agents_by_importance['high']),
                "medium": len(agents_by_importance['medium']),
                "low": len(agents_by_importance['low'])
            }
        })
        
    except Exception as e:
        logger.error(f"Error fetching agents by importance: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@agent_tracking_bp.route('/logs/search', methods=['POST'])
@require_auth
def search_logs():
    """
    POST /api/logs/search
    Search logs with filters including agent ID, importance, time range
    """
    try:
        data = request.get_json() or {}
        
        agent_id = data.get('agent_id')
        importance = data.get('importance')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        search_text = data.get('search_text')
        limit = min(data.get('limit', 100), 1000)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM agent_logs WHERE 1=1"
        params = []
        
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        
        if importance:
            query += " AND importance = ?"
            params.append(importance)
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        
        if search_text:
            query += " AND message LIKE ?"
            params.append(f"%{search_text}%")
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        logs = []
        for log in cursor.fetchall():
            logs.append({
                'id': log['id'],
                'agent_id': log['agent_id'],
                'timestamp': log['timestamp'],
                'level': log['level'],
                'source': log['source'],
                'message': log['message'],
                'importance': log['importance']
            })
        
        conn.close()
        
        return jsonify({
            "success": True,
            "logs": logs,
            "count": len(logs)
        })
        
    except Exception as e:
        logger.error(f"Log search error: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# Database schema updates needed
def update_database_schema():
    """Add new columns and tables for enhanced tracking"""
    conn = sqlite3.connect('soc_database.db')
    cursor = conn.cursor()
    
    # Add new columns to agents table
    try:
        cursor.execute("ALTER TABLE agents ADD COLUMN endpoint_importance TEXT DEFAULT 'medium'")
    except:
        pass
    
    try:
        cursor.execute("ALTER TABLE agents ADD COLUMN user_role TEXT")
    except:
        pass
    
    try:
        cursor.execute("ALTER TABLE agents ADD COLUMN role_confidence REAL")
    except:
        pass
    
    try:
        cursor.execute("ALTER TABLE agents ADD COLUMN configuration TEXT")
    except:
        pass
    
    try:
        cursor.execute("ALTER TABLE agents ADD COLUMN last_telemetry TIMESTAMP")
    except:
        pass
    
    # Create telemetry table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agent_telemetry (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            importance TEXT,
            user_role TEXT,
            role_confidence REAL,
            data TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents (id)
        )
    ''')
    
    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agent_logs (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            level TEXT,
            source TEXT,
            message TEXT,
            importance TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents (id)
        )
    ''')
    
    conn.commit()
    conn.close()
