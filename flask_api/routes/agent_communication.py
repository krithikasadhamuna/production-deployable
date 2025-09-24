"""
Agent Communication APIs
Critical endpoints for agent-to-server communication
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone, timedelta
import sqlite3
import json
import uuid
from functools import wraps
import logging

logger = logging.getLogger(__name__)
agent_comm_bp = Blueprint('agent_comm', __name__)

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
        
        # Validate API key
        token = auth_header.split(' ')[1]
        VALID_API_KEYS = {
            "soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs": "admin",
            "soc-agents-2024": "agent"
        }
        
        if token not in VALID_API_KEYS:
            return jsonify({
                'success': False,
                'error': 'Invalid API token',
                'error_code': 'UNAUTHORIZED'
            }), 401
            
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

@agent_comm_bp.route('/agents/register', methods=['POST'])
@require_auth
def register_agent():
    """
    POST /api/agents/register
    Register new agent or update existing agent
    """
    try:
        data = request.get_json()
        
        # Extract agent info
        agent_id = data.get('agent_id', f"agent_{uuid.uuid4().hex[:8]}")
        hostname = data.get('hostname', 'unknown')
        ip_address = data.get('ip_address', request.remote_addr)
        agent_type = data.get('type', 'endpoint')
        platform = data.get('platform', 'unknown')
        capabilities = data.get('capabilities', [])
        version = data.get('version', '1.0.0')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if agent exists
        cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
        existing = cursor.fetchone()
        
        now = datetime.now(timezone.utc).isoformat()
        
        if existing:
            # Update existing agent
            cursor.execute("""
                UPDATE agents 
                SET hostname = ?, ip_address = ?, status = 'online',
                    last_heartbeat = ?, capabilities = ?, version = ?,
                    platform = ?
                WHERE id = ?
            """, (hostname, ip_address, now, json.dumps(capabilities), 
                  version, platform, agent_id))
        else:
            # Register new agent
            cursor.execute("""
                INSERT INTO agents 
                (id, name, type, status, hostname, ip_address, 
                 capabilities, version, first_seen, last_heartbeat, platform)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (agent_id, hostname, agent_type, 'online', hostname, 
                  ip_address, json.dumps(capabilities), version, now, now, platform))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Agent {agent_id} registered successfully from {ip_address}")
        
        return jsonify({
            "success": True,
            "agent_id": agent_id,
            "status": "registered",
            "message": "Agent registered successfully"
        })
        
    except Exception as e:
        logger.error(f"Agent registration error: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "REGISTRATION_ERROR"
        }), 500

@agent_comm_bp.route('/agents/<agent_id>/heartbeat', methods=['POST'])
@require_auth
def agent_heartbeat(agent_id):
    """
    POST /api/agents/{agent_id}/heartbeat
    Update agent heartbeat and get pending commands
    """
    try:
        data = request.get_json() or {}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update heartbeat
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            UPDATE agents 
            SET last_heartbeat = ?, status = 'online'
            WHERE id = ?
        """, (now, agent_id))
        
        # Get pending commands for this agent
        cursor.execute("""
            SELECT * FROM commands 
            WHERE agent_id = ? AND status IN ('queued', 'pending')
            ORDER BY priority DESC, created_at ASC
            LIMIT 10
        """, (agent_id,))
        
        commands = []
        for cmd in cursor.fetchall():
            commands.append({
                'id': cmd['id'],
                'type': cmd['type'],
                'parameters': json.loads(cmd['parameters']) if cmd['parameters'] else {},
                'priority': cmd['priority']
            })
            
            # Mark commands as sent
            cursor.execute("""
                UPDATE commands 
                SET status = 'sent', sent_at = ?
                WHERE id = ?
            """, (now, cmd['id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "commands": commands,
            "server_time": now
        })
        
    except Exception as e:
        logger.error(f"Heartbeat error for agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "HEARTBEAT_ERROR"
        }), 500

@agent_comm_bp.route('/agents/<agent_id>/logs', methods=['POST'])
@require_auth
def receive_agent_logs(agent_id):
    """
    POST /api/agents/{agent_id}/logs
    Receive logs/events from agent
    """
    try:
        data = request.get_json()
        
        if not data or 'events' not in data:
            return jsonify({
                "success": False,
                "error": "Missing events data",
                "error_code": "INVALID_DATA"
            }), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Process each event
        processed = 0
        for event in data['events']:
            try:
                event_id = event.get('id', f"evt_{uuid.uuid4().hex[:12]}")
                event_type = event.get('type', 'unknown')
                severity = event.get('severity', 'info')
                timestamp = event.get('timestamp', datetime.now(timezone.utc).isoformat())
                event_data = event.get('data', {})
                
                # Store in detections table for threat analysis
                cursor.execute("""
                    INSERT INTO detections 
                    (id, agent_id, type, severity, timestamp, data, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (event_id, agent_id, event_type, severity, 
                      timestamp, json.dumps(event_data), 'pending'))
                
                processed += 1
                
                # Check if this is a critical event that needs immediate attention
                if severity in ['critical', 'high']:
                    logger.warning(f"Critical event from agent {agent_id}: {event_type}")
                    
            except Exception as e:
                logger.error(f"Error processing event: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        logger.info(f"Received {processed} events from agent {agent_id}")
        
        return jsonify({
            "success": True,
            "processed": processed,
            "message": f"Processed {processed} events successfully"
        })
        
    except Exception as e:
        logger.error(f"Log receiving error from agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "LOG_PROCESSING_ERROR"
        }), 500

@agent_comm_bp.route('/agents/<agent_id>/command-result', methods=['POST'])
@require_auth
def receive_command_result(agent_id):
    """
    POST /api/agents/{agent_id}/command-result
    Receive command execution results from agent
    """
    try:
        data = request.get_json()
        
        if not data or 'command_id' not in data:
            return jsonify({
                "success": False,
                "error": "Missing command_id",
                "error_code": "INVALID_DATA"
            }), 400
        
        command_id = data['command_id']
        success = data.get('success', False)
        output = data.get('output', '')
        error = data.get('error', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update command status
        now = datetime.now(timezone.utc).isoformat()
        status = 'completed' if success else 'failed'
        
        cursor.execute("""
            UPDATE commands 
            SET status = ?, completed_at = ?, result = ?
            WHERE id = ? AND agent_id = ?
        """, (status, now, json.dumps({
            'success': success,
            'output': output,
            'error': error
        }), command_id, agent_id))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Received command result from agent {agent_id}: {command_id} - {status}")
        
        return jsonify({
            "success": True,
            "message": "Command result recorded"
        })
        
    except Exception as e:
        logger.error(f"Command result error from agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "RESULT_PROCESSING_ERROR"
        }), 500

@agent_comm_bp.route('/agents/<agent_id>/execute', methods=['POST'])
@require_auth
def execute_attack_command(agent_id):
    """
    POST /api/agents/{agent_id}/execute
    Execute attack command on specific agent (from Attack Agent)
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or 'technique' not in data:
            return jsonify({
                "success": False,
                "error": "Missing required field: technique",
                "error_code": "INVALID_PARAMETERS"
            }), 400
        
        technique = data['technique']
        parameters = data.get('parameters', {})
        priority = 'high'  # Attack commands are high priority
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if agent exists and is online
        cursor.execute("SELECT status FROM agents WHERE id = ?", (agent_id,))
        agent = cursor.fetchone()
        
        if not agent:
            conn.close()
            return jsonify({
                "success": False,
                "error": "Agent not found",
                "error_code": "AGENT_NOT_FOUND"
            }), 404
        
        if agent['status'] != 'online':
            conn.close()
            return jsonify({
                "success": False,
                "error": "Agent is not online",
                "error_code": "AGENT_OFFLINE"
            }), 400
        
        # Create attack command
        command_id = f"atk_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute("""
            INSERT INTO commands 
            (id, agent_id, type, priority, parameters, status, created_at, scheduled_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            command_id,
            agent_id,
            f"attack_{technique}",
            priority,
            json.dumps(parameters),
            'queued',
            now,
            now
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Attack command {command_id} queued for agent {agent_id}: {technique}")
        
        return jsonify({
            "success": True,
            "command_id": command_id,
            "status": "queued",
            "message": f"Attack command queued for execution"
        })
        
    except Exception as e:
        logger.error(f"Attack execution error for agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "EXECUTION_ERROR"
        }), 500

# Additional utility endpoint for monitoring
@agent_comm_bp.route('/agents/status', methods=['GET'])
@require_auth
def get_agents_status():
    """
    GET /api/agents/status
    Get status of all agents (online/offline based on heartbeat)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update agent status based on last heartbeat
        # Mark as offline if no heartbeat for 5 minutes
        threshold = datetime.now(timezone.utc) - timedelta(minutes=5)
        cursor.execute("""
            UPDATE agents 
            SET status = 'offline'
            WHERE last_heartbeat < ? AND status = 'online'
        """, (threshold.isoformat(),))
        
        # Get all agents with status
        cursor.execute("""
            SELECT id, hostname, status, last_heartbeat, platform
            FROM agents
            ORDER BY status DESC, last_heartbeat DESC
        """)
        
        agents = []
        for agent in cursor.fetchall():
            agents.append({
                'id': agent['id'],
                'hostname': agent['hostname'],
                'status': agent['status'],
                'last_heartbeat': agent['last_heartbeat'],
                'platform': agent['platform']
            })
        
        conn.commit()
        conn.close()
        
        online_count = sum(1 for a in agents if a['status'] == 'online')
        offline_count = len(agents) - online_count
        
        return jsonify({
            "success": True,
            "total_agents": len(agents),
            "online": online_count,
            "offline": offline_count,
            "agents": agents
        })
        
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "STATUS_ERROR"
        }), 500
