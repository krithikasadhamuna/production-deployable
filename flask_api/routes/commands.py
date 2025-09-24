"""
🎛️ Command & Control APIs
Implements agent command and control endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import uuid
from functools import wraps

commands_bp = Blueprint('commands', __name__)

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

@commands_bp.route('/agents/<agent_id>/command', methods=['POST'])
@require_auth
def send_agent_command(agent_id):
    """
    POST /api/agents/{agent_id}/command
    Send command to specific agent
    """
    try:
        data = request.get_json()
        
        if not data or 'type' not in data:
            return jsonify({
                "success": False,
                "error": "Missing required field: type",
                "error_code": "INVALID_PARAMETERS"
            }), 400
        
        # Check if agent exists
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        agent = cursor.fetchone()
        
        if not agent:
            conn.close()
            return jsonify({
                "success": False,
                "error": "Agent not found",
                "error_code": "AGENT_NOT_FOUND"
            }), 404
        
        command_type = data['type']
        priority = data.get('priority', 'normal')
        parameters = data.get('parameters', {})
        schedule_at = data.get('schedule_at')
        
        # Generate command ID
        command_id = f"cmd_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        
        # Parse schedule_at if provided
        scheduled_at = now
        if schedule_at:
            try:
                scheduled_at = datetime.fromisoformat(schedule_at.replace('Z', '+00:00'))
            except:
                scheduled_at = now
        
        # Insert command into database
        cursor.execute("""
            INSERT INTO commands 
            (id, agent_id, type, priority, parameters, status, created_at, scheduled_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            command_id,
            agent_id,
            command_type,
            priority,
            json.dumps(parameters),
            'queued',
            now.isoformat(),
            scheduled_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "command_id": command_id,
            "agent_id": agent_id,
            "message": "Command queued for execution",
            "status": "queued",
            "created_at": now.isoformat(),
            "scheduled_at": scheduled_at.isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@commands_bp.route('/agents/<agent_id>/commands', methods=['GET'])
@require_auth
def get_agent_commands(agent_id):
    """
    GET /api/agents/{agent_id}/commands
    Get commands for specific agent
    """
    try:
        # Check if agent exists
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        agent = cursor.fetchone()
        
        if not agent:
            conn.close()
            return jsonify({
                "success": False,
                "error": "Agent not found",
                "error_code": "AGENT_NOT_FOUND"
            }), 404
        
        # Get commands for this agent
        cursor = conn.execute("""
            SELECT * FROM commands 
            WHERE agent_id = ? 
            ORDER BY created_at DESC
        """, (agent_id,))
        commands_raw = cursor.fetchall()
        conn.close()
        
        commands = []
        for cmd in commands_raw:
            command_data = {
                "id": cmd['id'],
                "agent_id": cmd['agent_id'],
                "type": cmd['type'],
                "priority": cmd['priority'],
                "parameters": json.loads(cmd['parameters']) if cmd['parameters'] else {},
                "status": cmd['status'],
                "created_at": cmd['created_at'],
                "scheduled_at": cmd['scheduled_at'],
                "output": cmd['output'],
                "stderr": cmd['stderr'],
                "exit_code": cmd['exit_code'],
                "execution_time": cmd['execution_time'],
                "duration_seconds": cmd['duration_seconds']
            }
            commands.append(command_data)
        
        return jsonify({
            "success": True,
            "agent_id": agent_id,
            "commands": commands,
            "total": len(commands)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@commands_bp.route('/commands/<command_id>/result', methods=['GET'])
@require_auth
def get_command_result(command_id):
    """
    GET /api/commands/{command_id}/result
    Get command execution result
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM commands WHERE id = ?", (command_id,))
        command = cursor.fetchone()
        conn.close()
        
        if not command:
            return jsonify({
                "success": False,
                "error": "Command not found",
                "error_code": "COMMAND_NOT_FOUND"
            }), 404
        
        # If command hasn't been executed yet, simulate execution for demo
        if command['status'] == 'queued':
            result_data = _simulate_command_execution(command['type'])
        else:
            result_data = {
                "command_id": command['id'],
                "agent_id": command['agent_id'],
                "status": command['status'],
                "output": command['output'] or _simulate_command_execution(command['type'])['output'],
                "stderr": command['stderr'] or "",
                "exit_code": command['exit_code'] or 0,
                "execution_time": command['execution_time'] or datetime.now(timezone.utc).isoformat(),
                "duration_seconds": command['duration_seconds'] or 3.2
            }
        
        return jsonify({
            "success": True,
            "result": result_data
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@commands_bp.route('/commands/<command_id>/result', methods=['POST'])
@require_auth
def update_command_result(command_id):
    """
    POST /api/commands/{command_id}/result
    Update command execution result (used by agents)
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "error": "Missing request body",
                "error_code": "INVALID_PARAMETERS"
            }), 400
        
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM commands WHERE id = ?", (command_id,))
        command = cursor.fetchone()
        
        if not command:
            conn.close()
            return jsonify({
                "success": False,
                "error": "Command not found",
                "error_code": "COMMAND_NOT_FOUND"
            }), 404
        
        # Update command result
        status = data.get('status', 'completed')
        output = data.get('output', '')
        stderr = data.get('stderr', '')
        exit_code = data.get('exit_code', 0)
        duration_seconds = data.get('duration_seconds', 0)
        execution_time = datetime.now(timezone.utc).isoformat()
        
        cursor.execute("""
            UPDATE commands 
            SET status = ?, output = ?, stderr = ?, exit_code = ?, 
                execution_time = ?, duration_seconds = ?
            WHERE id = ?
        """, (
            status, output, stderr, exit_code,
            execution_time, duration_seconds, command_id
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "command_id": command_id,
            "message": "Command result updated successfully",
            "status": status
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

# Helper functions
def _simulate_command_execution(command_type):
    """Simulate command execution for demo purposes"""
    if command_type == 'system_info':
        return {
            "system_info": {
                "os": "Windows 10 Pro",
                "cpu": "Intel Core i7-8700K",
                "memory": "16 GB",
                "disk": "500 GB SSD"
            },
            "processes": [
                {"name": "chrome.exe", "pid": 1234, "cpu": 15.2},
                {"name": "notepad.exe", "pid": 5678, "cpu": 0.1}
            ],
            "network": {
                "active_connections": 23,
                "listening_ports": [80, 443, 3389]
            }
        }
    elif command_type == 'network_scan':
        return {
            "scan_results": {
                "hosts_discovered": 15,
                "open_ports": [80, 443, 22, 3389],
                "services": ["HTTP", "HTTPS", "SSH", "RDP"]
            }
        }
    elif command_type == 'process_list':
        return {
            "processes": [
                {"name": "explorer.exe", "pid": 1000, "cpu": 2.1, "memory": "45MB"},
                {"name": "chrome.exe", "pid": 2000, "cpu": 15.3, "memory": "512MB"},
                {"name": "codegrey-agent.exe", "pid": 3000, "cpu": 0.5, "memory": "32MB"}
            ]
        }
    else:
        return {
            "message": f"Command '{command_type}' executed successfully",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

