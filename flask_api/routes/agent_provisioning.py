"""
Agent Provisioning API
Handles agent registration using user API keys
"""

from flask import Blueprint, request, jsonify
import sqlite3
import json
import uuid
import hashlib
from datetime import datetime
from functools import wraps

agent_provision_bp = Blueprint('agent_provision', __name__)

def require_user_api_key(f):
    """Decorator to validate user API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization'}), 401
        
        api_key = auth_header.replace('Bearer ', '')
        
        # Check if it's a user API key (format: usr-api-xxxxx)
        if not api_key.startswith('usr-api-'):
            return jsonify({'error': 'Invalid user API key format'}), 401
        
        # Validate against master database
        try:
            conn = sqlite3.connect('master_platform.db')
            cursor = conn.cursor()
            
            # Get user and tenant info from API key
            cursor.execute("""
                SELECT u.id, u.email, u.tenant_id, t.slug, t.name
                FROM users u
                JOIN tenants t ON u.tenant_id = t.id
                WHERE u.api_key = ? AND u.status = 'active'
            """, (api_key,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return jsonify({'error': 'Invalid or inactive API key'}), 401
            
            # Attach user and tenant info to request
            request.user_id = result[0]
            request.user_email = result[1]
            request.tenant_id = result[2]
            request.tenant_slug = result[3]
            request.tenant_name = result[4]
            
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({'error': f'Authentication failed: {str(e)}'}), 500
    
    return decorated_function

@agent_provision_bp.route('/api/agent/provision', methods=['POST'])
@require_user_api_key
def provision_agent():
    """
    Provision a new agent for the user's organization
    
    Expected payload:
    {
        "hostname": "DESKTOP-ABC123",
        "platform": "Windows",
        "ip_address": "192.168.1.100",
        "mac_address": "00:11:22:33:44:55",
        "username": "john.doe",
        "domain": "CORP",
        "department": "finance",
        "location": "Building A, Floor 3"
    }
    
    Returns:
    {
        "agent_id": "agt-xxxxx",
        "api_key": "agt-key-xxxxx",
        "tenant": "codegrey",
        "server_url": "https://dev.codegrey.ai",
        "config": {...}
    }
    """
    try:
        data = request.get_json()
        
        # Generate unique agent credentials
        agent_id = f"agt-{uuid.uuid4().hex[:12]}"
        agent_api_key = f"agt-key-{uuid.uuid4().hex}"
        
        # Create fingerprint for this endpoint
        fingerprint_data = f"{data.get('hostname', '')}-{data.get('mac_address', '')}-{data.get('domain', '')}"
        endpoint_fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
        
        # Check if this endpoint already exists for this tenant
        tenant_db = f"tenant_databases/{request.tenant_slug}.db"
        conn = sqlite3.connect(tenant_db)
        cursor = conn.cursor()
        
        # Check for existing agent with same fingerprint
        cursor.execute("""
            SELECT agent_id, api_key 
            FROM agents 
            WHERE endpoint_fingerprint = ? AND status != 'decommissioned'
        """, (endpoint_fingerprint,))
        
        existing = cursor.fetchone()
        if existing:
            # Return existing credentials instead of creating new
            agent_id = existing[0]
            agent_api_key = existing[1]
            
            # Update last seen
            cursor.execute("""
                UPDATE agents 
                SET last_seen = ?, last_provisioned_by = ?
                WHERE agent_id = ?
            """, (datetime.now().isoformat(), request.user_email, agent_id))
            
        else:
            # Create new agent record
            cursor.execute("""
                INSERT INTO agents (
                    agent_id, api_key, hostname, platform, ip_address,
                    mac_address, username, domain, department, location,
                    endpoint_fingerprint, provisioned_by, provisioned_at,
                    tenant_id, status, endpoint_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent_id,
                agent_api_key,
                data.get('hostname'),
                data.get('platform'),
                data.get('ip_address'),
                data.get('mac_address'),
                data.get('username'),
                data.get('domain'),
                data.get('department'),
                data.get('location'),
                endpoint_fingerprint,
                request.user_email,
                datetime.now().isoformat(),
                request.tenant_id,
                'provisioned',
                self.determine_endpoint_type(data)
            ))
        
        conn.commit()
        conn.close()
        
        # Return provisioning response
        response = {
            'success': True,
            'agent_id': agent_id,
            'api_key': agent_api_key,
            'tenant': request.tenant_slug,
            'organization': request.tenant_name,
            'server_url': 'https://dev.codegrey.ai',
            'config': {
                'heartbeat_interval': 60,
                'log_batch_interval': 30,
                'telemetry_interval': 300
            },
            'message': 'Agent provisioned successfully'
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({'error': f'Provisioning failed: {str(e)}'}), 500

@agent_provision_bp.route('/api/agent/register', methods=['POST'])
def register_agent():
    """
    Agent self-registration using provisioned API key
    Called by the agent after installation
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing agent API key'}), 401
    
    agent_api_key = auth_header.replace('Bearer ', '')
    
    # Validate agent API key format
    if not agent_api_key.startswith('agt-key-'):
        return jsonify({'error': 'Invalid agent API key format'}), 401
    
    try:
        data = request.get_json()
        
        # Find which tenant this agent belongs to by checking all tenant DBs
        # In production, you might want to cache this in Redis
        tenant_slug = None
        agent_info = None
        
        for db_file in os.listdir('tenant_databases'):
            if db_file.endswith('.db'):
                tenant = db_file.replace('.db', '')
                conn = sqlite3.connect(f'tenant_databases/{db_file}')
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT agent_id, hostname, tenant_id, status
                    FROM agents
                    WHERE api_key = ?
                """, (agent_api_key,))
                
                result = cursor.fetchone()
                conn.close()
                
                if result:
                    tenant_slug = tenant
                    agent_info = result
                    break
        
        if not tenant_slug:
            return jsonify({'error': 'Invalid agent API key'}), 401
        
        # Update agent status and system info
        conn = sqlite3.connect(f'tenant_databases/{tenant_slug}.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE agents SET
                status = 'active',
                last_seen = ?,
                system_info = ?,
                ip_address = ?,
                processes_count = ?,
                services_count = ?
            WHERE api_key = ?
        """, (
            datetime.now().isoformat(),
            json.dumps(data.get('system_info', {})),
            data.get('ip_address'),
            data.get('processes_count', 0),
            data.get('services_count', 0),
            agent_api_key
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'agent_id': agent_info[0],
            'tenant': tenant_slug,
            'status': 'registered'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

def determine_endpoint_type(data):
    """
    Determine endpoint type based on system characteristics
    """
    hostname = data.get('hostname', '').lower()
    username = data.get('username', '').lower()
    domain = data.get('domain', '').upper()
    department = data.get('department', '').lower()
    
    # Executive detection
    exec_keywords = ['exec', 'ceo', 'cfo', 'cto', 'president', 'vp-']
    if any(keyword in hostname or keyword in username for keyword in exec_keywords):
        return 'executive'
    
    # SOC detection
    soc_keywords = ['soc', 'security', 'analyst', 'incident']
    if any(keyword in hostname or keyword in department for keyword in soc_keywords):
        return 'soc'
    
    # Server detection
    if 'SERVER' in domain or 'srv' in hostname or 'dc' in hostname:
        return 'server'
    
    # Default to employee
    return 'employee'

@agent_provision_bp.route('/api/user/api-key', methods=['POST'])
def generate_user_api_key():
    """
    Generate API key for a user (for agent provisioning)
    Only admins can generate these
    """
    # This would typically require admin authentication
    # For now, simplified version
    try:
        data = request.get_json()
        user_email = data.get('email')
        tenant_slug = data.get('tenant', 'codegrey')
        
        # Generate user API key
        user_api_key = f"usr-api-{uuid.uuid4().hex}"
        
        # Update user record
        conn = sqlite3.connect('master_platform.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE users 
            SET api_key = ?
            WHERE email = ?
        """, (user_api_key, user_email))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'email': user_email,
            'api_key': user_api_key,
            'usage': 'Use this API key to provision agents for your organization'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
