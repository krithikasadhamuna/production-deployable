"""
Simplified Agent Authentication
Allows agents to register with just a user API key
"""

from flask import Blueprint, request, jsonify
import sqlite3
import uuid
import hashlib
from datetime import datetime

simple_auth_bp = Blueprint('simple_auth', __name__)

@simple_auth_bp.route('/api/agent/simple-register', methods=['POST'])
def simple_register():
    """
    Super simple agent registration
    Just needs API key and basic system info
    """
    try:
        data = request.get_json()
        api_key = data.get('api_key', '')
        
        # Determine tenant from API key
        tenant = 'codegrey'  # Default
        
        if api_key.startswith('usr-api-'):
            # User API key - look up tenant
            conn = sqlite3.connect('master_platform.db')
            cursor = conn.cursor()
            cursor.execute("""
                SELECT tenant_id FROM users 
                WHERE api_key = ? AND status = 'active'
            """, (api_key,))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                # Get tenant slug
                conn = sqlite3.connect('master_platform.db')
                cursor = conn.cursor()
                cursor.execute("SELECT slug FROM tenants WHERE id = ?", (result[0],))
                tenant_result = cursor.fetchone()
                if tenant_result:
                    tenant = tenant_result[0]
                conn.close()
        
        # Generate agent credentials
        agent_id = f"agt-{uuid.uuid4().hex[:12]}"
        agent_key = f"agt-key-{uuid.uuid4().hex}"
        
        # Save to tenant database
        tenant_db = f"tenant_databases/{tenant}.db"
        conn = sqlite3.connect(tenant_db)
        cursor = conn.cursor()
        
        # Create agents table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                api_key TEXT UNIQUE,
                hostname TEXT,
                platform TEXT,
                registered_at TIMESTAMP,
                last_seen TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        """)
        
        # Insert agent
        cursor.execute("""
            INSERT INTO agents (agent_id, api_key, hostname, platform, registered_at, status)
            VALUES (?, ?, ?, ?, ?, 'active')
        """, (
            agent_id,
            agent_key,
            data.get('hostname', 'unknown'),
            data.get('platform', 'unknown'),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'agent_id': agent_id,
            'agent_key': agent_key,
            'tenant': tenant,
            'message': 'Agent registered successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@simple_auth_bp.route('/api/agent/heartbeat', methods=['POST'])
def heartbeat():
    """
    Simple heartbeat endpoint
    """
    try:
        data = request.get_json()
        agent_key = data.get('agent_key', '')
        
        if not agent_key.startswith('agt-key-'):
            return jsonify({'error': 'Invalid agent key'}), 401
        
        # Find agent in any tenant DB (simplified)
        for db_file in os.listdir('tenant_databases'):
            if db_file.endswith('.db'):
                try:
                    conn = sqlite3.connect(f'tenant_databases/{db_file}')
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE agents 
                        SET last_seen = ? 
                        WHERE api_key = ?
                    """, (datetime.now().isoformat(), agent_key))
                    
                    if cursor.rowcount > 0:
                        conn.commit()
                        conn.close()
                        return jsonify({'success': True}), 200
                    conn.close()
                except:
                    pass
        
        return jsonify({'error': 'Agent not found'}), 404
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
