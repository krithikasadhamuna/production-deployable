"""
User Management APIs
Enhanced user management with agent download tracking and network topology
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone, timedelta
import sqlite3
import json
import uuid
import hashlib
from functools import wraps

user_management_bp = Blueprint('user_management', __name__)

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

@user_management_bp.route('/users', methods=['GET'])
@require_auth
def get_all_users():
    """Get all users with their agent download status"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get users with their download history and agent status
        cursor.execute('''
            SELECT 
                u.*,
                COUNT(ad.id) as total_downloads,
                MAX(ad.download_timestamp) as last_download,
                COUNT(CASE WHEN a.status = 'online' THEN 1 END) as active_agents,
                COUNT(a.id) as total_agents
            FROM users u
            LEFT JOIN agent_downloads ad ON u.id = ad.user_id
            LEFT JOIN agents a ON u.id = a.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        ''')
        
        users = []
        for row in cursor.fetchall():
            user = {
                'id': row['id'],
                'firstName': row['first_name'],
                'lastName': row['last_name'],
                'email': row['email'],
                'organizationId': row['organization_id'],
                'status': row['status'],
                'createdAt': row['created_at'],
                'lastLogin': row['last_login'],
                'totalDownloads': row['total_downloads'],
                'lastDownload': row['last_download'],
                'activeAgents': row['active_agents'],
                'totalAgents': row['total_agents'],
                'roles': []  # Will be populated if needed
            }
            users.append(user)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'users': users,
            'total': len(users)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_code': 'DATABASE_ERROR'
        }), 500

@user_management_bp.route('/users', methods=['POST'])
@require_auth
def create_user():
    """Create a new user"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'firstName', 'password', 'organizationId']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}',
                    'error_code': 'VALIDATION_ERROR'
                }), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user already exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (data['email'],))
        if cursor.fetchone():
            conn.close()
            return jsonify({
                'success': False,
                'error': 'User with this email already exists',
                'error_code': 'USER_EXISTS'
            }), 409
        
        # Hash password (in production, use proper password hashing)
        password_hash = hashlib.sha256(data['password'].encode()).hexdigest()
        
        # Create user
        user_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO users (
                id, username, email, first_name, last_name, password, password_hash,
                role, organization_id, status, created_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            data['email'],  # Use email as username
            data['email'],
            data['firstName'],
            data.get('lastName', ''),
            password_hash,  # For new password column
            password_hash,  # For existing password_hash column
            data.get('role', 'user'),
            data['organizationId'],
            data.get('status', 'ACTIVE'),
            datetime.now(timezone.utc).isoformat(),
            1  # is_active = true
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'userId': user_id
        }), 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_code': 'DATABASE_ERROR'
        }), 500

@user_management_bp.route('/users/<user_id>/downloads', methods=['POST'])
@require_auth
def track_agent_download():
    """Track when a user downloads an agent"""
    try:
        data = request.get_json()
        user_id = request.view_args['user_id']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Record the download
        download_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO agent_downloads (
                id, user_id, agent_type, platform, version, 
                download_timestamp, ip_address, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            download_id,
            user_id,
            data.get('agentType', 'endpoint'),
            data.get('platform', 'unknown'),
            data.get('version', '1.0.0'),
            datetime.now(timezone.utc).isoformat(),
            request.remote_addr,
            request.headers.get('User-Agent', '')
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Download tracked successfully',
            'downloadId': download_id
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_code': 'DATABASE_ERROR'
        }), 500

@user_management_bp.route('/users/<user_id>/agents', methods=['GET'])
@require_auth
def get_user_agents():
    """Get all agents for a specific user"""
    try:
        user_id = request.view_args['user_id']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                a.*,
                CASE 
                    WHEN a.last_heartbeat > datetime('now', '-5 minutes') THEN 'online'
                    WHEN a.last_heartbeat > datetime('now', '-1 hour') THEN 'idle'
                    ELSE 'offline'
                END as status,
                ad.download_timestamp
            FROM agents a
            LEFT JOIN agent_downloads ad ON a.user_id = ad.user_id 
                AND a.platform = ad.platform
            WHERE a.user_id = ?
            ORDER BY a.last_heartbeat DESC
        ''', (user_id,))
        
        agents = []
        for row in cursor.fetchall():
            agent = {
                'id': row['id'],
                'name': row['hostname'] or f"Agent-{row['id'][:8]}",
                'type': 'endpoint',  # All client agents are endpoint type
                'status': row['status'],
                'location': row['ip_address'] or 'Unknown',
                'lastActivity': row['last_heartbeat'],
                'platform': row['platform'],
                'capabilities': [
                    'Process Monitoring',
                    'File Monitoring', 
                    'Network Monitoring',
                    'Threat Detection',
                    'Log Collection'
                ],
                'downloadedAt': row['download_timestamp']
            }
            agents.append(agent)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'agents': agents,
            'total': len(agents)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_code': 'DATABASE_ERROR'
        }), 500

# Initialize required tables
def init_user_management_tables():
    """Initialize user management tables"""
    conn = sqlite3.connect(current_app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Users table (enhanced)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT,
            organization_id TEXT NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            created_at TEXT,
            last_login TEXT,
            created_by TEXT
        )
    ''')
    
    # Agent downloads tracking table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agent_downloads (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            agent_type TEXT NOT NULL,
            platform TEXT NOT NULL,
            version TEXT NOT NULL,
            download_timestamp TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Enhanced agents table with user tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            hostname TEXT,
            platform TEXT NOT NULL,
            ip_address TEXT,
            last_heartbeat TEXT,
            status TEXT DEFAULT 'offline',
            organization_id TEXT NOT NULL,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (organization_id) REFERENCES organizations (id)
        )
    ''')
    
    conn.commit()
    conn.close()
