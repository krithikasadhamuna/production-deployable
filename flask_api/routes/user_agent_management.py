"""
User and Client Agent Management API Routes
Handles user creation, agent downloads, and tracking
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone, timedelta
import json
import sqlite3
import uuid
import hashlib
import secrets
from functools import wraps

user_agent_bp = Blueprint('user_agent', __name__)

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(current_app.config.get('DATABASE', 'soc_database.db'))
    conn.row_factory = sqlite3.Row
    return conn

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'Missing or invalid Authorization header'
            }), 401
        
        token = auth_header.split(' ')[1]
        # Validate token (simplified for demo)
        VALID_API_KEYS = {
            "soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs": "admin",
            "soc-frontend-2024": "frontend"
        }
        
        if token not in VALID_API_KEYS:
            return jsonify({
                'success': False,
                'error': 'Invalid API token'
            }), 401
            
        return f(*args, **kwargs)
    return decorated_function

def generate_api_key(prefix="usr"):
    """Generate a unique API key"""
    return f"{prefix}-{secrets.token_urlsafe(32)}"

def calculate_time_ago(timestamp):
    """Calculate human-readable time difference"""
    if not timestamp:
        return "Never"
    
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = timestamp
        
        now = datetime.now(timezone.utc)
        diff = now - dt
        
        if diff.total_seconds() < 60:
            return "Just now"
        elif diff.total_seconds() < 3600:
            mins = int(diff.total_seconds() / 60)
            return f"{mins} min{'s' if mins > 1 else ''} ago"
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() / 3600)
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        else:
            days = int(diff.total_seconds() / 86400)
            return f"{days} day{'s' if days > 1 else ''} ago"
    except:
        return "Unknown"

# ============= USER MANAGEMENT =============

@user_agent_bp.route('/users/create', methods=['POST'])
@require_auth
def create_user():
    """Create a new user with auto-generated API key"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required = ['email', 'firstName', 'role', 'organizationId']
        for field in required:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Generate IDs and keys
        user_id = f"user-{uuid.uuid4().hex[:8]}"
        api_key = generate_api_key("usr")
        
        # Hash password if provided
        password_hash = None
        if 'password' in data:
            password_hash = hashlib.sha256(data['password'].encode()).hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert user
        cursor.execute("""
            INSERT INTO users (
                id, email, first_name, last_name, api_key,
                organization_id, role, password_hash, created_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            data['email'],
            data['firstName'],
            data.get('lastName', ''),
            api_key,
            data['organizationId'],
            data['role'],
            password_hash,
            datetime.now(timezone.utc).isoformat(),
            'active'
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'userId': user_id,
            'apiKey': api_key,
            'message': 'User created successfully'
        })
        
    except sqlite3.IntegrityError as e:
        return jsonify({
            'success': False,
            'error': 'Email already exists'
        }), 409
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@user_agent_bp.route('/users/list', methods=['GET'])
@require_auth
def list_users():
    """List all users with optional agent statistics"""
    try:
        include_stats = request.args.get('includeAgentStats', 'false').lower() == 'true'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get users
        cursor.execute("""
            SELECT id, email, first_name, last_name, role, 
                   created_at, last_login, status, organization_id
            FROM users
            ORDER BY created_at DESC
        """)
        users = cursor.fetchall()
        
        user_list = []
        for user in users:
            user_data = {
                'id': user['id'],
                'email': user['email'],
                'firstName': user['first_name'],
                'lastName': user['last_name'],
                'role': user['role'],
                'createdAt': user['created_at'],
                'lastLogin': user['last_login'],
                'status': user['status'],
                'organizationId': user['organization_id']
            }
            
            if include_stats:
                # Get agent statistics
                cursor.execute("""
                    SELECT COUNT(*) as total,
                           SUM(CASE WHEN platform = 'windows' THEN 1 ELSE 0 END) as windows,
                           SUM(CASE WHEN platform = 'linux' THEN 1 ELSE 0 END) as linux,
                           SUM(CASE WHEN platform = 'macos' THEN 1 ELSE 0 END) as macos
                    FROM agent_downloads
                    WHERE user_id = ?
                """, (user['id'],))
                
                stats = cursor.fetchone()
                
                # Get active agents
                cursor.execute("""
                    SELECT COUNT(*) as active
                    FROM agents
                    WHERE user_id = ? AND status = 'online'
                """, (user['id'],))
                
                active = cursor.fetchone()
                
                user_data['agentStats'] = {
                    'totalDownloads': stats['total'] or 0,
                    'activeAgents': active['active'] or 0,
                    'platforms': {
                        'windows': stats['windows'] or 0,
                        'linux': stats['linux'] or 0,
                        'macos': stats['macos'] or 0
                    }
                }
            
            user_list.append(user_data)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'users': user_list,
            'total': len(user_list)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============= AGENT DOWNLOAD TRACKING =============

@user_agent_bp.route('/agents/track-download', methods=['POST'])
@require_auth
def track_agent_download():
    """Track when a user downloads a client agent"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required = ['userId', 'platform', 'version']
        for field in required:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Generate IDs
        download_id = f"dl-{uuid.uuid4().hex[:8]}"
        agent_id = f"agent-{uuid.uuid4().hex[:8]}"
        installation_key = generate_api_key("inst")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Record download
        cursor.execute("""
            INSERT INTO agent_downloads (
                id, user_id, agent_id, platform, version,
                download_timestamp, installation_key, ip_address
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            download_id,
            data['userId'],
            agent_id,
            data['platform'],
            data['version'],
            datetime.now(timezone.utc).isoformat(),
            installation_key,
            request.remote_addr
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'downloadId': download_id,
            'agentId': agent_id,
            'installationKey': installation_key,
            'message': 'Download tracked, agent ID assigned'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@user_agent_bp.route('/users/<user_id>/agents', methods=['GET'])
@require_auth
def get_user_agents(user_id):
    """Get all agents downloaded/managed by a user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get downloaded agents with their current status
        cursor.execute("""
            SELECT 
                ad.id as download_id,
                ad.agent_id,
                ad.platform,
                ad.version,
                ad.download_timestamp,
                a.name as hostname,
                a.status,
                a.ip_address,
                a.last_heartbeat
            FROM agent_downloads ad
            LEFT JOIN agents a ON ad.agent_id = a.id
            WHERE ad.user_id = ?
            ORDER BY ad.download_timestamp DESC
        """, (user_id,))
        
        downloads = cursor.fetchall()
        
        agents = []
        for dl in downloads:
            agents.append({
                'id': dl['agent_id'],
                'downloadId': dl['download_id'],
                'platform': dl['platform'],
                'version': dl['version'],
                'downloadedAt': dl['download_timestamp'],
                'status': dl['status'] or 'not_installed',
                'lastHeartbeat': dl['last_heartbeat'],
                'hostname': dl['hostname'],
                'ipAddress': dl['ip_address']
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'userId': user_id,
            'agents': agents,
            'total': len(agents)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============= CLIENT AGENT LISTING =============

@user_agent_bp.route('/agents/list', methods=['GET'])
@require_auth
def list_client_agents():
    """List all client agents in tabular format"""
    try:
        # Get query parameters
        format_type = request.args.get('format', 'table')
        sort_by = request.args.get('sort', 'status')
        order = request.args.get('order', 'desc')
        filter_status = request.args.get('filter', 'all')
        user_id = request.args.get('userId')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build query
        query = """
            SELECT 
                a.id,
                a.name,
                a.type,
                a.platform,
                a.status,
                a.ip_address,
                a.location,
                a.zone,
                a.last_heartbeat,
                a.version,
                a.capabilities,
                a.metrics,
                a.user_id,
                u.first_name || ' ' || u.last_name as user_name
            FROM agents a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE a.type = 'endpoint'
        """
        
        params = []
        
        if filter_status != 'all':
            query += " AND a.status = ?"
            params.append(filter_status)
        
        if user_id:
            query += " AND a.user_id = ?"
            params.append(user_id)
        
        # Add sorting
        sort_column = {
            'name': 'a.name',
            'status': 'a.status',
            'lastActivity': 'a.last_heartbeat',
            'type': 'a.type',
            'location': 'a.ip_address'
        }.get(sort_by, 'a.status')
        
        query += f" ORDER BY {sort_column} {order.upper()}"
        
        cursor.execute(query, params)
        agents = cursor.fetchall()
        
        # Count totals
        cursor.execute("SELECT COUNT(*) as total FROM agents WHERE type = 'endpoint'")
        total = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as online FROM agents WHERE type = 'endpoint' AND status = 'online'")
        online = cursor.fetchone()['online']
        
        agent_list = []
        for agent in agents:
            # Parse capabilities and metrics
            capabilities = json.loads(agent['capabilities']) if agent['capabilities'] else [
                "Log Collection",
                "Command Execution",
                "File Monitoring",
                "Process Monitoring"
            ]
            
            metrics = json.loads(agent['metrics']) if agent['metrics'] else {
                "cpuUsage": 0,
                "memoryUsage": 0,
                "diskUsage": 0,
                "eventsPerMinute": 0
            }
            
            agent_data = {
                'id': agent['id'],
                'name': agent['name'] or 'Unknown',
                'type': 'endpoint',
                'platform': agent['platform'] or 'unknown',
                'status': agent['status'] or 'offline',
                'location': agent['ip_address'] or 'Unknown',
                'zone': agent['zone'] or 'Unknown',
                'lastActivity': calculate_time_ago(agent['last_heartbeat']),
                'lastHeartbeat': agent['last_heartbeat'],
                'userId': agent['user_id'],
                'userName': agent['user_name'] or 'System',
                'version': agent['version'] or '1.0.0',
                'capabilities': capabilities,
                'metrics': metrics
            }
            
            agent_list.append(agent_data)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'totalAgents': total,
            'onlineAgents': online,
            'agents': agent_list
        })
        
    except Exception as e:
        current_app.logger.error(f"Error listing agents: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============= NETWORK TOPOLOGY =============

@user_agent_bp.route('/network/topology', methods=['GET'])
@require_auth
def get_network_topology():
    """Get network topology in tabular format"""
    try:
        format_type = request.args.get('format', 'table')
        hierarchy = request.args.get('hierarchy', 'true').lower() == 'true'
        sort_by = request.args.get('sort', 'level')
        order = request.args.get('order', 'asc')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get topology nodes
        query = """
            SELECT 
                id, name, type, level, parent_id,
                agents, status, zone, ip_ranges
            FROM network_topology
        """
        
        if hierarchy:
            query += " ORDER BY level ASC, name ASC"
        else:
            sort_column = {
                'name': 'name',
                'type': 'type',
                'agents': 'agents',
                'status': 'status'
            }.get(sort_by, 'level')
            query += f" ORDER BY {sort_column} {order.upper()}"
        
        cursor.execute(query)
        nodes = cursor.fetchall()
        
        topology = []
        for node in nodes:
            # Parse agent list
            agent_ids = json.loads(node['agents']) if node['agents'] else []
            
            topology_node = {
                'id': node['id'],
                'name': node['name'],
                'type': node['type'],
                'level': node['level'] or 0,
                'parentId': node['parent_id'],
                'agentCount': len(agent_ids),
                'agents': agent_ids,
                'status': node['status'] or 'normal',
                'zone': node['zone'] or 'Unknown',
                'ipRange': node['ip_ranges'] or 'N/A'
            }
            
            topology.append(topology_node)
        
        # If no topology exists, create default
        if not topology:
            topology = create_default_topology(conn)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'topology': topology,
            'total': len(topology)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@user_agent_bp.route('/network/topology-detailed', methods=['GET'])
@require_auth
def get_detailed_topology():
    """Get network topology with agent details"""
    try:
        include_agents = request.args.get('includeAgents', 'false').lower() == 'true'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get topology nodes
        cursor.execute("""
            SELECT 
                id, name, type, level, parent_id,
                agents, status, zone, ip_ranges,
                x_position, y_position
            FROM network_topology
            ORDER BY level ASC
        """)
        
        nodes = cursor.fetchall()
        
        node_list = []
        for node in nodes:
            agent_ids = json.loads(node['agents']) if node['agents'] else []
            
            node_data = {
                'id': node['id'],
                'name': node['name'],
                'type': node['type'],
                'level': node['level'] or 0,
                'x': node['x_position'] or 50,
                'y': node['y_position'] or (10 + node['level'] * 30),
                'agents': [],
                'status': node['status'] or 'normal',
                'metrics': {
                    'totalTraffic': '0GB',
                    'threats': 0,
                    'connections': 0
                }
            }
            
            if include_agents and agent_ids:
                # Get agent details
                placeholders = ','.join(['?' for _ in agent_ids])
                cursor.execute(f"""
                    SELECT id, name, status, platform
                    FROM agents
                    WHERE id IN ({placeholders})
                """, agent_ids)
                
                agents = cursor.fetchall()
                for agent in agents:
                    node_data['agents'].append({
                        'id': agent['id'],
                        'name': agent['name'],
                        'status': agent['status'],
                        'platform': agent['platform']
                    })
            
            node_list.append(node_data)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'nodes': node_list,
            'total': len(node_list)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def create_default_topology(conn):
    """Create default network topology structure"""
    default_nodes = [
        {
            'id': 'node-internet',
            'name': 'Internet Gateway',
            'type': 'gateway',
            'level': 0,
            'parentId': None,
            'agentCount': 0,
            'agents': [],
            'status': 'normal',
            'zone': 'External',
            'ipRange': '0.0.0.0/0'
        },
        {
            'id': 'node-firewall',
            'name': 'Main Firewall',
            'type': 'firewall',
            'level': 1,
            'parentId': 'node-internet',
            'agentCount': 0,
            'agents': [],
            'status': 'normal',
            'zone': 'Perimeter',
            'ipRange': '203.0.113.0/24'
        },
        {
            'id': 'node-dmz',
            'name': 'DMZ Network',
            'type': 'network',
            'level': 2,
            'parentId': 'node-firewall',
            'agentCount': 0,
            'agents': [],
            'status': 'normal',
            'zone': 'DMZ',
            'ipRange': '10.0.1.0/24'
        },
        {
            'id': 'node-internal',
            'name': 'Corporate Network',
            'type': 'network',
            'level': 2,
            'parentId': 'node-firewall',
            'agentCount': 0,
            'agents': [],
            'status': 'normal',
            'zone': 'Internal',
            'ipRange': '192.168.0.0/16'
        }
    ]
    
    # Save to database
    cursor = conn.cursor()
    for node in default_nodes:
        cursor.execute("""
            INSERT OR IGNORE INTO network_topology (
                id, name, type, level, parent_id,
                agents, status, zone, ip_ranges
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            node['id'],
            node['name'],
            node['type'],
            node['level'],
            node['parentId'],
            json.dumps(node['agents']),
            node['status'],
            node['zone'],
            node['ipRange']
        ))
    conn.commit()
    
    return default_nodes

