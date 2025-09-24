"""
Network Topology APIs
Network topology visualization with real-time agent status
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone, timedelta
import sqlite3
import json
import ipaddress
from collections import defaultdict
from functools import wraps

network_topology_bp = Blueprint('network_topology', __name__)

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

def determine_network_zone(ip_address):
    """Determine network zone based on IP address"""
    if not ip_address:
        return 'Unknown'
    
    try:
        ip = ipaddress.ip_address(ip_address)
        
        # Private networks
        if ip.is_private:
            if ip in ipaddress.ip_network('10.0.0.0/8'):
                return 'Internal Network (10.x.x.x)'
            elif ip in ipaddress.ip_network('172.16.0.0/12'):
                return 'Internal Network (172.x.x.x)'
            elif ip in ipaddress.ip_network('192.168.0.0/16'):
                return 'Internal Network (192.168.x.x)'
            else:
                return 'Private Network'
        
        # Public networks
        elif ip.is_global:
            return 'External Network'
        
        # Loopback
        elif ip.is_loopback:
            return 'Localhost'
        
        else:
            return 'Unknown Network'
            
    except:
        return 'Invalid IP'

def calculate_node_position(network_zone, index, total_in_zone):
    """Calculate x,y position for network nodes"""
    zone_positions = {
        'External Network': {'base_x': 50, 'base_y': 50},
        'DMZ': {'base_x': 200, 'base_y': 100},
        'Internal Network (192.168.x.x)': {'base_x': 350, 'base_y': 150},
        'Internal Network (10.x.x.x)': {'base_x': 350, 'base_y': 200},
        'Internal Network (172.x.x.x)': {'base_x': 350, 'base_y': 250},
        'Private Network': {'base_x': 350, 'base_y': 300},
        'Localhost': {'base_x': 500, 'base_y': 200},
        'Unknown Network': {'base_x': 100, 'base_y': 400}
    }
    
    base_pos = zone_positions.get(network_zone, {'base_x': 200, 'base_y': 300})
    
    # Spread nodes within the zone
    if total_in_zone > 1:
        x_offset = (index % 5) * 40  # 5 nodes per row
        y_offset = (index // 5) * 30  # New row every 5 nodes
    else:
        x_offset = 0
        y_offset = 0
    
    return {
        'x': base_pos['base_x'] + x_offset,
        'y': base_pos['base_y'] + y_offset
    }

@network_topology_bp.route('/network/topology', methods=['GET'])
@require_auth
def get_network_topology():
    """Get network topology with agent status"""
    try:
        # Get query parameters
        hierarchy = request.args.get('hierarchy', 'asc')  # asc or desc
        organization_id = request.args.get('organization_id')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Base query for agents with status
        base_query = '''
            SELECT 
                a.id,
                a.hostname,
                a.platform,
                a.ip_address,
                a.last_heartbeat,
                a.organization_id,
                u.first_name,
                u.last_name,
                u.email,
                CASE 
                    WHEN a.last_heartbeat > datetime('now', '-2 minutes') THEN 'online'
                    WHEN a.last_heartbeat > datetime('now', '-10 minutes') THEN 'idle'
                    WHEN a.last_heartbeat > datetime('now', '-1 hour') THEN 'warning'
                    ELSE 'offline'
                END as status,
                CASE 
                    WHEN a.last_heartbeat > datetime('now', '-2 minutes') THEN 'normal'
                    WHEN a.last_heartbeat > datetime('now', '-10 minutes') THEN 'warning'
                    ELSE 'critical'
                END as health_status
            FROM agents a
            LEFT JOIN users u ON a.user_id = u.id
        '''
        
        # Add organization filter if provided
        if organization_id:
            base_query += ' WHERE a.organization_id = ?'
            cursor.execute(base_query, (organization_id,))
        else:
            cursor.execute(base_query)
        
        agents_data = cursor.fetchall()
        
        # Group agents by network zone
        network_zones = defaultdict(list)
        
        for agent in agents_data:
            network_zone = determine_network_zone(agent['ip_address'])
            
            agent_info = {
                'id': agent['id'],
                'name': agent['hostname'] or f"Agent-{agent['id'][:8]}",
                'type': 'endpoint',
                'status': agent['status'],
                'location': network_zone,
                'lastActivity': agent['last_heartbeat'] or 'Never',
                'ip_address': agent['ip_address'],
                'platform': agent['platform'],
                'user': {
                    'name': f"{agent['first_name']} {agent['last_name']}" if agent['first_name'] else 'Unknown',
                    'email': agent['email']
                },
                'capabilities': [
                    'Process Monitoring',
                    'File Monitoring', 
                    'Network Monitoring',
                    'System Monitoring',
                    'Log Collection'
                ]
            }
            
            network_zones[network_zone].append(agent_info)
        
        # Create network nodes structure
        network_nodes = []
        
        # Sort zones by hierarchy
        sorted_zones = sorted(network_zones.keys())
        if hierarchy == 'desc':
            sorted_zones.reverse()
        
        node_id = 1
        for zone_name in sorted_zones:
            zone_agents = network_zones[zone_name]
            
            # Calculate positions for agents in this zone
            for i, agent in enumerate(zone_agents):
                position = calculate_node_position(zone_name, i, len(zone_agents))
                
                node = {
                    'id': f'node-{node_id}',
                    'name': agent['name'],
                    'type': 'agent',
                    'x': position['x'],
                    'y': position['y'],
                    'agents': [agent],  # Single agent per node
                    'status': agent['status'],
                    'zone': zone_name,
                    'ip_address': agent['ip_address'],
                    'platform': agent['platform'],
                    'lastActivity': agent['lastActivity']
                }
                
                network_nodes.append(node)
                node_id += 1
        
        # Add gateway/internet node
        internet_node = {
            'id': 'internet',
            'name': 'Internet Gateway',
            'type': 'gateway',
            'x': 10,
            'y': 20,
            'agents': [],
            'status': 'normal',
            'zone': 'External',
            'description': 'External network gateway'
        }
        
        # Get topology summary
        total_agents = len(agents_data)
        online_agents = len([a for a in agents_data if a['status'] == 'online'])
        offline_agents = len([a for a in agents_data if a['status'] == 'offline'])
        
        topology_summary = {
            'total_nodes': len(network_nodes) + 1,  # +1 for internet node
            'total_agents': total_agents,
            'online_agents': online_agents,
            'offline_agents': offline_agents,
            'network_zones': len(network_zones),
            'last_updated': datetime.now(timezone.utc).isoformat()
        }
        
        conn.close()
        
        return jsonify({
            'success': True,
            'topology': {
                'nodes': [internet_node] + network_nodes,
                'summary': topology_summary,
                'hierarchy': hierarchy
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_code': 'TOPOLOGY_ERROR'
        }), 500

@network_topology_bp.route('/network/agents', methods=['GET'])
@require_auth
def get_network_agents():
    """Get agents list in tabular format with filtering and sorting"""
    try:
        # Get query parameters
        status_filter = request.args.get('status')  # online, offline, idle, warning
        platform_filter = request.args.get('platform')  # windows, linux, macos
        organization_id = request.args.get('organization_id')
        sort_by = request.args.get('sort_by', 'lastActivity')  # name, status, lastActivity, platform
        sort_order = request.args.get('sort_order', 'desc')  # asc, desc
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 50))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build query with filters
        query = '''
            SELECT 
                a.id,
                a.hostname,
                a.platform,
                a.ip_address,
                a.last_heartbeat,
                a.created_at,
                u.first_name,
                u.last_name,
                u.email,
                o.name as organization_name,
                CASE 
                    WHEN a.last_heartbeat > datetime('now', '-2 minutes') THEN 'online'
                    WHEN a.last_heartbeat > datetime('now', '-10 minutes') THEN 'idle'
                    WHEN a.last_heartbeat > datetime('now', '-1 hour') THEN 'warning'
                    ELSE 'offline'
                END as status
            FROM agents a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN organizations o ON a.organization_id = o.id
            WHERE 1=1
        '''
        
        params = []
        
        # Apply filters
        if status_filter:
            if status_filter == 'online':
                query += " AND a.last_heartbeat > datetime('now', '-2 minutes')"
            elif status_filter == 'idle':
                query += " AND a.last_heartbeat BETWEEN datetime('now', '-10 minutes') AND datetime('now', '-2 minutes')"
            elif status_filter == 'warning':
                query += " AND a.last_heartbeat BETWEEN datetime('now', '-1 hour') AND datetime('now', '-10 minutes')"
            elif status_filter == 'offline':
                query += " AND (a.last_heartbeat IS NULL OR a.last_heartbeat < datetime('now', '-1 hour'))"
        
        if platform_filter:
            query += " AND LOWER(a.platform) = LOWER(?)"
            params.append(platform_filter)
        
        if organization_id:
            query += " AND a.organization_id = ?"
            params.append(organization_id)
        
        # Apply sorting
        sort_mapping = {
            'name': 'a.hostname',
            'status': 'status',
            'lastActivity': 'a.last_heartbeat',
            'platform': 'a.platform',
            'user': 'u.first_name'
        }
        
        sort_column = sort_mapping.get(sort_by, 'a.last_heartbeat')
        sort_direction = 'ASC' if sort_order == 'asc' else 'DESC'
        query += f" ORDER BY {sort_column} {sort_direction}"
        
        # Apply pagination
        offset = (page - 1) * limit
        query += f" LIMIT {limit} OFFSET {offset}"
        
        cursor.execute(query, params)
        agents_data = cursor.fetchall()
        
        # Format agents for frontend
        agents = []
        for agent in agents_data:
            agent_obj = {
                'id': agent['id'],
                'name': agent['hostname'] or f"Agent-{agent['id'][:8]}",
                'type': 'endpoint',
                'status': agent['status'],
                'location': determine_network_zone(agent['ip_address']),
                'lastActivity': agent['last_heartbeat'] or 'Never',
                'platform': agent['platform'],
                'ip_address': agent['ip_address'],
                'user': {
                    'name': f"{agent['first_name']} {agent['last_name']}" if agent['first_name'] else 'Unknown',
                    'email': agent['email']
                },
                'organization': agent['organization_name'],
                'capabilities': [
                    'Process Monitoring',
                    'File Monitoring', 
                    'Network Monitoring',
                    'System Monitoring',
                    'Log Collection'
                ],
                'createdAt': agent['created_at']
            }
            agents.append(agent_obj)
        
        # Get total count for pagination
        count_query = query.split('ORDER BY')[0].replace('SELECT a.id, a.hostname, a.platform, a.ip_address, a.last_heartbeat, a.created_at, u.first_name, u.last_name, u.email, o.name as organization_name,', 'SELECT COUNT(*) as total,').split('CASE')[0]
        cursor.execute(count_query, params[:-2] if len(params) > 2 else params)
        total_count = cursor.fetchone()['total'] if cursor.fetchone() else 0
        
        conn.close()
        
        return jsonify({
            'success': True,
            'agents': agents,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_count,
                'pages': (total_count + limit - 1) // limit
            },
            'filters': {
                'status': status_filter,
                'platform': platform_filter,
                'sort_by': sort_by,
                'sort_order': sort_order
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_code': 'AGENTS_ERROR'
        }), 500

@network_topology_bp.route('/network/zones', methods=['GET'])
@require_auth
def get_network_zones():
    """Get network zones summary"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                a.ip_address,
                COUNT(*) as agent_count,
                SUM(CASE WHEN a.last_heartbeat > datetime('now', '-2 minutes') THEN 1 ELSE 0 END) as online_count,
                SUM(CASE WHEN a.last_heartbeat <= datetime('now', '-1 hour') OR a.last_heartbeat IS NULL THEN 1 ELSE 0 END) as offline_count
            FROM agents a
            GROUP BY a.ip_address
        ''')
        
        zones_data = cursor.fetchall()
        zones = defaultdict(lambda: {'total': 0, 'online': 0, 'offline': 0})
        
        for zone_data in zones_data:
            zone_name = determine_network_zone(zone_data['ip_address'])
            zones[zone_name]['total'] += zone_data['agent_count']
            zones[zone_name]['online'] += zone_data['online_count']
            zones[zone_name]['offline'] += zone_data['offline_count']
        
        zones_list = []
        for zone_name, stats in zones.items():
            zones_list.append({
                'name': zone_name,
                'total_agents': stats['total'],
                'online_agents': stats['online'],
                'offline_agents': stats['offline'],
                'health_percentage': (stats['online'] / stats['total'] * 100) if stats['total'] > 0 else 0
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'zones': zones_list,
            'total_zones': len(zones_list)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'error_code': 'ZONES_ERROR'
        }), 500
