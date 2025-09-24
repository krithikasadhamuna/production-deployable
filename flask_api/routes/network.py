"""
🌐 Network Topology APIs
Implements network topology and node management endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import uuid
from functools import wraps

network_bp = Blueprint('network', __name__)

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

@network_bp.route('/network/topology', methods=['GET'])
@require_auth
def get_network_topology():
    """
    GET /api/network/topology
    Query Parameters: ?hierarchy=true|false&include_agents=true|false&sort_order=asc|desc&sort_by=name|type|risk_level|agent_count
    """
    try:
        # Get query parameters
        hierarchy = request.args.get('hierarchy', 'true').lower() == 'true'
        include_agents = request.args.get('include_agents', 'true').lower() == 'true'
        sort_order = request.args.get('sort_order', 'asc')
        sort_by = request.args.get('sort_by', 'level')
        
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM network_topology ORDER BY level ASC, name ASC")
        nodes_raw = cursor.fetchall()
        conn.close()
        
        # If no nodes in DB, return sample data
        if not nodes_raw:
            topology = _get_sample_topology(include_agents)
        else:
            topology = []
            for node in nodes_raw:
                node_data = {
                    "id": node['id'],
                    "name": node['name'],
                    "type": node['type'],
                    "level": node['level'],
                    "parent_id": node['parent_id'],
                    "status": node['status'],
                    "risk_level": node['risk_level'],
                    "confidence": node['confidence'],
                    "characteristics": json.loads(node['characteristics']) if node['characteristics'] else {},
                    "security_zone": node['security_zone'],
                    "ip_ranges": json.loads(node['ip_ranges']) if node['ip_ranges'] else []
                }
                
                if include_agents:
                    node_data["agents"] = json.loads(node['agents']) if node['agents'] else []
                    node_data["agent_count"] = len(node_data["agents"])
                
                topology.append(node_data)
        
        # Apply sorting if requested
        if sort_by in ['name', 'type', 'risk_level', 'agent_count']:
            reverse_sort = sort_order.lower() == 'desc'
            if sort_by == 'agent_count' and include_agents:
                topology.sort(key=lambda x: x.get('agent_count', 0), reverse=reverse_sort)
            elif sort_by in ['name', 'type', 'risk_level']:
                topology.sort(key=lambda x: x.get(sort_by, ''), reverse=reverse_sort)
        
        return jsonify({
            "success": True,
            "topology": topology,
            "total_nodes": len(topology),
            "hierarchy_enabled": hierarchy,
            "last_updated": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@network_bp.route('/network/node/<node_id>', methods=['GET'])
@require_auth
def get_network_node(node_id):
    """
    GET /api/network/node/{node_id}
    Get specific network node details
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM network_topology WHERE id = ?", (node_id,))
        node = cursor.fetchone()
        conn.close()
        
        if not node:
            # Try to find in sample data
            sample_topology = _get_sample_topology(True)
            node_data = next((n for n in sample_topology if n['id'] == node_id), None)
            
            if not node_data:
                return jsonify({
                    "success": False,
                    "error": "Network node not found",
                    "error_code": "NODE_NOT_FOUND"
                }), 404
        else:
            node_data = {
                "id": node['id'],
                "name": node['name'],
                "type": node['type'],
                "level": node['level'],
                "parent_id": node['parent_id'],
                "agents": json.loads(node['agents']) if node['agents'] else [],
                "status": node['status'],
                "risk_level": node['risk_level'],
                "confidence": node['confidence'],
                "characteristics": json.loads(node['characteristics']) if node['characteristics'] else {},
                "security_zone": node['security_zone'],
                "ip_ranges": json.loads(node['ip_ranges']) if node['ip_ranges'] else []
            }
            node_data["agent_count"] = len(node_data["agents"])
        
        return jsonify({
            "success": True,
            "node": node_data
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@network_bp.route('/network/agents/<node_id>', methods=['GET'])
@require_auth
def get_network_agents(node_id):
    """
    GET /api/network/agents/{node_id}
    Get agents in a specific network node
    """
    try:
        conn = get_db_connection()
        
        # Get network node
        cursor = conn.execute("SELECT * FROM network_topology WHERE id = ?", (node_id,))
        node = cursor.fetchone()
        
        if not node:
            conn.close()
            return jsonify({
                "success": False,
                "error": "Network node not found",
                "error_code": "NODE_NOT_FOUND"
            }), 404
        
        # Get agents in this network element
        agent_ids = json.loads(node['agents']) if node['agents'] else []
        
        if agent_ids:
            placeholders = ','.join(['?'] * len(agent_ids))
            cursor = conn.execute(f"SELECT * FROM agents WHERE id IN ({placeholders})", agent_ids)
            agents_raw = cursor.fetchall()
        else:
            agents_raw = []
        
        conn.close()
        
        agents = []
        for agent in agents_raw:
            agent_data = {
                "id": agent['id'],
                "name": agent['name'],
                "type": agent['type'],
                "status": agent['status'],
                "ip_address": agent['ip_address'],
                "last_heartbeat": agent['last_heartbeat']
            }
            agents.append(agent_data)
        
        return jsonify({
            "success": True,
            "node_id": node_id,
            "node_name": node['name'],
            "agents": agents,
            "total": len(agents)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@network_bp.route('/network/summary', methods=['GET'])
@require_auth
def get_network_summary():
    """
    GET /api/network/summary
    Get network topology summary statistics
    """
    try:
        conn = get_db_connection()
        
        # Get network element counts
        cursor = conn.execute("SELECT type, COUNT(*) as count FROM network_topology GROUP BY type")
        element_counts = {row['type']: row['count'] for row in cursor.fetchall()}
        
        # Get security zone counts
        cursor = conn.execute("SELECT security_zone, COUNT(*) as count FROM network_topology GROUP BY security_zone")
        zone_counts = {row['security_zone']: row['count'] for row in cursor.fetchall()}
        
        # Get risk level distribution
        cursor = conn.execute("SELECT risk_level, COUNT(*) as count FROM network_topology GROUP BY risk_level")
        risk_counts = {row['risk_level']: row['count'] for row in cursor.fetchall()}
        
        # Get agent distribution
        cursor = conn.execute("SELECT network_element_type, COUNT(*) as count FROM agents WHERE network_element_type IS NOT NULL GROUP BY network_element_type")
        agent_dist = {row['network_element_type']: row['count'] for row in cursor.fetchall()}
        
        cursor = conn.execute("SELECT COUNT(*) as total FROM agents")
        total_agents = cursor.fetchone()['total']
        
        cursor = conn.execute("SELECT COUNT(*) as total FROM network_topology")
        total_elements = cursor.fetchone()['total']
        
        conn.close()
        
        # If no data in DB, return sample summary
        if total_elements == 0:
            return jsonify({
                "success": True,
                "summary": _get_sample_summary()
            })
        
        return jsonify({
            "success": True,
            "summary": {
                "total_network_elements": total_elements,
                "element_breakdown": element_counts,
                "security_zones": zone_counts,
                "risk_distribution": risk_counts,
                "agent_distribution": {
                    "total_agents": total_agents,
                    "by_element": agent_dist
                }
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

# Helper functions
def _get_sample_topology(include_agents=True):
    """Return sample network topology"""
    topology = [
        {
            "id": "internet",
            "name": "Internet",
            "type": "gateway",
            "level": 0,
            "parent_id": None,
            "status": "normal",
            "risk_level": "medium",
            "confidence": 0.95,
            "characteristics": {
                "ip_ranges": ["0.0.0.0/0"],
                "services": ["external_access"],
                "security_zone": "untrusted"
            },
            "security_zone": "untrusted",
            "ip_ranges": ["0.0.0.0/0"],
            "children": ["dmz", "firewall"]
        },
        {
            "id": "firewall",
            "name": "Corporate Firewall",
            "type": "security_device",
            "level": 1,
            "parent_id": "internet",
            "status": "normal",
            "risk_level": "low",
            "confidence": 0.98,
            "characteristics": {
                "ip_ranges": ["192.168.1.1/32"],
                "services": ["firewall", "nat"],
                "security_zone": "perimeter"
            },
            "security_zone": "perimeter",
            "ip_ranges": ["192.168.1.1/32"]
        },
        {
            "id": "dmz",
            "name": "DMZ Segment",
            "type": "network_segment",
            "level": 2,
            "parent_id": "firewall",
            "status": "normal",
            "risk_level": "high",
            "confidence": 0.88,
            "characteristics": {
                "ip_ranges": ["192.168.100.0/24"],
                "services": ["web_server", "mail_server"],
                "security_zone": "dmz"
            },
            "security_zone": "dmz",
            "ip_ranges": ["192.168.100.0/24"]
        }
    ]
    
    if include_agents:
        topology[0]["agents"] = [{"id": "phantom-ai-01", "name": "PhantomStrike AI", "type": "attack", "status": "idle"}]
        topology[0]["agent_count"] = 1
        topology[1]["agents"] = [{"id": "fw-agent-01", "name": "Firewall Monitor", "type": "detection", "status": "active"}]
        topology[1]["agent_count"] = 1
        topology[2]["agents"] = [{"id": "dmz-agent-01", "name": "DMZ Monitor", "type": "detection", "status": "active"}]
        topology[2]["agent_count"] = 1
    
    return topology

def _get_sample_summary():
    """Return sample network summary"""
    return {
        "total_network_elements": 8,
        "element_breakdown": {
            "internet": 1,
            "firewall": 1,
            "dmz": 1,
            "internal_network": 2,
            "endpoints": 2,
            "soc": 1
        },
        "security_zones": {
            "untrusted": 1,
            "dmz": 1,
            "trusted": 4,
            "secure": 2
        },
        "risk_distribution": {
            "critical": 0,
            "high": 2,
            "medium": 4,
            "low": 2
        },
        "agent_distribution": {
            "total_agents": 15,
            "by_element": {
                "endpoints": 8,
                "firewall": 2,
                "dmz": 2,
                "soc": 3
            }
        }
    }

