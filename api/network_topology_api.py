#!/usr/bin/env python3
"""
Network Topology API - Tabular Structure
Provides network hierarchy in table-friendly format
"""

from flask import Blueprint, jsonify, request, g
import sys
import os
import json
from datetime import datetime, timedelta

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.multi_tenant_agent_manager import multi_tenant_agent_manager

network_bp = Blueprint('network', __name__)

def get_network_hierarchy(tenant_context, sort_order='hierarchy'):
    """
    Get network structure in tabular format using detected network elements
    sort_order: 'hierarchy' (parent->child) or 'desc' (reverse)
    """
    try:
        # Get all agents for tenant with network element data
        agents = multi_tenant_agent_manager.get_agents(tenant_context)
        
        # Group agents by their detected network element type
        elements_by_type = {}
        for agent in agents:
            element_type = agent.get('network_element_type', 'endpoint')
            if element_type not in elements_by_type:
                elements_by_type[element_type] = []
            elements_by_type[element_type].append(agent)
        
        # Build network nodes structure based on detected elements
        network_nodes = []
        
        # 1. Internet/External elements (Level 0)
        internet_agents = elements_by_type.get('internet', []) + elements_by_type.get('cloud', [])
        if internet_agents or True:  # Always show internet gateway
            network_nodes.append({
                "id": "internet",
                "name": "Internet Gateway",
                "type": "gateway", 
                "level": 0,
                "parent_id": None,
                "subnet": "0.0.0.0/0",
                "agent_count": len(internet_agents),
                "agents": internet_agents,
                "status": "normal" if internet_agents else "unknown",
                "risk_level": "high",
                "last_seen": max([a.get('lastActivity', '') for a in internet_agents] + [datetime.now().isoformat()]),
                "description": "External network access point",
                "security_zone": "external",
                "avg_confidence": sum([a.get('element_confidence', 0.5) for a in internet_agents]) / max(len(internet_agents), 1)
            })
        
        # 2. DMZ elements (Level 1)
        dmz_agents = elements_by_type.get('dmz', [])
        if dmz_agents:
            network_nodes.append({
                "id": "dmz",
                "name": "DMZ",
                "type": "dmz",
                "level": 1,
                "parent_id": "internet",
                "subnet": dmz_agents[0].get('subnet', '10.0.0.0/24') if dmz_agents else "10.0.0.0/24",
                "agent_count": len(dmz_agents),
                "agents": dmz_agents,
                "status": "normal",
                "risk_level": "medium",
                "last_seen": max([a.get('lastActivity', '') for a in dmz_agents] + [datetime.now().isoformat()]),
                "description": "Demilitarized zone - Public-facing services",
                "security_zone": "dmz",
                "avg_confidence": sum([a.get('element_confidence', 0.5) for a in dmz_agents]) / len(dmz_agents)
            })
        
        # 3. Firewall elements (Level 1)
        firewall_agents = elements_by_type.get('firewall', [])
        network_nodes.append({
            "id": "firewall",
            "name": "Firewall",
            "type": "security",
            "level": 1,
            "parent_id": "internet",
            "subnet": firewall_agents[0].get('subnet', '10.1.0.0/24') if firewall_agents else "10.1.0.0/24",
            "agent_count": len(firewall_agents),
            "agents": firewall_agents,
            "status": "active" if firewall_agents else "missing",
            "risk_level": "critical" if not firewall_agents else "low",
            "last_seen": max([a.get('lastActivity', '') for a in firewall_agents] + ['Never']),
            "description": "Network security boundary",
            "security_zone": "perimeter",
            "avg_confidence": sum([a.get('element_confidence', 0.5) for a in firewall_agents]) / max(len(firewall_agents), 1)
        })
        
        # 4. SOC Infrastructure (Level 2)
        soc_agents = elements_by_type.get('soc', [])
        if soc_agents:
            network_nodes.append({
                "id": "soc",
                "name": "SOC Infrastructure",
                "type": "soc",
                "level": 2,
                "parent_id": "firewall",
                "subnet": soc_agents[0].get('subnet', '10.10.0.0/24') if soc_agents else "10.10.0.0/24",
                "agent_count": len(soc_agents),
                "agents": soc_agents,
                "status": "active",
                "risk_level": "low",
                "last_seen": max([a.get('lastActivity', '') for a in soc_agents] + [datetime.now().isoformat()]),
                "description": "Security operations center",
                "security_zone": "secure",
                "avg_confidence": sum([a.get('element_confidence', 0.5) for a in soc_agents]) / len(soc_agents)
            })
        
        # 5. Data Center (Level 2)
        datacenter_agents = elements_by_type.get('datacenter', []) + elements_by_type.get('domain_controller', [])
        if datacenter_agents:
            network_nodes.append({
                "id": "datacenter",
                "name": "Data Center",
                "type": "datacenter",
                "level": 2,
                "parent_id": "firewall",
                "subnet": datacenter_agents[0].get('subnet', '172.16.0.0/24') if datacenter_agents else "172.16.0.0/24",
                "agent_count": len(datacenter_agents),
                "agents": datacenter_agents,
                "status": "normal",
                "risk_level": "medium",
                "last_seen": max([a.get('lastActivity', '') for a in datacenter_agents] + [datetime.now().isoformat()]),
                "description": "Core server infrastructure",
                "security_zone": "secure",
                "avg_confidence": sum([a.get('element_confidence', 0.5) for a in datacenter_agents]) / len(datacenter_agents)
            })
        
        # 6. Internal Network (Level 2) - General internal systems
        internal_agents = [a for a in agents if a.get('network_element_type') == 'internal' or 
                          (a.get('security_zone') == 'internal' and a.get('network_element_type') not in ['endpoint', 'soc', 'datacenter'])]
        if internal_agents:
            network_nodes.append({
                "id": "internal",
                "name": "Internal Network",
                "type": "network",
                "level": 2,
                "parent_id": "firewall",
                "subnet": internal_agents[0].get('subnet', '192.168.1.0/24') if internal_agents else "192.168.1.0/24",
                "agent_count": len(internal_agents),
                "agents": internal_agents,
                "status": "normal",
                "risk_level": "low",
                "last_seen": max([a.get('lastActivity', '') for a in internal_agents] + [datetime.now().isoformat()]),
                "description": "Corporate internal network",
                "security_zone": "internal",
                "avg_confidence": sum([a.get('element_confidence', 0.5) for a in internal_agents]) / len(internal_agents)
            })
        
        # 7. Endpoints (Level 3)
        endpoint_agents = elements_by_type.get('endpoint', []) + elements_by_type.get('workstation', [])
        if endpoint_agents:
            # Group endpoints by subnet for better organization
            endpoint_subnets = {}
            for agent in endpoint_agents:
                subnet = agent.get('subnet', '192.168.1.0/24')
                if subnet not in endpoint_subnets:
                    endpoint_subnets[subnet] = []
                endpoint_subnets[subnet].append(agent)
            
            # Create endpoint groups by subnet
            for i, (subnet, agents_in_subnet) in enumerate(endpoint_subnets.items()):
                network_nodes.append({
                    "id": f"endpoints_{i}",
                    "name": f"Endpoints ({subnet})",
                    "type": "endpoints",
                    "level": 3,
                    "parent_id": "internal",
                    "subnet": subnet,
                    "agent_count": len(agents_in_subnet),
                    "agents": agents_in_subnet,
                    "status": "normal",
                    "risk_level": "medium",
                    "last_seen": max([a.get('lastActivity', '') for a in agents_in_subnet] + [datetime.now().isoformat()]),
                    "description": f"User workstations and devices in {subnet}",
                    "security_zone": "internal",
                    "avg_confidence": sum([a.get('element_confidence', 0.5) for a in agents_in_subnet]) / len(agents_in_subnet)
                })
        
        # 8. Cloud Services (already included in internet gateway, but create separate if many)
        cloud_agents = elements_by_type.get('cloud', [])
        if len(cloud_agents) > 3:  # Only create separate node if significant cloud presence
            network_nodes.append({
                "id": "cloud",
                "name": "Cloud Services",
                "type": "cloud",
                "level": 1,
                "parent_id": "internet",
                "subnet": "N/A",
                "agent_count": len(cloud_agents),
                "agents": cloud_agents,
                "status": "normal",
                "risk_level": "medium",
                "last_seen": max([a.get('lastActivity', '') for a in cloud_agents] + [datetime.now().isoformat()]),
                "description": "Cloud infrastructure and services",
                "security_zone": "external",
                "avg_confidence": sum([a.get('element_confidence', 0.5) for a in cloud_agents]) / len(cloud_agents)
            })
        
        # Sort based on requested order
        if sort_order == 'desc':
            network_nodes.sort(key=lambda x: (-x['level'], x['name']))
        else:  # hierarchy (default)
            network_nodes.sort(key=lambda x: (x['level'], x['name']))
        
        return network_nodes
        
    except Exception as e:
        print(f"Error building network hierarchy: {e}")
        return []

@network_bp.route('/api/network/topology', methods=['GET'])
def get_network_topology():
    """Get network topology in tabular format"""
    try:
        # Get sort order from query params
        sort_order = request.args.get('sort', 'hierarchy')  # 'hierarchy' or 'desc'
        
        # Get network hierarchy
        network_nodes = get_network_hierarchy(g.tenant_context, sort_order)
        
        # Calculate summary stats
        total_agents = sum(node['agent_count'] for node in network_nodes)
        active_nodes = len([node for node in network_nodes if node['status'] in ['active', 'normal']])
        critical_nodes = len([node for node in network_nodes if node['risk_level'] == 'critical'])
        
        return jsonify({
            "success": True,
            "network_topology": {
                "nodes": network_nodes,
                "summary": {
                    "total_nodes": len(network_nodes),
                    "total_agents": total_agents,
                    "active_nodes": active_nodes,
                    "critical_nodes": critical_nodes,
                    "sort_order": sort_order
                },
                "organization_id": g.tenant_context.organization_id
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@network_bp.route('/api/network/node/<node_id>', methods=['GET'])
def get_network_node_details(node_id):
    """Get detailed information about a specific network node"""
    try:
        network_nodes = get_network_hierarchy(g.tenant_context)
        node = next((n for n in network_nodes if n['id'] == node_id), None)
        
        if not node:
            return jsonify({
                "success": False,
                "error": "Network node not found"
            }), 404
        
        # Add additional details
        node_details = {
            **node,
            "connections": [],  # Could be populated with actual network connections
            "threats": [],      # Recent threats from this node
            "traffic_stats": {
                "bytes_in": 0,
                "bytes_out": 0,
                "connections": 0
            },
            "security_status": {
                "vulnerabilities": 0,
                "patches_needed": 0,
                "compliance_score": 95
            }
        }
        
        return jsonify({
            "success": True,
            "node": node_details
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@network_bp.route('/api/network/agents/<node_id>', methods=['GET'])
def get_node_agents(node_id):
    """Get all agents for a specific network node"""
    try:
        network_nodes = get_network_hierarchy(g.tenant_context)
        node = next((n for n in network_nodes if n['id'] == node_id), None)
        
        if not node:
            return jsonify({
                "success": False,
                "error": "Network node not found"
            }), 404
        
        return jsonify({
            "success": True,
            "node_id": node_id,
            "node_name": node['name'],
            "agents": node['agents'],
            "total": len(node['agents'])
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@network_bp.route('/api/network/summary', methods=['GET'])
def get_network_summary():
    """Get network topology summary statistics"""
    try:
        network_nodes = get_network_hierarchy(g.tenant_context)
        
        # Calculate detailed statistics
        stats_by_level = {}
        stats_by_type = {}
        risk_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for node in network_nodes:
            # By level
            level = f"Level {node['level']}"
            if level not in stats_by_level:
                stats_by_level[level] = {"nodes": 0, "agents": 0}
            stats_by_level[level]["nodes"] += 1
            stats_by_level[level]["agents"] += node['agent_count']
            
            # By type
            node_type = node['type']
            if node_type not in stats_by_type:
                stats_by_type[node_type] = {"nodes": 0, "agents": 0}
            stats_by_type[node_type]["nodes"] += 1
            stats_by_type[node_type]["agents"] += node['agent_count']
            
            # Risk distribution
            risk_distribution[node['risk_level']] += 1
        
        return jsonify({
            "success": True,
            "summary": {
                "total_nodes": len(network_nodes),
                "total_agents": sum(node['agent_count'] for node in network_nodes),
                "by_level": stats_by_level,
                "by_type": stats_by_type,
                "risk_distribution": risk_distribution,
                "last_updated": datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
