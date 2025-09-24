#!/usr/bin/env python3
"""
CodeGrey SOC Server - Multi-Tenant API
Provides REST API endpoints with complete tenant isolation
"""

from flask import Flask, jsonify, request, g
from flask_cors import CORS
import sys
import os
import logging
import hashlib
import json
from functools import wraps
from datetime import datetime

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.multi_tenant_agent_manager import multi_tenant_agent_manager, TenantContext
from api.network_topology_api import network_bp

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend access

# Register blueprints
app.register_blueprint(network_bp)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# AUTHENTICATION & TENANT CONTEXT MIDDLEWARE
# ============================================================================

def require_tenant_context(f):
    """Decorator to require and validate tenant context"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({
                'success': False,
                'error': 'Authorization required'
            }), 401
        
        try:
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                
                # Validate API key and get tenant context
                tenant_context = multi_tenant_agent_manager.validate_api_key(token)
                
                if not tenant_context:
                    return jsonify({
                        'success': False,
                        'error': 'Invalid or expired API key'
                    }), 401
                
                # Store tenant context in Flask's g object
                g.tenant_context = tenant_context
                return f(*args, **kwargs)
            else:
                return jsonify({
                    'success': False,
                    'error': 'Bearer token required'
                }), 401
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({
                'success': False,
                'error': 'Authentication failed'
            }), 401
    
    return decorated_function

# ============================================================================
# AGENT MANAGEMENT APIs (TENANT-SCOPED)
# ============================================================================

@app.route('/api/agents', methods=['GET'])
@require_tenant_context
def get_all_agents():
    """Get all agents for current tenant"""
    try:
        # Parse filters from query parameters
        filters = {}
        if request.args.get('status'):
            filters['status'] = request.args.get('status')
        if request.args.get('type'):
            filters['type'] = request.args.get('type')
        if request.args.get('hostname'):
            filters['hostname'] = request.args.get('hostname')
        
        # Get agents for current tenant
        agents = multi_tenant_agent_manager.get_agents(g.tenant_context, filters)
        
        return jsonify({
            "success": True,
            "agents": agents,
            "total": len(agents),
            "organization_id": g.tenant_context.organization_id
        })
        
    except Exception as e:
        logger.error(f"Error getting agents: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/agents/<agent_id>', methods=['GET'])
@require_tenant_context
def get_agent_by_id(agent_id):
    """Get specific agent for current tenant"""
    try:
        agent = multi_tenant_agent_manager.get_agent_by_id(g.tenant_context, agent_id)
        
        if not agent:
            return jsonify({
                "success": False,
                "error": "Agent not found"
            }), 404
        
        return jsonify({
            "success": True,
            "agent": agent
        })
        
    except Exception as e:
        logger.error(f"Error getting agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/agents/status/<status>', methods=['GET'])
@require_tenant_context
def get_agents_by_status(status):
    """Get agents by status for current tenant"""
    try:
        filters = {"status": status}
        agents = multi_tenant_agent_manager.get_agents(g.tenant_context, filters)
        
        return jsonify({
            "success": True,
            "agents": agents,
            "total": len(agents),
            "filter": {"status": status}
        })
        
    except Exception as e:
        logger.error(f"Error getting agents by status {status}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/agents/type/<agent_type>', methods=['GET'])
@require_tenant_context
def get_agents_by_type(agent_type):
    """Get agents by type for current tenant"""
    try:
        filters = {"type": agent_type}
        agents = multi_tenant_agent_manager.get_agents(g.tenant_context, filters)
        
        return jsonify({
            "success": True,
            "agents": agents,
            "total": len(agents),
            "filter": {"type": agent_type}
        })
        
    except Exception as e:
        logger.error(f"Error getting agents by type {agent_type}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/agents/statistics', methods=['GET'])
@require_tenant_context
def get_agent_statistics():
    """Get agent statistics for current tenant"""
    try:
        stats = multi_tenant_agent_manager.get_agent_statistics(g.tenant_context)
        
        return jsonify({
            "success": True,
            "statistics": stats
        })
        
    except Exception as e:
        logger.error(f"Error getting agent statistics: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# AGENT REGISTRATION & HEARTBEAT (TENANT-SCOPED)
# ============================================================================

@app.route('/api/agents/register', methods=['POST'])
@require_tenant_context
def register_agent():
    """Register new agent for current tenant"""
    try:
        agent_data = request.get_json()
        
        if not agent_data:
            return jsonify({
                "success": False,
                "error": "Agent data required"
            }), 400
        
        # Add client IP if not provided
        if not agent_data.get('ip_address'):
            agent_data['ip_address'] = request.remote_addr
        
        agent_id = multi_tenant_agent_manager.register_agent(g.tenant_context, agent_data)
        
        return jsonify({
            "success": True,
            "agent_id": agent_id,
            "organization_id": g.tenant_context.organization_id,
            "message": "Agent registered successfully"
        })
        
    except ValueError as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400
    except Exception as e:
        logger.error(f"Error registering agent: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/agents/<agent_id>/heartbeat', methods=['POST'])
@require_tenant_context
def agent_heartbeat(agent_id):
    """Update agent heartbeat (tenant-scoped)"""
    try:
        activity_data = request.get_json() or {}
        
        success = multi_tenant_agent_manager.update_agent_heartbeat(
            g.tenant_context, agent_id, activity_data
        )
        
        if not success:
            return jsonify({
                "success": False,
                "error": "Agent not found"
            }), 404
        
        return jsonify({
            "success": True,
            "message": "Heartbeat recorded"
        })
        
    except Exception as e:
        logger.error(f"Error updating heartbeat for agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# COMMAND EXECUTION (TENANT-SCOPED)
# ============================================================================

@app.route('/api/agents/<agent_id>/command', methods=['POST'])
@require_tenant_context
def send_command_to_agent(agent_id):
    """Send command to agent (tenant-scoped)"""
    try:
        command_data = request.get_json()
        
        if not command_data:
            return jsonify({
                "success": False,
                "error": "Command data required"
            }), 400
        
        command_id = multi_tenant_agent_manager.create_command(
            g.tenant_context, agent_id, command_data
        )
        
        return jsonify({
            "success": True,
            "command_id": command_id,
            "message": "Command queued for execution"
        })
        
    except ValueError as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 404
    except Exception as e:
        logger.error(f"Error sending command to agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/agents/<agent_id>/commands', methods=['GET'])
@require_tenant_context
def get_agent_commands(agent_id):
    """Get pending commands for agent (tenant-scoped)"""
    try:
        commands = multi_tenant_agent_manager.get_pending_commands(
            g.tenant_context, agent_id
        )
        
        return jsonify({
            "success": True,
            "commands": commands,
            "total": len(commands)
        })
        
    except Exception as e:
        logger.error(f"Error getting commands for agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/commands/<command_id>/result', methods=['GET'])
@require_tenant_context
def get_command_result(command_id):
    """Get command execution result (tenant-scoped)"""
    try:
        # This would fetch from database - simplified for now
        result = {
            "command_id": command_id,
            "status": "completed",
            "output": "Command executed successfully",
            "stderr": "",
            "exit_code": 0,
            "execution_time": datetime.now().isoformat()
        }
        
        return jsonify({
            "success": True,
            "result": result
        })
        
    except Exception as e:
        logger.error(f"Error getting command result {command_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/commands/<command_id>/result', methods=['POST'])
@require_tenant_context
def update_command_result(command_id):
    """Update command execution result (tenant-scoped)"""
    try:
        result_data = request.get_json()
        
        if not result_data:
            return jsonify({
                "success": False,
                "error": "Result data required"
            }), 400
        
        success = multi_tenant_agent_manager.update_command_result(
            g.tenant_context, command_id, result_data
        )
        
        if not success:
            return jsonify({
                "success": False,
                "error": "Command not found"
            }), 404
        
        return jsonify({
            "success": True,
            "message": "Command result updated"
        })
        
    except Exception as e:
        logger.error(f"Error updating command result {command_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# ATTACK SCENARIOS & TIMELINE (TENANT-SCOPED)
# ============================================================================

@app.route('/api/attack_scenarios', methods=['GET'])
@require_tenant_context
def get_attack_scenarios():
    """Get available attack scenarios for current tenant"""
    try:
        # Predefined attack scenarios
        scenarios = [
            {
                "id": "apt28_spear_phishing",
                "name": "Fancy Bear Email Campaign",
                "description": "Sophisticated spear-phishing campaign targeting government and military organizations using Zebrocy malware and domain fronting techniques",
                "apt_group": "APT28 (Fancy Bear)",
                "country": "Russia",
                "difficulty": "advanced",
                "duration_minutes": 45,
                "impact": "Critical Impact",
                "techniques": ["T1566.001", "T1071.001", "T1027", "T1055"],
                "target_sectors": ["Government", "Military", "Defense Contractors", "Think Tanks"],
                "motivation": "Espionage, Intelligence Gathering"
            },
            {
                "id": "apt29_cloud_intrusion",
                "name": "Cozy Bear Cloud Intrusion",
                "description": "Advanced cloud-focused attack using legitimate cloud services for C2 and Azure AD exploitation for persistence",
                "apt_group": "APT29 (Cozy Bear)",
                "country": "Russia",
                "difficulty": "expert",
                "duration_minutes": 60,
                "impact": "Critical Impact",
                "techniques": ["T1078.004", "T1550.001", "T1484.001", "T1136.003"],
                "target_sectors": ["Cloud Infrastructure", "SaaS Platforms", "Government Agencies", "Healthcare"],
                "motivation": "Intelligence Gathering, Political Espionage"
            },
            {
                "id": "lazarus_financial_heist",
                "name": "Lazarus Financial Heist",
                "description": "SWIFT network attack targeting financial institutions using custom malware and destructive payloads",
                "apt_group": "Lazarus Group",
                "country": "North Korea",
                "difficulty": "advanced",
                "duration_minutes": 90,
                "impact": "Critical Impact",
                "techniques": ["T1190", "T1078", "T1485", "T1490"],
                "target_sectors": ["Banks", "Financial Services", "Cryptocurrency Exchanges", "Payment Processors"],
                "motivation": "Financial Theft"
            },
            {
                "id": "apt40_maritime_espionage",
                "name": "Leviathan Maritime Espionage",
                "description": "Maritime industry espionage campaign targeting shipping, naval, and port management systems",
                "apt_group": "APT40 (Leviathan)",
                "country": "China",
                "difficulty": "intermediate",
                "duration_minutes": 35,
                "impact": "High Impact",
                "techniques": ["T1566.002", "T1059.001", "T1083", "T1005"],
                "target_sectors": ["Maritime Industry", "Shipping Companies", "Port Authorities", "Naval Organizations"],
                "motivation": "Intelligence Gathering, Political Espionage"
            },
            {
                "id": "carbanak_banking_trojan",
                "name": "Carbanak Banking Trojan",
                "description": "Advanced banking trojan campaign using social engineering and remote access tools for financial theft",
                "apt_group": "Carbanak (FIN7)",
                "country": "Eastern Europe",
                "difficulty": "advanced",
                "duration_minutes": 50,
                "impact": "Critical Impact",
                "techniques": ["T1566.001", "T1059.003", "T1055", "T1005"],
                "target_sectors": ["Banks", "Financial Services", "ATM Networks", "Point of Sale Systems"],
                "motivation": "Financial Theft"
            },
            {
                "id": "comment_crew_ip_theft",
                "name": "Comment Crew IP Theft",
                "description": "Long-term intellectual property theft campaign targeting technology and manufacturing companies",
                "apt_group": "APT1 (Comment Crew)",
                "country": "China",
                "difficulty": "beginner",
                "duration_minutes": 25,
                "impact": "High Impact",
                "techniques": ["T1566.001", "T1059.003", "T1083", "T1005"],
                "target_sectors": ["Technology Companies", "Manufacturing", "Intellectual Property"],
                "motivation": "Economic Espionage"
            }
        ]
        
        return jsonify({
            "success": True,
            "scenarios": scenarios,
            "total": len(scenarios)
        })
        
    except Exception as e:
        logger.error(f"Error getting attack scenarios: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/attack_scenarios/execute', methods=['POST'])
@require_tenant_context
def execute_attack_scenario():
    """Execute an attack scenario via attack agent"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "error": "Request data required"
            }), 400
        
        scenario_id = data.get('scenario_id')
        agent_id = data.get('agent_id')
        
        if not scenario_id or not agent_id:
            return jsonify({
                "success": False,
                "error": "scenario_id and agent_id required"
            }), 400
        
        # Verify agent exists and is attack type
        agent = multi_tenant_agent_manager.get_agent_by_id(g.tenant_context, agent_id)
        if not agent:
            return jsonify({
                "success": False,
                "error": "Agent not found"
            }), 404
        
        if agent.get('type') != 'attack':
            return jsonify({
                "success": False,
                "error": "Agent must be of type 'attack'"
            }), 400
        
        # Create command to execute scenario
        command_data = {
            "type": "execute_scenario",
            "scenario_id": scenario_id,
            "priority": "high",
            "timestamp": datetime.now().isoformat()
        }
        
        command_id = multi_tenant_agent_manager.create_command(
            g.tenant_context, agent_id, command_data
        )
        
        return jsonify({
            "success": True,
            "command_id": command_id,
            "scenario_id": scenario_id,
            "agent_id": agent_id,
            "message": "Attack scenario queued for execution"
        })
        
    except Exception as e:
        logger.error(f"Error executing attack scenario: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/attack_timeline', methods=['GET'])
@require_tenant_context
def get_attack_timeline():
    """Get attack timeline/history for current tenant"""
    try:
        # Mock attack timeline data - in production this would come from database
        timeline = [
            {
                "id": "attack_001",
                "scenario_id": "apt28_spear_phishing",
                "scenario_name": "Fancy Bear Email Campaign",
                "agent_id": "phantom-ai-01",
                "agent_name": "PhantomStrike AI",
                "status": "completed",
                "started_at": "2024-01-15T10:30:00Z",
                "completed_at": "2024-01-15T11:15:00Z",
                "duration_minutes": 45,
                "techniques_executed": ["T1566.001", "T1071.001", "T1027"],
                "targets_affected": 12,
                "success_rate": 85.5
            },
            {
                "id": "attack_002",
                "scenario_id": "lazarus_financial_heist",
                "scenario_name": "Lazarus Financial Heist",
                "agent_id": "phantom-ai-01",
                "agent_name": "PhantomStrike AI",
                "status": "in_progress",
                "started_at": "2024-01-15T14:00:00Z",
                "completed_at": None,
                "duration_minutes": 35,
                "techniques_executed": ["T1190", "T1078"],
                "targets_affected": 3,
                "success_rate": 67.0
            }
        ]
        
        return jsonify({
            "success": True,
            "timeline": timeline,
            "total": len(timeline)
        })
        
    except Exception as e:
        logger.error(f"Error getting attack timeline: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/attack_scenarios/<scenario_id>', methods=['GET'])
@require_tenant_context
def get_attack_scenario_details(scenario_id):
    """Get detailed information about a specific attack scenario"""
    try:
        # This would fetch from database - simplified for now
        scenario_details = {
            "id": scenario_id,
            "name": "Fancy Bear Email Campaign",
            "description": "Sophisticated spear-phishing campaign targeting government and military organizations",
            "playbook_steps": [
                "1. Reconnaissance and target identification",
                "2. Craft spear-phishing emails with malicious attachments",
                "3. Deploy Zebrocy malware payload",
                "4. Establish command and control channel",
                "5. Lateral movement and privilege escalation",
                "6. Data exfiltration"
            ],
            "required_capabilities": ["Email Simulation", "Web Exploitation", "Social Engineering"],
            "estimated_duration": 45,
            "difficulty": "advanced"
        }
        
        return jsonify({
            "success": True,
            "scenario": scenario_details
        })
        
    except Exception as e:
        logger.error(f"Error getting scenario details {scenario_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# DETECTION RESULTS & ANALYSIS (TENANT-SCOPED)
# ============================================================================

@app.route('/api/agents/<agent_id>/detections', methods=['GET'])
@require_tenant_context
def get_agent_detections(agent_id):
    """Get detection results for a specific detection agent"""
    try:
        # Verify agent exists and is detection type
        agent = multi_tenant_agent_manager.get_agent_by_id(g.tenant_context, agent_id)
        if not agent:
            return jsonify({
                "success": False,
                "error": "Agent not found"
            }), 404
        
        if agent.get('type') != 'detection':
            return jsonify({
                "success": False,
                "error": "Agent must be of type 'detection'"
            }), 400
        
        # Mock detection results - in production this would come from database
        detections = [
            {
                "id": "det_001",
                "timestamp": "2024-01-15T10:45:00Z",
                "threat_type": "malware",
                "severity": "high",
                "confidence": 0.92,
                "source_ip": "192.168.1.100",
                "target_ip": "10.0.1.50",
                "technique": "T1566.001",
                "description": "Suspicious email attachment detected",
                "status": "confirmed"
            },
            {
                "id": "det_002",
                "timestamp": "2024-01-15T11:20:00Z",
                "threat_type": "lateral_movement",
                "severity": "medium",
                "confidence": 0.78,
                "source_ip": "10.0.1.50",
                "target_ip": "10.0.1.75",
                "technique": "T1021.001",
                "description": "Unusual RDP connection pattern",
                "status": "investigating"
            }
        ]
        
        return jsonify({
            "success": True,
            "detections": detections,
            "agent_id": agent_id,
            "total": len(detections)
        })
        
    except Exception as e:
        logger.error(f"Error getting detections for agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/detections/live', methods=['GET'])
@require_tenant_context
def get_live_detections():
    """Get all live/active detections for current tenant"""
    try:
        # Mock live detections - in production this would come from database
        live_detections = [
            {
                "id": "live_001",
                "agent_id": "guardian-ai-01",
                "agent_name": "GuardianAlpha AI",
                "timestamp": "2024-01-15T15:30:00Z",
                "threat_type": "command_and_control",
                "severity": "critical",
                "confidence": 0.95,
                "source": "192.168.1.150",
                "technique": "T1071.001",
                "description": "Suspicious C2 communication detected",
                "status": "active"
            }
        ]
        
        return jsonify({
            "success": True,
            "detections": live_detections,
            "total": len(live_detections)
        })
        
    except Exception as e:
        logger.error(f"Error getting live detections: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/detections/missed', methods=['GET'])
@require_tenant_context
def get_missed_detections():
    """Get missed detections for current tenant"""
    try:
        # Mock missed detections - in production this would be calculated
        missed_detections = [
            {
                "id": "missed_001",
                "timestamp": "2024-01-15T12:15:00Z",
                "threat_type": "data_exfiltration",
                "severity": "high",
                "source": "10.0.1.100",
                "technique": "T1041",
                "description": "Data exfiltration attempt not detected in real-time",
                "discovered_at": "2024-01-15T14:30:00Z",
                "delay_minutes": 135
            }
        ]
        
        return jsonify({
            "success": True,
            "missed_detections": missed_detections,
            "total": len(missed_detections)
        })
        
    except Exception as e:
        logger.error(f"Error getting missed detections: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# AI CHAT & REASONING (TENANT-SCOPED)
# ============================================================================

@app.route('/api/v1/chat', methods=['POST'])
@require_tenant_context
def ai_chat_endpoint():
    """AI chat interface for SOC operations"""
    try:
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({
                "success": False,
                "error": "Message required"
            }), 400
        
        message = data.get('message', '').strip()
        agent_id = data.get('agent_id')  # Optional: specific reasoning agent
        
        if not message:
            return jsonify({
                "success": False,
                "error": "Message cannot be empty"
            }), 400
        
        # If no specific agent provided, find first available reasoning agent
        if not agent_id:
            reasoning_agents = multi_tenant_agent_manager.get_agents(
                g.tenant_context, {"type": "reasoning", "status": "online"}
            )
            if reasoning_agents:
                agent_id = reasoning_agents[0]['id']
            else:
                return jsonify({
                    "success": False,
                    "error": "No reasoning agents available"
                }), 503
        
        # Create chat command
        command_data = {
            "type": "ai_chat",
            "message": message,
            "priority": "normal",
            "timestamp": datetime.now().isoformat()
        }
        
        command_id = multi_tenant_agent_manager.create_command(
            g.tenant_context, agent_id, command_data
        )
        
        # For demo purposes, return a mock response
        # In production, this would wait for the agent's response or use async processing
        mock_response = f"SOC AI Assistant: I understand you're asking about '{message}'. I'm analyzing the current security posture and will provide recommendations based on our threat intelligence and active monitoring data."
        
        return jsonify({
            "success": True,
            "response": mock_response,
            "command_id": command_id,
            "agent_id": agent_id,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in AI chat: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/agents/<agent_id>/capabilities', methods=['GET'])
@require_tenant_context
def get_agent_capabilities(agent_id):
    """Get detailed capabilities for a specific agent"""
    try:
        agent = multi_tenant_agent_manager.get_agent_by_id(g.tenant_context, agent_id)
        
        if not agent:
            return jsonify({
                "success": False,
                "error": "Agent not found"
            }), 404
        
        # Enhanced capabilities based on agent type
        capabilities = agent.get('capabilities', [])
        
        if agent.get('type') == 'attack':
            detailed_capabilities = {
                "primary": capabilities,
                "attack_vectors": [
                    "Spear Phishing Campaigns",
                    "Web Application Exploitation",
                    "Social Engineering",
                    "Lateral Movement Techniques",
                    "Persistence Mechanisms",
                    "Command & Control Channels"
                ],
                "supported_frameworks": ["MITRE ATT&CK", "Cyber Kill Chain"],
                "automation_level": "Fully Automated"
            }
        elif agent.get('type') == 'detection':
            detailed_capabilities = {
                "primary": capabilities,
                "detection_methods": [
                    "Behavioral Analysis",
                    "Signature-based Detection",
                    "Machine Learning Models",
                    "Anomaly Detection",
                    "Threat Hunting",
                    "IOC Correlation"
                ],
                "supported_frameworks": ["MITRE ATT&CK", "NIST Cybersecurity Framework"],
                "automation_level": "Fully Automated"
            }
        elif agent.get('type') == 'reasoning':
            detailed_capabilities = {
                "primary": capabilities,
                "reasoning_types": [
                    "Threat Analysis",
                    "Risk Assessment",
                    "Incident Response Planning",
                    "Natural Language Processing",
                    "Decision Support",
                    "Automated Reporting"
                ],
                "supported_frameworks": ["NIST IR", "SANS Incident Response"],
                "automation_level": "AI-Powered"
            }
        else:
            detailed_capabilities = {
                "primary": capabilities,
                "automation_level": "Standard"
            }
        
        return jsonify({
            "success": True,
            "agent_id": agent_id,
            "capabilities": detailed_capabilities
        })
        
    except Exception as e:
        logger.error(f"Error getting capabilities for agent {agent_id}: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# THREAT INTELLIGENCE (TENANT-SCOPED)
# ============================================================================

@app.route('/api/threats/metrics', methods=['GET'])
@require_tenant_context
def get_threat_metrics():
    """Get threat intelligence metrics for current tenant"""
    try:
        # Mock data for now - would be calculated from tenant's threat data
        metrics = {
            "threatLevel": "medium",
            "activeCampaigns": 2,
            "detectionRate": 94.5,
            "meanTimeToDetection": 45,
            "falsePositiveRate": 2.1,
            "complianceScore": 98.7
        }
        
        return jsonify({
            "success": True,
            "metrics": metrics,
            "organization_id": g.tenant_context.organization_id
        })
        
    except Exception as e:
        logger.error(f"Error getting threat metrics: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# SYSTEM STATUS (TENANT-SCOPED)
# ============================================================================

@app.route('/api/system/status', methods=['GET'])
@require_tenant_context
def get_system_status():
    """Get system status for current tenant"""
    try:
        import psutil
        
        # Get tenant-specific statistics
        stats = multi_tenant_agent_manager.get_agent_statistics(g.tenant_context)
        
        status = {
            "server_version": "2.1.0",
            "uptime": "5 days, 12 hours",  # Calculate actual uptime
            "connected_agents": stats.get('online', 0),
            "total_agents": stats.get('total', 0),
            "active_campaigns": 2,  # Would be calculated from tenant data
            "database_status": "healthy",
            "memory_usage": psutil.virtual_memory().percent,
            "cpu_usage": psutil.cpu_percent(interval=1),
            "organization_id": g.tenant_context.organization_id
        }
        
        return jsonify({
            "success": True,
            "status": status
        })
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# ORGANIZATION MANAGEMENT (ADMIN ONLY)
# ============================================================================

@app.route('/api/organizations', methods=['POST'])
def create_organization():
    """Create new organization (public endpoint for admin)"""
    try:
        data = request.get_json()
        
        if not data or not data.get('name'):
            return jsonify({
                "success": False,
                "error": "Organization name required"
            }), 400
        
        org_data = multi_tenant_agent_manager.create_organization(
            name=data['name'],
            domain=data.get('domain'),
            subdomain=data.get('subdomain'),
            settings=data.get('settings'),
            limits=data.get('limits')
        )
        
        return jsonify({
            "success": True,
            "organization": org_data
        })
        
    except Exception as e:
        logger.error(f"Error creating organization: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# TESTING & DEVELOPMENT
# ============================================================================

@app.route('/api/test/create-sample-agents', methods=['POST'])
@require_tenant_context
def create_sample_agents():
    """Create sample agents for testing (tenant-scoped)"""
    try:
        sample_agents = [
            {
                "name": "PhantomStrike AI",
                "type": "attack",
                "hostname": "phantom-ai-01",
                "ip_address": "10.0.1.100",
                "capabilities": ["Email Simulation", "Web Exploitation", "Social Engineering", "Lateral Movement", "Persistence Testing"]
            },
            {
                "name": "GuardianAlpha AI", 
                "type": "detection",
                "hostname": "guardian-ai-01",
                "ip_address": "10.0.1.101",
                "capabilities": ["Behavioral Analysis", "Signature Detection", "Threat Hunting", "ML-based Detection", "Anomaly Correlation"]
            },
            {
                "name": "Windows Workstation",
                "type": "windows",
                "hostname": "WIN-WS-001",
                "ip_address": "192.168.1.100",
                "capabilities": ["Log Collection", "Command Execution", "File Download", "Registry Access"]
            },
            {
                "name": "Linux Server",
                "type": "linux", 
                "hostname": "linux-srv-01",
                "ip_address": "192.168.1.101",
                "capabilities": ["Log Collection", "Command Execution", "File Download", "Process Monitoring"]
            },
            {
                "name": "ThreatMind AI",
                "type": "reasoning",
                "hostname": "threatmind-ai-01", 
                "ip_address": "10.0.1.102",
                "capabilities": ["Threat Analysis", "Risk Assessment", "Incident Response Planning", "Natural Language Processing", "Decision Support", "Automated Reporting"]
            }
        ]
        
        created_agents = []
        for agent_data in sample_agents:
            try:
                agent_id = multi_tenant_agent_manager.register_agent(g.tenant_context, agent_data)
                created_agents.append({
                    "id": agent_id,
                    "name": agent_data["name"],
                    "type": agent_data["type"]
                })
            except Exception as e:
                logger.warning(f"Failed to create sample agent {agent_data['name']}: {e}")
        
        return jsonify({
            "success": True,
            "created": len(created_agents),
            "agents": created_agents,
            "organization_id": g.tenant_context.organization_id
        })
        
    except Exception as e:
        logger.error(f"Error creating sample agents: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500

# ============================================================================
# STARTUP
# ============================================================================

if __name__ == '__main__':
    logger.info("Starting CodeGrey Multi-Tenant SOC Server...")
    logger.info("Available endpoints:")
    logger.info("  GET  /api/agents - Get all agents (tenant-scoped)")
    logger.info("  GET  /api/agents/<id> - Get specific agent")
    logger.info("  GET  /api/agents/status/<status> - Get agents by status")
    logger.info("  GET  /api/agents/type/<type> - Get agents by type")
    logger.info("  GET  /api/agents/statistics - Get agent statistics")
    logger.info("  POST /api/agents/register - Register new agent")
    logger.info("  POST /api/agents/<id>/heartbeat - Update agent heartbeat")
    logger.info("  POST /api/agents/<id>/command - Send command to agent")
    
    logger.info("🚀 Attack Agent APIs:")
    logger.info("  GET  /api/attack_scenarios - List attack scenarios")
    logger.info("  POST /api/attack_scenarios/execute - Execute attack scenario")
    logger.info("  GET  /api/attack_timeline - Get attack timeline/history")
    logger.info("  GET  /api/attack_scenarios/<id> - Get scenario details")
    
    logger.info("🛡️ Detection Agent APIs:")
    logger.info("  GET  /api/agents/<id>/detections - Get agent detections")
    logger.info("  GET  /api/detections/live - Get live detections")
    logger.info("  GET  /api/detections/missed - Get missed detections")
    
    logger.info("🧠 AI Reasoning Agent APIs:")
    logger.info("  POST /api/v1/chat - AI chat interface")
    logger.info("  GET  /api/agents/<id>/capabilities - Get agent capabilities")
    
    logger.info("  GET  /api/threats/metrics - Get threat metrics")
    logger.info("  GET  /api/system/status - Get system status")
    logger.info("  POST /api/organizations - Create organization")
    logger.info("  POST /api/test/create-sample-agents - Create sample data")
    logger.info("")
    logger.info("Multi-tenant isolation: ENABLED")
    logger.info("Authentication: Bearer token required")
    logger.info("")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
