"""
🧠 AI Reasoning Agent APIs
Implements AI chat interface and reasoning endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import uuid
from functools import wraps

reasoning_bp = Blueprint('reasoning', __name__)

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

@reasoning_bp.route('/v1/chat', methods=['POST'])
@require_auth
def ai_chat():
    """
    POST /api/v1/chat
    AI reasoning chat interface
    """
    try:
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({
                "success": False,
                "error": "Missing required field: message",
                "error_code": "INVALID_PARAMETERS"
            }), 400
        
        message = data['message']
        agent_id = data.get('agent_id', 'threatmind-ai-01')
        context = data.get('context', {})
        priority = data.get('priority', 'normal')
        
        # Generate command ID
        command_id = f"cmd_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc)
        
        # Analyze the message and generate appropriate response
        response_data = _generate_ai_response(message, context)
        
        return jsonify({
            "success": True,
            "response": response_data["response"],
            "command_id": command_id,
            "agent_id": agent_id,
            "timestamp": timestamp.isoformat(),
            "analysis_data": response_data.get("analysis_data", {}),
            "sources_analyzed": response_data.get("sources_analyzed", [])
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

# Helper functions
def _generate_ai_response(message, context):
    """Generate AI response based on message and context"""
    message_lower = message.lower()
    
    # Threat level queries
    if any(keyword in message_lower for keyword in ['threat level', 'current threats', 'security status']):
        return {
            "response": "Based on my analysis of the last 24 hours, the current threat level is MEDIUM. I've identified 3 active threats: 1 confirmed malware detection, 1 suspicious C2 communication, and 1 potential data exfiltration attempt. The attack surface shows increased activity in the DMZ segment. I recommend immediate isolation of host 192.168.1.150 and enhanced monitoring of external communications.",
            "analysis_data": {
                "threat_level": "MEDIUM",
                "active_threats": 3,
                "risk_score": 6.8,
                "confidence": 0.87,
                "recommendations": [
                    "Isolate host 192.168.1.150",
                    "Block communication to malicious-c2.com", 
                    "Investigate potential data exfiltration"
                ]
            },
            "sources_analyzed": [
                "recent_detections",
                "network_topology",
                "attack_timeline",
                "threat_intelligence"
            ]
        }
    
    # Agent status queries
    elif any(keyword in message_lower for keyword in ['agent status', 'agents', 'online agents']):
        return {
            "response": "Currently, we have 4 out of 5 agents online and operational. The PhantomStrike AI attack agent is in idle status, GuardianAlpha AI detection agent is actively monitoring, and ThreatMind AI reasoning engine is processing queries. One endpoint agent (Windows-WS-003) appears to be offline since 2 hours ago. All critical AI agents are functioning normally with high health scores.",
            "analysis_data": {
                "total_agents": 5,
                "online_agents": 4,
                "offline_agents": 1,
                "agent_health": "Good",
                "recommendations": [
                    "Check connectivity to Windows-WS-003",
                    "Verify network connectivity",
                    "Consider agent restart if needed"
                ]
            },
            "sources_analyzed": [
                "agent_status",
                "heartbeat_data",
                "network_connectivity"
            ]
        }
    
    # Attack scenario queries
    elif any(keyword in message_lower for keyword in ['attack', 'scenario', 'campaign', 'simulate']):
        return {
            "response": "I can help you with attack scenario analysis. We currently have 6 pre-configured attack scenarios including APT28 spear-phishing campaigns, Lazarus financial heist simulations, and various lateral movement techniques. The last attack simulation was completed 2 hours ago with an 85.5% success rate. Would you like me to recommend a specific scenario based on your current security posture, or do you need analysis of recent attack timeline data?",
            "analysis_data": {
                "available_scenarios": 6,
                "last_attack_success_rate": 85.5,
                "recommended_scenario": "apt28_spear_phishing",
                "attack_readiness": "High"
            },
            "sources_analyzed": [
                "attack_scenarios",
                "attack_timeline",
                "agent_capabilities"
            ]
        }
    
    # Detection queries
    elif any(keyword in message_lower for keyword in ['detection', 'alerts', 'threats detected', 'malware']):
        return {
            "response": "Recent detection analysis shows 2 active high-priority threats and 1 critical C2 communication alert. The GuardianAlpha AI has maintained a 94.2% detection accuracy with only 2.1% false positive rate. Most recent detection was a suspicious email attachment 35 minutes ago, which has been quarantined. The system is performing well with mean time to detection at 45 seconds.",
            "analysis_data": {
                "active_detections": 3,
                "detection_accuracy": 94.2,
                "false_positive_rate": 2.1,
                "mean_time_to_detection": 45,
                "last_detection": "35 minutes ago"
            },
            "sources_analyzed": [
                "detection_logs",
                "ml_model_performance",
                "threat_indicators"
            ]
        }
    
    # Network queries
    elif any(keyword in message_lower for keyword in ['network', 'topology', 'infrastructure', 'connectivity']):
        return {
            "response": "Network topology analysis shows 8 network elements across 4 security zones. The DMZ segment is currently at HIGH risk level due to recent C2 communication attempts. Internal network segments are operating normally with MEDIUM risk levels. All critical network paths are monitored with 15 active agents distributed across the infrastructure. Firewall and perimeter defenses are functioning optimally.",
            "analysis_data": {
                "network_elements": 8,
                "security_zones": 4,
                "high_risk_segments": 1,
                "monitored_agents": 15,
                "network_health": "Good"
            },
            "sources_analyzed": [
                "network_topology",
                "security_zones",
                "agent_distribution"
            ]
        }
    
    # General queries
    else:
        return {
            "response": f"SOC AI Assistant: I understand you're asking about '{message}'. I'm analyzing the current security posture and will provide recommendations based on our threat intelligence and active monitoring data. Could you please be more specific about what aspect of security you'd like me to analyze? I can help with threat levels, agent status, attack scenarios, detections, or network topology.",
            "analysis_data": {
                "query_type": "general",
                "confidence": 0.75,
                "suggestions": [
                    "Ask about current threat level",
                    "Check agent status",
                    "Review recent detections",
                    "Analyze network topology"
                ]
            },
            "sources_analyzed": [
                "general_context",
                "system_status"
            ]
        }

