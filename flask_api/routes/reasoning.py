"""
Enhanced AI Reasoning Agent APIs
Implements AI chat interface with attack command capabilities
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import uuid
import asyncio
import sys
from pathlib import Path
from functools import wraps

# Import enhanced reasoning engine
sys.path.append(str(Path(__file__).parent.parent.parent / "agents" / "ai_reasoning_agent"))
from enhanced_reasoning_engine import enhanced_reasoning_engine

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
    Enhanced AI reasoning chat interface with attack command capabilities
    """
    try:
        data = request.get_json()
        
        if not data or 'query' not in data and 'message' not in data:
            return jsonify({
                "success": False,
                "error": "Missing required field: 'query' or 'message'",
                "error_code": "INVALID_PARAMETERS"
            }), 400
        
        # Support both 'query' and 'message' for backward compatibility
        user_query = data.get('query') or data.get('message')
        user_context = data.get('context', {})
        
        # Add request metadata to context
        user_context.update({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'ip_address': request.remote_addr
        })
        
        # Process command using enhanced reasoning engine
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                enhanced_reasoning_engine.process_chat_command(user_query, user_context)
            )
        finally:
            loop.close()
        
        # Format response for API
        return jsonify({
            "success": result['success'],
            "response": result['response'],
            "response_type": result.get('response_type', 'general'),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": result.get('data', {}),
            "command_processed": True
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Chat processing failed: {str(e)}",
            "error_code": "PROCESSING_ERROR",
            "timestamp": datetime.now(timezone.utc).isoformat()
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


