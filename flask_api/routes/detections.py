"""
🛡️ Detection Agent APIs
Implements detection results and threat monitoring endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone, timedelta
import sqlite3
import json
import uuid
from functools import wraps

detections_bp = Blueprint('detections', __name__)

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

@detections_bp.route('/agents/<agent_id>/detections', methods=['GET'])
@require_auth
def get_agent_detections(agent_id):
    """
    GET /api/agents/{agent_id}/detections
    Get detections from a specific agent
    """
    try:
        conn = get_db_connection()
        
        # Check if agent exists
        cursor = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        agent = cursor.fetchone()
        
        if not agent:
            conn.close()
            return jsonify({
                "success": False,
                "error": "Agent not found",
                "error_code": "AGENT_NOT_FOUND"
            }), 404
        
        # Get detections for this agent
        cursor = conn.execute("""
            SELECT * FROM detections 
            WHERE agent_id = ? 
            ORDER BY timestamp DESC
        """, (agent_id,))
        detections_raw = cursor.fetchall()
        conn.close()
        
        detections = []
        for detection in detections_raw:
            detection_data = {
                "id": detection['id'],
                "timestamp": detection['timestamp'],
                "threat_type": detection['threat_type'],
                "severity": detection['severity'],
                "confidence": detection['confidence'],
                "source_ip": detection['source_ip'],
                "target_ip": detection['target_ip'],
                "technique": detection['technique'],
                "technique_name": detection['technique_name'],
                "description": detection['description'],
                "status": detection['status'],
                "indicators": json.loads(detection['indicators']) if detection['indicators'] else {},
                "risk_score": detection['risk_score'],
                "false_positive_probability": detection['false_positive_probability']
            }
            detections.append(detection_data)
        
        # If no detections in DB, return sample data
        if not detections:
            detections = _get_sample_detections(agent_id)
        
        return jsonify({
            "success": True,
            "detections": detections,
            "agent_id": agent_id,
            "total": len(detections)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@detections_bp.route('/detections/live', methods=['GET'])
@require_auth
def get_live_detections():
    """
    GET /api/detections/live
    Get live/recent detections from all agents
    """
    try:
        # Get query parameters for filtering
        sort_by = request.args.get('sort_by', 'timestamp')
        sort_order = request.args.get('sort_order', 'desc')
        filter_severity = request.args.get('filter_severity')
        limit = int(request.args.get('limit', 100))
        
        conn = get_db_connection()
        
        # Build query
        query = "SELECT d.*, a.name as agent_name FROM detections d LEFT JOIN agents a ON d.agent_id = a.id WHERE 1=1"
        params = []
        
        if filter_severity:
            query += " AND d.severity = ?"
            params.append(filter_severity)
        
        # Add ordering
        if sort_by in ['timestamp', 'severity', 'confidence', 'threat_type']:
            order_clause = f" ORDER BY d.{sort_by}"
            if sort_order.lower() == 'desc':
                order_clause += " DESC"
            query += order_clause
        
        # Add limit
        query += f" LIMIT {limit}"
        
        cursor = conn.execute(query, params)
        detections_raw = cursor.fetchall()
        conn.close()
        
        detections = []
        for detection in detections_raw:
            detection_data = {
                "id": detection['id'],
                "agent_id": detection['agent_id'],
                "agent_name": detection['agent_name'] or "Unknown Agent",
                "timestamp": detection['timestamp'],
                "time_ago": _format_time_ago(detection['timestamp']),
                "threat_type": detection['threat_type'],
                "threat_name": _format_threat_name(detection['threat_type']),
                "severity": detection['severity'],
                "confidence": detection['confidence'],
                "source": detection['source_ip'],
                "target": detection['target_ip'],
                "technique": detection['technique'],
                "technique_name": detection['technique_name'],
                "description": detection['description'],
                "status": detection['status'],
                "risk_score": detection['risk_score'],
                "recommended_action": _get_recommended_action(detection['threat_type'], detection['severity']),
                "network_element": "internal_network",
                "affected_systems": 1,
                "network_indicators": json.loads(detection['indicators']) if detection['indicators'] else {}
            }
            detections.append(detection_data)
        
        # If no detections in DB, return sample data
        if not detections:
            detections = _get_sample_live_detections()
        
        # Calculate summary
        summary = _calculate_detection_summary(detections)
        
        return jsonify({
            "success": True,
            "detections": detections,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "total": len(detections),
            "summary": summary
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@detections_bp.route('/detections/missed', methods=['GET'])
@require_auth
def get_missed_detections():
    """
    GET /api/detections/missed
    Get missed detections analysis
    """
    try:
        # For now, return sample missed detections
        # In production, this would analyze detection gaps
        missed_detections = _get_sample_missed_detections()
        
        return jsonify({
            "success": True,
            "missed_detections": missed_detections,
            "total": len(missed_detections)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

# Helper functions
def _get_sample_detections(agent_id):
    """Return sample detections for an agent"""
    return [
        {
            "id": "det_001",
            "timestamp": "2024-01-15T10:45:00Z",
            "threat_type": "malware",
            "severity": "high",
            "confidence": 0.92,
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.1.50",
            "technique": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "description": "Suspicious email attachment detected",
            "status": "confirmed",
            "indicators": {
                "file_hash": "a1b2c3d4e5f6...",
                "file_name": "invoice.pdf.exe",
                "email_sender": "finance@suspicious-domain.com"
            },
            "risk_score": 8.5,
            "false_positive_probability": 0.08
        }
    ]

def _get_sample_live_detections():
    """Return sample live detections"""
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "live_001",
            "agent_id": "guardian-ai-01",
            "agent_name": "GuardianAlpha AI",
            "timestamp": (now - timedelta(minutes=30)).isoformat(),
            "time_ago": "30 mins ago",
            "threat_type": "command_and_control",
            "threat_name": "Suspicious C2 Communication",
            "severity": "critical",
            "confidence": 95.2,
            "source": "192.168.1.150",
            "target": "malicious-c2.com",
            "technique": "T1071.001",
            "technique_name": "Web Protocols",
            "description": "Suspicious C2 communication detected via HTTPS",
            "status": "active",
            "risk_score": 8.7,
            "recommended_action": "Block communication, isolate host",
            "network_element": "internal_network",
            "affected_systems": 1,
            "network_indicators": {
                "destination_domain": "malicious-c2.com",
                "protocol": "HTTPS",
                "frequency": "every_60_seconds",
                "data_volume": "1.2MB"
            }
        },
        {
            "id": "live_002",
            "agent_id": "guardian-ai-01",
            "agent_name": "GuardianAlpha AI",
            "timestamp": (now - timedelta(minutes=35)).isoformat(),
            "time_ago": "35 mins ago",
            "threat_type": "malware",
            "threat_name": "Suspicious Email Attachment",
            "severity": "high",
            "confidence": 92.1,
            "source": "finance@suspicious-domain.com",
            "target": "user@company.com",
            "technique": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "description": "Malicious PDF attachment detected",
            "status": "confirmed",
            "risk_score": 7.2,
            "recommended_action": "Quarantine email, scan endpoint",
            "network_element": "dmz",
            "affected_systems": 1,
            "network_indicators": {}
        }
    ]

def _get_sample_missed_detections():
    """Return sample missed detections"""
    return [
        {
            "id": "missed_001",
            "timestamp": "2024-01-15T12:15:00Z",
            "threat_type": "data_exfiltration",
            "severity": "high",
            "source": "10.0.1.100",
            "technique": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "description": "Data exfiltration attempt not detected in real-time",
            "discovered_at": "2024-01-15T14:30:00Z",
            "delay_minutes": 135,
            "reason_missed": "New attack pattern not in ML model",
            "data_indicators": {
                "volume_exfiltrated": "500MB",
                "destination": "external_server_xyz",
                "file_types": ["pdf", "docx", "xlsx"]
            },
            "lessons_learned": [
                "Update ML model with new pattern",
                "Add behavioral rule for large file transfers",
                "Enhance monitoring for off-hours activity"
            ]
        }
    ]

def _format_time_ago(timestamp):
    """Format timestamp to human readable time ago"""
    if not timestamp:
        return "Unknown"
    
    try:
        # Parse timestamp
        time_obj = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        diff = now - time_obj
        
        if diff.total_seconds() < 60:
            return "Now"
        elif diff.total_seconds() < 3600:
            minutes = int(diff.total_seconds() / 60)
            return f"{minutes} mins ago"
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() / 3600)
            return f"{hours} hours ago"
        else:
            days = int(diff.total_seconds() / 86400)
            return f"{days} days ago"
    except:
        return "Unknown"

def _format_threat_name(threat_type):
    """Format threat type to human readable name"""
    threat_names = {
        "malware": "Malware Detection",
        "command_and_control": "C2 Communication",
        "data_exfiltration": "Data Exfiltration",
        "lateral_movement": "Lateral Movement",
        "privilege_escalation": "Privilege Escalation",
        "persistence": "Persistence Mechanism"
    }
    return threat_names.get(threat_type, threat_type.title())

def _get_recommended_action(threat_type, severity):
    """Get recommended action based on threat type and severity"""
    actions = {
        ("command_and_control", "critical"): "Block communication, isolate host",
        ("command_and_control", "high"): "Monitor closely, consider blocking",
        ("malware", "critical"): "Quarantine immediately, full scan",
        ("malware", "high"): "Quarantine email, scan endpoint",
        ("data_exfiltration", "critical"): "Block traffic, investigate source",
        ("data_exfiltration", "high"): "Monitor data flows, alert admin"
    }
    
    return actions.get((threat_type, severity), "Monitor and investigate")

def _calculate_detection_summary(detections):
    """Calculate summary statistics for detections"""
    if not detections:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "avg_confidence": 0}
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    confidence_sum = 0
    
    for detection in detections:
        severity = detection.get('severity', 'low')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        confidence_sum += detection.get('confidence', 0)
    
    avg_confidence = confidence_sum / len(detections) if detections else 0
    
    return {
        **severity_counts,
        "avg_confidence": round(avg_confidence, 1)
    }

