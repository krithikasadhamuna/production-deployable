"""
Attack Agent APIs
Implements all attack scenario and timeline endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import uuid
from functools import wraps

attacks_bp = Blueprint('attacks', __name__)

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

@attacks_bp.route('/attack_scenarios', methods=['GET'])
@require_auth
def get_attack_scenarios():
    """
    GET /api/attack_scenarios
    List all available attack scenarios
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM attack_scenarios")
        scenarios_raw = cursor.fetchall()
        conn.close()
        
        scenarios = []
        for scenario in scenarios_raw:
            scenario_data = {
                "id": scenario['id'],
                "name": scenario['name'],
                "description": scenario['description'],
                "apt_group": scenario['apt_group'],
                "country": scenario['country'],
                "difficulty": scenario['difficulty'],
                "duration_minutes": scenario['duration_minutes'],
                "impact": scenario['impact'],
                "techniques": json.loads(scenario['techniques']) if scenario['techniques'] else [],
                "target_sectors": json.loads(scenario['target_sectors']) if scenario['target_sectors'] else [],
                "motivation": scenario['motivation']
            }
            scenarios.append(scenario_data)
        
        # If no scenarios in DB, return sample data
        if not scenarios:
            scenarios = _get_sample_scenarios()
        
        return jsonify({
            "success": True,
            "scenarios": scenarios,
            "total": len(scenarios)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@attacks_bp.route('/attack_scenarios/execute', methods=['POST'])
@require_auth
def execute_attack_scenario():
    """
    POST /api/attack_scenarios/execute
    Execute an attack scenario
    """
    try:
        data = request.get_json()
        
        if not data or 'scenario_id' not in data or 'agent_id' not in data:
            return jsonify({
                "success": False,
                "error": "Missing required fields: scenario_id, agent_id",
                "error_code": "INVALID_PARAMETERS"
            }), 400
        
        scenario_id = data['scenario_id']
        agent_id = data['agent_id']
        priority = data.get('priority', 'normal')
        parameters = data.get('parameters', {})
        
        # Check if scenario exists
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM attack_scenarios WHERE id = ?", (scenario_id,))
        scenario = cursor.fetchone()
        
        if not scenario:
            conn.close()
            return jsonify({
                "success": False,
                "error": "Attack scenario not found",
                "error_code": "SCENARIO_NOT_FOUND"
            }), 404
        
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
        
        # Generate command ID and create timeline entry
        command_id = f"cmd_{uuid.uuid4().hex[:12]}"
        timeline_id = f"attack_{uuid.uuid4().hex[:6]}"
        
        now = datetime.now(timezone.utc)
        scheduled_at = now
        
        # Override duration if specified in parameters
        duration = parameters.get('duration_override', scenario['duration_minutes'])
        
        # Insert into attack timeline
        cursor.execute("""
            INSERT INTO attack_timeline 
            (id, scenario_id, scenario_name, agent_id, agent_name, status, started_at, 
             duration_minutes, techniques_executed, targets_affected, success_rate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timeline_id,
            scenario_id,
            scenario['name'],
            agent_id,
            agent['name'],
            'queued',
            now.isoformat(),
            duration,
            scenario['techniques'],
            parameters.get('target_count', 10),
            0.0
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "command_id": command_id,
            "scenario_id": scenario_id,
            "agent_id": agent_id,
            "message": "Attack scenario queued for execution",
            "estimated_duration": duration,
            "scheduled_at": scheduled_at.isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@attacks_bp.route('/attack_timeline', methods=['GET'])
@require_auth
def get_attack_timeline():
    """
    GET /api/attack_timeline
    Get attack execution timeline
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT * FROM attack_timeline 
            ORDER BY started_at DESC
        """)
        timeline_raw = cursor.fetchall()
        conn.close()
        
        timeline = []
        for entry in timeline_raw:
            timeline_data = {
                "id": entry['id'],
                "scenario_id": entry['scenario_id'],
                "scenario_name": entry['scenario_name'],
                "agent_id": entry['agent_id'],
                "agent_name": entry['agent_name'],
                "status": entry['status'],
                "started_at": entry['started_at'],
                "completed_at": entry['completed_at'],
                "duration_minutes": entry['duration_minutes'],
                "techniques_executed": json.loads(entry['techniques_executed']) if entry['techniques_executed'] else [],
                "targets_affected": entry['targets_affected'],
                "success_rate": entry['success_rate'],
                "results": json.loads(entry['results']) if entry['results'] else {}
            }
            timeline.append(timeline_data)
        
        # If no timeline in DB, return sample data
        if not timeline:
            timeline = _get_sample_timeline()
        
        return jsonify({
            "success": True,
            "timeline": timeline,
            "total": len(timeline)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@attacks_bp.route('/attack_scenarios/<scenario_id>', methods=['GET'])
@require_auth
def get_attack_scenario(scenario_id):
    """
    GET /api/attack_scenarios/{scenario_id}
    Get specific attack scenario details
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM attack_scenarios WHERE id = ?", (scenario_id,))
        scenario = cursor.fetchone()
        conn.close()
        
        if not scenario:
            # Try to find in sample scenarios
            sample_scenarios = _get_sample_scenarios()
            scenario_data = next((s for s in sample_scenarios if s['id'] == scenario_id), None)
            
            if not scenario_data:
                return jsonify({
                    "success": False,
                    "error": "Attack scenario not found",
                    "error_code": "SCENARIO_NOT_FOUND"
                }), 404
        else:
            scenario_data = {
                "id": scenario['id'],
                "name": scenario['name'],
                "description": scenario['description'],
                "playbook_steps": json.loads(scenario['playbook_steps']) if scenario['playbook_steps'] else [],
                "required_capabilities": ["Email Simulation", "Web Exploitation", "Social Engineering"],
                "estimated_duration": scenario['duration_minutes'],
                "difficulty": scenario['difficulty'],
                "mitre_techniques": _get_mitre_techniques(json.loads(scenario['techniques']) if scenario['techniques'] else [])
            }
        
        return jsonify({
            "success": True,
            "scenario": scenario_data
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

# Helper functions
def _get_sample_scenarios():
    """Return sample attack scenarios"""
    return [
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
            "motivation": "Espionage, Intelligence Gathering",
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
            "mitre_techniques": [
                {
                    "id": "T1566.001",
                    "name": "Spearphishing Attachment",
                    "tactic": "Initial Access"
                },
                {
                    "id": "T1071.001", 
                    "name": "Web Protocols",
                    "tactic": "Command and Control"
                }
            ]
        },
        {
            "id": "lazarus_financial_heist",
            "name": "Lazarus Financial Heist",
            "description": "Advanced persistent threat campaign targeting financial institutions using custom malware and SWIFT network exploitation",
            "apt_group": "Lazarus Group",
            "country": "North Korea",
            "difficulty": "expert",
            "duration_minutes": 120,
            "impact": "Critical Impact",
            "techniques": ["T1190", "T1078", "T1055", "T1041"],
            "target_sectors": ["Financial Services", "Banking", "Cryptocurrency"],
            "motivation": "Financial Gain, State Funding"
        }
    ]

def _get_sample_timeline():
    """Return sample attack timeline"""
    return [
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
            "success_rate": 85.5,
            "results": {
                "emails_sent": 50,
                "clicks_received": 12,
                "payloads_executed": 8,
                "lateral_moves": 3
            }
        }
    ]

def _get_mitre_techniques(technique_ids):
    """Convert technique IDs to detailed objects"""
    technique_map = {
        "T1566.001": {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
        "T1071.001": {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
        "T1027": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
        "T1055": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
        "T1190": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        "T1078": {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        "T1041": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}
    }
    
    return [technique_map.get(tid, {"id": tid, "name": "Unknown Technique", "tactic": "Unknown"}) for tid in technique_ids]


