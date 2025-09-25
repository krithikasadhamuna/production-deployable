#!/usr/bin/env python3
"""
MITRE Evaluation Attack Control API
User-controlled attack planning and execution with golden image support
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import asyncio
import logging

# Import MITRE evaluation agent
try:
    from agents.attack_agent.mitre_evaluation_agent import mitre_evaluation_agent
    AGENT_AVAILABLE = True
except ImportError as e:
    logging.warning(f"MITRE evaluation agent not available: {e}")
    AGENT_AVAILABLE = False

logger = logging.getLogger(__name__)
mitre_attack_bp = Blueprint('mitre_attack', __name__)

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(current_app.config.get('DATABASE', 'soc_database.db'))
    conn.row_factory = sqlite3.Row
    return conn

@mitre_attack_bp.route('/attack/network-status', methods=['GET'])
def get_network_status():
    """
    GET /api/attack/network-status
    Get current network topology with online/offline agents
    """
    try:
        if not AGENT_AVAILABLE:
            # Fallback to direct database query
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    id, hostname, ip_address, platform, status,
                    endpoint_importance, user_role, last_heartbeat
                FROM agents
                ORDER BY 
                    CASE status WHEN 'online' THEN 0 ELSE 1 END,
                    CASE endpoint_importance 
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END
            """)
            
            agents = []
            for row in cursor.fetchall():
                agents.append({
                    'id': row['id'],
                    'hostname': row['hostname'],
                    'ip_address': row['ip_address'],
                    'platform': row['platform'],
                    'status': row['status'],
                    'importance': row['endpoint_importance'] or 'medium',
                    'role': row['user_role'] or 'unknown',
                    'last_seen': row['last_heartbeat']
                })
            
            conn.close()
            
            return jsonify({
                'success': True,
                'agents': agents,
                'summary': {
                    'total': len(agents),
                    'online': len([a for a in agents if a['status'] == 'online']),
                    'offline': len([a for a in agents if a['status'] == 'offline'])
                }
            })
        
        # Use MITRE agent for comprehensive topology
        topology = mitre_evaluation_agent.get_network_topology()
        
        return jsonify({
            'success': True,
            'topology': topology,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting network status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mitre_attack_bp.route('/attack/plan', methods=['POST'])
def plan_attack():
    """
    POST /api/attack/plan
    Generate attack plan based on user prompt and network topology
    
    Request body:
    {
        "prompt": "Execute T1082 attack" or "DNS tunneling" or custom scenario,
        "scenario_type": "stealth" | "ransomware" | "exfiltration",
        "targets": ["agent_id1", "agent_id2"] (optional)
    }
    """
    try:
        if not AGENT_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'MITRE evaluation agent not available'
            }), 503
        
        data = request.get_json()
        user_prompt = data.get('prompt', '')
        scenario_type = data.get('scenario_type')
        
        # Run async function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Generate playbook based on user request
            playbook = loop.run_until_complete(
                mitre_evaluation_agent.generate_attack_playbook(user_prompt)
            )
        finally:
            loop.close()
        
        # Store playbook in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO attack_playbooks 
            (id, name, description, created_at, created_by, status, playbook_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            playbook['id'],
            f"User Request: {user_prompt[:50]}",
            user_prompt,
            playbook['created_at'],
            'user',
            'pending_approval',
            json.dumps(playbook)
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'playbook_id': playbook['id'],
            'playbook': playbook,
            'requires_approval': True,
            'message': 'Attack playbook generated. Review and approve before execution.'
        })
        
    except Exception as e:
        logger.error(f"Error planning attack: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mitre_attack_bp.route('/attack/scenarios', methods=['GET'])
def get_attack_scenarios():
    """
    GET /api/attack/scenarios
    Get predefined attack scenarios
    """
    try:
        scenarios = [
            {
                'id': 'apt29_stealth',
                'name': 'APT29 - Stealthy Persistence',
                'description': 'Advanced persistent threat with focus on stealth and data exfiltration',
                'techniques': ['T1078', 'T1053', 'T1055', 'T1021', 'T1048'],
                'duration_minutes': 180,
                'sophistication': 'advanced',
                'objectives': ['persistence', 'exfiltration']
            },
            {
                'id': 'ransomware_fast',
                'name': 'Ransomware - Rapid Encryption',
                'description': 'Fast-moving ransomware attack with lateral movement',
                'techniques': ['T1566', 'T1055', 'T1021', 'T1486', 'T1490'],
                'duration_minutes': 60,
                'sophistication': 'medium',
                'objectives': ['encryption', 'impact']
            },
            {
                'id': 'insider_theft',
                'name': 'Insider Threat - Data Theft',
                'description': 'Malicious insider stealing sensitive data',
                'techniques': ['T1078', 'T1005', 'T1074', 'T1048', 'T1070'],
                'duration_minutes': 120,
                'sophistication': 'low',
                'objectives': ['collection', 'exfiltration']
            },
            {
                'id': 'supply_chain',
                'name': 'Supply Chain Compromise',
                'description': 'Attack through third-party software or services',
                'techniques': ['T1195', 'T1199', 'T1078', 'T1021', 'T1005'],
                'duration_minutes': 240,
                'sophistication': 'advanced',
                'objectives': ['initial_access', 'persistence']
            },
            {
                'id': 'dns_tunnel',
                'name': 'DNS Tunneling Exfiltration',
                'description': 'Covert data exfiltration using DNS protocol',
                'techniques': ['T1071', 'T1048', 'T1005', 'T1074'],
                'duration_minutes': 90,
                'sophistication': 'medium',
                'objectives': ['exfiltration', 'stealth']
            }
        ]
        
        return jsonify({
            'success': True,
            'scenarios': scenarios
        })
        
    except Exception as e:
        logger.error(f"Error getting scenarios: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mitre_attack_bp.route('/attack/techniques', methods=['GET'])
def get_mitre_techniques():
    """
    GET /api/attack/techniques
    Get available MITRE ATT&CK techniques
    """
    techniques = {
        'T1082': {'name': 'System Information Discovery', 'tactic': 'discovery'},
        'T1566': {'name': 'Phishing', 'tactic': 'initial_access'},
        'T1078': {'name': 'Valid Accounts', 'tactic': 'initial_access'},
        'T1053': {'name': 'Scheduled Task/Job', 'tactic': 'persistence'},
        'T1055': {'name': 'Process Injection', 'tactic': 'privilege_escalation'},
        'T1021': {'name': 'Remote Services', 'tactic': 'lateral_movement'},
        'T1005': {'name': 'Data from Local System', 'tactic': 'collection'},
        'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'exfiltration'},
        'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'impact'},
        'T1057': {'name': 'Process Discovery', 'tactic': 'discovery'},
        'T1016': {'name': 'System Network Configuration Discovery', 'tactic': 'discovery'},
        'T1071': {'name': 'Application Layer Protocol', 'tactic': 'command_control'},
        'T1003': {'name': 'OS Credential Dumping', 'tactic': 'credential_access'},
        'T1070': {'name': 'Indicator Removal', 'tactic': 'defense_evasion'}
    }
    
    return jsonify({
        'success': True,
        'techniques': techniques
    })

@mitre_attack_bp.route('/attack/playbook/<playbook_id>/review', methods=['GET'])
def review_playbook(playbook_id):
    """
    GET /api/attack/playbook/{playbook_id}/review
    Review attack playbook before execution
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM attack_playbooks WHERE id = ?
        """, (playbook_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Playbook not found'
            }), 404
        
        playbook = json.loads(row['playbook_data'])
        
        # Add editable sections
        review_data = {
            'id': playbook_id,
            'name': row['name'],
            'description': row['description'],
            'status': row['status'],
            'created_at': row['created_at'],
            'playbook': playbook,
            'editable_elements': {
                'targets': [t for phase in playbook['emulation_plan']['phases'] 
                          for t in phase.get('targets', [])],
                'techniques': [t for phase in playbook['emulation_plan']['phases'] 
                             for t in phase.get('techniques', [])],
                'duration': playbook['emulation_plan'].get('expected_duration'),
                'phases': len(playbook['emulation_plan']['phases'])
            },
            'golden_images_ready': playbook['preparation']['rollback_ready']
        }
        
        conn.close()
        
        return jsonify({
            'success': True,
            'review_data': review_data
        })
        
    except Exception as e:
        logger.error(f"Error reviewing playbook: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mitre_attack_bp.route('/attack/playbook/<playbook_id>/modify', methods=['POST'])
def modify_playbook(playbook_id):
    """
    POST /api/attack/playbook/{playbook_id}/modify
    Modify attack playbook elements before execution
    
    Request body:
    {
        "modifications": {
            "add_targets": ["agent_id"],
            "remove_targets": ["agent_id"],
            "add_techniques": ["T1082"],
            "remove_techniques": ["T1055"],
            "change_duration": 120
        }
    }
    """
    try:
        data = request.get_json()
        modifications = data.get('modifications', {})
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get existing playbook
        cursor.execute("SELECT playbook_data FROM attack_playbooks WHERE id = ?", (playbook_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return jsonify({'success': False, 'error': 'Playbook not found'}), 404
        
        playbook = json.loads(row['playbook_data'])
        
        # Apply modifications
        if 'add_targets' in modifications:
            for phase in playbook['emulation_plan']['phases']:
                phase['targets'].extend(modifications['add_targets'])
        
        if 'remove_targets' in modifications:
            for phase in playbook['emulation_plan']['phases']:
                phase['targets'] = [t for t in phase['targets'] 
                                  if t not in modifications['remove_targets']]
        
        if 'add_techniques' in modifications:
            # Add techniques to appropriate phases
            for tech in modifications['add_techniques']:
                playbook['emulation_plan']['techniques'].append(tech)
        
        if 'change_duration' in modifications:
            playbook['emulation_plan']['expected_duration'] = modifications['change_duration']
        
        # Update database
        cursor.execute("""
            UPDATE attack_playbooks 
            SET playbook_data = ?, modified_at = ?, status = 'modified'
            WHERE id = ?
        """, (json.dumps(playbook), datetime.now(timezone.utc).isoformat(), playbook_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Playbook modified successfully',
            'playbook_id': playbook_id
        })
        
    except Exception as e:
        logger.error(f"Error modifying playbook: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@mitre_attack_bp.route('/attack/playbook/<playbook_id>/approve', methods=['POST'])
def approve_playbook(playbook_id):
    """
    POST /api/attack/playbook/{playbook_id}/approve
    Approve playbook for execution
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE attack_playbooks 
            SET status = 'approved', approved_at = ?, approved_by = ?
            WHERE id = ?
        """, (datetime.now(timezone.utc).isoformat(), 'user', playbook_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Playbook approved for execution',
            'playbook_id': playbook_id
        })
        
    except Exception as e:
        logger.error(f"Error approving playbook: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@mitre_attack_bp.route('/attack/playbook/<playbook_id>/execute', methods=['POST'])
def execute_playbook(playbook_id):
    """
    POST /api/attack/playbook/{playbook_id}/execute
    Execute approved attack playbook
    """
    try:
        if not AGENT_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'MITRE evaluation agent not available'
            }), 503
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get playbook
        cursor.execute("""
            SELECT * FROM attack_playbooks WHERE id = ? AND status = 'approved'
        """, (playbook_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Playbook not found or not approved'
            }), 404
        
        playbook = json.loads(row['playbook_data'])
        
        # Update status to executing
        cursor.execute("""
            UPDATE attack_playbooks 
            SET status = 'executing', execution_started_at = ?
            WHERE id = ?
        """, (datetime.now(timezone.utc).isoformat(), playbook_id))
        
        conn.commit()
        conn.close()
        
        # Execute playbook asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            execution_log = loop.run_until_complete(
                mitre_evaluation_agent.execute_evaluation(
                    playbook['emulation_plan'],
                    require_approval=False  # Already approved
                )
            )
        finally:
            loop.close()
        
        # Update execution results
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE attack_playbooks 
            SET status = ?, execution_completed_at = ?, execution_log = ?
            WHERE id = ?
        """, (execution_log['status'], datetime.now(timezone.utc).isoformat(), 
              json.dumps(execution_log), playbook_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Playbook execution started',
            'playbook_id': playbook_id,
            'execution_log': execution_log
        })
        
    except Exception as e:
        logger.error(f"Error executing playbook: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@mitre_attack_bp.route('/attack/golden-images', methods=['GET'])
def get_golden_images():
    """
    GET /api/attack/golden-images
    Get status of golden images for all agents
    """
    try:
        if not AGENT_AVAILABLE:
            return jsonify({
                'success': True,
                'golden_images': [],
                'message': 'Golden image agent not available'
            })
        
        import os
        golden_dir = mitre_evaluation_agent.golden_images_dir
        
        images = []
        if os.path.exists(golden_dir):
            for folder in os.listdir(golden_dir):
                metadata_path = os.path.join(golden_dir, folder, 'metadata.json')
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                        images.append(metadata)
        
        return jsonify({
            'success': True,
            'golden_images': images,
            'total': len(images)
        })
        
    except Exception as e:
        logger.error(f"Error getting golden images: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@mitre_attack_bp.route('/attack/golden-images/<agent_id>/create', methods=['POST'])
def create_golden_image(agent_id):
    """
    POST /api/attack/golden-images/{agent_id}/create
    Create golden image for specific agent
    """
    try:
        if not AGENT_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'Golden image agent not available'
            }), 503
        
        success = mitre_evaluation_agent.create_golden_image(agent_id)
        
        return jsonify({
            'success': success,
            'agent_id': agent_id,
            'message': 'Golden image created' if success else 'Failed to create golden image'
        })
        
    except Exception as e:
        logger.error(f"Error creating golden image: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@mitre_attack_bp.route('/attack/golden-images/<agent_id>/restore', methods=['POST'])
def restore_golden_image(agent_id):
    """
    POST /api/attack/golden-images/{agent_id}/restore
    Restore agent from golden image
    """
    try:
        if not AGENT_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'Golden image agent not available'
            }), 503
        
        success = mitre_evaluation_agent.restore_from_golden_image(agent_id)
        
        return jsonify({
            'success': success,
            'agent_id': agent_id,
            'message': 'System restored' if success else 'Failed to restore system'
        })
        
    except Exception as e:
        logger.error(f"Error restoring golden image: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Add database tables if needed
def init_attack_tables():
    """Initialize attack-related database tables"""
    conn = sqlite3.connect('soc_database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_playbooks (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            created_at TIMESTAMP,
            created_by TEXT,
            approved_at TIMESTAMP,
            approved_by TEXT,
            modified_at TIMESTAMP,
            execution_started_at TIMESTAMP,
            execution_completed_at TIMESTAMP,
            status TEXT,
            playbook_data TEXT,
            execution_log TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
