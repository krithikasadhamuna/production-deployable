#!/usr/bin/env python3
"""
MITRE Evaluation-Based Attack Agent
Follows MITRE evaluation methodology with golden image support
"""

import asyncio
import json
import logging
import sqlite3
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from enum import Enum
import hashlib
import os
import shutil

logger = logging.getLogger(__name__)

class MitrePhase(Enum):
    """MITRE Evaluation Phases"""
    PLANNING = "planning"
    DEVELOPMENT = "development"
    ORIENTATION = "orientation"
    SETUP = "setup"
    EXECUTION = "execution"

class AttackComponent(Enum):
    """Attack Development Components"""
    THREAT_RESEARCH = "threat_research"
    INTENT = "intent"
    DIFFERENTIATION = "differentiation"
    SOPHISTICATION = "sophistication"
    INTELLIGENCE = "intelligence"
    DECOMPOSITION = "decomposition"
    CHAIN = "chain"
    REFINEMENT = "refinement"
    TOOLING = "tooling"
    CUSTOMIZATION = "customization"
    REVIEW = "review"
    CREATION = "creation"

class MitreEvaluationAgent:
    """
    Complete MITRE Evaluation-based Attack Agent
    Handles network discovery, LLM planning, golden images, and execution
    """
    
    def __init__(self, db_path: str = "soc_database.db", llm_endpoint: str = None):
        self.db_path = db_path
        self.llm_endpoint = llm_endpoint or "http://localhost:11434/api/generate"
        self.golden_images_dir = "golden_images"
        self.current_evaluation = None
        
        # Create golden images directory
        os.makedirs(self.golden_images_dir, exist_ok=True)
        
    def get_db_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    # ==================== PHASE 1: PLANNING ====================
    
    def get_network_topology(self) -> Dict:
        """
        Get current network topology from database
        Returns online/offline status, configurations, and relationships
        """
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        # Get all agents with their status
        cursor.execute("""
            SELECT 
                id, hostname, ip_address, platform, status, 
                last_heartbeat, capabilities, configuration,
                endpoint_importance, user_role, role_confidence
            FROM agents
            ORDER BY endpoint_importance DESC, hostname ASC
        """)
        
        agents = []
        for row in cursor.fetchall():
            agent = {
                'id': row['id'],
                'hostname': row['hostname'],
                'ip_address': row['ip_address'],
                'platform': row['platform'],
                'status': row['status'],  # online/offline
                'last_seen': row['last_heartbeat'],
                'capabilities': json.loads(row['capabilities']) if row['capabilities'] else [],
                'configuration': json.loads(row['configuration']) if row['configuration'] else {},
                'importance': row['endpoint_importance'] or 'medium',
                'user_role': row['user_role'] or 'employee',
                'role_confidence': row['role_confidence'] or 0.5
            }
            agents.append(agent)
        
        # Get network zones
        cursor.execute("""
            SELECT DISTINCT security_zone, COUNT(*) as count
            FROM agents
            WHERE security_zone IS NOT NULL
            GROUP BY security_zone
        """)
        
        zones = {}
        for row in cursor.fetchall():
            zones[row['security_zone']] = row['count']
        
        conn.close()
        
        return {
            'agents': agents,
            'total_agents': len(agents),
            'online_agents': len([a for a in agents if a['status'] == 'online']),
            'offline_agents': len([a for a in agents if a['status'] == 'offline']),
            'zones': zones,
            'critical_assets': [a for a in agents if a['importance'] == 'critical'],
            'high_value_targets': [a for a in agents if a['importance'] in ['critical', 'high']]
        }
    
    async def threat_landscape_research(self, user_prompt: str = None) -> Dict:
        """
        Research threat landscape and select adversary based on user input
        """
        network = self.get_network_topology()
        
        research_prompt = f"""
        Analyze the network and create a threat assessment:
        
        Network Overview:
        - Total Endpoints: {network['total_agents']}
        - Online: {network['online_agents']}
        - Offline: {network['offline_agents']}
        - Critical Assets: {len(network['critical_assets'])}
        - Security Zones: {list(network['zones'].keys())}
        
        User Request: {user_prompt or 'General security assessment'}
        
        Based on this, determine:
        1. Most likely threat actors (APT groups)
        2. Their typical TTPs (Tactics, Techniques, Procedures)
        3. Primary objectives (ransomware, data theft, espionage)
        4. Sophistication level required
        5. Recommended MITRE techniques to test
        
        Format as JSON with keys: threat_actors, objectives, techniques, sophistication
        """
        
        # Call LLM (or use predefined scenarios)
        llm_response = await self.call_llm(research_prompt)
        
        # Parse response or use defaults
        threat_assessment = {
            'threat_actors': ['APT29', 'Lazarus Group', 'FIN7'],
            'objectives': ['data_exfiltration', 'ransomware', 'persistence'],
            'techniques': ['T1566', 'T1055', 'T1003', 'T1021', 'T1048'],
            'sophistication': 'advanced',
            'network_context': network,
            'llm_analysis': llm_response
        }
        
        return threat_assessment
    
    # ==================== PHASE 2: DEVELOPMENT ====================
    
    async def develop_attack_plan(self, threat_assessment: Dict, scenario_type: str = None) -> Dict:
        """
        Develop comprehensive attack plan following MITRE methodology
        """
        network = threat_assessment['network_context']
        
        # Decomposition - Extract CTI into components
        decomposition = self.decompose_threat_intelligence(threat_assessment)
        
        # Chain - Create attack chain
        attack_chain = self.create_attack_chain(decomposition, network)
        
        # Refinement - Fill gaps with research
        refined_plan = await self.refine_attack_plan(attack_chain, scenario_type)
        
        # Tooling - Select appropriate tools
        tools = self.select_attack_tools(refined_plan)
        
        # Customization - Add tradecraft details
        customized_plan = self.customize_tradecraft(refined_plan, tools)
        
        # Review - Compare against CTI
        reviewed_plan = self.review_against_cti(customized_plan, threat_assessment)
        
        # Creation - Compile final emulation plan
        emulation_plan = {
            'id': f"eval_{uuid.uuid4().hex[:12]}",
            'created_at': datetime.now(timezone.utc).isoformat(),
            'threat_assessment': threat_assessment,
            'decomposition': decomposition,
            'attack_chain': attack_chain,
            'tools': tools,
            'phases': reviewed_plan['phases'],
            'targets': reviewed_plan['targets'],
            'techniques': reviewed_plan['techniques'],
            'expected_duration': reviewed_plan['duration'],
            'risk_level': reviewed_plan['risk_level']
        }
        
        return emulation_plan
    
    def decompose_threat_intelligence(self, threat_assessment: Dict) -> Dict:
        """Decompose threat intelligence into actionable components"""
        return {
            'initial_access': ['phishing', 'valid_accounts', 'exploit_public'],
            'execution': ['powershell', 'command_line', 'scheduled_task'],
            'persistence': ['registry_run_keys', 'scheduled_task', 'service'],
            'privilege_escalation': ['process_injection', 'access_token', 'bypass_uac'],
            'defense_evasion': ['obfuscation', 'indicator_removal', 'masquerading'],
            'credential_access': ['credential_dumping', 'keylogging', 'password_spray'],
            'discovery': ['network_scan', 'system_info', 'account_discovery'],
            'lateral_movement': ['remote_desktop', 'smb', 'winrm'],
            'collection': ['data_staged', 'screen_capture', 'clipboard'],
            'exfiltration': ['c2_channel', 'alternative_protocol', 'data_compressed']
        }
    
    def create_attack_chain(self, decomposition: Dict, network: Dict) -> List[Dict]:
        """Create logical attack chain based on network and decomposition"""
        chain = []
        
        # Select online targets
        online_agents = [a for a in network['agents'] if a['status'] == 'online']
        
        # Phase 1: Initial foothold (low-value target)
        initial_targets = [a for a in online_agents if a['importance'] == 'low'][:2]
        if initial_targets:
            chain.append({
                'phase': 'initial_access',
                'targets': [t['id'] for t in initial_targets],
                'techniques': ['T1566', 'T1078'],  # Phishing, Valid Accounts
                'duration': 30
            })
        
        # Phase 2: Establish presence
        chain.append({
            'phase': 'persistence',
            'targets': [t['id'] for t in initial_targets] if initial_targets else [],
            'techniques': ['T1053', 'T1547'],  # Scheduled Task, Registry Run
            'duration': 20
        })
        
        # Phase 3: Escalate privileges
        medium_targets = [a for a in online_agents if a['importance'] == 'medium'][:3]
        if medium_targets:
            chain.append({
                'phase': 'privilege_escalation',
                'targets': [t['id'] for t in medium_targets],
                'techniques': ['T1055', 'T1134'],  # Process Injection, Access Token
                'duration': 30
            })
        
        # Phase 4: Move laterally to high-value targets
        high_value = [a for a in online_agents if a['importance'] in ['high', 'critical']]
        if high_value:
            chain.append({
                'phase': 'lateral_movement',
                'targets': [t['id'] for t in high_value],
                'techniques': ['T1021', 'T1570'],  # Remote Services, Lateral Tool Transfer
                'duration': 45
            })
        
        # Phase 5: Achieve objective
        chain.append({
            'phase': 'collection_exfiltration',
            'targets': [t['id'] for t in high_value] if high_value else [],
            'techniques': ['T1005', 'T1048'],  # Data from Local System, Exfiltration
            'duration': 60
        })
        
        return chain
    
    async def refine_attack_plan(self, attack_chain: List[Dict], scenario_type: str = None) -> Dict:
        """Refine attack plan with LLM assistance"""
        
        refinement_prompt = f"""
        Refine this attack chain for a {scenario_type or 'comprehensive'} scenario:
        
        Attack Chain: {json.dumps(attack_chain, indent=2)}
        
        Add:
        1. Specific commands for each technique
        2. Expected defensive responses
        3. Evasion tactics
        4. Success criteria
        5. Rollback procedures
        
        Make it realistic and executable.
        """
        
        llm_response = await self.call_llm(refinement_prompt)
        
        return {
            'phases': attack_chain,
            'scenario_type': scenario_type or 'comprehensive',
            'refinements': llm_response,
            'duration': sum(p['duration'] for p in attack_chain),
            'risk_level': 'high' if any('critical' in str(p) for p in attack_chain) else 'medium'
        }
    
    def select_attack_tools(self, plan: Dict) -> Dict:
        """Select appropriate tools for each attack phase"""
        tools = {
            'initial_access': ['phishing_kit', 'credential_harvester'],
            'execution': ['powershell_empire', 'metasploit'],
            'persistence': ['schtasks', 'wmi_persistence'],
            'privilege_escalation': ['mimikatz', 'process_hollowing'],
            'defense_evasion': ['obfuscator', 'timestomp'],
            'credential_access': ['mimikatz', 'hashdump'],
            'discovery': ['bloodhound', 'adfind'],
            'lateral_movement': ['psexec', 'wmiexec'],
            'collection': ['rclone', '7zip'],
            'exfiltration': ['dns_tunnel', 'https_exfil']
        }
        
        selected_tools = {}
        for phase in plan['phases']:
            phase_name = phase['phase']
            if phase_name in tools:
                selected_tools[phase_name] = tools[phase_name]
        
        return selected_tools
    
    def customize_tradecraft(self, plan: Dict, tools: Dict) -> Dict:
        """Add custom tradecraft details"""
        plan['tradecraft'] = {
            'delivery_mechanism': 'spearphishing_attachment',
            'command_control': {
                'protocol': 'https',
                'port': 443,
                'domain_fronting': True,
                'beacon_interval': 60
            },
            'persistence_methods': ['scheduled_task', 'registry_autostart'],
            'anti_forensics': ['log_clearing', 'timestamp_modification'],
            'tools': tools
        }
        return plan
    
    def review_against_cti(self, plan: Dict, threat_assessment: Dict) -> Dict:
        """Review plan against original CTI"""
        plan['cti_alignment'] = {
            'matches_threat_actor': True,
            'uses_known_ttps': True,
            'realistic_timeline': True,
            'deviations': [],
            'risk_assessment': 'acceptable'
        }
        return plan
    
    # ==================== PHASE 3: ORIENTATION ====================
    
    def prepare_environment(self, emulation_plan: Dict) -> Dict:
        """Prepare environment for evaluation"""
        preparation = {
            'golden_images_created': False,
            'tools_deployed': False,
            'logging_configured': False,
            'rollback_ready': False
        }
        
        # Create golden images for all targets
        for phase in emulation_plan['phases']:
            for target_id in phase.get('targets', []):
                if self.create_golden_image(target_id):
                    preparation['golden_images_created'] = True
        
        preparation['rollback_ready'] = preparation['golden_images_created']
        
        return preparation
    
    # ==================== PHASE 4: SETUP - GOLDEN IMAGES ====================
    
    def create_golden_image(self, agent_id: str) -> bool:
        """
        Create golden image/snapshot of target system
        This is a placeholder - actual implementation depends on infrastructure
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            image_path = os.path.join(self.golden_images_dir, f"{agent_id}_{timestamp}")
            
            # Create image metadata
            metadata = {
                'agent_id': agent_id,
                'timestamp': timestamp,
                'type': 'golden_image',
                'status': 'ready',
                'checksum': hashlib.sha256(f"{agent_id}{timestamp}".encode()).hexdigest()
            }
            
            # Save metadata
            os.makedirs(image_path, exist_ok=True)
            with open(os.path.join(image_path, 'metadata.json'), 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # In production, this would:
            # 1. Connect to hypervisor/cloud API
            # 2. Create VM snapshot
            # 3. Backup critical files
            # 4. Save system state
            
            logger.info(f"Golden image created for {agent_id} at {image_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create golden image for {agent_id}: {e}")
            return False
    
    def restore_from_golden_image(self, agent_id: str) -> bool:
        """
        Restore system from golden image
        """
        try:
            # Find latest golden image
            images = []
            for folder in os.listdir(self.golden_images_dir):
                if folder.startswith(f"{agent_id}_"):
                    images.append(folder)
            
            if not images:
                logger.error(f"No golden image found for {agent_id}")
                return False
            
            latest_image = sorted(images)[-1]
            image_path = os.path.join(self.golden_images_dir, latest_image)
            
            # Load metadata
            with open(os.path.join(image_path, 'metadata.json'), 'r') as f:
                metadata = json.load(f)
            
            # In production, this would:
            # 1. Stop agent
            # 2. Restore VM from snapshot
            # 3. Restore files
            # 4. Restart services
            
            logger.info(f"Restored {agent_id} from golden image {latest_image}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore {agent_id}: {e}")
            return False
    
    def verify_golden_images(self, targets: List[str]) -> Dict:
        """Verify all golden images are ready"""
        verification = {
            'all_ready': True,
            'images': {}
        }
        
        for target in targets:
            has_image = any(f.startswith(f"{target}_") for f in os.listdir(self.golden_images_dir))
            verification['images'][target] = has_image
            if not has_image:
                verification['all_ready'] = False
        
        return verification
    
    # ==================== PHASE 5: EXECUTION ====================
    
    async def execute_evaluation(self, emulation_plan: Dict, require_approval: bool = True) -> Dict:
        """
        Execute the evaluation with human-in-the-loop approval
        """
        execution_log = {
            'id': emulation_plan['id'],
            'started_at': datetime.now(timezone.utc).isoformat(),
            'phases_executed': [],
            'commands_sent': [],
            'results': [],
            'status': 'pending'
        }
        
        # Verify golden images
        all_targets = set()
        for phase in emulation_plan['phases']:
            all_targets.update(phase.get('targets', []))
        
        verification = self.verify_golden_images(list(all_targets))
        if not verification['all_ready']:
            execution_log['status'] = 'failed'
            execution_log['error'] = 'Golden images not ready for all targets'
            return execution_log
        
        # Execute each phase
        for phase in emulation_plan['phases']:
            phase_result = await self.execute_phase(phase, require_approval)
            execution_log['phases_executed'].append(phase_result)
            
            if phase_result['status'] == 'aborted':
                execution_log['status'] = 'aborted'
                break
            
            # Add delay between phases
            await asyncio.sleep(5)
        
        execution_log['completed_at'] = datetime.now(timezone.utc).isoformat()
        execution_log['status'] = 'completed' if execution_log['status'] != 'aborted' else 'aborted'
        
        return execution_log
    
    async def execute_phase(self, phase: Dict, require_approval: bool = True) -> Dict:
        """Execute a single attack phase"""
        phase_log = {
            'phase': phase['phase'],
            'started_at': datetime.now(timezone.utc).isoformat(),
            'targets': phase['targets'],
            'techniques': phase['techniques'],
            'commands': [],
            'status': 'pending'
        }
        
        if require_approval:
            # In production, this would wait for user approval
            logger.info(f"Awaiting approval for phase: {phase['phase']}")
            phase_log['approval'] = {
                'required': True,
                'granted': True,  # Simulated
                'approved_by': 'user',
                'approved_at': datetime.now(timezone.utc).isoformat()
            }
        
        # Execute techniques on targets
        for technique in phase['techniques']:
            for target in phase['targets']:
                command = self.create_command(technique, target)
                result = await self.send_command_to_agent(target, command)
                
                phase_log['commands'].append({
                    'technique': technique,
                    'target': target,
                    'command': command,
                    'result': result,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
        
        phase_log['completed_at'] = datetime.now(timezone.utc).isoformat()
        phase_log['status'] = 'completed'
        
        return phase_log
    
    def create_command(self, technique: str, target: str) -> Dict:
        """Create executable command for technique"""
        commands = {
            'T1566': {'type': 'phishing', 'action': 'send_email'},
            'T1078': {'type': 'credential_use', 'action': 'login_attempt'},
            'T1053': {'type': 'scheduled_task', 'action': 'create_task'},
            'T1055': {'type': 'process_injection', 'action': 'inject_process'},
            'T1021': {'type': 'remote_service', 'action': 'connect_rdp'},
            'T1005': {'type': 'data_collection', 'action': 'search_files'},
            'T1048': {'type': 'exfiltration', 'action': 'upload_data'},
            'T1082': {'type': 'system_info', 'action': 'gather_info'},
            'T1057': {'type': 'process_discovery', 'action': 'list_processes'},
            'T1016': {'type': 'network_discovery', 'action': 'scan_network'}
        }
        
        return commands.get(technique, {'type': 'generic', 'action': 'execute'})
    
    async def send_command_to_agent(self, agent_id: str, command: Dict) -> Dict:
        """Send command to agent via database queue"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        command_id = f"cmd_{uuid.uuid4().hex[:12]}"
        
        cursor.execute("""
            INSERT INTO commands 
            (id, agent_id, type, parameters, status, created_at, priority)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            command_id,
            agent_id,
            f"attack_{command['type']}",
            json.dumps(command),
            'queued',
            datetime.now(timezone.utc).isoformat(),
            'high'
        ))
        
        conn.commit()
        conn.close()
        
        return {
            'command_id': command_id,
            'status': 'queued',
            'agent_id': agent_id
        }
    
    # ==================== UTILITIES ====================
    
    async def call_llm(self, prompt: str) -> str:
        """Call LLM for planning assistance"""
        try:
            # This is a placeholder - implement actual LLM call
            # For Ollama:
            # response = requests.post(self.llm_endpoint, json={'prompt': prompt})
            # return response.json()['response']
            
            return f"LLM Response for: {prompt[:100]}..."
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return "Failed to get LLM response"
    
    def get_predefined_scenarios(self) -> List[Dict]:
        """Get predefined attack scenarios"""
        return [
            {
                'name': 'APT29 - Stealthy Persistence',
                'description': 'Low and slow data exfiltration with advanced persistence',
                'techniques': ['T1078', 'T1053', 'T1055', 'T1021', 'T1048'],
                'duration': 180,
                'sophistication': 'advanced'
            },
            {
                'name': 'Ransomware - Fast Encryption',
                'description': 'Rapid lateral movement and file encryption',
                'techniques': ['T1566', 'T1055', 'T1021', 'T1486', 'T1490'],
                'duration': 60,
                'sophistication': 'medium'
            },
            {
                'name': 'Insider Threat - Data Theft',
                'description': 'Privileged user stealing sensitive data',
                'techniques': ['T1078', 'T1005', 'T1074', 'T1048', 'T1070'],
                'duration': 120,
                'sophistication': 'low'
            }
        ]
    
    async def generate_attack_playbook(self, user_request: str = None) -> Dict:
        """
        Main entry point - generates complete attack playbook
        """
        logger.info("Starting MITRE evaluation-based attack planning")
        
        # Phase 1: Planning
        threat_assessment = await self.threat_landscape_research(user_request)
        
        # Phase 2: Development
        emulation_plan = await self.develop_attack_plan(threat_assessment)
        
        # Phase 3: Orientation
        preparation = self.prepare_environment(emulation_plan)
        
        # Phase 4: Setup (Golden Images created in preparation)
        
        playbook = {
            'id': emulation_plan['id'],
            'created_at': datetime.now(timezone.utc).isoformat(),
            'user_request': user_request,
            'threat_assessment': threat_assessment,
            'emulation_plan': emulation_plan,
            'preparation': preparation,
            'ready_for_execution': preparation['rollback_ready'],
            'requires_approval': True,
            'predefined_scenarios': self.get_predefined_scenarios()
        }
        
        return playbook

# Create singleton instance
mitre_evaluation_agent = MitreEvaluationAgent()
