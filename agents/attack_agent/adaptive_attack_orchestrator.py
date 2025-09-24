#!/usr/bin/env python3
"""
Adaptive Attack Orchestrator - Production SOC Platform
Dynamically generates attack scenarios based on live network topology and user prompts
No hardcoded scenarios - everything is adaptive and context-aware
"""

import json
import asyncio
import logging
import sqlite3
import requests
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
import uuid
import yaml

logger = logging.getLogger(__name__)

@dataclass
class NetworkContext:
    """Current network topology context for attack planning"""
    domain_controllers: List[Dict]
    endpoints: List[Dict] 
    dmz_servers: List[Dict]
    firewalls: List[Dict]
    soc_systems: List[Dict]
    cloud_resources: List[Dict]
    security_zones: List[str]
    total_agents: int
    high_value_targets: List[Dict]
    attack_paths: List[List[str]]

@dataclass
class AttackScenario:
    """Dynamically generated attack scenario"""
    id: str
    name: str
    description: str
    attack_type: str  # apt, ransomware, insider, supply_chain, etc.
    complexity: str   # simple, intermediate, advanced, expert
    estimated_duration: int  # minutes
    target_elements: List[str]
    attack_path: List[str]
    mitre_techniques: List[str]
    success_criteria: Dict[str, Any]
    risk_level: str
    prerequisites: List[str]
    generated_at: str
    confidence_score: float

@dataclass
class AttackExecution:
    """Attack execution tracking"""
    execution_id: str
    scenario: AttackScenario
    target_agents: List[str]
    status: str  # queued, executing, paused, completed, failed
    started_at: Optional[str]
    completed_at: Optional[str]
    current_phase: str
    phases_completed: List[str]
    results: Dict[str, Any]
    detections_triggered: List[str]
    success_rate: float

class AdaptiveAttackOrchestrator:
    """Production-grade adaptive attack orchestrator for SOC platforms"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.db_path = self._get_db_path()
        self.active_executions: Dict[str, AttackExecution] = {}
        self.network_cache = {}
        self.cache_ttl = 300  # 5 minutes
        self.last_network_scan = None
        
        # APT behavior patterns for dynamic generation
        self.apt_patterns = {
            "apt29": {
                "initial_access": ["T1566.001", "T1190", "T1078"],
                "persistence": ["T1053.005", "T1547.001", "T1136.001"],
                "privilege_escalation": ["T1055", "T1068", "T1134"],
                "lateral_movement": ["T1021.001", "T1021.002", "T1550.002"],
                "collection": ["T1005", "T1039", "T1114.002"],
                "exfiltration": ["T1041", "T1020", "T1567.002"]
            },
            "apt28": {
                "initial_access": ["T1566.001", "T1566.002", "T1190"],
                "persistence": ["T1547.001", "T1136.001", "T1053.005"],
                "defense_evasion": ["T1055", "T1027", "T1070.004"],
                "lateral_movement": ["T1021.001", "T1550.002", "T1076"],
                "collection": ["T1005", "T1074.001", "T1560.001"],
                "command_control": ["T1071.001", "T1573.001"]
            },
            "lazarus": {
                "initial_access": ["T1566.001", "T1190", "T1195.002"],
                "persistence": ["T1547.001", "T1053.005", "T1136.001"],
                "defense_evasion": ["T1027", "T1055", "T1112"],
                "lateral_movement": ["T1021.001", "T1021.002", "T1550.002"],
                "impact": ["T1486", "T1490", "T1491.001"]
            }
        }
        
        logger.info("Adaptive Attack Orchestrator initialized - Production Mode")
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        """Load configuration for production deployment"""
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            return {
                'database': {'path': 'soc_multi_tenant.db'},
                'llm': {
                    'ollama_endpoint': 'http://localhost:11434',
                    'ollama_model': 'cybersec-ai',
                    'fallback_order': ['ollama', 'openai']
                },
                'attack': {
                    'max_concurrent_scenarios': 3,
                    'default_timeout_minutes': 120,
                    'enable_destructive_attacks': False
                }
            }
    
    def _get_db_path(self) -> str:
        """Get database path for production deployment"""
        db_name = self.config.get('database', {}).get('path', 'soc_multi_tenant.db')
        return str(Path(__file__).parent.parent.parent / db_name)
    
    async def get_network_context(self, force_refresh: bool = False) -> NetworkContext:
        """Get current network topology context for attack planning"""
        
        # Check cache first
        if (not force_refresh and 
            self.last_network_scan and 
            (datetime.now() - self.last_network_scan).seconds < self.cache_ttl):
            return self.network_cache.get('context')
        
        logger.info("Scanning network topology for attack planning...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            
            # Get all active agents with their network classifications
            cursor = conn.execute("""
                SELECT id, name, type, hostname, ip_address, network_element_type,
                       network_role, security_zone, subnet, element_confidence,
                       network_characteristics, detected_services, open_ports,
                       status, last_heartbeat
                FROM agents 
                WHERE status IN ('active', 'online', 'idle')
                ORDER BY element_confidence DESC
            """)
            
            agents = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            # Categorize agents by network element type
            domain_controllers = [a for a in agents if a['network_element_type'] == 'domain_controller']
            endpoints = [a for a in agents if a['network_element_type'] == 'endpoint']
            dmz_servers = [a for a in agents if a['security_zone'] == 'dmz']
            firewalls = [a for a in agents if a['network_element_type'] == 'firewall']
            soc_systems = [a for a in agents if a['network_element_type'] == 'soc']
            cloud_resources = [a for a in agents if a['network_element_type'] == 'cloud']
            
            # Identify high-value targets
            high_value_targets = []
            high_value_targets.extend(domain_controllers)  # Always high value
            high_value_targets.extend([a for a in dmz_servers if 'database' in str(a.get('detected_services', ''))])
            high_value_targets.extend([a for a in endpoints if a.get('network_role') == 'admin'])
            
            # Generate potential attack paths
            attack_paths = self._generate_attack_paths(agents)
            
            # Get unique security zones
            security_zones = list(set([a['security_zone'] for a in agents if a['security_zone']]))
            
            context = NetworkContext(
                domain_controllers=domain_controllers,
                endpoints=endpoints,
                dmz_servers=dmz_servers,
                firewalls=firewalls,
                soc_systems=soc_systems,
                cloud_resources=cloud_resources,
                security_zones=security_zones,
                total_agents=len(agents),
                high_value_targets=high_value_targets,
                attack_paths=attack_paths
            )
            
            # Cache the context
            self.network_cache['context'] = context
            self.last_network_scan = datetime.now()
            
            logger.info(f"Network scan complete: {len(agents)} agents, {len(high_value_targets)} HVTs")
            return context
            
        except Exception as e:
            logger.error(f"Network context scan failed: {e}")
            # Return empty context on error
            return NetworkContext([], [], [], [], [], [], [], 0, [], [])
    
    def _generate_attack_paths(self, agents: List[Dict]) -> List[List[str]]:
        """Generate realistic attack paths through the network"""
        paths = []
        
        # Group agents by security zone
        zones = {}
        for agent in agents:
            zone = agent.get('security_zone', 'unknown')
            if zone not in zones:
                zones[zone] = []
            zones[zone].append(agent)
        
        # Generate common attack paths
        # Path 1: External -> DMZ -> Internal -> Secure
        if 'dmz' in zones and 'internal' in zones and 'secure' in zones:
            dmz_agent = zones['dmz'][0]['id'] if zones['dmz'] else None
            internal_agent = zones['internal'][0]['id'] if zones['internal'] else None
            secure_agent = zones['secure'][0]['id'] if zones['secure'] else None
            
            if all([dmz_agent, internal_agent, secure_agent]):
                paths.append([dmz_agent, internal_agent, secure_agent])
        
        # Path 2: Endpoint -> Domain Controller
        endpoints = [a for a in agents if a['network_element_type'] == 'endpoint']
        dcs = [a for a in agents if a['network_element_type'] == 'domain_controller']
        
        if endpoints and dcs:
            paths.append([endpoints[0]['id'], dcs[0]['id']])
        
        # Path 3: DMZ -> Internal endpoints -> Privilege escalation
        dmz_servers = [a for a in agents if a['security_zone'] == 'dmz']
        internal_endpoints = [a for a in agents if a['security_zone'] == 'internal' and a['network_element_type'] == 'endpoint']
        
        if dmz_servers and internal_endpoints and dcs:
            paths.append([dmz_servers[0]['id'], internal_endpoints[0]['id'], dcs[0]['id']])
        
        return paths
    
    async def generate_dynamic_scenario(self, prompt: str, network_context: NetworkContext) -> AttackScenario:
        """Generate attack scenario dynamically based on prompt and network topology"""
        
        logger.info(f"Generating dynamic scenario for prompt: '{prompt[:50]}...'")
        
        # Parse prompt to understand intent
        intent = await self._parse_attack_intent(prompt)
        
        # Select appropriate APT pattern based on intent and network
        apt_pattern = self._select_apt_pattern(intent, network_context)
        
        # Generate scenario using cybersec-ai model
        scenario = await self._ai_generate_scenario(prompt, intent, network_context, apt_pattern)
        
        # Validate and enrich scenario
        validated_scenario = self._validate_scenario(scenario, network_context)
        
        logger.info(f"Generated scenario: {validated_scenario.name}")
        return validated_scenario
    
    async def _parse_attack_intent(self, prompt: str) -> Dict[str, Any]:
        """Parse user prompt to understand attack intent"""
        
        # Use cybersec-ai model for intent recognition
        ollama_endpoint = self.config['llm']['ollama_endpoint']
        ollama_model = self.config['llm']['ollama_model']
        
        intent_prompt = f"""
Analyze this attack request and extract the intent:

User Request: "{prompt}"

Extract and return JSON with:
{{
    "attack_type": "apt|ransomware|insider|supply_chain|credential_harvesting|lateral_movement",
    "target_preference": "random|high_value|specific|all",
    "complexity": "simple|intermediate|advanced|expert",
    "specific_targets": ["agent_id1", "agent_id2"],
    "techniques_requested": ["T1566.001", "T1055"],
    "urgency": "low|medium|high",
    "stealth_level": "loud|moderate|stealthy",
    "objectives": ["credential_theft", "data_exfiltration", "persistence", "disruption"]
}}
"""
        
        try:
            response = requests.post(
                f"{ollama_endpoint}/api/generate",
                json={
                    "model": ollama_model,
                    "prompt": intent_prompt,
                    "stream": False,
                    "options": {"temperature": 0.3}
                },
                timeout=30
            )
            
            if response.status_code == 200:
                ai_response = response.json().get('response', '{}')
                try:
                    intent = json.loads(ai_response)
                    logger.info(f"Parsed intent: {intent.get('attack_type', 'unknown')}")
                    return intent
                except json.JSONDecodeError:
                    logger.warning("AI response was not valid JSON, using fallback parsing")
            
        except Exception as e:
            logger.warning(f"AI intent parsing failed: {e}")
        
        # Fallback: simple keyword-based intent parsing
        return self._fallback_intent_parsing(prompt)
    
    def _fallback_intent_parsing(self, prompt: str) -> Dict[str, Any]:
        """Fallback intent parsing using keywords"""
        prompt_lower = prompt.lower()
        
        # Detect attack type
        attack_type = "apt"  # default
        if any(word in prompt_lower for word in ["ransom", "encrypt", "crypto"]):
            attack_type = "ransomware"
        elif any(word in prompt_lower for word in ["insider", "internal", "employee"]):
            attack_type = "insider"
        elif any(word in prompt_lower for word in ["credential", "password", "hash"]):
            attack_type = "credential_harvesting"
        elif any(word in prompt_lower for word in ["lateral", "pivot", "move"]):
            attack_type = "lateral_movement"
        
        # Detect complexity
        complexity = "intermediate"  # default
        if any(word in prompt_lower for word in ["simple", "basic", "easy"]):
            complexity = "simple"
        elif any(word in prompt_lower for word in ["advanced", "complex", "sophisticated"]):
            complexity = "advanced"
        elif any(word in prompt_lower for word in ["expert", "nation-state", "apt"]):
            complexity = "expert"
        
        return {
            "attack_type": attack_type,
            "target_preference": "high_value",
            "complexity": complexity,
            "specific_targets": [],
            "techniques_requested": [],
            "urgency": "medium",
            "stealth_level": "moderate",
            "objectives": ["persistence", "credential_theft"]
        }
    
    def _select_apt_pattern(self, intent: Dict, network_context: NetworkContext) -> Dict:
        """Select appropriate APT pattern based on intent and network"""
        
        attack_type = intent.get('attack_type', 'apt')
        complexity = intent.get('complexity', 'intermediate')
        
        # Select APT group pattern based on network characteristics
        if len(network_context.domain_controllers) > 0 and len(network_context.endpoints) > 5:
            # Large enterprise - use APT29 pattern
            base_pattern = self.apt_patterns['apt29']
        elif len(network_context.cloud_resources) > 0:
            # Cloud-heavy environment - use APT28 pattern
            base_pattern = self.apt_patterns['apt28']
        else:
            # Smaller environment - use Lazarus pattern
            base_pattern = self.apt_patterns['lazarus']
        
        # Adapt pattern based on attack type
        if attack_type == "ransomware":
            base_pattern = {**base_pattern, "impact": ["T1486", "T1490", "T1491.001"]}
        elif attack_type == "credential_harvesting":
            base_pattern = {**base_pattern, "credential_access": ["T1003.001", "T1558.003", "T1110"]}
        
        return base_pattern
    
    async def _ai_generate_scenario(self, prompt: str, intent: Dict, network_context: NetworkContext, apt_pattern: Dict) -> AttackScenario:
        """Use cybersec-ai model to generate detailed attack scenario"""
        
        ollama_endpoint = self.config['llm']['ollama_endpoint']
        ollama_model = self.config['llm']['ollama_model']
        
        scenario_prompt = f"""
Generate a realistic attack scenario based on this context:

USER REQUEST: "{prompt}"

NETWORK TOPOLOGY:
- Domain Controllers: {len(network_context.domain_controllers)}
- Endpoints: {len(network_context.endpoints)}
- DMZ Servers: {len(network_context.dmz_servers)}
- Security Zones: {network_context.security_zones}
- High Value Targets: {len(network_context.high_value_targets)}

INTENT ANALYSIS: {json.dumps(intent, indent=2)}

APT PATTERN: {json.dumps(apt_pattern, indent=2)}

Generate a JSON response with:
{{
    "name": "Descriptive scenario name",
    "description": "Detailed scenario description",
    "attack_type": "{intent.get('attack_type', 'apt')}",
    "complexity": "{intent.get('complexity', 'intermediate')}",
    "estimated_duration": 120,
    "target_elements": ["specific_agent_types"],
    "attack_path": ["phase1", "phase2", "phase3"],
    "mitre_techniques": ["T1566.001", "T1059.001"],
    "success_criteria": {{
        "credentials_obtained": true,
        "persistence_established": true,
        "data_exfiltrated": false
    }},
    "risk_level": "medium",
    "prerequisites": ["active_endpoints", "network_connectivity"]
}}

Make it realistic for the detected network topology and ensure techniques are appropriate for available targets.
"""
        
        try:
            response = requests.post(
                f"{ollama_endpoint}/api/generate",
                json={
                    "model": ollama_model,
                    "prompt": scenario_prompt,
                    "stream": False,
                    "options": {"temperature": 0.7}
                },
                timeout=60
            )
            
            if response.status_code == 200:
                ai_response = response.json().get('response', '{}')
                try:
                    scenario_data = json.loads(ai_response)
                    
                    # Create AttackScenario object
                    scenario = AttackScenario(
                        id=f"dynamic_{uuid.uuid4().hex[:8]}",
                        name=scenario_data.get('name', 'AI Generated Scenario'),
                        description=scenario_data.get('description', 'Dynamic scenario generated by cybersec-ai'),
                        attack_type=scenario_data.get('attack_type', intent.get('attack_type', 'apt')),
                        complexity=scenario_data.get('complexity', intent.get('complexity', 'intermediate')),
                        estimated_duration=scenario_data.get('estimated_duration', 120),
                        target_elements=scenario_data.get('target_elements', ['endpoint']),
                        attack_path=scenario_data.get('attack_path', ['initial_access', 'persistence', 'lateral_movement']),
                        mitre_techniques=scenario_data.get('mitre_techniques', ['T1566.001', 'T1059.001']),
                        success_criteria=scenario_data.get('success_criteria', {}),
                        risk_level=scenario_data.get('risk_level', 'medium'),
                        prerequisites=scenario_data.get('prerequisites', []),
                        generated_at=datetime.now().isoformat(),
                        confidence_score=0.85
                    )
                    
                    return scenario
                    
                except json.JSONDecodeError:
                    logger.warning("AI scenario generation returned invalid JSON")
            
        except Exception as e:
            logger.warning(f"AI scenario generation failed: {e}")
        
        # Fallback: generate basic scenario
        return self._generate_fallback_scenario(intent, network_context)
    
    def _generate_fallback_scenario(self, intent: Dict, network_context: NetworkContext) -> AttackScenario:
        """Generate basic scenario when AI generation fails"""
        
        attack_type = intent.get('attack_type', 'apt')
        
        # Select techniques based on available targets
        techniques = []
        if network_context.endpoints:
            techniques.extend(['T1566.001', 'T1059.001'])  # Phishing, PowerShell
        if network_context.domain_controllers:
            techniques.extend(['T1078', 'T1003.001'])  # Valid accounts, credential dumping
        if network_context.dmz_servers:
            techniques.extend(['T1190', 'T1105'])  # Exploit public app, ingress transfer
        
        return AttackScenario(
            id=f"fallback_{uuid.uuid4().hex[:8]}",
            name=f"Dynamic {attack_type.title()} Scenario",
            description=f"Adaptive {attack_type} attack targeting available network elements",
            attack_type=attack_type,
            complexity=intent.get('complexity', 'intermediate'),
            estimated_duration=90,
            target_elements=['endpoint'] if network_context.endpoints else ['any'],
            attack_path=['initial_access', 'persistence', 'lateral_movement'],
            mitre_techniques=techniques[:5],  # Limit to 5 techniques
            success_criteria={'persistence_established': True},
            risk_level='medium',
            prerequisites=['active_agents'],
            generated_at=datetime.now().isoformat(),
            confidence_score=0.6
        )
    
    def _validate_scenario(self, scenario: AttackScenario, network_context: NetworkContext) -> AttackScenario:
        """Validate and enrich generated scenario against network reality"""
        
        # Ensure target elements exist in network
        available_elements = []
        if network_context.endpoints:
            available_elements.append('endpoint')
        if network_context.domain_controllers:
            available_elements.append('domain_controller')
        if network_context.dmz_servers:
            available_elements.append('dmz_server')
        if network_context.firewalls:
            available_elements.append('firewall')
        
        # Filter target elements to only include available ones
        valid_targets = [t for t in scenario.target_elements if t in available_elements]
        if not valid_targets:
            valid_targets = available_elements[:1] if available_elements else ['any']
        
        # Update scenario with validated targets
        scenario.target_elements = valid_targets
        
        # Adjust duration based on complexity and network size
        if network_context.total_agents > 10:
            scenario.estimated_duration = int(scenario.estimated_duration * 1.5)
        
        # Update confidence based on network match
        if len(valid_targets) == len(scenario.target_elements):
            scenario.confidence_score = min(scenario.confidence_score + 0.1, 1.0)
        
        return scenario
    
    async def execute_dynamic_scenario(self, scenario: AttackScenario, target_agents: List[str] = None) -> AttackExecution:
        """Execute dynamically generated attack scenario"""
        
        execution_id = f"exec_{scenario.id}_{uuid.uuid4().hex[:8]}"
        
        # Select target agents if not specified
        if not target_agents:
            network_context = await self.get_network_context()
            target_agents = self._select_target_agents(scenario, network_context)
        
        # Create execution tracking
        execution = AttackExecution(
            execution_id=execution_id,
            scenario=scenario,
            target_agents=target_agents,
            status='queued',
            started_at=None,
            completed_at=None,
            current_phase='preparation',
            phases_completed=[],
            results={},
            detections_triggered=[],
            success_rate=0.0
        )
        
        # Store execution
        self.active_executions[execution_id] = execution
        
        # Start execution in background
        asyncio.create_task(self._execute_scenario_phases(execution))
        
        logger.info(f"Started execution {execution_id} for scenario {scenario.name}")
        
        return execution
    
    def _select_target_agents(self, scenario: AttackScenario, network_context: NetworkContext) -> List[str]:
        """Select appropriate target agents for scenario execution"""
        
        targets = []
        
        for target_type in scenario.target_elements:
            if target_type == 'endpoint' and network_context.endpoints:
                targets.append(network_context.endpoints[0]['id'])
            elif target_type == 'domain_controller' and network_context.domain_controllers:
                targets.append(network_context.domain_controllers[0]['id'])
            elif target_type == 'dmz_server' and network_context.dmz_servers:
                targets.append(network_context.dmz_servers[0]['id'])
            elif target_type == 'firewall' and network_context.firewalls:
                targets.append(network_context.firewalls[0]['id'])
        
        # If no specific targets found, use high-value targets
        if not targets and network_context.high_value_targets:
            targets.append(network_context.high_value_targets[0]['id'])
        
        # Fallback: use any available agent
        if not targets and network_context.total_agents > 0:
            # Get first available agent from database
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.execute("SELECT id FROM agents WHERE status = 'active' LIMIT 1")
                result = cursor.fetchone()
                if result:
                    targets.append(result[0])
                conn.close()
            except Exception as e:
                logger.error(f"Error selecting fallback target: {e}")
        
        return targets
    
    async def _execute_scenario_phases(self, execution: AttackExecution):
        """Execute attack scenario phases"""
        
        execution.status = 'executing'
        execution.started_at = datetime.now().isoformat()
        
        try:
            for phase in execution.scenario.attack_path:
                execution.current_phase = phase
                logger.info(f"Executing phase: {phase} for {execution.execution_id}")
                
                # Execute phase (this would integrate with your dynamic attack generator)
                phase_result = await self._execute_phase(execution, phase)
                
                execution.results[phase] = phase_result
                execution.phases_completed.append(phase)
                
                # Check for detections (this would query your detection system)
                detections = await self._check_for_detections(execution)
                execution.detections_triggered.extend(detections)
                
                # Brief pause between phases
                await asyncio.sleep(5)
            
            # Calculate success rate
            execution.success_rate = len(execution.phases_completed) / len(execution.scenario.attack_path)
            execution.status = 'completed'
            execution.completed_at = datetime.now().isoformat()
            
            logger.info(f"Completed execution {execution.execution_id} with {execution.success_rate:.1%} success")
            
        except Exception as e:
            execution.status = 'failed'
            execution.results['error'] = str(e)
            logger.error(f"Execution {execution.execution_id} failed: {e}")
    
    async def _execute_phase(self, execution: AttackExecution, phase: str) -> Dict[str, Any]:
        """Execute individual attack phase"""
        
        # This would integrate with your dynamic attack generator
        # For now, simulate phase execution
        
        phase_techniques = []
        scenario = execution.scenario
        
        # Map phase to techniques
        if phase == 'initial_access':
            phase_techniques = [t for t in scenario.mitre_techniques if t.startswith('T1566') or t.startswith('T1190')]
        elif phase == 'persistence':
            phase_techniques = [t for t in scenario.mitre_techniques if t.startswith('T1547') or t.startswith('T1053')]
        elif phase == 'lateral_movement':
            phase_techniques = [t for t in scenario.mitre_techniques if t.startswith('T1021') or t.startswith('T1550')]
        
        if not phase_techniques:
            phase_techniques = scenario.mitre_techniques[:2]  # Use first 2 techniques
        
        # Simulate command execution (integrate with your dynamic attack generator here)
        commands_executed = []
        for technique in phase_techniques:
            # This is where you'd call your dynamic_attack_generator
            command = f"Simulated command for {technique} in phase {phase}"
            commands_executed.append({
                'technique': technique,
                'command': command,
                'status': 'executed',
                'timestamp': datetime.now().isoformat()
            })
        
        return {
            'phase': phase,
            'techniques': phase_techniques,
            'commands': commands_executed,
            'status': 'completed',
            'duration_seconds': 30
        }
    
    async def _check_for_detections(self, execution: AttackExecution) -> List[str]:
        """Check if attack execution triggered any detections"""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("""
                SELECT id, threat_type, technique 
                FROM detections 
                WHERE timestamp > datetime('now', '-5 minutes')
                AND agent_id IN ({})
            """.format(','.join(['?' for _ in execution.target_agents])), 
            execution.target_agents)
            
            detections = [f"{row[1]}:{row[2]}" for row in cursor.fetchall()]
            conn.close()
            
            return detections
            
        except Exception as e:
            logger.error(f"Error checking detections: {e}")
            return []
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of attack execution"""
        
        execution = self.active_executions.get(execution_id)
        if not execution:
            return None
        
        return {
            'execution_id': execution_id,
            'scenario_name': execution.scenario.name,
            'status': execution.status,
            'current_phase': execution.current_phase,
            'phases_completed': execution.phases_completed,
            'success_rate': execution.success_rate,
            'detections_triggered': len(execution.detections_triggered),
            'started_at': execution.started_at,
            'completed_at': execution.completed_at
        }
    
    def list_active_executions(self) -> List[Dict[str, Any]]:
        """List all active attack executions"""
        
        return [
            {
                'execution_id': exec_id,
                'scenario_name': execution.scenario.name,
                'status': execution.status,
                'target_count': len(execution.target_agents),
                'started_at': execution.started_at
            }
            for exec_id, execution in self.active_executions.items()
            if execution.status in ['queued', 'executing', 'paused']
        ]
    
    async def stop_execution(self, execution_id: str) -> bool:
        """Stop running attack execution"""
        
        execution = self.active_executions.get(execution_id)
        if not execution:
            return False
        
        if execution.status in ['queued', 'executing', 'paused']:
            execution.status = 'stopped'
            execution.completed_at = datetime.now().isoformat()
            logger.info(f"🛑 Stopped execution {execution_id}")
            return True
        
        return False

# Global instance for production use
adaptive_orchestrator = AdaptiveAttackOrchestrator()
