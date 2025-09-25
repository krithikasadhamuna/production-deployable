"""
LangGraph Attack Workflow with Nodes and Tools
Complete MITRE evaluation-based attack agent using LangGraph
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, TypedDict, Annotated, Sequence
from enum import Enum
from datetime import datetime, timezone
import uuid

# LangGraph imports
try:
    from langgraph.graph import StateGraph, END
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
    from langgraph.prebuilt import ToolExecutor
    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    logging.warning("LangGraph not available. Install with: pip install langgraph")

# Import our tools
from ..tools.network_tools import NetworkDiscoveryTool, VulnerabilityAnalysisTool, AttackScenarioTool, CommandExecutionTool
from ..tools.golden_image_tools import GoldenImageTool
from ..tools.llm_manager import llm_manager, LLMProvider
from ..prompts.attack_prompts import attack_prompts

logger = logging.getLogger(__name__)

# ============= STATE DEFINITION =============

class AttackPhase(Enum):
    """Attack workflow phases"""
    PLANNING = "planning"
    NETWORK_DISCOVERY = "network_discovery"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    THREAT_ASSESSMENT = "threat_assessment"
    SCENARIO_GENERATION = "scenario_generation"
    TARGET_PRIORITIZATION = "target_prioritization"
    ATTACK_PLANNING = "attack_planning"
    USER_REVIEW = "user_review"
    GOLDEN_IMAGE_CREATION = "golden_image_creation"
    EXECUTION = "execution"
    MONITORING = "monitoring"
    RESTORATION = "restoration"
    COMPLETE = "complete"

class AttackState(TypedDict):
    """State for attack workflow"""
    # User inputs
    user_request: str
    scenario_type: str
    constraints: Dict
    
    # Network information
    network_topology: Dict
    online_agents: List[Dict]
    offline_agents: List[Dict]
    critical_assets: List[Dict]
    
    # Analysis results
    vulnerabilities: Dict
    threat_assessment: Dict
    
    # Attack planning
    attack_scenarios: List[Dict]
    selected_scenario: Dict
    attack_plan: Dict
    target_priority: List[str]
    techniques_selected: List[str]
    
    # Execution
    golden_images: Dict
    execution_log: List[Dict]
    commands_sent: List[Dict]
    results_received: List[Dict]
    
    # Control
    current_phase: AttackPhase
    requires_approval: bool
    approved: bool
    abort: bool
    
    # LLM
    llm_provider: str
    llm_responses: List[Dict]
    
    # Messages/History
    messages: Sequence[str]
    errors: List[str]

# ============= NODES =============

class AttackWorkflowNodes:
    """Nodes for the attack workflow"""
    
    def __init__(self):
        # Initialize tools
        self.network_tool = NetworkDiscoveryTool()
        self.vuln_tool = VulnerabilityAnalysisTool()
        self.scenario_tool = AttackScenarioTool()
        self.command_tool = CommandExecutionTool()
        self.golden_image_tool = GoldenImageTool()
        
        # Tool executor for LangGraph
        self.tools = [
            self.network_tool,
            self.vuln_tool,
            self.scenario_tool,
            self.command_tool,
            self.golden_image_tool
        ]
    
    async def network_discovery_node(self, state: AttackState) -> AttackState:
        """Discover network topology and agent status"""
        logger.info("Executing network discovery node")
        
        try:
            # Run network discovery tool
            network_data = self.network_tool.run("all")
            
            if network_data['success']:
                # Update state with network information
                state['network_topology'] = network_data
                state['online_agents'] = [a for a in network_data['agents'] if a['status'] == 'online']
                state['offline_agents'] = [a for a in network_data['agents'] if a['status'] == 'offline']
                state['critical_assets'] = [a for a in network_data['agents'] if a['importance'] == 'critical']
                
                # Get LLM analysis of network
                prompt = attack_prompts.get_prompt(
                    'network_analysis',
                    total_endpoints=len(network_data['agents']),
                    online_agents=len(state['online_agents']),
                    offline_agents=len(state['offline_agents']),
                    critical_assets=state['critical_assets'],
                    security_zones=list(set(a.get('security_zone', 'unknown') for a in network_data['agents'])),
                    endpoint_details=json.dumps(network_data['agents'][:10], indent=2)  # First 10 for analysis
                )
                
                llm_response = await llm_manager.generate(
                    prompt,
                    provider=LLMProvider(state.get('llm_provider', 'ollama'))
                )
                
                state['llm_responses'].append({
                    'phase': 'network_discovery',
                    'response': llm_response,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                
                state['messages'].append(f"Network discovery complete: {len(network_data['agents'])} agents found")
            else:
                state['errors'].append(f"Network discovery failed: {network_data.get('error')}")
            
            state['current_phase'] = AttackPhase.VULNERABILITY_ANALYSIS
            
        except Exception as e:
            logger.error(f"Network discovery error: {e}")
            state['errors'].append(str(e))
        
        return state
    
    async def vulnerability_analysis_node(self, state: AttackState) -> AttackState:
        """Analyze vulnerabilities in discovered endpoints"""
        logger.info("Executing vulnerability analysis node")
        
        try:
            # Run vulnerability analysis tool
            vuln_data = self.vuln_tool.run(state['online_agents'])
            
            if vuln_data['success']:
                state['vulnerabilities'] = vuln_data
                
                # Get LLM analysis of vulnerabilities
                prompt = attack_prompts.get_prompt(
                    'vulnerability_analysis',
                    endpoints_json=json.dumps(state['online_agents'][:10], indent=2)
                )
                
                llm_response = await llm_manager.generate(
                    prompt,
                    provider=LLMProvider(state.get('llm_provider', 'ollama'))
                )
                
                state['llm_responses'].append({
                    'phase': 'vulnerability_analysis',
                    'response': llm_response,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                
                state['messages'].append(f"Vulnerability analysis complete: {vuln_data['total_vulnerabilities']} vulnerabilities found")
            else:
                state['errors'].append("Vulnerability analysis failed")
            
            state['current_phase'] = AttackPhase.THREAT_ASSESSMENT
            
        except Exception as e:
            logger.error(f"Vulnerability analysis error: {e}")
            state['errors'].append(str(e))
        
        return state
    
    async def threat_assessment_node(self, state: AttackState) -> AttackState:
        """Assess threats based on user request and network"""
        logger.info("Executing threat assessment node")
        
        try:
            # Get LLM threat assessment
            prompt = attack_prompts.get_prompt(
                'threat_assessment',
                user_request=state['user_request'],
                industry='Technology',  # Could be dynamic
                organization_size=len(state['network_topology'].get('agents', [])),
                critical_assets=state['critical_assets'],
                current_threats='APT groups, Ransomware, Insider threats'
            )
            
            llm_response = await llm_manager.generate(
                prompt,
                provider=LLMProvider(state.get('llm_provider', 'ollama'))
            )
            
            # Parse or structure the response
            state['threat_assessment'] = {
                'analysis': llm_response,
                'threat_level': 'high',  # Could be parsed from LLM
                'recommended_approach': 'stealthy' if 'stealth' in state['user_request'].lower() else 'aggressive',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            state['llm_responses'].append({
                'phase': 'threat_assessment',
                'response': llm_response,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            state['messages'].append("Threat assessment complete")
            state['current_phase'] = AttackPhase.SCENARIO_GENERATION
            
        except Exception as e:
            logger.error(f"Threat assessment error: {e}")
            state['errors'].append(str(e))
        
        return state
    
    async def scenario_generation_node(self, state: AttackState) -> AttackState:
        """Generate attack scenarios based on analysis"""
        logger.info("Executing scenario generation node")
        
        try:
            # Use tool to generate base scenarios
            scenarios = self.scenario_tool.run(
                state['network_topology'],
                state['vulnerabilities']
            )
            
            # Enhance with LLM
            prompt = attack_prompts.get_prompt(
                'scenario_generation',
                user_request=state['user_request'],
                targets=json.dumps([a['hostname'] for a in state['online_agents'][:5]]),
                time_limit=state['constraints'].get('time_limit', '4 hours'),
                constraints=json.dumps(state['constraints']),
                scenario_type=state.get('scenario_type', 'Custom Attack')
            )
            
            llm_response = await llm_manager.generate(
                prompt,
                provider=LLMProvider(state.get('llm_provider', 'ollama'))
            )
            
            state['attack_scenarios'] = scenarios
            state['llm_responses'].append({
                'phase': 'scenario_generation',
                'response': llm_response,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            # Select first scenario by default (user can change)
            if scenarios:
                state['selected_scenario'] = scenarios[0]
            
            state['messages'].append(f"Generated {len(scenarios)} attack scenarios")
            state['current_phase'] = AttackPhase.TARGET_PRIORITIZATION
            
        except Exception as e:
            logger.error(f"Scenario generation error: {e}")
            state['errors'].append(str(e))
        
        return state
    
    async def target_prioritization_node(self, state: AttackState) -> AttackState:
        """Prioritize targets for attack"""
        logger.info("Executing target prioritization node")
        
        try:
            # Get LLM to prioritize targets
            prompt = attack_prompts.get_prompt(
                'target_prioritization',
                targets_list=json.dumps([{
                    'id': a['id'],
                    'hostname': a['hostname'],
                    'importance': a['importance'],
                    'role': a.get('user_role', 'unknown')
                } for a in state['online_agents']]),
                objectives=state['selected_scenario'].get('objectives', ['compromise']),
                time_limit=state['constraints'].get('time_limit', '4 hours'),
                resources='unlimited',
                risk_tolerance=state['constraints'].get('risk_tolerance', 'medium')
            )
            
            llm_response = await llm_manager.generate(
                prompt,
                provider=LLMProvider(state.get('llm_provider', 'ollama'))
            )
            
            # Create priority list (could parse from LLM response)
            priority_targets = []
            
            # Priority 1: Low-value for initial access
            low_value = [a['id'] for a in state['online_agents'] if a['importance'] == 'low'][:2]
            priority_targets.extend(low_value)
            
            # Priority 2: Medium for escalation
            medium_value = [a['id'] for a in state['online_agents'] if a['importance'] == 'medium'][:3]
            priority_targets.extend(medium_value)
            
            # Priority 3: High-value targets
            high_value = [a['id'] for a in state['online_agents'] if a['importance'] in ['high', 'critical']]
            priority_targets.extend(high_value)
            
            state['target_priority'] = priority_targets
            state['llm_responses'].append({
                'phase': 'target_prioritization',
                'response': llm_response,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            state['messages'].append(f"Prioritized {len(priority_targets)} targets")
            state['current_phase'] = AttackPhase.ATTACK_PLANNING
            
        except Exception as e:
            logger.error(f"Target prioritization error: {e}")
            state['errors'].append(str(e))
        
        return state
    
    async def attack_planning_node(self, state: AttackState) -> AttackState:
        """Create detailed attack plan"""
        logger.info("Executing attack planning node")
        
        try:
            # Get LLM to create detailed plan
            prompt = attack_prompts.get_prompt(
                'attack_planning',
                network_topology=json.dumps(state['network_topology']['statistics']),
                vulnerabilities=json.dumps(state['vulnerabilities'].get('summary', {})),
                attack_objective=state['user_request'],
                time_limit=state['constraints'].get('time_limit', '4 hours'),
                sophistication=state['threat_assessment'].get('recommended_approach', 'medium')
            )
            
            llm_response = await llm_manager.generate(
                prompt,
                provider=LLMProvider(state.get('llm_provider', 'ollama'))
            )
            
            # Structure the attack plan
            attack_plan = {
                'id': f"plan_{uuid.uuid4().hex[:12]}",
                'name': f"Attack Plan - {state['user_request'][:50]}",
                'scenario': state['selected_scenario'],
                'phases': state['selected_scenario'].get('phases', []),
                'targets': state['target_priority'],
                'techniques': [],
                'llm_plan': llm_response,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'requires_approval': True
            }
            
            # Extract techniques from scenario
            for phase in attack_plan['phases']:
                attack_plan['techniques'].extend(phase.get('techniques', []))
            
            state['attack_plan'] = attack_plan
            state['techniques_selected'] = attack_plan['techniques']
            state['llm_responses'].append({
                'phase': 'attack_planning',
                'response': llm_response,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            state['messages'].append("Attack plan created - requires approval")
            state['current_phase'] = AttackPhase.USER_REVIEW
            state['requires_approval'] = True
            
        except Exception as e:
            logger.error(f"Attack planning error: {e}")
            state['errors'].append(str(e))
        
        return state
    
    async def user_review_node(self, state: AttackState) -> AttackState:
        """Wait for user review and approval"""
        logger.info("Awaiting user review and approval")
        
        # In a real implementation, this would pause and wait for user input
        # For now, we'll simulate approval
        state['messages'].append("Attack plan pending user approval")
        
        # Check if already approved
        if state.get('approved', False):
            state['current_phase'] = AttackPhase.GOLDEN_IMAGE_CREATION
            state['messages'].append("Attack plan approved by user")
        else:
            state['messages'].append("Waiting for user approval...")
            # In production, this would actually pause the workflow
        
        return state
    
    async def golden_image_creation_node(self, state: AttackState) -> AttackState:
        """Create golden images for all targets"""
        logger.info("Creating golden images for targets")
        
        try:
            golden_images = {}
            targets = state['target_priority']
            
            for target_id in targets:
                result = self.golden_image_tool.create_golden_image(
                    target_id,
                    image_type='full',
                    metadata={'attack_plan_id': state['attack_plan']['id']}
                )
                
                if result['success']:
                    golden_images[target_id] = result
                    logger.info(f"Golden image created for {target_id}")
                else:
                    state['errors'].append(f"Failed to create golden image for {target_id}: {result.get('error')}")
            
            state['golden_images'] = golden_images
            
            # Verify all images created
            verification = self.golden_image_tool.verify_golden_images(targets)
            
            if verification['all_ready']:
                state['messages'].append(f"Golden images created for {len(golden_images)} targets")
                state['current_phase'] = AttackPhase.EXECUTION
            else:
                state['errors'].append("Not all golden images ready")
                state['abort'] = True
            
        except Exception as e:
            logger.error(f"Golden image creation error: {e}")
            state['errors'].append(str(e))
            state['abort'] = True
        
        return state
    
    async def execution_node(self, state: AttackState) -> AttackState:
        """Execute the attack plan"""
        logger.info("Executing attack plan")
        
        try:
            execution_log = []
            commands_sent = []
            
            # Execute each phase
            for phase in state['attack_plan']['phases']:
                phase_log = {
                    'phase': phase['name'],
                    'started_at': datetime.now(timezone.utc).isoformat(),
                    'targets': phase['targets'],
                    'techniques': phase['techniques'],
                    'commands': []
                }
                
                # Execute techniques on targets
                for technique in phase['techniques']:
                    for target_id in phase['targets']:
                        # Check if target is in our priority list
                        if target_id in state['target_priority']:
                            result = self.command_tool.run(
                                target_id,
                                technique,
                                {'phase': phase['name']}
                            )
                            
                            if result['success']:
                                commands_sent.append(result)
                                phase_log['commands'].append(result)
                            else:
                                state['errors'].append(f"Failed to send command: {result.get('error')}")
                
                phase_log['completed_at'] = datetime.now(timezone.utc).isoformat()
                execution_log.append(phase_log)
                
                # Simulate delay between phases
                await asyncio.sleep(2)
                
                # Check for abort
                if state.get('abort', False):
                    state['messages'].append("Attack execution aborted")
                    break
            
            state['execution_log'] = execution_log
            state['commands_sent'] = commands_sent
            state['messages'].append(f"Attack executed: {len(commands_sent)} commands sent")
            state['current_phase'] = AttackPhase.MONITORING
            
        except Exception as e:
            logger.error(f"Execution error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = AttackPhase.RESTORATION
        
        return state
    
    async def monitoring_node(self, state: AttackState) -> AttackState:
        """Monitor attack execution and collect results"""
        logger.info("Monitoring attack execution")
        
        # In production, this would monitor command results
        # For now, simulate monitoring
        state['messages'].append("Monitoring attack execution...")
        
        # Simulate some results
        state['results_received'] = [
            {
                'command_id': cmd['command_id'],
                'status': 'completed',
                'output': 'Command executed successfully'
            }
            for cmd in state.get('commands_sent', [])[:5]
        ]
        
        state['messages'].append(f"Received {len(state['results_received'])} results")
        state['current_phase'] = AttackPhase.COMPLETE
        
        return state
    
    async def restoration_node(self, state: AttackState) -> AttackState:
        """Restore systems from golden images if needed"""
        logger.info("Restoration node - checking if restoration needed")
        
        if state.get('abort', False) or state['errors']:
            state['messages'].append("Restoring systems from golden images...")
            
            for target_id, image_info in state.get('golden_images', {}).items():
                result = self.golden_image_tool.restore_golden_image(
                    target_id,
                    image_info['image_id']
                )
                
                if result['success']:
                    state['messages'].append(f"Restored {target_id}")
                else:
                    state['errors'].append(f"Failed to restore {target_id}")
        
        state['current_phase'] = AttackPhase.COMPLETE
        return state
    
    def should_continue(self, state: AttackState) -> str:
        """Determine next node based on state"""
        if state.get('abort', False):
            return 'restoration'
        
        phase = state.get('current_phase', AttackPhase.PLANNING)
        
        if phase == AttackPhase.PLANNING:
            return 'network_discovery'
        elif phase == AttackPhase.NETWORK_DISCOVERY:
            return 'network_discovery'
        elif phase == AttackPhase.VULNERABILITY_ANALYSIS:
            return 'vulnerability_analysis'
        elif phase == AttackPhase.THREAT_ASSESSMENT:
            return 'threat_assessment'
        elif phase == AttackPhase.SCENARIO_GENERATION:
            return 'scenario_generation'
        elif phase == AttackPhase.TARGET_PRIORITIZATION:
            return 'target_prioritization'
        elif phase == AttackPhase.ATTACK_PLANNING:
            return 'attack_planning'
        elif phase == AttackPhase.USER_REVIEW:
            if state.get('approved', False):
                return 'golden_image_creation'
            else:
                return 'user_review'
        elif phase == AttackPhase.GOLDEN_IMAGE_CREATION:
            return 'golden_image_creation'
        elif phase == AttackPhase.EXECUTION:
            return 'execution'
        elif phase == AttackPhase.MONITORING:
            return 'monitoring'
        elif phase == AttackPhase.RESTORATION:
            return 'restoration'
        else:
            return END


# ============= WORKFLOW BUILDER =============

class AttackWorkflow:
    """Main attack workflow using LangGraph"""
    
    def __init__(self, checkpoint_dir: str = "checkpoints"):
        if not LANGGRAPH_AVAILABLE:
            raise ImportError("LangGraph not installed. Run: pip install langgraph")
        
        self.nodes = AttackWorkflowNodes()
        self.checkpoint_dir = checkpoint_dir
        self.workflow = self._build_workflow()
    
    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow"""
        workflow = StateGraph(AttackState)
        
        # Add nodes
        workflow.add_node("network_discovery", self.nodes.network_discovery_node)
        workflow.add_node("vulnerability_analysis", self.nodes.vulnerability_analysis_node)
        workflow.add_node("threat_assessment", self.nodes.threat_assessment_node)
        workflow.add_node("scenario_generation", self.nodes.scenario_generation_node)
        workflow.add_node("target_prioritization", self.nodes.target_prioritization_node)
        workflow.add_node("attack_planning", self.nodes.attack_planning_node)
        workflow.add_node("user_review", self.nodes.user_review_node)
        workflow.add_node("golden_image_creation", self.nodes.golden_image_creation_node)
        workflow.add_node("execution", self.nodes.execution_node)
        workflow.add_node("monitoring", self.nodes.monitoring_node)
        workflow.add_node("restoration", self.nodes.restoration_node)
        
        # Add edges
        workflow.set_entry_point("network_discovery")
        
        # Conditional edges based on state
        workflow.add_conditional_edges(
            "network_discovery",
            self.nodes.should_continue,
            {
                "vulnerability_analysis": "vulnerability_analysis",
                "restoration": "restoration",
                END: END
            }
        )
        
        workflow.add_edge("vulnerability_analysis", "threat_assessment")
        workflow.add_edge("threat_assessment", "scenario_generation")
        workflow.add_edge("scenario_generation", "target_prioritization")
        workflow.add_edge("target_prioritization", "attack_planning")
        workflow.add_edge("attack_planning", "user_review")
        
        workflow.add_conditional_edges(
            "user_review",
            self.nodes.should_continue,
            {
                "golden_image_creation": "golden_image_creation",
                "user_review": "user_review",
                END: END
            }
        )
        
        workflow.add_edge("golden_image_creation", "execution")
        workflow.add_edge("execution", "monitoring")
        workflow.add_edge("monitoring", END)
        workflow.add_edge("restoration", END)
        
        return workflow.compile()
    
    async def run(self, user_request: str, scenario_type: str = None, 
                  constraints: Dict = None, llm_provider: str = "ollama") -> Dict:
        """
        Run the attack workflow
        
        Args:
            user_request: User's attack request
            scenario_type: Type of scenario (stealth, ransomware, etc.)
            constraints: Constraints like time_limit, risk_tolerance
            llm_provider: Which LLM to use
        
        Returns:
            Final state with results
        """
        # Initialize state
        initial_state = {
            'user_request': user_request,
            'scenario_type': scenario_type or 'adaptive',
            'constraints': constraints or {},
            'llm_provider': llm_provider,
            'current_phase': AttackPhase.PLANNING,
            'messages': [],
            'errors': [],
            'llm_responses': [],
            'network_topology': {},
            'online_agents': [],
            'offline_agents': [],
            'critical_assets': [],
            'vulnerabilities': {},
            'threat_assessment': {},
            'attack_scenarios': [],
            'selected_scenario': {},
            'attack_plan': {},
            'target_priority': [],
            'techniques_selected': [],
            'golden_images': {},
            'execution_log': [],
            'commands_sent': [],
            'results_received': [],
            'requires_approval': False,
            'approved': False,
            'abort': False
        }
        
        # Run workflow
        try:
            # Use checkpointing for resumability
            async with AsyncSqliteSaver.from_path(f"{self.checkpoint_dir}/attack.db") as saver:
                config = {"configurable": {"thread_id": f"attack_{uuid.uuid4().hex[:8]}"}}
                
                # Run the workflow
                final_state = await self.workflow.ainvoke(
                    initial_state,
                    config,
                    {"checkpointer": saver}
                )
                
                return final_state
                
        except Exception as e:
            logger.error(f"Workflow execution error: {e}")
            initial_state['errors'].append(str(e))
            return initial_state
    
    async def approve_plan(self, thread_id: str) -> Dict:
        """Approve a pending attack plan"""
        try:
            async with AsyncSqliteSaver.from_path(f"{self.checkpoint_dir}/attack.db") as saver:
                config = {"configurable": {"thread_id": thread_id}}
                
                # Get current state
                state = await saver.aget(config)
                
                # Update approval
                state['approved'] = True
                state['current_phase'] = AttackPhase.GOLDEN_IMAGE_CREATION
                
                # Continue workflow
                final_state = await self.workflow.ainvoke(
                    state,
                    config,
                    {"checkpointer": saver}
                )
                
                return final_state
                
        except Exception as e:
            logger.error(f"Approval error: {e}")
            return {'error': str(e)}


# Create singleton instance
attack_workflow = AttackWorkflow() if LANGGRAPH_AVAILABLE else None
