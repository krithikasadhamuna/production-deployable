"""
AI Attacker Brain - Advanced Attack Planning with LangGraph
Uses LangGraph for stateful, human-in-the-loop attack orchestration
"""

import json
import logging
from typing import Dict, List, Any, TypedDict, Annotated, Sequence
from datetime import datetime
import uuid
import sqlite3
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.prebuilt import ToolExecutor
import asyncio
import aiosqlite

try:
    from langchain_ollama import ChatOllama
except ImportError:
    from langchain_community.chat_models import ChatOllama

from langchain.prompts import ChatPromptTemplate
from langchain.schema import HumanMessage, AIMessage, SystemMessage
from langchain_core.messages import BaseMessage
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# Define the state for our attack workflow
class AttackState(TypedDict):
    """State for the attack planning and execution workflow"""
    # Network discovery
    network_topology: Dict
    available_endpoints: List[Dict]
    vulnerable_services: List[Dict]
    
    # Attack planning
    attack_objective: str
    attack_scenarios: List[Dict]
    selected_scenario: Dict
    attack_plan: Dict
    
    # User interaction
    user_approval: bool
    user_modifications: Dict
    approval_timestamp: str
    
    # Execution
    execution_status: str
    execution_results: List[Dict]
    current_phase: int
    
    # Messaging
    messages: Annotated[Sequence[BaseMessage], "append"]
    
    # Control flow
    next_action: str
    error: str

class AIAttackerBrain:
    """
    Advanced AI Attack Agent using LangGraph for stateful attack orchestration
    """
    
    def __init__(self, db_path="soc_database.db"):
        self.db_path = db_path
        self.llm = self._initialize_llm()
        self.checkpointer = AsyncSqliteSaver.from_conn_string("attack_workflows.db")
        self.graph = self._build_attack_graph()
        logger.info("AI Attacker Brain initialized with LangGraph workflow")
    
    def _initialize_llm(self):
        """Initialize the Ollama LLM for attack planning"""
        return ChatOllama(
            model="cybersec-ai",
            temperature=0.7,
            base_url="http://localhost:11434"
        )
    
    def _build_attack_graph(self) -> StateGraph:
        """Build the LangGraph workflow for attack orchestration"""
        workflow = StateGraph(AttackState)
        
        # Add nodes for each phase
        workflow.add_node("network_discovery", self.network_discovery_node)
        workflow.add_node("vulnerability_analysis", self.vulnerability_analysis_node)
        workflow.add_node("attack_planning", self.attack_planning_node)
        workflow.add_node("scenario_generation", self.scenario_generation_node)
        workflow.add_node("human_review", self.human_review_node)
        workflow.add_node("plan_modification", self.plan_modification_node)
        workflow.add_node("execution_preparation", self.execution_preparation_node)
        workflow.add_node("phased_execution", self.phased_execution_node)
        workflow.add_node("result_analysis", self.result_analysis_node)
        
        # Set entry point
        workflow.set_entry_point("network_discovery")
        
        # Add edges
        workflow.add_edge("network_discovery", "vulnerability_analysis")
        workflow.add_edge("vulnerability_analysis", "attack_planning")
        workflow.add_edge("attack_planning", "scenario_generation")
        workflow.add_edge("scenario_generation", "human_review")
        
        # Conditional routing from human review
        workflow.add_conditional_edges(
            "human_review",
            self.route_after_review,
            {
                "approved": "execution_preparation",
                "modify": "plan_modification",
                "reject": END
            }
        )
        
        workflow.add_edge("plan_modification", "human_review")
        workflow.add_edge("execution_preparation", "phased_execution")
        workflow.add_edge("phased_execution", "result_analysis")
        workflow.add_edge("result_analysis", END)
        
        return workflow.compile(checkpointer=self.checkpointer)
    
    async def network_discovery_node(self, state: AttackState) -> AttackState:
        """Discover network topology and available endpoints"""
        logger.info("Starting network discovery phase")
        
        # Query database for registered agents
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                SELECT id, hostname, ip_address, platform, capabilities, status
                FROM agents 
                WHERE status = 'online'
            """)
            agents = await cursor.fetchall()
        
        endpoints = []
        for agent in agents:
            endpoint = {
                "id": agent[0],
                "hostname": agent[1],
                "ip_address": agent[2],
                "platform": agent[3],
                "capabilities": json.loads(agent[4]) if agent[4] else [],
                "status": agent[5]
            }
            endpoints.append(endpoint)
        
        # Use AI to analyze network structure
        discovery_prompt = f"""
        Analyze this network topology and identify key targets:
        
        Endpoints discovered: {len(endpoints)}
        Platforms: {[e['platform'] for e in endpoints]}
        
        Identify:
        1. Critical systems (domain controllers, databases, etc.)
        2. Network segments
        3. Potential pivot points
        4. High-value targets
        
        Endpoints: {json.dumps(endpoints, indent=2)}
        """
        
        response = await self.llm.ainvoke([SystemMessage(content=discovery_prompt)])
        
        state["available_endpoints"] = endpoints
        state["network_topology"] = {
            "total_endpoints": len(endpoints),
            "platforms": list(set(e['platform'] for e in endpoints)),
            "analysis": response.content
        }
        state["messages"].append(AIMessage(content=f"Network discovery complete. Found {len(endpoints)} active endpoints."))
        
        return state
    
    async def vulnerability_analysis_node(self, state: AttackState) -> AttackState:
        """Analyze vulnerabilities in discovered endpoints"""
        logger.info("Analyzing vulnerabilities in network")
        
        endpoints = state["available_endpoints"]
        
        vuln_prompt = f"""
        As an expert penetration tester, analyze these endpoints for vulnerabilities:
        
        {json.dumps(endpoints, indent=2)}
        
        For each endpoint, identify:
        1. Likely vulnerabilities based on platform
        2. Exposed services
        3. Potential attack vectors
        4. Privilege escalation opportunities
        5. Data exfiltration paths
        
        Provide a detailed vulnerability assessment.
        """
        
        response = await self.llm.ainvoke([SystemMessage(content=vuln_prompt)])
        
        # Parse vulnerabilities
        vulnerable_services = []
        for endpoint in endpoints:
            if "windows" in endpoint["platform"].lower():
                vulnerable_services.append({
                    "endpoint_id": endpoint["id"],
                    "service": "SMB",
                    "vulnerability": "EternalBlue",
                    "severity": "critical"
                })
            if "database" in str(endpoint["capabilities"]):
                vulnerable_services.append({
                    "endpoint_id": endpoint["id"],
                    "service": "SQL",
                    "vulnerability": "SQL Injection",
                    "severity": "high"
                })
        
        state["vulnerable_services"] = vulnerable_services
        state["messages"].append(AIMessage(content=f"Vulnerability analysis complete. Found {len(vulnerable_services)} potential attack vectors."))
        
        return state
    
    async def attack_planning_node(self, state: AttackState) -> AttackState:
        """Create comprehensive attack plan based on network and vulnerabilities"""
        logger.info("Planning attack strategy")
        
        planning_prompt = f"""
        Create a sophisticated multi-phase attack plan based on:
        
        Network Topology: {state['network_topology']}
        Vulnerable Services: {state['vulnerable_services']}
        Attack Objective: {state.get('attack_objective', 'Full network compromise')}
        
        Design an APT-style attack with:
        1. Initial Access phase
        2. Execution phase
        3. Persistence phase
        4. Privilege Escalation phase
        5. Defense Evasion phase
        6. Credential Access phase
        7. Discovery phase
        8. Lateral Movement phase
        9. Collection phase
        10. Exfiltration phase
        
        For each phase, specify:
        - Target endpoints
        - MITRE techniques to use
        - Expected outcomes
        - Risk level
        - Detection likelihood
        """
        
        response = await self.llm.ainvoke([SystemMessage(content=planning_prompt)])
        
        # Create structured attack plan
        attack_plan = {
            "objective": state.get("attack_objective", "Full network compromise"),
            "phases": [
                {
                    "phase": 1,
                    "name": "Initial Access",
                    "techniques": ["T1566", "T1078"],
                    "targets": state["available_endpoints"][:2] if state["available_endpoints"] else [],
                    "duration": "30 minutes"
                },
                {
                    "phase": 2,
                    "name": "Privilege Escalation",
                    "techniques": ["T1055", "T1053"],
                    "targets": state["available_endpoints"][1:3] if len(state["available_endpoints"]) > 1 else [],
                    "duration": "45 minutes"
                },
                {
                    "phase": 3,
                    "name": "Lateral Movement",
                    "techniques": ["T1021", "T1570"],
                    "targets": state["available_endpoints"],
                    "duration": "60 minutes"
                }
            ],
            "ai_analysis": response.content
        }
        
        state["attack_plan"] = attack_plan
        state["messages"].append(AIMessage(content="Attack plan created. Ready for scenario generation."))
        
        return state
    
    async def scenario_generation_node(self, state: AttackState) -> AttackState:
        """Generate multiple attack scenarios for user to choose from"""
        logger.info("Generating attack scenarios")
        
        scenarios_prompt = f"""
        Based on the attack plan, generate 3 different attack scenarios:
        
        1. Stealthy APT scenario (low and slow)
        2. Ransomware scenario (fast and noisy)
        3. Data exfiltration scenario (targeted)
        
        For each scenario, provide:
        - Name and description
        - Techniques to use
        - Target priority
        - Expected impact
        - Detection risk
        - Estimated duration
        
        Network: {state['network_topology']}
        Available targets: {[e['hostname'] for e in state['available_endpoints']]}
        """
        
        response = await self.llm.ainvoke([SystemMessage(content=scenarios_prompt)])
        
        # Create scenario options
        scenarios = [
            {
                "id": "scenario_1",
                "name": "Operation Silent Storm - APT Simulation",
                "description": "Stealthy advanced persistent threat simulation",
                "techniques": ["T1055", "T1003", "T1021"],
                "targets": state["available_endpoints"][:3] if state["available_endpoints"] else [],
                "impact": "high",
                "detection_risk": "low",
                "duration": "3 hours"
            },
            {
                "id": "scenario_2",
                "name": "Operation Crypto Lock - Ransomware Simulation",
                "description": "Fast-spreading ransomware attack simulation",
                "techniques": ["T1486", "T1490", "T1489"],
                "targets": state["available_endpoints"],
                "impact": "critical",
                "detection_risk": "high",
                "duration": "1 hour"
            },
            {
                "id": "scenario_3",
                "name": "Operation Data Heist - Exfiltration Simulation",
                "description": "Targeted data theft simulation",
                "techniques": ["T1005", "T1114", "T1041"],
                "targets": [e for e in state["available_endpoints"] if "database" in str(e.get("capabilities", []))],
                "impact": "medium",
                "detection_risk": "medium",
                "duration": "2 hours"
            }
        ]
        
        state["attack_scenarios"] = scenarios
        state["messages"].append(AIMessage(content=f"Generated {len(scenarios)} attack scenarios. Awaiting user selection and approval."))
        state["next_action"] = "awaiting_approval"
        
        return state
    
    async def human_review_node(self, state: AttackState) -> AttackState:
        """Present scenarios to human for review and approval"""
        logger.info("Awaiting human review and approval")
        
        # This node would typically wait for user input
        # For now, we'll mark it as requiring approval
        state["execution_status"] = "awaiting_approval"
        
        review_message = """
        ATTACK SCENARIOS READY FOR REVIEW
        ==================================
        
        Please review the following attack scenarios:
        """
        
        for scenario in state["attack_scenarios"]:
            review_message += f"""
            
            {scenario['name']}
            Description: {scenario['description']}
            Techniques: {', '.join(scenario['techniques'])}
            Targets: {len(scenario['targets'])} endpoints
            Impact: {scenario['impact']}
            Detection Risk: {scenario['detection_risk']}
            Duration: {scenario['duration']}
            """
        
        review_message += """
        
        Options:
        1. APPROVE - Execute selected scenario
        2. MODIFY - Request changes to scenario
        3. REJECT - Cancel operation
        
        Please provide your decision.
        """
        
        state["messages"].append(AIMessage(content=review_message))
        
        return state
    
    def route_after_review(self, state: AttackState) -> str:
        """Route based on human review decision"""
        if state.get("user_approval"):
            return "approved"
        elif state.get("user_modifications"):
            return "modify"
        else:
            return "reject"
    
    async def plan_modification_node(self, state: AttackState) -> AttackState:
        """Modify attack plan based on user feedback"""
        logger.info("Modifying attack plan based on user input")
        
        modifications = state.get("user_modifications", {})
        
        modification_prompt = f"""
        Modify the attack scenario based on user requirements:
        
        Current scenario: {state.get('selected_scenario')}
        User modifications: {modifications}
        
        Update the scenario to incorporate these changes while maintaining:
        - Technical feasibility
        - Operational security
        - Attack effectiveness
        """
        
        response = await self.llm.ainvoke([SystemMessage(content=modification_prompt)])
        
        # Update selected scenario
        if state.get("selected_scenario"):
            state["selected_scenario"].update(modifications)
        
        state["messages"].append(AIMessage(content="Attack plan modified per user requirements. Please review again."))
        
        return state
    
    async def execution_preparation_node(self, state: AttackState) -> AttackState:
        """Prepare for attack execution"""
        logger.info("Preparing for attack execution")
        
        selected = state.get("selected_scenario", state["attack_scenarios"][0])
        
        prep_message = f"""
        ATTACK EXECUTION PREPARATION
        ============================
        
        Scenario: {selected['name']}
        Approved at: {datetime.now().isoformat()}
        
        Preparing:
        - Command sequences
        - Payload generation
        - Evasion techniques
        - Rollback procedures
        
        Target endpoints: {len(selected['targets'])}
        Techniques: {', '.join(selected['techniques'])}
        
        Execution will begin in phased approach...
        """
        
        state["messages"].append(AIMessage(content=prep_message))
        state["execution_status"] = "preparing"
        state["current_phase"] = 0
        
        return state
    
    async def phased_execution_node(self, state: AttackState) -> AttackState:
        """Execute attack in phases with monitoring"""
        logger.info("Executing attack phases")
        
        scenario = state.get("selected_scenario", state["attack_scenarios"][0])
        results = []
        
        for i, technique in enumerate(scenario["techniques"]):
            # Simulate attack execution
            phase_result = await self._execute_technique(
                technique,
                scenario["targets"][i % len(scenario["targets"])] if scenario["targets"] else None
            )
            results.append(phase_result)
            
            # Update progress
            state["current_phase"] = i + 1
            state["messages"].append(
                AIMessage(content=f"Phase {i+1}: Executing {technique} - {phase_result['status']}")
            )
        
        state["execution_results"] = results
        state["execution_status"] = "completed"
        
        return state
    
    async def result_analysis_node(self, state: AttackState) -> AttackState:
        """Analyze attack results and generate report"""
        logger.info("Analyzing attack results")
        
        analysis_prompt = f"""
        Analyze the attack execution results:
        
        Scenario: {state.get('selected_scenario', {}).get('name', 'Unknown')}
        Results: {state.get('execution_results', [])}
        
        Provide:
        1. Success rate
        2. Objectives achieved
        3. Detection events triggered
        4. Lessons learned
        5. Recommendations for improvement
        """
        
        response = await self.llm.ainvoke([SystemMessage(content=analysis_prompt)])
        
        final_report = f"""
        ATTACK EXECUTION COMPLETE
        ========================
        
        {response.content}
        
        Results stored in database for analysis.
        """
        
        state["messages"].append(AIMessage(content=final_report))
        
        # Store results in database
        await self._store_attack_results(state)
        
        return state
    
    async def _execute_technique(self, technique: str, target: Dict) -> Dict:
        """Execute a specific MITRE technique on target"""
        # This would integrate with the actual attack execution engine
        return {
            "technique": technique,
            "target": target.get("hostname") if target else "unknown",
            "status": "success",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _store_attack_results(self, state: AttackState):
        """Store attack results in database"""
        async with aiosqlite.connect(self.db_path) as conn:
            scenario = state.get("selected_scenario", {})
            await conn.execute("""
                INSERT INTO attack_timeline 
                (id, scenario_name, status, started_at, completed_at, results)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                scenario.get("name", "Unknown"),
                "completed",
                state.get("approval_timestamp"),
                datetime.now().isoformat(),
                json.dumps(state.get("execution_results", []))
            ))
            await conn.commit()
    
    async def run_attack_workflow(self, objective: str = None, config: Dict = None):
        """Run the complete attack workflow"""
        initial_state = AttackState(
            network_topology={},
            available_endpoints=[],
            vulnerable_services=[],
            attack_objective=objective or "Network security assessment",
            attack_scenarios=[],
            selected_scenario={},
            attack_plan={},
            user_approval=False,
            user_modifications={},
            approval_timestamp="",
            execution_status="initializing",
            execution_results=[],
            current_phase=0,
            messages=[],
            next_action="",
            error=""
        )
        
        # Run the workflow
        thread_id = str(uuid.uuid4())
        config = config or {"configurable": {"thread_id": thread_id}}
        
        async for chunk in self.graph.astream(initial_state, config):
            for node, state_update in chunk.items():
                logger.info(f"Node {node} completed")
                if state_update.get("messages"):
                    for msg in state_update["messages"]:
                        print(f"[{node}]: {msg.content}")
        
        return state_update
    
    async def approve_scenario(self, thread_id: str, scenario_id: str):
        """Approve a specific scenario for execution"""
        config = {"configurable": {"thread_id": thread_id}}
        
        # Get current state
        state = await self.graph.aget_state(config)
        
        # Find and select scenario
        scenarios = state.values.get("attack_scenarios", [])
        selected = next((s for s in scenarios if s["id"] == scenario_id), None)
        
        if selected:
            # Update state with approval
            await self.graph.aupdate_state(
                config,
                {
                    "selected_scenario": selected,
                    "user_approval": True,
                    "approval_timestamp": datetime.now().isoformat()
                }
            )
            
            # Continue workflow from human_review node
            async for chunk in self.graph.astream(None, config):
                for node, state_update in chunk.items():
                    logger.info(f"Node {node} executed after approval")
        
        return selected
    
    async def modify_scenario(self, thread_id: str, modifications: Dict):
        """Modify attack scenario parameters"""
        config = {"configurable": {"thread_id": thread_id}}
        
        # Update state with modifications
        await self.graph.aupdate_state(
            config,
            {
                "user_modifications": modifications,
                "user_approval": False
            }
        )
        
        # Continue workflow
        async for chunk in self.graph.astream(None, config):
            for node, state_update in chunk.items():
                logger.info(f"Node {node} executed after modification")
        
        return state_update
