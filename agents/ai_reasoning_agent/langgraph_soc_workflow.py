#!/usr/bin/env python3
"""
LangGraph-Powered SOC Workflow Engine
Stateful, multi-actor SOC operations with human-in-the-loop controls
"""

import json
import asyncio
import logging
from typing import Dict, List, Optional, Any, TypedDict, Annotated
from datetime import datetime
import uuid

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.prebuilt import ToolNode
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_community.chat_models import ChatOllama
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# Define the workflow state
class SOCWorkflowState(TypedDict):
    """State for SOC workflow operations"""
    messages: Annotated[List[Any], "The conversation messages"]
    current_step: str
    attack_scenario: Optional[Dict]
    network_context: Optional[Dict]
    approval_required: bool
    human_approval: Optional[bool]
    execution_status: str
    attack_results: List[Dict]
    checkpoints: List[Dict]
    user_id: str
    organization_id: str

class LangGraphSOCWorkflow:
    """Production SOC workflow using LangGraph for stateful operations"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config()
        self.llm = self._initialize_llm()
        
        # Initialize SQLite checkpointer for persistence
        self.checkpointer = SqliteSaver.from_conn_string("soc_workflows.db")
        
        # Build the workflow graph
        self.workflow = self._build_workflow()
        
        logger.info("LangGraph SOC Workflow initialized with stateful persistence")
    
    def _load_config(self) -> Dict:
        """Load configuration"""
        return {
            'llm': {
                'ollama_endpoint': 'http://localhost:11434',
                'ollama_model': 'cybersec-ai',
                'temperature': 0.3
            }
        }
    
    def _initialize_llm(self):
        """Initialize LLM for workflow"""
        return ChatOllama(
            model=self.config['llm']['ollama_model'],
            base_url=self.config['llm']['ollama_endpoint'],
            temperature=self.config['llm']['temperature']
        )
    
    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow for SOC operations"""
        
        workflow = StateGraph(SOCWorkflowState)
        
        # Add nodes
        workflow.add_node("intent_analysis", self._analyze_intent)
        workflow.add_node("network_discovery", self._discover_network)
        workflow.add_node("scenario_generation", self._generate_scenario)
        workflow.add_node("human_approval", self._request_human_approval)
        workflow.add_node("attack_execution", self._execute_attack)
        workflow.add_node("monitoring", self._monitor_execution)
        workflow.add_node("response_generation", self._generate_response)
        
        # Define the workflow edges
        workflow.set_entry_point("intent_analysis")
        
        # Intent analysis routes
        workflow.add_conditional_edges(
            "intent_analysis",
            self._route_after_intent,
            {
                "attack_request": "network_discovery",
                "query_request": "response_generation",
                "status_request": "monitoring"
            }
        )
        
        # Network discovery to scenario generation
        workflow.add_edge("network_discovery", "scenario_generation")
        
        # Scenario generation routes to approval or direct execution
        workflow.add_conditional_edges(
            "scenario_generation",
            self._route_after_scenario,
            {
                "needs_approval": "human_approval",
                "auto_execute": "attack_execution"
            }
        )
        
        # Human approval routes
        workflow.add_conditional_edges(
            "human_approval",
            self._route_after_approval,
            {
                "approved": "attack_execution",
                "denied": "response_generation",
                "pending": END  # Wait for human input
            }
        )
        
        # Attack execution to monitoring
        workflow.add_edge("attack_execution", "monitoring")
        
        # Monitoring can loop back or finish
        workflow.add_conditional_edges(
            "monitoring",
            self._route_after_monitoring,
            {
                "continue": "monitoring",
                "complete": "response_generation"
            }
        )
        
        # Response generation ends the workflow
        workflow.add_edge("response_generation", END)
        
        return workflow.compile(checkpointer=self.checkpointer)
    
    async def _analyze_intent(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Analyze user intent using AI"""
        logger.info("Analyzing user intent...")
        
        last_message = state["messages"][-1] if state["messages"] else None
        user_query = last_message.content if last_message else ""
        
        intent_prompt = f"""
        Analyze this SOC command and determine intent:
        
        User Query: "{user_query}"
        
        Classify as:
        1. "attack_request" - User wants to execute/simulate attacks
        2. "query_request" - User wants information/status
        3. "status_request" - User wants current operation status
        
        Also determine:
        - Risk level (low/medium/high/critical)
        - Requires human approval (true/false)
        - Urgency (low/medium/high)
        
        Respond with JSON only.
        """
        
        try:
            response = await self.llm.ainvoke([SystemMessage(content=intent_prompt)])
            intent_data = json.loads(response.content)
            
            state["current_step"] = "intent_analyzed"
            state["approval_required"] = intent_data.get("requires_approval", False)
            
            # Add AI analysis to messages
            state["messages"].append(
                AIMessage(content=f"Intent analyzed: {intent_data.get('intent', 'unknown')}")
            )
            
            # Create checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "step": "intent_analysis",
                "data": intent_data
            }
            state["checkpoints"].append(checkpoint)
            
            return state
            
        except Exception as e:
            logger.error(f"Intent analysis failed: {e}")
            state["current_step"] = "error"
            return state
    
    async def _discover_network(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Discover network topology for attack planning"""
        logger.info("Discovering network topology...")
        
        # Simulate network discovery (integrate with your existing network context manager)
        network_context = {
            "agents_count": 5,
            "high_value_targets": ["DC01", "DB-SERVER"],
            "operating_systems": ["Windows Server 2019", "Ubuntu 20.04"],
            "discovered_vulnerabilities": ["CVE-2023-1234", "CVE-2023-5678"],
            "network_segments": ["DMZ", "Internal", "Management"]
        }
        
        state["network_context"] = network_context
        state["current_step"] = "network_discovered"
        
        # Create checkpoint
        checkpoint = {
            "timestamp": datetime.now().isoformat(),
            "step": "network_discovery",
            "data": network_context
        }
        state["checkpoints"].append(checkpoint)
        
        state["messages"].append(
            AIMessage(content=f"Network discovered: {network_context['agents_count']} agents, {len(network_context['high_value_targets'])} HVTs")
        )
        
        return state
    
    async def _generate_scenario(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Generate adaptive attack scenario based on network context"""
        logger.info("Generating attack scenario...")
        
        network_context = state.get("network_context", {})
        last_message = state["messages"][0] if state["messages"] else None
        user_request = last_message.content if last_message else ""
        
        scenario_prompt = f"""
        Generate an attack scenario based on:
        
        User Request: "{user_request}"
        Network Context: {json.dumps(network_context, indent=2)}
        
        Create a realistic attack scenario with:
        1. Attack phases (initial access, persistence, lateral movement, exfiltration)
        2. MITRE ATT&CK techniques
        3. Target selection strategy
        4. Expected timeline
        5. Success criteria
        
        Format as JSON with detailed execution steps.
        """
        
        try:
            response = await self.llm.ainvoke([SystemMessage(content=scenario_prompt)])
            scenario_data = json.loads(response.content)
            
            state["attack_scenario"] = scenario_data
            state["current_step"] = "scenario_generated"
            
            # Create checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "step": "scenario_generation",
                "data": scenario_data
            }
            state["checkpoints"].append(checkpoint)
            
            state["messages"].append(
                AIMessage(content=f"Attack scenario generated: {scenario_data.get('name', 'Unnamed scenario')}")
            )
            
            return state
            
        except Exception as e:
            logger.error(f"Scenario generation failed: {e}")
            state["current_step"] = "error"
            return state
    
    async def _request_human_approval(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Request human approval for attack execution"""
        logger.info("Requesting human approval...")
        
        scenario = state.get("attack_scenario", {})
        
        approval_message = f"""
        ATTACK EXECUTION APPROVAL REQUIRED
        
        Scenario: {scenario.get('name', 'Unknown')}
        Risk Level: {scenario.get('risk_level', 'Unknown')}
        Targets: {', '.join(scenario.get('targets', []))}
        
        Techniques: {', '.join(scenario.get('techniques', []))}
        
        Do you approve this attack execution?
        - Type 'approve' to proceed
        - Type 'deny' to cancel
        - Type 'modify' to adjust parameters
        """
        
        state["current_step"] = "awaiting_approval"
        state["messages"].append(
            AIMessage(content=approval_message)
        )
        
        # In a real implementation, this would trigger notifications
        # to SOC analysts via Slack, email, etc.
        
        return state
    
    async def _execute_attack(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Execute the approved attack scenario"""
        logger.info("Executing attack scenario...")
        
        scenario = state.get("attack_scenario", {})
        
        # Simulate attack execution (integrate with your adaptive_attack_orchestrator)
        execution_result = {
            "scenario_id": str(uuid.uuid4()),
            "status": "executing",
            "started_at": datetime.now().isoformat(),
            "phases_completed": 0,
            "total_phases": len(scenario.get("phases", [])),
            "current_phase": "initial_access",
            "targets_compromised": [],
            "techniques_executed": []
        }
        
        state["execution_status"] = "executing"
        state["attack_results"] = [execution_result]
        state["current_step"] = "attack_executing"
        
        # Create checkpoint
        checkpoint = {
            "timestamp": datetime.now().isoformat(),
            "step": "attack_execution",
            "data": execution_result
        }
        state["checkpoints"].append(checkpoint)
        
        state["messages"].append(
            AIMessage(content=f"Attack execution started: {execution_result['scenario_id']}")
        )
        
        return state
    
    async def _monitor_execution(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Monitor ongoing attack execution"""
        logger.info("Monitoring attack execution...")
        
        # Simulate monitoring (integrate with your real monitoring)
        current_results = state["attack_results"][-1] if state["attack_results"] else {}
        
        # Update execution progress
        updated_result = current_results.copy()
        updated_result["phases_completed"] += 1
        updated_result["targets_compromised"].append("TARGET-01")
        updated_result["techniques_executed"].append("T1566.001")
        
        if updated_result["phases_completed"] >= updated_result["total_phases"]:
            updated_result["status"] = "completed"
            updated_result["completed_at"] = datetime.now().isoformat()
            state["execution_status"] = "completed"
        
        state["attack_results"].append(updated_result)
        state["current_step"] = "monitoring"
        
        # Create checkpoint
        checkpoint = {
            "timestamp": datetime.now().isoformat(),
            "step": "monitoring",
            "data": updated_result
        }
        state["checkpoints"].append(checkpoint)
        
        return state
    
    async def _generate_response(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Generate final response to user"""
        logger.info("💬 Generating response...")
        
        # Create comprehensive response based on workflow results
        if state["execution_status"] == "completed":
            results = state["attack_results"][-1] if state["attack_results"] else {}
            response_content = f"""
            Attack execution completed successfully!
            
            Scenario: {state.get('attack_scenario', {}).get('name', 'Unknown')}
            Duration: {results.get('completed_at', 'Unknown')}
            Targets Compromised: {len(results.get('targets_compromised', []))}
            Techniques Executed: {len(results.get('techniques_executed', []))}
            
            Full results available in attack logs.
            """
        else:
            response_content = "SOC workflow completed. Check logs for details."
        
        state["messages"].append(
            AIMessage(content=response_content)
        )
        
        state["current_step"] = "completed"
        
        return state
    
    # Routing functions
    def _route_after_intent(self, state: SOCWorkflowState) -> str:
        """Route after intent analysis"""
        last_message = state["messages"][-1] if state["messages"] else None
        if last_message and "attack" in last_message.content.lower():
            return "attack_request"
        elif last_message and "status" in last_message.content.lower():
            return "status_request"
        else:
            return "query_request"
    
    def _route_after_scenario(self, state: SOCWorkflowState) -> str:
        """Route after scenario generation"""
        return "needs_approval" if state.get("approval_required", False) else "auto_execute"
    
    def _route_after_approval(self, state: SOCWorkflowState) -> str:
        """Route after human approval"""
        approval = state.get("human_approval")
        if approval is True:
            return "approved"
        elif approval is False:
            return "denied"
        else:
            return "pending"
    
    def _route_after_monitoring(self, state: SOCWorkflowState) -> str:
        """Route after monitoring"""
        return "complete" if state.get("execution_status") == "completed" else "continue"
    
    async def process_soc_command(self, user_query: str, user_id: str = "analyst-1", 
                                organization_id: str = "org-123") -> Dict[str, Any]:
        """Process SOC command through LangGraph workflow"""
        
        # Create initial state
        initial_state = {
            "messages": [HumanMessage(content=user_query)],
            "current_step": "starting",
            "attack_scenario": None,
            "network_context": None,
            "approval_required": False,
            "human_approval": None,
            "execution_status": "pending",
            "attack_results": [],
            "checkpoints": [],
            "user_id": user_id,
            "organization_id": organization_id
        }
        
        # Create thread for this conversation
        thread_id = f"soc-{user_id}-{int(datetime.now().timestamp())}"
        config = {"configurable": {"thread_id": thread_id}}
        
        try:
            # Execute the workflow
            final_state = await self.workflow.ainvoke(initial_state, config)
            
            # Extract final response
            final_message = final_state["messages"][-1] if final_state["messages"] else None
            
            return {
                "success": True,
                "response": final_message.content if final_message else "Workflow completed",
                "thread_id": thread_id,
                "execution_status": final_state.get("execution_status", "unknown"),
                "checkpoints_count": len(final_state.get("checkpoints", [])),
                "workflow_state": final_state.get("current_step", "unknown")
            }
            
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "thread_id": thread_id
            }
    
    async def resume_workflow(self, thread_id: str, human_input: Optional[str] = None) -> Dict[str, Any]:
        """Resume a paused workflow (e.g., after human approval)"""
        
        config = {"configurable": {"thread_id": thread_id}}
        
        try:
            # Get current state
            current_state = await self.workflow.aget_state(config)
            
            if human_input:
                # Update state with human input
                if "approve" in human_input.lower():
                    current_state.values["human_approval"] = True
                elif "deny" in human_input.lower():
                    current_state.values["human_approval"] = False
                
                # Add human message
                current_state.values["messages"].append(
                    HumanMessage(content=human_input)
                )
            
            # Resume execution
            final_state = await self.workflow.ainvoke(current_state.values, config)
            
            final_message = final_state["messages"][-1] if final_state["messages"] else None
            
            return {
                "success": True,
                "response": final_message.content if final_message else "Workflow resumed",
                "execution_status": final_state.get("execution_status", "unknown"),
                "workflow_state": final_state.get("current_step", "unknown")
            }
            
        except Exception as e:
            logger.error(f"Workflow resume failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

# Global instance
langgraph_soc_workflow = LangGraphSOCWorkflow()
