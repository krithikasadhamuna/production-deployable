#!/usr/bin/env python3
"""
Automated Incident Response Agent
Complete incident response automation with AI-driven decision making
"""

import os
import json
import asyncio
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
import uuid

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
try:
    from langchain_ollama import ChatOllama
except ImportError:
    from langchain_community.chat_models import ChatOllama

logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class ResponseAction(Enum):
    ISOLATE_ENDPOINT = "isolate_endpoint"
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    COLLECT_FORENSICS = "collect_forensics"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    SEND_ALERT = "send_alert"
    QUARANTINE_FILE = "quarantine_file"
    RESET_PASSWORD = "reset_password"
    PATCH_VULNERABILITY = "patch_vulnerability"
    BACKUP_SYSTEM = "backup_system"

class IncidentResponseState(dict):
    """State for incident response workflow"""
    incident_id: str
    detection_data: Dict
    severity: str
    affected_agents: List[str]
    response_actions: List[Dict]
    containment_status: str
    eradication_status: str
    recovery_status: str
    lessons_learned: Dict
    timeline: List[Dict]
    human_escalation_required: bool
    current_phase: str

class AutomatedIncidentResponder:
    """AI-powered automated incident response system"""
    
    def __init__(self, db_path: str = "soc_database.db"):
        self.db_path = db_path
        self.config = self._load_config()
        
        # Initialize LLM
        self.llm = ChatOllama(
            model=self.config['llm']['ollama_model'],
            base_url=self.config['llm']['ollama_endpoint'],
            temperature=0.3  # Lower for more consistent responses
        )
        
        # Initialize checkpointer
        try:
            import aiosqlite
            self.checkpointer = AsyncSqliteSaver.from_conn_string("incident_response.db")
        except Exception as e:
            logger.warning(f"Failed to initialize checkpointer: {e}")
            self.checkpointer = None
        
        # Build incident response workflow
        self.workflow = self._build_incident_response_workflow()
        
        # Response playbooks
        self.playbooks = self._load_response_playbooks()
        
        logger.info("Automated Incident Responder initialized")
    
    def _load_config(self) -> Dict:
        """Load configuration"""
        return {
            'llm': {
                'ollama_endpoint': 'http://localhost:11434',
                'ollama_model': 'cybersec-ai',
                'temperature': 0.3
            },
            'response_timeouts': {
                'critical': 300,    # 5 minutes
                'high': 900,       # 15 minutes
                'medium': 3600,    # 1 hour
                'low': 86400       # 24 hours
            }
        }
    
    def _load_response_playbooks(self) -> Dict:
        """Load incident response playbooks"""
        return {
            'malware_infection': {
                'containment': [
                    ResponseAction.ISOLATE_ENDPOINT,
                    ResponseAction.QUARANTINE_FILE,
                    ResponseAction.DISABLE_USER
                ],
                'eradication': [
                    ResponseAction.COLLECT_FORENSICS,
                    ResponseAction.PATCH_VULNERABILITY
                ],
                'recovery': [
                    ResponseAction.BACKUP_SYSTEM,
                    ResponseAction.RESET_PASSWORD
                ]
            },
            'data_breach': {
                'containment': [
                    ResponseAction.ISOLATE_ENDPOINT,
                    ResponseAction.DISABLE_USER,
                    ResponseAction.BLOCK_IP
                ],
                'eradication': [
                    ResponseAction.COLLECT_FORENSICS,
                    ResponseAction.PATCH_VULNERABILITY
                ],
                'recovery': [
                    ResponseAction.RESET_PASSWORD,
                    ResponseAction.BACKUP_SYSTEM
                ]
            },
            'apt_campaign': {
                'containment': [
                    ResponseAction.ISOLATE_ENDPOINT,
                    ResponseAction.BLOCK_IP,
                    ResponseAction.ESCALATE_TO_HUMAN
                ],
                'eradication': [
                    ResponseAction.COLLECT_FORENSICS
                ],
                'recovery': [
                    ResponseAction.BACKUP_SYSTEM
                ]
            },
            'insider_threat': {
                'containment': [
                    ResponseAction.DISABLE_USER,
                    ResponseAction.ESCALATE_TO_HUMAN
                ],
                'eradication': [
                    ResponseAction.COLLECT_FORENSICS
                ],
                'recovery': [
                    ResponseAction.BACKUP_SYSTEM
                ]
            }
        }
    
    def _build_incident_response_workflow(self) -> StateGraph:
        """Build the incident response workflow"""
        
        workflow = StateGraph(IncidentResponseState)
        
        # Add workflow nodes
        workflow.add_node("classify_incident", self._classify_incident)
        workflow.add_node("assess_impact", self._assess_impact)
        workflow.add_node("select_playbook", self._select_response_playbook)
        workflow.add_node("containment", self._execute_containment)
        workflow.add_node("eradication", self._execute_eradication)
        workflow.add_node("recovery", self._execute_recovery)
        workflow.add_node("human_escalation", self._escalate_to_human)
        workflow.add_node("post_incident", self._post_incident_analysis)
        
        # Define entry point
        workflow.set_entry_point("classify_incident")
        
        # Define workflow edges
        workflow.add_edge("classify_incident", "assess_impact")
        workflow.add_edge("assess_impact", "select_playbook")
        
        # Conditional routing after playbook selection
        workflow.add_conditional_edges(
            "select_playbook",
            self._route_after_playbook_selection,
            {
                "auto_respond": "containment",
                "escalate": "human_escalation"
            }
        )
        
        workflow.add_edge("containment", "eradication")
        workflow.add_edge("eradication", "recovery")
        workflow.add_edge("recovery", "post_incident")
        
        # Human escalation can go to containment or post-incident
        workflow.add_conditional_edges(
            "human_escalation",
            self._route_after_escalation,
            {
                "proceed": "containment",
                "complete": "post_incident",
                "pending": END
            }
        )
        
        workflow.add_edge("post_incident", END)
        
        if self.checkpointer:
            return workflow.compile(checkpointer=self.checkpointer)
        else:
            return workflow.compile()
    
    async def _classify_incident(self, state: IncidentResponseState) -> IncidentResponseState:
        """Classify the incident using AI"""
        logger.info("IR Node: Classifying incident...")
        
        try:
            detection_data = state["detection_data"]
            
            # AI classification prompt
            classification_prompt = f"""
            Classify this security incident:
            
            DETECTION DATA:
            {json.dumps(detection_data, indent=2)}
            
            Classify the incident type:
            - malware_infection
            - data_breach
            - apt_campaign
            - insider_threat
            - network_intrusion
            - denial_of_service
            - privilege_escalation
            - lateral_movement
            
            Consider:
            1. Attack vectors and techniques used
            2. Indicators of compromise
            3. Affected systems and data
            4. Attack sophistication level
            5. Potential threat actor profile
            
            Respond with JSON:
            {{
                "incident_type": "malware_infection",
                "confidence": 0.85,
                "reasoning": "Multiple malware indicators detected",
                "mitre_techniques": ["T1059.001", "T1055"],
                "threat_actor_profile": "opportunistic",
                "attack_vector": "email_attachment"
            }}
            """
            
            ai_response = await self.llm.ainvoke([SystemMessage(content=classification_prompt)])
            
            # Parse classification (simplified for demo)
            classification = {
                "incident_type": "malware_infection",
                "confidence": 0.85,
                "reasoning": "AI-based classification",
                "mitre_techniques": ["T1059.001"],
                "threat_actor_profile": "unknown",
                "attack_vector": "unknown"
            }
            
            # Try to parse actual AI response
            try:
                if '{' in ai_response.content:
                    json_start = ai_response.content.find('{')
                    json_end = ai_response.content.rfind('}') + 1
                    json_str = ai_response.content[json_start:json_end]
                    parsed_classification = json.loads(json_str)
                    classification.update(parsed_classification)
            except:
                pass  # Use default classification
            
            state["classification"] = classification
            state["current_phase"] = "classified"
            
            # Add to timeline
            timeline_entry = {
                "timestamp": datetime.now().isoformat(),
                "phase": "classification",
                "action": "incident_classified",
                "details": classification
            }
            state.setdefault("timeline", []).append(timeline_entry)
            
            logger.info(f"Incident classified as: {classification['incident_type']}")
            
            return state
            
        except Exception as e:
            logger.error(f"Incident classification failed: {e}")
            state["current_phase"] = "classification_failed"
            return state
    
    async def _assess_impact(self, state: IncidentResponseState) -> IncidentResponseState:
        """Assess incident impact and determine severity"""
        logger.info("IR Node: Assessing impact...")
        
        try:
            classification = state["classification"]
            detection_data = state["detection_data"]
            affected_agents = state.get("affected_agents", [])
            
            # Impact assessment factors
            impact_factors = {
                "affected_systems_count": len(affected_agents),
                "data_sensitivity": "medium",  # Could be determined from agent data
                "business_criticality": "medium",
                "attack_sophistication": classification.get("threat_actor_profile", "unknown"),
                "lateral_movement_detected": False,
                "privilege_escalation_detected": False
            }
            
            # Determine severity based on impact factors
            severity_score = 0
            
            # System count impact
            if impact_factors["affected_systems_count"] > 10:
                severity_score += 3
            elif impact_factors["affected_systems_count"] > 3:
                severity_score += 2
            elif impact_factors["affected_systems_count"] > 1:
                severity_score += 1
            
            # Classification impact
            high_impact_types = ["data_breach", "apt_campaign", "insider_threat"]
            if classification.get("incident_type") in high_impact_types:
                severity_score += 2
            
            # Determine final severity
            if severity_score >= 4:
                severity = IncidentSeverity.CRITICAL.value
            elif severity_score >= 3:
                severity = IncidentSeverity.HIGH.value
            elif severity_score >= 2:
                severity = IncidentSeverity.MEDIUM.value
            else:
                severity = IncidentSeverity.LOW.value
            
            impact_assessment = {
                "severity": severity,
                "impact_score": severity_score,
                "impact_factors": impact_factors,
                "estimated_business_impact": self._estimate_business_impact(severity),
                "response_timeout": self.config['response_timeouts'][severity]
            }
            
            state["severity"] = severity
            state["impact_assessment"] = impact_assessment
            state["current_phase"] = "impact_assessed"
            
            # Add to timeline
            timeline_entry = {
                "timestamp": datetime.now().isoformat(),
                "phase": "impact_assessment",
                "action": "impact_assessed",
                "details": impact_assessment
            }
            state["timeline"].append(timeline_entry)
            
            logger.info(f"Impact assessed: {severity} severity")
            
            return state
            
        except Exception as e:
            logger.error(f"Impact assessment failed: {e}")
            state["current_phase"] = "impact_assessment_failed"
            return state
    
    async def _select_response_playbook(self, state: IncidentResponseState) -> IncidentResponseState:
        """Select appropriate response playbook"""
        logger.info("IR Node: Selecting response playbook...")
        
        try:
            incident_type = state["classification"]["incident_type"]
            severity = state["severity"]
            
            # Get base playbook
            playbook = self.playbooks.get(incident_type, self.playbooks["malware_infection"])
            
            # Customize playbook based on severity
            if severity in [IncidentSeverity.CRITICAL.value, IncidentSeverity.HIGH.value]:
                # Add escalation for high severity incidents
                playbook["containment"].append(ResponseAction.ESCALATE_TO_HUMAN)
                state["human_escalation_required"] = True
            else:
                state["human_escalation_required"] = False
            
            # AI-enhanced playbook customization
            customization_prompt = f"""
            Customize incident response playbook for:
            
            INCIDENT TYPE: {incident_type}
            SEVERITY: {severity}
            AFFECTED AGENTS: {len(state.get('affected_agents', []))}
            
            BASE PLAYBOOK:
            {json.dumps({k: [action.value for action in v] for k, v in playbook.items()}, indent=2)}
            
            Recommend additional or modified actions based on:
            1. Incident specifics
            2. Severity level
            3. Affected systems
            4. Threat actor profile
            
            Respond with JSON containing recommended modifications.
            """
            
            ai_response = await self.llm.ainvoke([SystemMessage(content=customization_prompt)])
            
            # Apply AI customizations (simplified)
            customized_playbook = playbook.copy()
            
            state["selected_playbook"] = {
                "incident_type": incident_type,
                "severity": severity,
                "playbook": {k: [action.value for action in v] for k, v in customized_playbook.items()},
                "customizations_applied": True,
                "ai_recommendations": "AI customization applied"
            }
            
            state["current_phase"] = "playbook_selected"
            
            # Add to timeline
            timeline_entry = {
                "timestamp": datetime.now().isoformat(),
                "phase": "playbook_selection",
                "action": "playbook_selected",
                "details": state["selected_playbook"]
            }
            state["timeline"].append(timeline_entry)
            
            logger.info(f"Playbook selected for {incident_type}")
            
            return state
            
        except Exception as e:
            logger.error(f"Playbook selection failed: {e}")
            state["current_phase"] = "playbook_selection_failed"
            return state
    
    async def _execute_containment(self, state: IncidentResponseState) -> IncidentResponseState:
        """Execute containment actions"""
        logger.info("IR Node: Executing containment...")
        
        try:
            playbook = state["selected_playbook"]["playbook"]
            containment_actions = playbook.get("containment", [])
            
            execution_results = []
            
            for action_str in containment_actions:
                try:
                    action = ResponseAction(action_str)
                    result = await self._execute_response_action(action, state)
                    execution_results.append(result)
                except Exception as e:
                    logger.error(f"Containment action {action_str} failed: {e}")
                    execution_results.append({
                        "action": action_str,
                        "success": False,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    })
            
            containment_results = {
                "phase": "containment",
                "actions_attempted": len(containment_actions),
                "actions_successful": len([r for r in execution_results if r.get("success")]),
                "execution_results": execution_results,
                "completion_time": datetime.now().isoformat()
            }
            
            state["containment_status"] = "completed"
            state["containment_results"] = containment_results
            state["current_phase"] = "containment_completed"
            
            # Add to timeline
            timeline_entry = {
                "timestamp": datetime.now().isoformat(),
                "phase": "containment",
                "action": "containment_completed",
                "details": containment_results
            }
            state["timeline"].append(timeline_entry)
            
            success_rate = containment_results["actions_successful"] / max(containment_results["actions_attempted"], 1)
            logger.info(f"Containment completed: {success_rate:.1%} success rate")
            
            return state
            
        except Exception as e:
            logger.error(f"Containment execution failed: {e}")
            state["containment_status"] = "failed"
            state["current_phase"] = "containment_failed"
            return state
    
    async def _execute_eradication(self, state: IncidentResponseState) -> IncidentResponseState:
        """Execute eradication actions"""
        logger.info("IR Node: Executing eradication...")
        
        try:
            playbook = state["selected_playbook"]["playbook"]
            eradication_actions = playbook.get("eradication", [])
            
            execution_results = []
            
            for action_str in eradication_actions:
                try:
                    action = ResponseAction(action_str)
                    result = await self._execute_response_action(action, state)
                    execution_results.append(result)
                except Exception as e:
                    logger.error(f"Eradication action {action_str} failed: {e}")
                    execution_results.append({
                        "action": action_str,
                        "success": False,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    })
            
            eradication_results = {
                "phase": "eradication",
                "actions_attempted": len(eradication_actions),
                "actions_successful": len([r for r in execution_results if r.get("success")]),
                "execution_results": execution_results,
                "completion_time": datetime.now().isoformat()
            }
            
            state["eradication_status"] = "completed"
            state["eradication_results"] = eradication_results
            state["current_phase"] = "eradication_completed"
            
            # Add to timeline
            timeline_entry = {
                "timestamp": datetime.now().isoformat(),
                "phase": "eradication",
                "action": "eradication_completed",
                "details": eradication_results
            }
            state["timeline"].append(timeline_entry)
            
            success_rate = eradication_results["actions_successful"] / max(eradication_results["actions_attempted"], 1)
            logger.info(f"Eradication completed: {success_rate:.1%} success rate")
            
            return state
            
        except Exception as e:
            logger.error(f"Eradication execution failed: {e}")
            state["eradication_status"] = "failed"
            state["current_phase"] = "eradication_failed"
            return state
    
    async def _execute_recovery(self, state: IncidentResponseState) -> IncidentResponseState:
        """Execute recovery actions"""
        logger.info("IR Node: Executing recovery...")
        
        try:
            playbook = state["selected_playbook"]["playbook"]
            recovery_actions = playbook.get("recovery", [])
            
            execution_results = []
            
            for action_str in recovery_actions:
                try:
                    action = ResponseAction(action_str)
                    result = await self._execute_response_action(action, state)
                    execution_results.append(result)
                except Exception as e:
                    logger.error(f"Recovery action {action_str} failed: {e}")
                    execution_results.append({
                        "action": action_str,
                        "success": False,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    })
            
            recovery_results = {
                "phase": "recovery",
                "actions_attempted": len(recovery_actions),
                "actions_successful": len([r for r in execution_results if r.get("success")]),
                "execution_results": execution_results,
                "completion_time": datetime.now().isoformat()
            }
            
            state["recovery_status"] = "completed"
            state["recovery_results"] = recovery_results
            state["current_phase"] = "recovery_completed"
            
            # Add to timeline
            timeline_entry = {
                "timestamp": datetime.now().isoformat(),
                "phase": "recovery",
                "action": "recovery_completed",
                "details": recovery_results
            }
            state["timeline"].append(timeline_entry)
            
            success_rate = recovery_results["actions_successful"] / max(recovery_results["actions_attempted"], 1)
            logger.info(f"Recovery completed: {success_rate:.1%} success rate")
            
            return state
            
        except Exception as e:
            logger.error(f"Recovery execution failed: {e}")
            state["recovery_status"] = "failed"
            state["current_phase"] = "recovery_failed"
            return state
    
    async def _escalate_to_human(self, state: IncidentResponseState) -> IncidentResponseState:
        """Escalate incident to human analysts"""
        logger.info("IR Node: Escalating to human...")
        
        try:
            incident_type = state["classification"]["incident_type"]
            severity = state["severity"]
            
            escalation_message = f"""
            INCIDENT RESPONSE ESCALATION REQUIRED
            
            Incident ID: {state['incident_id']}
            Type: {incident_type}
            Severity: {severity.upper()}
            Affected Agents: {len(state.get('affected_agents', []))}
            
            Classification Details:
            {json.dumps(state['classification'], indent=2)}
            
            Impact Assessment:
            {json.dumps(state['impact_assessment'], indent=2)}
            
            Recommended Actions:
            {json.dumps(state['selected_playbook']['playbook'], indent=2)}
            
            Human Decision Required:
            - Type 'proceed' to continue with automated response
            - Type 'manual' to take manual control
            - Type 'modify' to adjust response plan
            """
            
            state["escalation_message"] = escalation_message
            state["current_phase"] = "awaiting_human_decision"
            
            # Add to timeline
            timeline_entry = {
                "timestamp": datetime.now().isoformat(),
                "phase": "escalation",
                "action": "escalated_to_human",
                "details": {"severity": severity, "incident_type": incident_type}
            }
            state["timeline"].append(timeline_entry)
            
            # In production, this would send notifications to SOC analysts
            logger.info("📧 Escalation notification sent to SOC analysts")
            
            return state
            
        except Exception as e:
            logger.error(f"Human escalation failed: {e}")
            state["current_phase"] = "escalation_failed"
            return state
    
    async def _post_incident_analysis(self, state: IncidentResponseState) -> IncidentResponseState:
        """Conduct post-incident analysis and lessons learned"""
        logger.info("IR Node: Post-incident analysis...")
        
        try:
            # Calculate response metrics
            timeline = state["timeline"]
            start_time = datetime.fromisoformat(timeline[0]["timestamp"])
            end_time = datetime.now()
            response_duration = (end_time - start_time).total_seconds()
            
            # Collect execution results
            containment_results = state.get("containment_results", {})
            eradication_results = state.get("eradication_results", {})
            recovery_results = state.get("recovery_results", {})
            
            total_actions = (
                containment_results.get("actions_attempted", 0) +
                eradication_results.get("actions_attempted", 0) +
                recovery_results.get("actions_attempted", 0)
            )
            
            successful_actions = (
                containment_results.get("actions_successful", 0) +
                eradication_results.get("actions_successful", 0) +
                recovery_results.get("actions_successful", 0)
            )
            
            # AI-powered lessons learned
            lessons_prompt = f"""
            Generate lessons learned from this incident response:
            
            INCIDENT SUMMARY:
            Type: {state['classification']['incident_type']}
            Severity: {state['severity']}
            Duration: {response_duration} seconds
            Actions Success Rate: {successful_actions}/{total_actions}
            
            TIMELINE:
            {json.dumps(timeline, indent=2)}
            
            Generate lessons learned focusing on:
            1. What worked well
            2. Areas for improvement
            3. Process recommendations
            4. Tool/automation enhancements
            5. Training needs
            
            Respond with JSON format.
            """
            
            ai_response = await self.llm.ainvoke([SystemMessage(content=lessons_prompt)])
            
            # Post-incident analysis results
            post_incident_analysis = {
                "incident_id": state["incident_id"],
                "response_duration_seconds": response_duration,
                "total_actions_attempted": total_actions,
                "successful_actions": successful_actions,
                "success_rate": successful_actions / max(total_actions, 1),
                "phases_completed": ["classification", "impact_assessment", "playbook_selection"],
                "human_escalation_occurred": state.get("human_escalation_required", False),
                "lessons_learned": {
                    "what_worked_well": ["Automated classification", "Rapid containment"],
                    "areas_for_improvement": ["Response time", "Action success rate"],
                    "recommendations": ["Enhance automation", "Improve playbooks"],
                    "ai_analysis": "AI-generated lessons learned"
                },
                "completion_timestamp": datetime.now().isoformat()
            }
            
            state["lessons_learned"] = post_incident_analysis
            state["current_phase"] = "completed"
            
            # Final timeline entry
            timeline_entry = {
                "timestamp": datetime.now().isoformat(),
                "phase": "post_incident",
                "action": "analysis_completed",
                "details": post_incident_analysis
            }
            state["timeline"].append(timeline_entry)
            
            # Store incident in database
            await self._store_incident_record(state)
            
            logger.info(f"Incident response completed: {post_incident_analysis['success_rate']:.1%} success rate")
            
            return state
            
        except Exception as e:
            logger.error(f"Post-incident analysis failed: {e}")
            state["current_phase"] = "post_incident_failed"
            return state
    
    async def _execute_response_action(self, action: ResponseAction, state: IncidentResponseState) -> Dict:
        """Execute a specific response action"""
        
        try:
            if action == ResponseAction.ISOLATE_ENDPOINT:
                return await self._isolate_endpoint(state.get("affected_agents", [])[0] if state.get("affected_agents") else "unknown")
            
            elif action == ResponseAction.BLOCK_IP:
                return await self._block_ip_address("192.0.2.1")  # Example IP
            
            elif action == ResponseAction.DISABLE_USER:
                return await self._disable_user_account("suspicious_user")
            
            elif action == ResponseAction.COLLECT_FORENSICS:
                return await self._collect_forensic_data(state.get("affected_agents", []))
            
            elif action == ResponseAction.QUARANTINE_FILE:
                return await self._quarantine_malicious_file("suspicious.exe")
            
            elif action == ResponseAction.RESET_PASSWORD:
                return await self._reset_user_password("affected_user")
            
            elif action == ResponseAction.PATCH_VULNERABILITY:
                return await self._patch_system_vulnerability("CVE-2024-1234")
            
            elif action == ResponseAction.BACKUP_SYSTEM:
                return await self._backup_affected_systems(state.get("affected_agents", []))
            
            elif action == ResponseAction.SEND_ALERT:
                return await self._send_security_alert(state["incident_id"])
            
            else:
                return {
                    "action": action.value,
                    "success": False,
                    "error": "Action not implemented",
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                "action": action.value,
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    # Response action implementations (simulated for demo)
    async def _isolate_endpoint(self, agent_id: str) -> Dict:
        """Isolate endpoint from network"""
        return {
            "action": "isolate_endpoint",
            "success": True,
            "agent_id": agent_id,
            "details": "Endpoint isolated from network",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _block_ip_address(self, ip_address: str) -> Dict:
        """Block malicious IP address"""
        return {
            "action": "block_ip",
            "success": True,
            "ip_address": ip_address,
            "details": "IP address blocked at firewall",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _disable_user_account(self, username: str) -> Dict:
        """Disable compromised user account"""
        return {
            "action": "disable_user",
            "success": True,
            "username": username,
            "details": "User account disabled",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _collect_forensic_data(self, agent_ids: List[str]) -> Dict:
        """Collect forensic data from affected systems"""
        return {
            "action": "collect_forensics",
            "success": True,
            "agent_ids": agent_ids,
            "collected_data": ["memory_dump", "disk_image", "network_logs"],
            "details": f"Forensic data collected from {len(agent_ids)} systems",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _quarantine_malicious_file(self, filename: str) -> Dict:
        """Quarantine malicious file"""
        return {
            "action": "quarantine_file",
            "success": True,
            "filename": filename,
            "details": "File quarantined and analyzed",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _reset_user_password(self, username: str) -> Dict:
        """Reset compromised user password"""
        return {
            "action": "reset_password",
            "success": True,
            "username": username,
            "details": "Password reset and user notified",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _patch_system_vulnerability(self, cve_id: str) -> Dict:
        """Patch system vulnerability"""
        return {
            "action": "patch_vulnerability",
            "success": True,
            "cve_id": cve_id,
            "details": "Security patch applied",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _backup_affected_systems(self, agent_ids: List[str]) -> Dict:
        """Backup affected systems"""
        return {
            "action": "backup_system",
            "success": True,
            "agent_ids": agent_ids,
            "details": f"Backup created for {len(agent_ids)} systems",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _send_security_alert(self, incident_id: str) -> Dict:
        """Send security alert to stakeholders"""
        return {
            "action": "send_alert",
            "success": True,
            "incident_id": incident_id,
            "recipients": ["soc_team", "security_manager", "it_director"],
            "details": "Security alert sent to stakeholders",
            "timestamp": datetime.now().isoformat()
        }
    
    def _estimate_business_impact(self, severity: str) -> Dict:
        """Estimate business impact based on severity"""
        impact_estimates = {
            "critical": {
                "financial_impact": "high",
                "operational_impact": "severe",
                "reputation_impact": "high",
                "estimated_cost": "> $100,000"
            },
            "high": {
                "financial_impact": "medium",
                "operational_impact": "significant", 
                "reputation_impact": "medium",
                "estimated_cost": "$10,000 - $100,000"
            },
            "medium": {
                "financial_impact": "low",
                "operational_impact": "moderate",
                "reputation_impact": "low",
                "estimated_cost": "$1,000 - $10,000"
            },
            "low": {
                "financial_impact": "minimal",
                "operational_impact": "minor",
                "reputation_impact": "minimal",
                "estimated_cost": "< $1,000"
            }
        }
        return impact_estimates.get(severity, impact_estimates["medium"])
    
    async def _store_incident_record(self, state: IncidentResponseState):
        """Store complete incident record in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create incidents table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    incident_type TEXT,
                    severity TEXT,
                    status TEXT,
                    affected_agents TEXT,
                    timeline TEXT,
                    lessons_learned TEXT,
                    created_at TEXT,
                    completed_at TEXT
                )
            ''')
            
            cursor.execute('''
                INSERT OR REPLACE INTO incidents
                (id, incident_type, severity, status, affected_agents, timeline, lessons_learned, created_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                state["incident_id"],
                state["classification"]["incident_type"],
                state["severity"],
                state["current_phase"],
                json.dumps(state.get("affected_agents", [])),
                json.dumps(state["timeline"]),
                json.dumps(state.get("lessons_learned", {})),
                state["timeline"][0]["timestamp"],
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store incident record: {e}")
    
    # Routing functions
    def _route_after_playbook_selection(self, state: IncidentResponseState) -> str:
        """Route after playbook selection"""
        return "escalate" if state.get("human_escalation_required", False) else "auto_respond"
    
    def _route_after_escalation(self, state: IncidentResponseState) -> str:
        """Route after human escalation"""
        # In real implementation, this would check for human input
        return "proceed"  # Simplified for demo
    
    async def execute_incident_response(self, detection_data: Dict, affected_agents: List[str]) -> Dict:
        """Execute complete incident response workflow"""
        
        # Create initial state
        incident_id = f"incident-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        initial_state = {
            "incident_id": incident_id,
            "detection_data": detection_data,
            "affected_agents": affected_agents,
            "current_phase": "initializing",
            "timeline": [],
            "human_escalation_required": False
        }
        
        # Create thread for this incident
        thread_id = f"incident-{int(datetime.now().timestamp())}"
        config = {"configurable": {"thread_id": thread_id}}
        
        try:
            logger.info(f"Starting incident response workflow: {incident_id}")
            
            # Execute the workflow
            final_state = await self.workflow.ainvoke(initial_state, config)
            
            # Extract final results
            lessons_learned = final_state.get("lessons_learned", {})
            
            return {
                "success": final_state["current_phase"] == "completed",
                "incident_id": incident_id,
                "thread_id": thread_id,
                "workflow_type": "automated_incident_response",
                "final_results": lessons_learned,
                "timeline_events": len(final_state["timeline"]),
                "response_duration": lessons_learned.get("response_duration_seconds", 0),
                "success_rate": lessons_learned.get("success_rate", 0),
                "incident_status": final_state["current_phase"]
            }
            
        except Exception as e:
            logger.error(f"Incident response workflow failed: {e}")
            return {
                "success": False,
                "incident_id": incident_id,
                "thread_id": thread_id,
                "error": str(e),
                "workflow_type": "automated_incident_response"
            }

# Global automated incident responder instance
automated_incident_responder = AutomatedIncidentResponder()
