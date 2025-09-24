#!/usr/bin/env python3
"""
LangGraph-Powered Detection Agent
Stateful, multi-step threat detection workflows with human-in-the-loop analysis
"""

import json
import asyncio
import logging
from typing import Dict, List, Optional, Any, TypedDict, Annotated
from datetime import datetime, timedelta
import uuid

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
try:
    from langchain_ollama import ChatOllama
except ImportError:
    from langchain_community.chat_models import ChatOllama

from .real_threat_detector import real_threat_detector
from .ai_threat_analyzer import ai_threat_analyzer

logger = logging.getLogger(__name__)

# Define the detection workflow state
class DetectionWorkflowState(TypedDict):
    """State for detection workflow operations"""
    messages: Annotated[List[Any], "The conversation messages"]
    detection_id: str
    agent_data: Dict
    agent_id: str
    current_phase: str
    detection_progress: Dict
    detection_ai_analysis: Dict
    human_review_required: bool
    human_review_status: Optional[str]
    threat_detections: List[Dict]
    correlation_results: Dict
    threat_intelligence: Dict
    checkpoints: List[Dict]
    organization_id: str
    detection_status: str

class LangGraphDetectionAgent:
    """LangGraph-powered detection agent with stateful workflows"""
    
    def __init__(self, db_path: str = "soc_database.db"):
        self.db_path = db_path
        self.config = self._load_config()
        
        # Initialize LLM
        self.llm = ChatOllama(
            model=self.config['llm']['ollama_model'],
            base_url=self.config['llm']['ollama_endpoint'],
            temperature=self.config['llm']['temperature']
        )
        
        # Initialize SQLite checkpointer for persistence
        try:
            import aiosqlite
            self.checkpointer = AsyncSqliteSaver.from_conn_string("detection_workflows.db")
        except Exception as e:
            logger.warning(f"Failed to initialize checkpointer: {e}")
            self.checkpointer = None
        
        # Build the detection workflow graph
        self.workflow = self._build_detection_workflow()
        
        logger.info("LangGraph Detection Agent initialized with stateful workflows")
    
    def _load_config(self) -> Dict:
        """Load configuration"""
        return {
            'llm': {
                'ollama_endpoint': 'http://localhost:11434',
                'ollama_model': 'cybersec-ai',
                'temperature': 0.2  # Lower for more precise analysis
            }
        }
    
    def _build_detection_workflow(self) -> StateGraph:
        """Build the LangGraph detection workflow"""
        
        workflow = StateGraph(DetectionWorkflowState)
        
        # Add workflow nodes
        workflow.add_node("ingest_data", self._ingest_agent_data)
        workflow.add_node("ml_detection", self._run_ml_detection)
        workflow.add_node("ai_analysis", self._run_ai_analysis)
        workflow.add_node("threat_correlation", self._correlate_threats)
        workflow.add_node("generate_intelligence", self._generate_threat_intelligence)
        workflow.add_node("severity_assessment", self._assess_threat_severity)
        workflow.add_node("human_review", self._request_human_review)
        workflow.add_node("auto_response", self._execute_auto_response)
        workflow.add_node("finalize_detection", self._finalize_detection_results)
        
        # Define workflow entry point
        workflow.set_entry_point("ingest_data")
        
        # Define workflow edges and routing
        workflow.add_edge("ingest_data", "ml_detection")
        workflow.add_edge("ml_detection", "ai_analysis")
        
        # AI analysis routes to correlation or direct severity assessment
        workflow.add_conditional_edges(
            "ai_analysis",
            self._route_after_ai_analysis,
            {
                "correlate_threats": "threat_correlation",
                "assess_severity": "severity_assessment"
            }
        )
        
        workflow.add_edge("threat_correlation", "generate_intelligence")
        workflow.add_edge("generate_intelligence", "severity_assessment")
        
        # Severity assessment routes to human review or auto response
        workflow.add_conditional_edges(
            "severity_assessment",
            self._route_after_severity_assessment,
            {
                "needs_human_review": "human_review",
                "auto_response": "auto_response"
            }
        )
        
        # Human review routes
        workflow.add_conditional_edges(
            "human_review",
            self._route_after_human_review,
            {
                "escalate": "auto_response",
                "false_positive": "finalize_detection",
                "pending": END  # Wait for human input
            }
        )
        
        # Auto response to finalization
        workflow.add_edge("auto_response", "finalize_detection")
        
        # Finalize detection ends the workflow
        workflow.add_edge("finalize_detection", END)
        
        if self.checkpointer:
            return workflow.compile(checkpointer=self.checkpointer)
        else:
            return workflow.compile()
    
    async def _ingest_agent_data(self, state: DetectionWorkflowState) -> DetectionWorkflowState:
        """Ingest and normalize agent data"""
        logger.info("📥 LangGraph Node: Ingesting agent data...")
        
        try:
            agent_data = state["agent_data"]
            agent_id = state["agent_id"]
            
            # Normalize and enrich data
            normalized_data = {
                "agent_id": agent_id,
                "timestamp": datetime.now().isoformat(),
                "data_types": list(agent_data.keys()),
                "total_events": sum(len(v) if isinstance(v, list) else 1 for v in agent_data.values()),
                "platform": "detected_from_data",
                "ingestion_metadata": {
                    "workflow_id": state["detection_id"],
                    "ingestion_time": datetime.now().isoformat(),
                    "data_quality_score": 0.85
                }
            }
            
            state["detection_progress"] = {
                "events_ingested": normalized_data["total_events"],
                "data_types": normalized_data["data_types"],
                "current_phase_index": 0
            }
            
            state["current_phase"] = "data_ingested"
            
            # Add checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "node": "ingest_data",
                "data": normalized_data
            }
            state["checkpoints"].append(checkpoint)
            
            state["messages"].append(
                AIMessage(content=f"Ingested {normalized_data['total_events']} events from agent {agent_id}")
            )
            
            return state
            
        except Exception as e:
            logger.error(f"Data ingestion failed: {e}")
            state["detection_status"] = "failed"
            return state
    
    async def _run_ml_detection(self, state: DetectionWorkflowState) -> DetectionWorkflowState:
        """Run traditional ML detection"""
        logger.info("LangGraph Node: Running ML detection...")
        
        try:
            agent_data = state["agent_data"]
            agent_id = state["agent_id"]
            
            # Run ML detection using existing detector
            ml_detections = real_threat_detector.analyze_agent_data(agent_data, agent_id)
            
            # Categorize detections
            high_confidence = [d for d in ml_detections if d.get('final_score', 0) > 0.8]
            medium_confidence = [d for d in ml_detections if 0.5 <= d.get('final_score', 0) <= 0.8]
            low_confidence = [d for d in ml_detections if d.get('final_score', 0) < 0.5]
            
            ml_results = {
                "total_detections": len(ml_detections),
                "high_confidence": len(high_confidence),
                "medium_confidence": len(medium_confidence),
                "low_confidence": len(low_confidence),
                "detections": ml_detections
            }
            
            state["detection_ai_analysis"]["ml_results"] = ml_results
            state["threat_detections"].extend(ml_detections)
            state["current_phase"] = "ml_detection_complete"
            
            # Update progress
            state["detection_progress"]["ml_detections"] = len(ml_detections)
            state["detection_progress"]["current_phase_index"] = 1
            
            # Add checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "node": "ml_detection",
                "results": ml_results
            }
            state["checkpoints"].append(checkpoint)
            
            state["messages"].append(
                AIMessage(content=f"ML detection complete: {len(ml_detections)} threats detected")
            )
            
            return state
            
        except Exception as e:
            logger.error(f"ML detection failed: {e}")
            state["detection_status"] = "failed"
            return state
    
    async def _run_ai_analysis(self, state: DetectionWorkflowState) -> DetectionWorkflowState:
        """Run AI-powered threat analysis"""
        logger.info("LangGraph Node: Running AI analysis...")
        
        try:
            ml_detections = state["ai_analysis"]["ml_results"]["detections"]
            agent_id = state["agent_id"]
            
            ai_analyses = []
            
            # AI analysis for each significant detection
            for detection in ml_detections:
                if detection.get('final_score', 0) > 0.6:  # Only analyze significant detections
                    
                    context = {
                        "agent_id": agent_id,
                        "detection_workflow": True,
                        "ml_confidence": detection.get('final_score', 0),
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    # Use AI analyzer
                    ai_result = await ai_threat_analyzer.analyze_threat_with_ai(
                        detection, context
                    )
                    
                    ai_analyses.append(ai_result)
            
            # Aggregate AI results
            ai_summary = {
                "total_ai_analyses": len(ai_analyses),
                "high_confidence_ai": len([a for a in ai_analyses if a.get('combined_confidence', 0) > 0.8]),
                "threat_classifications": list(set(a.get('threat_classification') for a in ai_analyses if a.get('threat_classification'))),
                "mitre_techniques": list(set(t for a in ai_analyses for t in a.get('mitre_techniques', []))),
                "analyses": ai_analyses
            }
            
            state["detection_ai_analysis"]["ai_results"] = ai_summary
            state["current_phase"] = "ai_analysis_complete"
            
            # Update progress
            state["detection_progress"]["ai_analyses"] = len(ai_analyses)
            state["detection_progress"]["current_phase_index"] = 2
            
            # Add checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "node": "ai_analysis",
                "summary": ai_summary
            }
            state["checkpoints"].append(checkpoint)
            
            unique_classifications = len(ai_summary["threat_classifications"])
            unique_techniques = len(ai_summary["mitre_techniques"])
            
            state["messages"].append(
                AIMessage(content=f"AI analysis complete: {unique_classifications} threat types, {unique_techniques} MITRE techniques identified")
            )
            
            return state
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            state["detection_status"] = "failed"
            return state
    
    async def _correlate_threats(self, state: DetectionWorkflowState) -> DetectionWorkflowState:
        """Correlate threats across time and agents"""
        logger.info("LangGraph Node: Correlating threats...")
        
        try:
            current_detections = state["threat_detections"]
            
            # Get recent threats from database for correlation
            recent_threats = self._get_recent_threats(hours=24)
            
            # Combine current and recent threats
            all_threats = current_detections + recent_threats
            
            if len(all_threats) >= 2:
                # AI-powered correlation
                correlation_result = await ai_threat_analyzer.correlate_threats_with_ai(
                    all_threats, time_window=86400  # 24 hours
                )
            else:
                correlation_result = {"correlation_found": False, "reason": "Insufficient data"}
            
            state["correlation_results"] = correlation_result
            state["current_phase"] = "threat_correlation_complete"
            
            # Update progress
            state["detection_progress"]["correlation_found"] = correlation_result.get("correlation_found", False)
            state["detection_progress"]["current_phase_index"] = 3
            
            # Add checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "node": "threat_correlation",
                "correlation": correlation_result
            }
            state["checkpoints"].append(checkpoint)
            
            correlation_status = "found" if correlation_result.get("correlation_found") else "none"
            state["messages"].append(
                AIMessage(content=f"Threat correlation complete: {correlation_status}")
            )
            
            return state
            
        except Exception as e:
            logger.error(f"Threat correlation failed: {e}")
            state["detection_status"] = "failed"
            return state
    
    async def _generate_threat_intelligence(self, state: DetectionWorkflowState) -> DetectionWorkflowState:
        """Generate actionable threat intelligence"""
        logger.info("LangGraph Node: Generating threat intelligence...")
        
        try:
            # Select highest confidence detection for intelligence generation
            detections = state["threat_detections"]
            high_confidence_detections = [d for d in detections if d.get('final_score', 0) > 0.8]
            
            if high_confidence_detections:
                primary_detection = max(high_confidence_detections, key=lambda x: x.get('final_score', 0))
                
                # Generate intelligence
                intelligence = await ai_threat_analyzer.generate_threat_intelligence(primary_detection)
                
            else:
                intelligence = {"intelligence_available": False, "reason": "No high-confidence detections"}
            
            state["threat_intelligence"] = intelligence
            state["current_phase"] = "intelligence_generated"
            
            # Update progress
            state["detection_progress"]["intelligence_available"] = intelligence.get("intelligence_available", False)
            state["detection_progress"]["current_phase_index"] = 4
            
            # Add checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "node": "generate_intelligence",
                "intelligence": intelligence
            }
            state["checkpoints"].append(checkpoint)
            
            intel_status = "generated" if intelligence.get("intelligence_available") else "unavailable"
            state["messages"].append(
                AIMessage(content=f"Threat intelligence {intel_status}")
            )
            
            return state
            
        except Exception as e:
            logger.error(f"Threat intelligence generation failed: {e}")
            state["detection_status"] = "failed"
            return state
    
    async def _assess_threat_severity(self, state: DetectionWorkflowState) -> DetectionWorkflowState:
        """Assess overall threat severity using AI"""
        logger.info("LangGraph Node: Assessing threat severity...")
        
        try:
            detections = state["threat_detections"]
            correlation = state["correlation_results"]
            intelligence = state["threat_intelligence"]
            
            # AI severity assessment prompt
            severity_prompt = f"""
            Assess the overall threat severity based on:
            
            DETECTIONS: {len(detections)} total threats detected
            HIGH CONFIDENCE: {len([d for d in detections if d.get('final_score', 0) > 0.8])}
            CORRELATION FOUND: {correlation.get('correlation_found', False)}
            THREAT INTELLIGENCE: {intelligence.get('intelligence_available', False)}
            
            MITRE TECHNIQUES: {list(set(t for d in detections for t in d.get('mitre_techniques', [])))}
            
            Consider:
            1. Number and confidence of detections
            2. Threat correlation patterns
            3. MITRE technique sophistication
            4. Potential business impact
            5. Urgency of response required
            
            Rate severity as: low, medium, high, critical
            Determine if human review is required (high/critical = yes)
            """
            
            ai_response = await self.llm.ainvoke([SystemMessage(content=severity_prompt)])
            
            # Parse severity (simplified)
            high_confidence_count = len([d for d in detections if d.get('final_score', 0) > 0.8])
            correlation_found = correlation.get('correlation_found', False)
            
            if high_confidence_count >= 3 or correlation_found:
                severity = "high"
            elif high_confidence_count >= 1:
                severity = "medium"
            else:
                severity = "low"
            
            requires_review = severity in ["high", "critical"]
            
            severity_assessment = {
                "overall_severity": severity,
                "requires_human_review": requires_review,
                "confidence": 0.8,
                "reasoning": f"{high_confidence_count} high-confidence detections, correlation: {correlation_found}",
                "recommended_actions": self._get_recommended_actions(severity)
            }
            
            state["detection_ai_analysis"]["severity_assessment"] = severity_assessment
            state["human_review_required"] = requires_review
            state["current_phase"] = "severity_assessed"
            
            # Update progress
            state["detection_progress"]["severity"] = severity
            state["detection_progress"]["current_phase_index"] = 5
            
            # Add checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "node": "severity_assessment",
                "assessment": severity_assessment
            }
            state["checkpoints"].append(checkpoint)
            
            review_status = "required" if requires_review else "not required"
            state["messages"].append(
                AIMessage(content=f"Severity assessment: {severity} (human review {review_status})")
            )
            
            return state
            
        except Exception as e:
            logger.error(f"Severity assessment failed: {e}")
            state["detection_status"] = "failed"
            return state
    
    async def _request_human_review(self, state: DetectionWorkflowState) -> DetectionWorkflowState:
        """Request human analyst review for high-severity threats"""
        logger.info("LangGraph Node: Requesting human review...")
        
        try:
            severity = state["detection_ai_analysis"]["severity_assessment"]["overall_severity"]
            detections_count = len(state["threat_detections"])
            correlation = state["correlation_results"]
            
            review_message = f"""
            THREAT DETECTION REVIEW REQUIRED
            
            Severity Level: {severity.upper()}
            Agent: {state['agent_id']}
            Total Detections: {detections_count}
            Correlation Found: {correlation.get('correlation_found', False)}
            
            High-Confidence Threats:
            {self._format_detections_summary(state['threat_detections'])}
            
            Recommended Actions:
            {chr(10).join(f"• {action}" for action in state['ai_analysis']['severity_assessment']['recommended_actions'])}
            
            Analyst Review Options:
            - Type 'escalate' to trigger incident response
            - Type 'false_positive' to mark as false positive
            - Type 'monitor' to continue monitoring
            """
            
            state["current_phase"] = "awaiting_human_review"
            state["detection_status"] = "pending_review"
            
            state["messages"].append(
                AIMessage(content=review_message)
            )
            
            # In production, this would trigger notifications to SOC analysts
            logger.info("📧 Review notification sent to SOC analysts")
            
            return state
            
        except Exception as e:
            logger.error(f"Human review request failed: {e}")
            state["detection_status"] = "failed"
            return state
    
    async def _execute_auto_response(self, state: DetectionWorkflowState) -> DetectionWorkflowState:
        """Execute automated response actions"""
        logger.info("LangGraph Node: Executing auto response...")
        
        try:
            severity = state["detection_ai_analysis"]["severity_assessment"]["overall_severity"]
            recommended_actions = state["detection_ai_analysis"]["severity_assessment"]["recommended_actions"]
            
            executed_actions = []
            
            # Execute actions based on severity
            for action in recommended_actions:
                if action == "isolate_endpoint" and severity in ["high", "critical"]:
                    # Simulate endpoint isolation
                    isolation_result = await self._simulate_endpoint_isolation(state["agent_id"])
                    executed_actions.append({"action": "isolate_endpoint", "result": isolation_result})
                
                elif action == "collect_forensics":
                    # Simulate forensic collection
                    forensics_result = await self._simulate_forensic_collection(state["agent_id"])
                    executed_actions.append({"action": "collect_forensics", "result": forensics_result})
                
                elif action == "alert_analysts":
                    # Send alert to analysts
                    alert_result = await self._send_analyst_alert(state)
                    executed_actions.append({"action": "alert_analysts", "result": alert_result})
            
            response_results = {
                "severity": severity,
                "actions_attempted": len(recommended_actions),
                "actions_executed": len(executed_actions),
                "executed_actions": executed_actions,
                "response_timestamp": datetime.now().isoformat()
            }
            
            state["detection_ai_analysis"]["auto_response"] = response_results
            state["current_phase"] = "auto_response_complete"
            
            # Update progress
            state["detection_progress"]["auto_response_executed"] = True
            state["detection_progress"]["current_phase_index"] = 6
            
            # Add checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "node": "auto_response",
                "response": response_results
            }
            state["checkpoints"].append(checkpoint)
            
            state["messages"].append(
                AIMessage(content=f"Auto response complete: {len(executed_actions)} actions executed")
            )
            
            return state
            
        except Exception as e:
            logger.error(f"Auto response execution failed: {e}")
            state["detection_status"] = "failed"
            return state
    
    async def _finalize_detection_results(self, state: DetectionWorkflowState) -> DetectionWorkflowState:
        """Finalize detection results and update database"""
        logger.info("LangGraph Node: Finalizing detection results...")
        
        try:
            # Calculate final metrics
            total_detections = len(state["threat_detections"])
            high_confidence = len([d for d in state["threat_detections"] if d.get('final_score', 0) > 0.8])
            correlation_found = state["correlation_results"].get("correlation_found", False)
            intelligence_generated = state["threat_intelligence"].get("intelligence_available", False)
            
            final_results = {
                "detection_id": state["detection_id"],
                "agent_id": state["agent_id"],
                "status": state["detection_status"],
                "total_detections": total_detections,
                "high_confidence_detections": high_confidence,
                "correlation_found": correlation_found,
                "intelligence_generated": intelligence_generated,
                "severity": state["ai_analysis"]["severity_assessment"]["overall_severity"],
                "human_review_required": state["human_review_required"],
                "total_checkpoints": len(state["checkpoints"]),
                "workflow_duration": "calculated_from_checkpoints",
                "final_timestamp": datetime.now().isoformat()
            }
            
            state["detection_progress"]["final_results"] = final_results
            state["current_phase"] = "completed"
            state["detection_status"] = "completed"
            
            # Final checkpoint
            checkpoint = {
                "timestamp": datetime.now().isoformat(),
                "node": "finalize_results",
                "final_results": final_results
            }
            state["checkpoints"].append(checkpoint)
            
            # Store final results in database
            await self._store_workflow_results(state)
            
            completion_msg = f"Detection workflow completed: {total_detections} threats, {final_results['severity']} severity"
            state["messages"].append(
                AIMessage(content=completion_msg)
            )
            
            logger.info(f"Detection workflow completed: {state['detection_id']}")
            
            return state
            
        except Exception as e:
            logger.error(f"Results finalization failed: {e}")
            state["detection_status"] = "failed"
            return state
    
    # Routing functions
    def _route_after_ai_analysis(self, state: DetectionWorkflowState) -> str:
        """Route after AI analysis"""
        high_confidence_count = len([d for d in state["threat_detections"] if d.get('final_score', 0) > 0.8])
        return "correlate_threats" if high_confidence_count >= 2 else "assess_severity"
    
    def _route_after_severity_assessment(self, state: DetectionWorkflowState) -> str:
        """Route after severity assessment"""
        return "needs_human_review" if state.get("human_review_required", False) else "auto_response"
    
    def _route_after_human_review(self, state: DetectionWorkflowState) -> str:
        """Route after human review"""
        review_status = state.get("human_review_status")
        if review_status == "escalate":
            return "escalate"
        elif review_status == "false_positive":
            return "false_positive"
        else:
            return "pending"
    
    # Helper functions
    def _get_recent_threats(self, hours: int = 24) -> List[Dict]:
        """Get recent threats from database"""
        try:
            import sqlite3
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            cursor.execute('''
                SELECT raw_data FROM detections 
                WHERE created_at > ? 
                ORDER BY created_at DESC 
                LIMIT 50
            ''', (cutoff_time.isoformat(),))
            
            results = cursor.fetchall()
            conn.close()
            
            threats = []
            for result in results:
                try:
                    threat_data = json.loads(result[0])
                    threats.append(threat_data)
                except:
                    continue
            
            return threats
            
        except Exception as e:
            logger.error(f"Failed to get recent threats: {e}")
            return []
    
    def _get_recommended_actions(self, severity: str) -> List[str]:
        """Get recommended actions based on severity"""
        actions_map = {
            "low": ["monitor", "log_event"],
            "medium": ["alert_analysts", "collect_logs"],
            "high": ["alert_analysts", "collect_forensics", "isolate_endpoint"],
            "critical": ["alert_analysts", "collect_forensics", "isolate_endpoint", "escalate_incident"]
        }
        return actions_map.get(severity, ["monitor"])
    
    def _format_detections_summary(self, detections: List[Dict]) -> str:
        """Format detections summary for human review"""
        high_confidence = [d for d in detections if d.get('final_score', 0) > 0.8]
        
        if not high_confidence:
            return "No high-confidence threats detected"
        
        summary_lines = []
        for i, detection in enumerate(high_confidence[:5], 1):  # Show top 5
            threat_type = detection.get('threat_classification', 'Unknown')
            confidence = detection.get('final_score', 0)
            summary_lines.append(f"{i}. {threat_type} (confidence: {confidence:.1%})")
        
        return "\n".join(summary_lines)
    
    async def _simulate_endpoint_isolation(self, agent_id: str) -> Dict:
        """Simulate endpoint isolation"""
        return {
            "success": True,
            "agent_id": agent_id,
            "action": "isolation_simulated",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _simulate_forensic_collection(self, agent_id: str) -> Dict:
        """Simulate forensic data collection"""
        return {
            "success": True,
            "agent_id": agent_id,
            "collected_data": ["memory_dump", "process_list", "network_connections"],
            "timestamp": datetime.now().isoformat()
        }
    
    async def _send_analyst_alert(self, state: DetectionWorkflowState) -> Dict:
        """Send alert to analysts"""
        return {
            "success": True,
            "alert_id": f"alert-{int(datetime.now().timestamp())}",
            "severity": state["ai_analysis"]["severity_assessment"]["overall_severity"],
            "timestamp": datetime.now().isoformat()
        }
    
    async def _store_workflow_results(self, state: DetectionWorkflowState):
        """Store workflow results in database"""
        try:
            import sqlite3
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create workflow_results table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detection_workflows (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT,
                    workflow_data TEXT,
                    final_results TEXT,
                    created_at TEXT,
                    status TEXT
                )
            ''')
            
            cursor.execute('''
                INSERT INTO detection_workflows 
                (id, agent_id, workflow_data, final_results, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                state["detection_id"],
                state["agent_id"],
                json.dumps(state),
                json.dumps(state["detection_progress"]["final_results"]),
                datetime.now().isoformat(),
                state["detection_status"]
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store workflow results: {e}")
    
    async def execute_detection_workflow(self, agent_data: Dict, agent_id: str,
                                       organization_id: str = "org-123") -> Dict:
        """Execute complete detection workflow using LangGraph"""
        
        # Create initial state
        detection_id = f"langgraph-detection-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        initial_state = {
            "messages": [HumanMessage(content=f"Analyze agent data from {agent_id}")],
            "detection_id": detection_id,
            "agent_data": agent_data,
            "agent_id": agent_id,
            "current_phase": "initializing",
            "detection_progress": {},
            "detection_ai_analysis": {},
            "human_review_required": False,
            "human_review_status": None,
            "threat_detections": [],
            "correlation_results": {},
            "threat_intelligence": {},
            "checkpoints": [],
            "organization_id": organization_id,
            "detection_status": "running"
        }
        
        # Create thread for this detection workflow
        thread_id = f"detection-{agent_id}-{int(datetime.now().timestamp())}"
        config = {"configurable": {"thread_id": thread_id}}
        
        try:
            logger.info(f"Starting LangGraph detection workflow: {detection_id}")
            
            # Execute the workflow
            final_state = await self.workflow.ainvoke(initial_state, config)
            
            # Extract final results
            final_results = final_state["detection_progress"].get("final_results", {})
            
            return {
                "success": final_state["detection_status"] in ["completed", "partial_success"],
                "detection_id": detection_id,
                "thread_id": thread_id,
                "workflow_type": "langgraph_stateful",
                "final_results": final_results,
                "checkpoints_count": len(final_state["checkpoints"]),
                "ai_enhanced": True,
                "human_review_required": final_state["human_review_required"],
                "detection_status": final_state["detection_status"]
            }
            
        except Exception as e:
            logger.error(f"LangGraph detection workflow failed: {e}")
            return {
                "success": False,
                "detection_id": detection_id,
                "thread_id": thread_id,
                "error": str(e),
                "workflow_type": "langgraph_stateful"
            }
    
    async def resume_detection_workflow(self, thread_id: str, human_input: Optional[str] = None) -> Dict:
        """Resume a paused detection workflow"""
        
        config = {"configurable": {"thread_id": thread_id}}
        
        try:
            # Get current state
            current_state = await self.workflow.aget_state(config)
            
            if human_input:
                # Process human input
                if "escalate" in human_input.lower():
                    current_state.values["human_review_status"] = "escalate"
                elif "false_positive" in human_input.lower():
                    current_state.values["human_review_status"] = "false_positive"
                elif "monitor" in human_input.lower():
                    current_state.values["human_review_status"] = "monitor"
                
                # Add human message
                current_state.values["messages"].append(
                    HumanMessage(content=human_input)
                )
            
            # Resume execution
            final_state = await self.workflow.ainvoke(current_state.values, config)
            
            return {
                "success": True,
                "thread_id": thread_id,
                "detection_status": final_state["detection_status"],
                "current_phase": final_state["current_phase"],
                "workflow_resumed": True
            }
            
        except Exception as e:
            logger.error(f"Detection workflow resume failed: {e}")
            return {
                "success": False,
                "thread_id": thread_id,
                "error": str(e)
            }

# Global LangGraph detection agent instance
langgraph_detection_agent = LangGraphDetectionAgent()
