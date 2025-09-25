"""
LangGraph Detection Workflow with ML and LLM Integration
Continuous threat detection system with AI reasoning
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, TypedDict, Annotated, Sequence, Optional
from enum import Enum
from datetime import datetime, timezone
import uuid
import numpy as np

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
from ..tools.log_processing_tools import LogFetcherTool, LogParserTool, LogAggregatorTool
from ..tools.ml_detection_tools import MLModelManager, LogEnrichmentTool, ThreatIntelligenceTool
from ..tools.llm_manager import llm_manager, LLMProvider
from ..prompts.detection_prompts import detection_prompts

logger = logging.getLogger(__name__)

# ============= STATE DEFINITION =============

class DetectionPhase(Enum):
    """Detection workflow phases"""
    IDLE = "idle"
    LOG_FETCHING = "log_fetching"
    LOG_PARSING = "log_parsing"
    LOG_ENRICHMENT = "log_enrichment"
    ML_DETECTION = "ml_detection"
    LLM_ANALYSIS = "llm_analysis"
    THREAT_INTELLIGENCE = "threat_intelligence"
    CORRELATION = "correlation"
    AI_REASONING = "ai_reasoning"
    VERDICT = "verdict"
    ALERT_GENERATION = "alert_generation"
    NOTIFICATION = "notification"
    COMPLETE = "complete"

class ThreatVerdict(Enum):
    """Final threat verdict categories"""
    CONFIRMED_THREAT = "confirmed_threat"
    LIKELY_THREAT = "likely_threat"
    SUSPICIOUS = "suspicious"
    LIKELY_BENIGN = "likely_benign"
    CONFIRMED_BENIGN = "confirmed_benign"

class DetectionState(TypedDict):
    """State for detection workflow"""
    # Configuration
    batch_size: int
    time_window: int  # minutes
    llm_provider: str
    continuous_mode: bool
    
    # Raw data
    raw_logs: List[Dict]
    parsed_logs: List[Dict]
    enriched_logs: List[Dict]
    
    # ML Detection results
    ml_results: Dict[str, Any]
    ml_anomalies: List[Dict]
    ml_malware: List[Dict]
    ml_confidence_scores: List[float]
    
    # LLM Analysis results
    llm_results: List[Dict]
    llm_threats: List[Dict]
    llm_confidence_scores: List[float]
    
    # Threat Intelligence
    threat_intel_results: Dict[str, Any]
    known_iocs: List[Dict]
    
    # Correlation and aggregation
    aggregated_data: Dict[str, Any]
    correlations: List[Dict]
    patterns: List[Dict]
    
    # AI Reasoning results
    reasoning_analysis: Dict[str, Any]
    final_verdict: ThreatVerdict
    verdict_confidence: float
    
    # Alerts and notifications
    alerts_generated: List[Dict]
    notifications_sent: List[Dict]
    
    # Control and status
    current_phase: DetectionPhase
    iteration_count: int
    threats_detected: int
    false_positives: int
    processing_time: float
    
    # Messages and errors
    messages: Sequence[str]
    errors: List[str]

# ============= DETECTION NODES =============

class DetectionWorkflowNodes:
    """Nodes for the detection workflow"""
    
    def __init__(self, db_path: str = "soc_database.db"):
        # Initialize tools
        self.log_fetcher = LogFetcherTool(db_path)
        self.log_parser = LogParserTool()
        self.log_aggregator = LogAggregatorTool()
        self.log_enricher = LogEnrichmentTool(db_path)
        self.ml_manager = MLModelManager()
        self.threat_intel = ThreatIntelligenceTool()
        
        # Track processing state
        self.last_fetch_time = None
    
    async def log_fetching_node(self, state: DetectionState) -> DetectionState:
        """Fetch logs from database"""
        logger.info("Fetching logs from database")
        
        try:
            # Fetch logs
            result = self.log_fetcher.run(
                batch_size=state.get('batch_size', 100),
                time_window=state.get('time_window', 5)
            )
            
            if result['success']:
                # Combine detection and agent logs
                all_logs = result['detection_logs'] + result['agent_logs']
                state['raw_logs'] = all_logs
                state['messages'].append(f"Fetched {len(all_logs)} logs for analysis")
                
                if len(all_logs) == 0:
                    state['current_phase'] = DetectionPhase.IDLE
                    state['messages'].append("No new logs to process")
                else:
                    state['current_phase'] = DetectionPhase.LOG_PARSING
            else:
                state['errors'].append(f"Log fetching failed: {result.get('error')}")
                state['current_phase'] = DetectionPhase.IDLE
            
        except Exception as e:
            logger.error(f"Log fetching error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = DetectionPhase.IDLE
        
        return state
    
    async def log_parsing_node(self, state: DetectionState) -> DetectionState:
        """Parse and structure logs"""
        logger.info("Parsing logs")
        
        try:
            if not state.get('raw_logs'):
                state['current_phase'] = DetectionPhase.IDLE
                return state
            
            # Parse logs
            parsed_logs = self.log_parser.run(state['raw_logs'])
            state['parsed_logs'] = parsed_logs
            
            # Filter high-risk logs for priority processing
            high_risk_logs = [
                log for log in parsed_logs 
                if log.get('initial_risk_score', 0) > 50
            ]
            
            state['messages'].append(
                f"Parsed {len(parsed_logs)} logs, {len(high_risk_logs)} high-risk"
            )
            
            state['current_phase'] = DetectionPhase.LOG_ENRICHMENT
            
        except Exception as e:
            logger.error(f"Log parsing error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = DetectionPhase.LOG_ENRICHMENT
        
        return state
    
    async def log_enrichment_node(self, state: DetectionState) -> DetectionState:
        """Enrich logs with context"""
        logger.info("Enriching logs with context")
        
        try:
            logs_to_enrich = state.get('parsed_logs', state.get('raw_logs', []))
            
            # Enrich logs
            enriched_logs = self.log_enricher.run(logs_to_enrich)
            state['enriched_logs'] = enriched_logs
            
            state['messages'].append(f"Enriched {len(enriched_logs)} logs")
            state['current_phase'] = DetectionPhase.ML_DETECTION
            
        except Exception as e:
            logger.error(f"Log enrichment error: {e}")
            state['errors'].append(str(e))
            # Continue even if enrichment fails
            state['enriched_logs'] = state.get('parsed_logs', state.get('raw_logs', []))
            state['current_phase'] = DetectionPhase.ML_DETECTION
        
        return state
    
    async def ml_detection_node(self, state: DetectionState) -> DetectionState:
        """Run ML models for detection"""
        logger.info("Running ML detection models")
        
        try:
            logs = state.get('enriched_logs', [])
            
            if not logs:
                state['current_phase'] = DetectionPhase.LLM_ANALYSIS
                return state
            
            # Prepare log texts for ML analysis
            log_texts = []
            for log in logs:
                log_text = f"{log.get('message', '')} {log.get('description', '')} {json.dumps(log.get('data', {}))}"
                log_texts.append(log_text)
            
            # Run ML analysis
            ml_results = self.ml_manager.analyze_logs(log_texts)
            state['ml_results'] = ml_results
            
            if ml_results['success']:
                # Extract anomalies and malware
                state['ml_anomalies'] = [
                    r for r in ml_results['results'] 
                    if r['anomaly_detected'] == 1
                ]
                
                state['ml_malware'] = [
                    r for r in ml_results['results']
                    if r['malware_detected'] == 1
                ]
                
                state['ml_confidence_scores'] = [
                    max(r['anomaly_score'], r['malware_confidence'])
                    for r in ml_results['results']
                ]
                
                state['messages'].append(
                    f"ML Detection: {ml_results['anomalies_found']} anomalies, "
                    f"{ml_results['malware_found']} malware indicators"
                )
            else:
                state['errors'].append(f"ML detection failed: {ml_results.get('error')}")
            
            state['current_phase'] = DetectionPhase.LLM_ANALYSIS
            
        except Exception as e:
            logger.error(f"ML detection error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = DetectionPhase.LLM_ANALYSIS
        
        return state
    
    async def llm_analysis_node(self, state: DetectionState) -> DetectionState:
        """Analyze logs using LLM"""
        logger.info("Running LLM analysis")
        
        try:
            logs = state.get('enriched_logs', [])
            
            if not logs:
                state['current_phase'] = DetectionPhase.THREAT_INTELLIGENCE
                return state
            
            # Batch logs for LLM analysis (limit to avoid token limits)
            logs_to_analyze = logs[:20]  # Analyze top 20 logs
            
            # Prepare log entries for LLM
            log_entries = []
            for log in logs_to_analyze:
                entry = f"[{log.get('timestamp')}] {log.get('agent_id')}: {log.get('message', '')} {log.get('description', '')}"
                log_entries.append(entry)
            
            # Get LLM analysis
            prompt = detection_prompts.get_prompt(
                'log_analysis',
                log_entries='\n'.join(log_entries),
                agent_info=json.dumps({
                    'agents': list(set(log.get('agent_id') for log in logs))
                }),
                time_period=f"{state.get('time_window', 5)} minutes",
                log_count=len(logs),
                agent_importance='mixed'  # Could be determined from enrichment
            )
            
            llm_response = await llm_manager.generate(
                prompt,
                provider=LLMProvider(state.get('llm_provider', 'ollama'))
            )
            
            # Store LLM analysis
            state['llm_results'].append({
                'phase': 'log_analysis',
                'response': llm_response,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'logs_analyzed': len(logs_to_analyze)
            })
            
            # Parse threats from LLM response (simplified)
            threats = self._parse_llm_threats(llm_response)
            state['llm_threats'] = threats
            
            state['messages'].append(f"LLM analyzed {len(logs_to_analyze)} logs")
            state['current_phase'] = DetectionPhase.THREAT_INTELLIGENCE
            
        except Exception as e:
            logger.error(f"LLM analysis error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = DetectionPhase.THREAT_INTELLIGENCE
        
        return state
    
    async def threat_intelligence_node(self, state: DetectionState) -> DetectionState:
        """Check against threat intelligence"""
        logger.info("Checking threat intelligence")
        
        try:
            logs = state.get('enriched_logs', [])
            
            # Run threat intelligence check
            threat_intel_results = self.threat_intel.run(logs)
            state['threat_intel_results'] = threat_intel_results
            
            if threat_intel_results['success']:
                state['known_iocs'] = threat_intel_results['threat_details']
                state['messages'].append(
                    f"Threat Intel: {threat_intel_results['threats_found']} IOCs matched"
                )
            
            state['current_phase'] = DetectionPhase.CORRELATION
            
        except Exception as e:
            logger.error(f"Threat intelligence error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = DetectionPhase.CORRELATION
        
        return state
    
    async def correlation_node(self, state: DetectionState) -> DetectionState:
        """Correlate and aggregate findings"""
        logger.info("Correlating detection results")
        
        try:
            logs = state.get('enriched_logs', [])
            
            # Aggregate logs
            aggregated = self.log_aggregator.run(logs)
            state['aggregated_data'] = aggregated
            state['correlations'] = aggregated.get('correlations', [])
            state['patterns'] = aggregated.get('patterns', [])
            
            # Get LLM correlation analysis
            if state['correlations'] or state['patterns']:
                prompt = detection_prompts.get_prompt(
                    'correlation_analysis',
                    primary_event=json.dumps(logs[0] if logs else {}),
                    related_events=json.dumps(logs[1:5] if len(logs) > 1 else []),
                    network_context='Multiple agents detected',
                    time_window=f"{state.get('time_window', 5)} minutes"
                )
                
                llm_response = await llm_manager.generate(
                    prompt,
                    provider=LLMProvider(state.get('llm_provider', 'ollama'))
                )
                
                state['llm_results'].append({
                    'phase': 'correlation',
                    'response': llm_response,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
            
            state['messages'].append(
                f"Found {len(state['correlations'])} correlations, "
                f"{len(state['patterns'])} patterns"
            )
            
            state['current_phase'] = DetectionPhase.AI_REASONING
            
        except Exception as e:
            logger.error(f"Correlation error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = DetectionPhase.AI_REASONING
        
        return state
    
    async def ai_reasoning_node(self, state: DetectionState) -> DetectionState:
        """AI reasoning for final verdict"""
        logger.info("AI reasoning for final verdict")
        
        try:
            # Prepare data for reasoning
            ml_summary = {
                'anomalies': len(state.get('ml_anomalies', [])),
                'malware': len(state.get('ml_malware', [])),
                'avg_confidence': np.mean(state.get('ml_confidence_scores', [0]))
            }
            
            llm_summary = {
                'threats_identified': len(state.get('llm_threats', [])),
                'analysis_count': len(state.get('llm_results', []))
            }
            
            correlation_summary = {
                'correlations': len(state.get('correlations', [])),
                'patterns': len(state.get('patterns', []))
            }
            
            threat_intel_summary = {
                'iocs_matched': len(state.get('known_iocs', []))
            }
            
            # Get reasoning verdict
            prompt = detection_prompts.get_prompt(
                'reasoning_verdict',
                ml_results=json.dumps(ml_summary),
                llm_results=json.dumps(llm_summary),
                correlation_data=json.dumps(correlation_summary),
                threat_intel=json.dumps(threat_intel_summary),
                asset_criticality='high',  # Could be dynamic
                detection_time=datetime.now(timezone.utc).isoformat(),
                network_zone='internal',
                previous_incidents='0'
            )
            
            reasoning_response = await llm_manager.generate(
                prompt,
                provider=LLMProvider(state.get('llm_provider', 'ollama'))
            )
            
            # Parse verdict
            verdict = self._parse_verdict(reasoning_response)
            state['final_verdict'] = verdict['verdict']
            state['verdict_confidence'] = verdict['confidence']
            state['reasoning_analysis'] = {
                'response': reasoning_response,
                'verdict': verdict,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Update threat count
            if verdict['verdict'] in [ThreatVerdict.CONFIRMED_THREAT, ThreatVerdict.LIKELY_THREAT]:
                state['threats_detected'] += 1
            elif verdict['verdict'] in [ThreatVerdict.LIKELY_BENIGN, ThreatVerdict.CONFIRMED_BENIGN]:
                state['false_positives'] += 1
            
            state['messages'].append(
                f"AI Verdict: {verdict['verdict'].value} "
                f"(Confidence: {verdict['confidence']:.1f}%)"
            )
            
            state['current_phase'] = DetectionPhase.VERDICT
            
        except Exception as e:
            logger.error(f"AI reasoning error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = DetectionPhase.VERDICT
        
        return state
    
    async def verdict_node(self, state: DetectionState) -> DetectionState:
        """Process final verdict"""
        logger.info("Processing final verdict")
        
        # Determine if alert is needed
        if state['final_verdict'] in [ThreatVerdict.CONFIRMED_THREAT, 
                                      ThreatVerdict.LIKELY_THREAT,
                                      ThreatVerdict.SUSPICIOUS]:
            state['current_phase'] = DetectionPhase.ALERT_GENERATION
        else:
            state['current_phase'] = DetectionPhase.COMPLETE
        
        return state
    
    async def alert_generation_node(self, state: DetectionState) -> DetectionState:
        """Generate security alerts"""
        logger.info("Generating security alerts")
        
        try:
            # Generate alert
            prompt = detection_prompts.get_prompt(
                'alert_generation',
                verdict_data=json.dumps({
                    'verdict': state['final_verdict'].value,
                    'confidence': state['verdict_confidence']
                }),
                incident_info=json.dumps({
                    'logs': len(state.get('raw_logs', [])),
                    'threats': state['threats_detected']
                }),
                affected_systems=json.dumps(
                    list(state.get('aggregated_data', {}).get('by_agent', {}).keys())
                )
            )
            
            alert_response = await llm_manager.generate(
                prompt,
                provider=LLMProvider(state.get('llm_provider', 'ollama'))
            )
            
            # Create alert
            alert = {
                'id': f"alert_{uuid.uuid4().hex[:12]}",
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'severity': self._get_severity(state['final_verdict']),
                'verdict': state['final_verdict'].value,
                'confidence': state['verdict_confidence'],
                'description': alert_response[:500],  # First 500 chars
                'affected_agents': list(state.get('aggregated_data', {}).get('by_agent', {}).keys()),
                'ml_detections': len(state.get('ml_anomalies', [])) + len(state.get('ml_malware', [])),
                'iocs': state.get('known_iocs', [])
            }
            
            state['alerts_generated'].append(alert)
            state['messages'].append(f"Generated alert: {alert['id']}")
            
            state['current_phase'] = DetectionPhase.NOTIFICATION
            
        except Exception as e:
            logger.error(f"Alert generation error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = DetectionPhase.NOTIFICATION
        
        return state
    
    async def notification_node(self, state: DetectionState) -> DetectionState:
        """Send notifications to SOC users"""
        logger.info("Sending notifications")
        
        try:
            # In production, this would send actual notifications
            # For now, log the notification
            for alert in state.get('alerts_generated', []):
                notification = {
                    'alert_id': alert['id'],
                    'sent_to': ['soc_team@company.com'],
                    'method': 'email',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'status': 'sent'
                }
                state['notifications_sent'].append(notification)
                logger.info(f"Notification sent for alert {alert['id']}")
            
            state['messages'].append(f"Sent {len(state['notifications_sent'])} notifications")
            state['current_phase'] = DetectionPhase.COMPLETE
            
        except Exception as e:
            logger.error(f"Notification error: {e}")
            state['errors'].append(str(e))
            state['current_phase'] = DetectionPhase.COMPLETE
        
        return state
    
    # ========== Helper Methods ==========
    
    def _parse_llm_threats(self, llm_response: str) -> List[Dict]:
        """Parse threats from LLM response"""
        threats = []
        
        # Simple parsing - in production would be more sophisticated
        if 'critical' in llm_response.lower():
            threats.append({'severity': 'critical', 'confidence': 0.8})
        if 'malware' in llm_response.lower():
            threats.append({'type': 'malware', 'confidence': 0.7})
        if 'suspicious' in llm_response.lower():
            threats.append({'type': 'suspicious', 'confidence': 0.6})
        
        return threats
    
    def _parse_verdict(self, reasoning_response: str) -> Dict:
        """Parse verdict from reasoning response"""
        response_lower = reasoning_response.lower()
        
        if 'confirmed threat' in response_lower:
            verdict = ThreatVerdict.CONFIRMED_THREAT
            confidence = 90.0
        elif 'likely threat' in response_lower:
            verdict = ThreatVerdict.LIKELY_THREAT
            confidence = 70.0
        elif 'suspicious' in response_lower:
            verdict = ThreatVerdict.SUSPICIOUS
            confidence = 50.0
        elif 'likely benign' in response_lower:
            verdict = ThreatVerdict.LIKELY_BENIGN
            confidence = 30.0
        else:
            verdict = ThreatVerdict.CONFIRMED_BENIGN
            confidence = 10.0
        
        # Try to extract confidence score
        import re
        confidence_match = re.search(r'(\d+)%', reasoning_response)
        if confidence_match:
            confidence = float(confidence_match.group(1))
        
        return {'verdict': verdict, 'confidence': confidence}
    
    def _get_severity(self, verdict: ThreatVerdict) -> str:
        """Get severity level from verdict"""
        if verdict == ThreatVerdict.CONFIRMED_THREAT:
            return 'critical'
        elif verdict == ThreatVerdict.LIKELY_THREAT:
            return 'high'
        elif verdict == ThreatVerdict.SUSPICIOUS:
            return 'medium'
        else:
            return 'low'
    
    def should_continue(self, state: DetectionState) -> str:
        """Determine next node based on state"""
        phase = state.get('current_phase', DetectionPhase.IDLE)
        
        # Check if continuous mode
        if state.get('continuous_mode', False) and phase == DetectionPhase.COMPLETE:
            # Reset for next iteration
            state['current_phase'] = DetectionPhase.LOG_FETCHING
            state['iteration_count'] += 1
            return 'log_fetching'
        
        # Map phases to nodes
        phase_to_node = {
            DetectionPhase.IDLE: END,
            DetectionPhase.LOG_FETCHING: 'log_fetching',
            DetectionPhase.LOG_PARSING: 'log_parsing',
            DetectionPhase.LOG_ENRICHMENT: 'log_enrichment',
            DetectionPhase.ML_DETECTION: 'ml_detection',
            DetectionPhase.LLM_ANALYSIS: 'llm_analysis',
            DetectionPhase.THREAT_INTELLIGENCE: 'threat_intelligence',
            DetectionPhase.CORRELATION: 'correlation',
            DetectionPhase.AI_REASONING: 'ai_reasoning',
            DetectionPhase.VERDICT: 'verdict',
            DetectionPhase.ALERT_GENERATION: 'alert_generation',
            DetectionPhase.NOTIFICATION: 'notification',
            DetectionPhase.COMPLETE: END
        }
        
        return phase_to_node.get(phase, END)


# ============= WORKFLOW BUILDER =============

class DetectionWorkflow:
    """Main detection workflow using LangGraph"""
    
    def __init__(self, checkpoint_dir: str = "checkpoints", db_path: str = "soc_database.db"):
        if not LANGGRAPH_AVAILABLE:
            raise ImportError("LangGraph not installed. Run: pip install langgraph")
        
        self.nodes = DetectionWorkflowNodes(db_path)
        self.checkpoint_dir = checkpoint_dir
        self.workflow = self._build_workflow()
        self.running = False
    
    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow"""
        workflow = StateGraph(DetectionState)
        
        # Add nodes
        workflow.add_node("log_fetching", self.nodes.log_fetching_node)
        workflow.add_node("log_parsing", self.nodes.log_parsing_node)
        workflow.add_node("log_enrichment", self.nodes.log_enrichment_node)
        workflow.add_node("ml_detection", self.nodes.ml_detection_node)
        workflow.add_node("llm_analysis", self.nodes.llm_analysis_node)
        workflow.add_node("threat_intelligence", self.nodes.threat_intelligence_node)
        workflow.add_node("correlation", self.nodes.correlation_node)
        workflow.add_node("ai_reasoning", self.nodes.ai_reasoning_node)
        workflow.add_node("verdict", self.nodes.verdict_node)
        workflow.add_node("alert_generation", self.nodes.alert_generation_node)
        workflow.add_node("notification", self.nodes.notification_node)
        
        # Set entry point
        workflow.set_entry_point("log_fetching")
        
        # Add edges
        workflow.add_edge("log_fetching", "log_parsing")
        workflow.add_edge("log_parsing", "log_enrichment")
        workflow.add_edge("log_enrichment", "ml_detection")
        workflow.add_edge("ml_detection", "llm_analysis")
        workflow.add_edge("llm_analysis", "threat_intelligence")
        workflow.add_edge("threat_intelligence", "correlation")
        workflow.add_edge("correlation", "ai_reasoning")
        workflow.add_edge("ai_reasoning", "verdict")
        
        # Conditional edges
        workflow.add_conditional_edges(
            "verdict",
            self.nodes.should_continue,
            {
                "alert_generation": "alert_generation",
                END: END
            }
        )
        
        workflow.add_edge("alert_generation", "notification")
        
        workflow.add_conditional_edges(
            "notification",
            self.nodes.should_continue,
            {
                "log_fetching": "log_fetching",  # For continuous mode
                END: END
            }
        )
        
        return workflow.compile()
    
    async def run(self, 
                  batch_size: int = 100,
                  time_window: int = 5,
                  continuous_mode: bool = False,
                  llm_provider: str = "ollama") -> Dict:
        """
        Run the detection workflow
        
        Args:
            batch_size: Number of logs to process per batch
            time_window: Time window in minutes for log fetching
            continuous_mode: If True, run continuously
            llm_provider: Which LLM provider to use
        
        Returns:
            Final state with detection results
        """
        # Initialize state
        initial_state = {
            'batch_size': batch_size,
            'time_window': time_window,
            'continuous_mode': continuous_mode,
            'llm_provider': llm_provider,
            'current_phase': DetectionPhase.LOG_FETCHING,
            'iteration_count': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'processing_time': 0.0,
            'raw_logs': [],
            'parsed_logs': [],
            'enriched_logs': [],
            'ml_results': {},
            'ml_anomalies': [],
            'ml_malware': [],
            'ml_confidence_scores': [],
            'llm_results': [],
            'llm_threats': [],
            'llm_confidence_scores': [],
            'threat_intel_results': {},
            'known_iocs': [],
            'aggregated_data': {},
            'correlations': [],
            'patterns': [],
            'reasoning_analysis': {},
            'final_verdict': ThreatVerdict.CONFIRMED_BENIGN,
            'verdict_confidence': 0.0,
            'alerts_generated': [],
            'notifications_sent': [],
            'messages': [],
            'errors': []
        }
        
        # Run workflow
        try:
            start_time = datetime.now(timezone.utc)
            
            # Use checkpointing for resumability
            async with AsyncSqliteSaver.from_path(f"{self.checkpoint_dir}/detection.db") as saver:
                config = {"configurable": {"thread_id": f"detection_{uuid.uuid4().hex[:8]}"}}
                
                self.running = True
                
                # Run the workflow
                final_state = await self.workflow.ainvoke(
                    initial_state,
                    config,
                    {"checkpointer": saver}
                )
                
                # Calculate processing time
                end_time = datetime.now(timezone.utc)
                final_state['processing_time'] = (end_time - start_time).total_seconds()
                
                self.running = False
                
                return final_state
                
        except Exception as e:
            logger.error(f"Workflow execution error: {e}")
            self.running = False
            initial_state['errors'].append(str(e))
            return initial_state
    
    async def run_continuous(self, **kwargs):
        """Run detection continuously in background"""
        kwargs['continuous_mode'] = True
        
        while self.running:
            try:
                await self.run(**kwargs)
                await asyncio.sleep(30)  # Wait 30 seconds between iterations
            except Exception as e:
                logger.error(f"Continuous detection error: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    def stop(self):
        """Stop continuous detection"""
        self.running = False
        logger.info("Stopping continuous detection")


# Create singleton instance
detection_workflow = DetectionWorkflow() if LANGGRAPH_AVAILABLE else None
