#!/usr/bin/env python3
"""
Enhanced AI Reasoning Engine - Production SOC Platform
Bridges natural language chat commands to attack execution and system control
Provides intelligent SOC analysis and operational command processing
"""

import json
import asyncio
import logging
import requests
import sqlite3
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import re
import yaml
import uuid

# Import the adaptive attack orchestrator
import sys
sys.path.append(str(Path(__file__).parent.parent))
from attack_agent.adaptive_attack_orchestrator import adaptive_orchestrator

logger = logging.getLogger(__name__)

class EnhancedReasoningEngine:
    """Production-grade AI reasoning engine with attack command capabilities"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.db_path = self._get_db_path()
        self.attack_orchestrator = adaptive_orchestrator
        
        # Command patterns for intent recognition
        self.command_patterns = {
            'attack_execution': [
                r'(?:launch|execute|run|start)\s+(?:attack|scenario|campaign)',
                r'(?:attack|target|compromise)\s+(?:agent|endpoint|server)',
                r'(?:simulate|test)\s+(?:apt|ransomware|breach|intrusion)',
                r'(?:penetration|pen)\s+test',
                r'(?:red\s+team|redteam)\s+(?:exercise|operation)',
            ],
            'network_query': [
                r'(?:show|list|get)\s+(?:network|topology|agents|endpoints)',
                r'(?:what|which)\s+(?:agents|endpoints|servers)\s+(?:are|do)',
                r'network\s+(?:status|overview|map)',
                r'(?:domain\s+controllers?|dc)',
                r'(?:high\s+value\s+targets?|hvt)',
            ],
            'detection_query': [
                r'(?:show|list|get)\s+(?:detections?|alerts?|threats?)',
                r'(?:what|any)\s+(?:threats?|attacks?|incidents?)',
                r'(?:security\s+events?|soc\s+alerts?)',
                r'(?:detection\s+status|threat\s+status)',
            ],
            'system_control': [
                r'(?:stop|pause|halt)\s+(?:attack|execution|scenario)',
                r'(?:status|progress)\s+(?:of|for)\s+(?:attack|execution)',
                r'(?:list|show)\s+(?:active|running)\s+(?:attacks?|executions?)',
            ],
            'analysis_request': [
                r'(?:analyze|assessment|evaluate)\s+(?:security|risk|threat)',
                r'(?:what\s+(?:is|are)\s+the|how\s+(?:is|are)\s+our)',
                r'(?:security\s+posture|risk\s+level|threat\s+landscape)',
                r'(?:recommend|suggest|advise)',
            ]
        }
        
        logger.info("Enhanced AI Reasoning Engine initialized - Production Mode")
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        """Load configuration"""
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
        
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            return {
                'llm': {
                    'ollama_endpoint': 'http://localhost:11434',
                    'ollama_model': 'cybersec-ai',
                    'fallback_order': ['ollama', 'openai']
                }
            }
    
    def _get_db_path(self) -> str:
        """Get database path"""
        db_name = self.config.get('database', {}).get('path', 'soc_multi_tenant.db')
        return str(Path(__file__).parent.parent.parent / db_name)
    
    async def process_chat_command(self, user_query: str, user_context: Dict = None) -> Dict[str, Any]:
        """Process chat command and route to appropriate handler"""
        
        logger.info(f"💬 Processing chat command: '{user_query[:50]}...'")
        
        # Classify the intent
        intent_type = self._classify_intent(user_query)
        
        # Route to appropriate handler
        if intent_type == 'attack_execution':
            return await self._handle_attack_command(user_query, user_context)
        elif intent_type == 'network_query':
            return await self._handle_network_query(user_query, user_context)
        elif intent_type == 'detection_query':
            return await self._handle_detection_query(user_query, user_context)
        elif intent_type == 'system_control':
            return await self._handle_system_control(user_query, user_context)
        elif intent_type == 'analysis_request':
            return await self._handle_analysis_request(user_query, user_context)
        else:
            # General AI reasoning
            return await self._handle_general_query(user_query, user_context)
    
    def _classify_intent(self, query: str) -> str:
        """Classify user intent based on query patterns"""
        
        query_lower = query.lower()
        
        # Check each pattern category
        for intent_type, patterns in self.command_patterns.items():
            for pattern in patterns:
                if re.search(pattern, query_lower):
                    logger.info(f"Classified intent: {intent_type}")
                    return intent_type
        
        return 'general_query'
    
    async def _handle_attack_command(self, query: str, user_context: Dict = None) -> Dict[str, Any]:
        """Handle attack execution commands"""
        
        logger.info("Processing attack execution command")
        
        try:
            # Get current network context
            network_context = await self.attack_orchestrator.get_network_context()
            
            # Check if network has agents
            if network_context.total_agents == 0:
                return {
                    'success': False,
                    'response': "No active agents found in the network. Deploy client agents first before executing attacks.",
                    'response_type': 'error',
                    'data': {
                        'error_type': 'no_targets',
                        'suggestion': 'Deploy codegrey-agent on target endpoints and ensure they register with the SOC server.'
                    }
                }
            
            # Generate dynamic scenario based on query and network
            scenario = await self.attack_orchestrator.generate_dynamic_scenario(query, network_context)
            
            # Execute the scenario
            execution = await self.attack_orchestrator.execute_dynamic_scenario(scenario)
            
            # Format response
            response = f"""**Attack Scenario Launched**

**Scenario:** {scenario.name}
**Type:** {scenario.attack_type.title()}
**Complexity:** {scenario.complexity.title()}
**Estimated Duration:** {scenario.estimated_duration} minutes

**Target Network Elements:**
{chr(10).join([f"• {target.title()}" for target in scenario.target_elements])}

**Attack Path:**
{chr(10).join([f"{i+1}. {phase.title().replace('_', ' ')}" for i, phase in enumerate(scenario.attack_path)])}

**MITRE Techniques:**
{', '.join(scenario.mitre_techniques)}

**Execution ID:** `{execution.execution_id}`
**Status:** {execution.status.title()}

Use `status {execution.execution_id}` to monitor progress.
"""
            
            return {
                'success': True,
                'response': response,
                'response_type': 'attack_execution',
                'data': {
                    'execution_id': execution.execution_id,
                    'scenario': scenario.__dict__,
                    'network_context': {
                        'total_agents': network_context.total_agents,
                        'high_value_targets': len(network_context.high_value_targets),
                        'security_zones': network_context.security_zones
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Attack command failed: {e}")
            return {
                'success': False,
                'response': f"Attack execution failed: {str(e)}",
                'response_type': 'error',
                'data': {'error': str(e)}
            }
    
    async def _handle_network_query(self, query: str, user_context: Dict = None) -> Dict[str, Any]:
        """Handle network topology queries"""
        
        logger.info("Processing network query")
        
        try:
            # Get network context
            network_context = await self.attack_orchestrator.get_network_context(force_refresh=True)
            
            # Format network overview
            response = f"""**Network Topology Overview**

**Total Active Agents:** {network_context.total_agents}

**Network Elements:**
• **Domain Controllers:** {len(network_context.domain_controllers)}
• **Endpoints:** {len(network_context.endpoints)}
• **DMZ Servers:** {len(network_context.dmz_servers)}
• **Firewalls:** {len(network_context.firewalls)}
• **SOC Systems:** {len(network_context.soc_systems)}
• **Cloud Resources:** {len(network_context.cloud_resources)}

**Security Zones:** {', '.join(network_context.security_zones) if network_context.security_zones else 'None detected'}

**High-Value Targets:** {len(network_context.high_value_targets)}

**Attack Paths Identified:** {len(network_context.attack_paths)}
"""
            
            # Add specific details based on query
            if 'domain controller' in query.lower() or 'dc' in query.lower():
                if network_context.domain_controllers:
                    response += "\n**Domain Controllers:**\n"
                    for dc in network_context.domain_controllers[:3]:  # Show first 3
                        response += f"• {dc['hostname']} ({dc['ip_address']}) - Zone: {dc['security_zone']}\n"
                else:
                    response += "\n⚠️ No domain controllers detected in the network."
            
            if 'high value' in query.lower() or 'hvt' in query.lower():
                if network_context.high_value_targets:
                    response += "\n**High-Value Targets:**\n"
                    for hvt in network_context.high_value_targets[:5]:  # Show first 5
                        response += f"• {hvt['hostname']} ({hvt['network_element_type']}) - {hvt['security_zone']}\n"
                else:
                    response += "\n⚠️ No high-value targets identified."
            
            return {
                'success': True,
                'response': response,
                'response_type': 'network_info',
                'data': {
                    'network_summary': {
                        'total_agents': network_context.total_agents,
                        'domain_controllers': len(network_context.domain_controllers),
                        'endpoints': len(network_context.endpoints),
                        'dmz_servers': len(network_context.dmz_servers),
                        'security_zones': network_context.security_zones,
                        'high_value_targets': len(network_context.high_value_targets)
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Network query failed: {e}")
            return {
                'success': False,
                'response': f"Network query failed: {str(e)}",
                'response_type': 'error',
                'data': {'error': str(e)}
            }
    
    async def _handle_detection_query(self, query: str, user_context: Dict = None) -> Dict[str, Any]:
        """Handle detection and alert queries"""
        
        logger.info("Processing detection query")
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            
            # Get recent detections
            cursor = conn.execute("""
                SELECT id, agent_id, timestamp, threat_type, severity, confidence,
                       source_ip, target_ip, technique, technique_name, description,
                       status, risk_score
                FROM detections 
                WHERE timestamp > datetime('now', '-24 hours')
                ORDER BY timestamp DESC, risk_score DESC
                LIMIT 20
            """)
            
            detections = [dict(row) for row in cursor.fetchall()]
            
            # Get detection summary
            cursor = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM detections 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY severity
            """)
            
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
            conn.close()
            
            # Format response
            total_detections = len(detections)
            
            response = f"""**Security Detections (Last 24 Hours)**

**Total Detections:** {total_detections}

**By Severity:**
• **Critical:** {severity_counts.get('critical', 0)}
• **High:** {severity_counts.get('high', 0)}
• **Medium:** {severity_counts.get('medium', 0)}
• **Low:** {severity_counts.get('low', 0)}
"""
            
            if detections:
                response += "\n**Recent High-Priority Detections:**\n"
                for detection in detections[:5]:  # Show top 5
                    timestamp = datetime.fromisoformat(detection['timestamp'].replace('Z', '+00:00'))
                    time_ago = datetime.now() - timestamp.replace(tzinfo=None)
                    
                    response += f"""
• **{detection['threat_type']}** ({detection['severity'].upper()})
  Agent: {detection['agent_id']}
  Technique: {detection['technique']} - {detection['technique_name']}
  Risk Score: {detection['risk_score']:.1f}
  Time: {time_ago.seconds // 3600}h {(time_ago.seconds % 3600) // 60}m ago
"""
            else:
                response += "\nNo security detections in the last 24 hours."
            
            return {
                'success': True,
                'response': response,
                'response_type': 'detection_info',
                'data': {
                    'total_detections': total_detections,
                    'severity_breakdown': severity_counts,
                    'recent_detections': detections[:10]
                }
            }
            
        except Exception as e:
            logger.error(f"Detection query failed: {e}")
            return {
                'success': False,
                'response': f"Detection query failed: {str(e)}",
                'response_type': 'error',
                'data': {'error': str(e)}
            }
    
    async def _handle_system_control(self, query: str, user_context: Dict = None) -> Dict[str, Any]:
        """Handle system control commands (stop attacks, check status, etc.)"""
        
        logger.info("⚙️ Processing system control command")
        
        try:
            # Check for execution ID in query
            execution_id_match = re.search(r'exec_[a-f0-9]{8}_[a-f0-9]{8}', query)
            
            if 'stop' in query.lower() or 'halt' in query.lower() or 'pause' in query.lower():
                if execution_id_match:
                    execution_id = execution_id_match.group()
                    success = await self.attack_orchestrator.stop_execution(execution_id)
                    
                    if success:
                        response = f"🛑 **Attack Execution Stopped**\n\nExecution ID: `{execution_id}`\nStatus: Stopped"
                    else:
                        response = f"Could not stop execution `{execution_id}`. It may have already completed or doesn't exist."
                else:
                    response = "Please specify an execution ID to stop (e.g., 'stop exec_abc123_def456')"
            
            elif 'status' in query.lower() or 'progress' in query.lower():
                if execution_id_match:
                    execution_id = execution_id_match.group()
                    status = self.attack_orchestrator.get_execution_status(execution_id)
                    
                    if status:
                        response = f"""**Execution Status**

**Execution ID:** `{execution_id}`
**Scenario:** {status['scenario_name']}
**Status:** {status['status'].title()}
**Current Phase:** {status['current_phase'].title().replace('_', ' ')}
**Progress:** {len(status['phases_completed'])}/{len(status['phases_completed']) + 1} phases
**Success Rate:** {status['success_rate']:.1%}
**Detections Triggered:** {status['detections_triggered']}
**Started:** {status['started_at']}
{'**Completed:** ' + status['completed_at'] if status['completed_at'] else ''}
"""
                    else:
                        response = f"Execution `{execution_id}` not found."
                else:
                    response = "Please specify an execution ID for status (e.g., 'status exec_abc123_def456')"
            
            elif 'list' in query.lower() or 'active' in query.lower() or 'running' in query.lower():
                active_executions = self.attack_orchestrator.list_active_executions()
                
                if active_executions:
                    response = "**Active Attack Executions:**\n\n"
                    for execution in active_executions:
                        response += f"""• **{execution['scenario_name']}**
  ID: `{execution['execution_id']}`
  Status: {execution['status'].title()}
  Targets: {execution['target_count']}
  Started: {execution['started_at']}

"""
                else:
                    response = "No active attack executions running."
            
            else:
                response = """⚙️ **Available System Commands:**

• `stop <execution_id>` - Stop running attack
• `status <execution_id>` - Check execution progress  
• `list active attacks` - Show running executions
• `pause <execution_id>` - Pause execution

Example: `stop exec_abc123_def456`
"""
            
            return {
                'success': True,
                'response': response,
                'response_type': 'system_control',
                'data': {}
            }
            
        except Exception as e:
            logger.error(f"System control failed: {e}")
            return {
                'success': False,
                'response': f"System control failed: {str(e)}",
                'response_type': 'error',
                'data': {'error': str(e)}
            }
    
    async def _handle_analysis_request(self, query: str, user_context: Dict = None) -> Dict[str, Any]:
        """Handle security analysis and assessment requests"""
        
        logger.info("Processing analysis request")
        
        try:
            # Get comprehensive data for analysis
            network_context = await self.attack_orchestrator.get_network_context()
            
            # Get recent detections
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("""
                SELECT threat_type, severity, COUNT(*) as count
                FROM detections 
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY threat_type, severity
                ORDER BY count DESC
            """)
            threat_summary = cursor.fetchall()
            
            # Get agent status distribution
            cursor = conn.execute("""
                SELECT status, COUNT(*) as count
                FROM agents
                GROUP BY status
            """)
            agent_status = cursor.fetchall()
            conn.close()
            
            # Use cybersec-ai for intelligent analysis
            analysis_prompt = f"""
Provide a comprehensive security analysis based on this SOC data:

NETWORK TOPOLOGY:
- Total Agents: {network_context.total_agents}
- Domain Controllers: {len(network_context.domain_controllers)}
- Endpoints: {len(network_context.endpoints)}
- DMZ Servers: {len(network_context.dmz_servers)}
- Security Zones: {network_context.security_zones}
- High-Value Targets: {len(network_context.high_value_targets)}

THREAT LANDSCAPE (Last 7 days):
{chr(10).join([f"- {row[0]} ({row[1]}): {row[2]} incidents" for row in threat_summary])}

AGENT STATUS:
{chr(10).join([f"- {row[0]}: {row[1]} agents" for row in agent_status])}

USER QUERY: "{query}"

Provide analysis covering:
1. Current security posture
2. Key risk areas
3. Threat trends
4. Recommendations
5. Priority actions

Format as a professional SOC report.
"""
            
            # Get AI analysis
            ai_analysis = await self._get_ai_analysis(analysis_prompt)
            
            return {
                'success': True,
                'response': ai_analysis,
                'response_type': 'security_analysis',
                'data': {
                    'network_summary': {
                        'total_agents': network_context.total_agents,
                        'security_zones': network_context.security_zones,
                        'high_value_targets': len(network_context.high_value_targets)
                    },
                    'threat_summary': threat_summary,
                    'agent_status': agent_status
                }
            }
            
        except Exception as e:
            logger.error(f"Analysis request failed: {e}")
            return {
                'success': False,
                'response': f"Security analysis failed: {str(e)}",
                'response_type': 'error',
                'data': {'error': str(e)}
            }
    
    async def _handle_general_query(self, query: str, user_context: Dict = None) -> Dict[str, Any]:
        """Handle general cybersecurity questions"""
        
        logger.info("💭 Processing general query")
        
        # Use cybersec-ai model for general cybersecurity Q&A
        ai_response = await self._get_ai_analysis(f"""
As a cybersecurity expert for a SOC platform, answer this question:

"{query}"

Provide a helpful, accurate response focused on cybersecurity, threat detection, 
incident response, or SOC operations. If the question is about attack techniques,
reference MITRE ATT&CK framework where appropriate.
""")
        
        return {
            'success': True,
            'response': ai_response,
            'response_type': 'general_response',
            'data': {}
        }
    
    async def _get_ai_analysis(self, prompt: str) -> str:
        """Get analysis from cybersec-ai model"""
        
        try:
            ollama_endpoint = self.config['llm']['ollama_endpoint']
            ollama_model = self.config['llm']['ollama_model']
            
            response = requests.post(
                f"{ollama_endpoint}/api/generate",
                json={
                    "model": ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.7}
                },
                timeout=60
            )
            
            if response.status_code == 200:
                return response.json().get('response', 'Analysis unavailable - AI model error')
            else:
                return f"⚠️ AI analysis temporarily unavailable (HTTP {response.status_code})"
                
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")
            return "⚠️ AI analysis temporarily unavailable. Please try again later."

# Global instance for production use
enhanced_reasoning_engine = EnhancedReasoningEngine()
