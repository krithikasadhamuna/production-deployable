#!/usr/bin/env python3
"""
AI Threat Analyzer - Full AI-Powered Detection
Uses cybersec-ai LLM for intelligent threat analysis and decision making
"""

import os
import json
import logging
import requests
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import asyncio

from .real_threat_detector import real_threat_detector

logger = logging.getLogger(__name__)

class AIThreatAnalyzer:
    """AI-powered threat analysis using cybersec-ai LLM"""
    
    def __init__(self, db_path: str = "soc_database.db"):
        self.db_path = db_path
        self.config = self._load_config()
        
        # AI model configuration
        self.ollama_endpoint = self.config['llm']['ollama_endpoint']
        self.ollama_model = self.config['llm']['ollama_model']
        
        # AI threat knowledge base
        self.threat_intelligence = {}
        self.attack_patterns = {}
        self.false_positive_patterns = {}
        
        # Learning parameters
        self.confidence_threshold = 0.7
        self.ai_enabled = True
        
        logger.info("AI Threat Analyzer initialized with cybersec-ai intelligence")
    
    def _load_config(self) -> Dict:
        """Load AI configuration"""
        return {
            'llm': {
                'ollama_endpoint': 'http://localhost:11434',
                'ollama_model': 'cybersec-ai',
                'temperature': 0.2,  # Lower for more precise analysis
                'max_tokens': 1024
            }
        }
    
    async def analyze_threat_with_ai(self, detection_data: Dict, context: Dict) -> Dict:
        """Analyze threat using AI intelligence"""
        
        if not self.ai_enabled:
            return self._fallback_analysis(detection_data)
        
        try:
            # Build comprehensive analysis prompt
            prompt = self._build_threat_analysis_prompt(detection_data, context)
            
            # Get AI analysis
            ai_response = await self._query_cybersec_ai(prompt)
            
            # Parse AI analysis
            ai_analysis = self._parse_ai_analysis(ai_response)
            
            # Enhance with traditional ML
            ml_analysis = self._get_ml_analysis(detection_data)
            
            # Combine AI and ML insights
            final_analysis = self._combine_analyses(ai_analysis, ml_analysis, detection_data)
            
            return final_analysis
            
        except Exception as e:
            logger.error(f"AI threat analysis failed: {e}")
            return self._fallback_analysis(detection_data)
    
    def _build_threat_analysis_prompt(self, detection_data: Dict, context: Dict) -> str:
        """Build comprehensive threat analysis prompt"""
        
        # Get historical context
        similar_threats = self._get_similar_threats(detection_data)
        recent_activity = context.get('recent_activity', [])
        
        prompt = f"""
You are an elite cybersecurity analyst with deep knowledge of MITRE ATT&CK and threat hunting.

THREAT DETECTION DATA:
{json.dumps(detection_data, indent=2)}

CONTEXT INFORMATION:
- Agent ID: {context.get('agent_id', 'unknown')}
- Platform: {context.get('platform', 'unknown')}
- User Context: {context.get('user_context', 'unknown')}
- Network Segment: {context.get('network_segment', 'unknown')}
- Time: {context.get('timestamp', 'unknown')}

RECENT ACTIVITY (Last 1 hour):
{json.dumps(recent_activity[-5:], indent=2) if recent_activity else 'No recent activity'}

SIMILAR HISTORICAL THREATS:
{json.dumps(similar_threats[:3], indent=2) if similar_threats else 'No similar threats found'}

ANALYSIS REQUIRED:
1. Threat Classification (malware, apt, insider, false_positive)
2. Confidence Level (0.0 to 1.0)
3. MITRE ATT&CK Technique Mapping
4. Attack Phase (reconnaissance, initial_access, execution, etc.)
5. Threat Actor Profiling (if applicable)
6. Impact Assessment
7. Recommended Actions
8. False Positive Likelihood

CRITICAL FACTORS TO CONSIDER:
- Behavioral context and timing
- User and system context
- Attack pattern sophistication
- Evasion techniques used
- Correlation with known campaigns

Respond with JSON format:
{{
    "threat_classification": "apt|malware|insider|lateral_movement|false_positive|unknown",
    "confidence_level": 0.85,
    "threat_severity": "low|medium|high|critical",
    "mitre_techniques": ["T1059.001", "T1055"],
    "attack_phase": "execution",
    "threat_actor_profile": {{
        "sophistication": "low|medium|high|nation_state",
        "likely_group": "APT29|Lazarus|Unknown",
        "motivation": "espionage|financial|disruption"
    }},
    "impact_assessment": {{
        "data_risk": "low|medium|high|critical",
        "system_risk": "low|medium|high|critical",
        "business_impact": "minimal|moderate|significant|severe"
    }},
    "false_positive_likelihood": 0.15,
    "recommended_actions": [
        "isolate_endpoint",
        "collect_memory_dump",
        "analyze_network_traffic",
        "check_lateral_movement"
    ],
    "reasoning": "Detailed explanation of the analysis and decision-making process",
    "indicators_of_compromise": ["file_hash", "ip_address", "domain"],
    "hunting_queries": ["process_name:powershell.exe AND cmdline:*encodedcommand*"]
}}
"""
        
        return prompt
    
    async def correlate_threats_with_ai(self, threat_events: List[Dict], 
                                      time_window: int = 3600) -> Dict:
        """AI-powered threat correlation across multiple events"""
        
        if not self.ai_enabled or len(threat_events) < 2:
            return {'correlation_found': False, 'reason': 'Insufficient data or AI disabled'}
        
        try:
            prompt = f"""
You are analyzing multiple security events for potential correlation and attack campaigns.

SECURITY EVENTS (Last {time_window} seconds):
{json.dumps(threat_events, indent=2)}

CORRELATION ANALYSIS REQUIRED:
1. Are these events part of a coordinated attack?
2. What is the attack progression/kill chain?
3. Which events are related vs. independent?
4. What is the overall campaign objective?
5. Threat actor attribution analysis
6. Predicted next attack steps

Consider:
- Timing patterns and sequences
- Target relationships
- Technique progression
- Infrastructure overlap
- Behavioral consistency

Respond with JSON:
{{
    "correlation_found": true,
    "campaign_name": "Suspected APT Campaign Alpha",
    "confidence_level": 0.92,
    "attack_progression": [
        {{
            "phase": "initial_access",
            "events": ["event_id_1", "event_id_2"],
            "techniques": ["T1566.001"]
        }}
    ],
    "threat_actor_assessment": {{
        "likely_group": "APT29",
        "confidence": 0.75,
        "attribution_factors": ["technique_overlap", "infrastructure_reuse"]
    }},
    "campaign_objective": "credential_harvesting",
    "predicted_next_steps": ["lateral_movement", "privilege_escalation"],
    "recommended_response": [
        "activate_incident_response",
        "isolate_affected_systems",
        "hunt_for_additional_compromises"
    ],
    "timeline_analysis": "Events show clear progression from spearphishing to code execution",
    "risk_assessment": "high"
}}
"""
            
            ai_response = await self._query_cybersec_ai(prompt)
            correlation = self._parse_correlation_analysis(ai_response)
            
            return correlation
            
        except Exception as e:
            logger.error(f"AI threat correlation failed: {e}")
            return {'correlation_found': False, 'error': str(e)}
    
    async def generate_threat_intelligence(self, threat_data: Dict) -> Dict:
        """Generate actionable threat intelligence using AI"""
        
        if not self.ai_enabled:
            return {'intelligence_available': False}
        
        try:
            prompt = f"""
Generate actionable threat intelligence based on this security event:

THREAT DATA:
{json.dumps(threat_data, indent=2)}

INTELLIGENCE REQUIREMENTS:
1. Threat attribution and profiling
2. Infrastructure analysis (IPs, domains, hashes)
3. Behavioral pattern analysis
4. Defense recommendations
5. Hunting opportunities
6. Similar attack campaigns

Generate comprehensive threat intelligence report in JSON:
{{
    "threat_profile": {{
        "name": "Cobalt Strike Beacon Activity",
        "family": "post_exploitation_framework",
        "first_seen": "2024-01-15",
        "last_seen": "2024-09-24"
    }},
    "infrastructure_analysis": {{
        "command_control_servers": ["192.0.2.1", "malicious.example.com"],
        "infrastructure_confidence": 0.85,
        "hosting_analysis": "Bulletproof hosting provider"
    }},
    "behavioral_patterns": [
        "Uses living-off-the-land techniques",
        "Employs process hollowing for stealth",
        "Communicates via HTTPS on port 443"
    ],
    "defense_recommendations": [
        "Block C2 domains at DNS level",
        "Monitor for process injection techniques",
        "Implement application whitelisting"
    ],
    "hunting_opportunities": [
        "Search for similar process injection patterns",
        "Hunt for network beaconing behavior",
        "Look for persistence mechanisms"
    ],
    "similar_campaigns": [
        {{
            "name": "APT29 Campaign 2024",
            "similarity_score": 0.78,
            "shared_ttps": ["T1055", "T1071.001"]
        }}
    ],
    "yara_rules": "rule Cobalt_Strike_Beacon {{ ... }}",
    "sigma_rules": "title: Cobalt Strike Process Injection\\ndetection: ...",
    "confidence_assessment": 0.88
}}
"""
            
            ai_response = await self._query_cybersec_ai(prompt)
            intelligence = self._parse_threat_intelligence(ai_response)
            
            # Store intelligence for future reference
            self._store_threat_intelligence(threat_data, intelligence)
            
            return intelligence
            
        except Exception as e:
            logger.error(f"Threat intelligence generation failed: {e}")
            return {'intelligence_available': False, 'error': str(e)}
    
    async def adaptive_threshold_tuning(self, detection_history: List[Dict]) -> Dict:
        """AI-powered adaptive threshold tuning based on environment"""
        
        if not self.ai_enabled or len(detection_history) < 10:
            return {'tuning_applied': False, 'reason': 'Insufficient data'}
        
        try:
            # Analyze detection patterns
            false_positives = [d for d in detection_history if d.get('false_positive', False)]
            true_positives = [d for d in detection_history if not d.get('false_positive', False)]
            
            prompt = f"""
Analyze detection patterns and recommend threshold adjustments:

DETECTION HISTORY SUMMARY:
- Total Detections: {len(detection_history)}
- True Positives: {len(true_positives)}
- False Positives: {len(false_positives)}
- False Positive Rate: {len(false_positives)/len(detection_history)*100:.1f}%

RECENT FALSE POSITIVES:
{json.dumps(false_positives[-5:], indent=2)}

RECENT TRUE POSITIVES:
{json.dumps(true_positives[-5:], indent=2)}

CURRENT THRESHOLDS:
- Anomaly Score: 0.7
- Malware Confidence: 0.8
- Behavioral Risk: 0.6
- Network Anomaly: 0.75

OPTIMIZATION GOALS:
1. Reduce false positive rate to <5%
2. Maintain 95%+ true positive detection
3. Adapt to environment baseline
4. Consider business impact

Recommend threshold adjustments in JSON:
{{
    "threshold_adjustments": {{
        "anomaly_score": 0.75,
        "malware_confidence": 0.85,
        "behavioral_risk": 0.65,
        "network_anomaly": 0.8
    }},
    "confidence_level": 0.82,
    "expected_improvements": {{
        "false_positive_reduction": "15%",
        "detection_accuracy": "97%"
    }},
    "reasoning": "Analysis shows current thresholds are too sensitive for this environment",
    "monitoring_recommendations": [
        "Monitor FP rate for 7 days",
        "Adjust if FP rate exceeds 3%"
    ]
}}
"""
            
            ai_response = await self._query_cybersec_ai(prompt)
            tuning = self._parse_threshold_tuning(ai_response)
            
            # Apply tuning if confidence is high enough
            if tuning.get('confidence_level', 0) > self.confidence_threshold:
                self._apply_threshold_tuning(tuning)
            
            return tuning
            
        except Exception as e:
            logger.error(f"Adaptive threshold tuning failed: {e}")
            return {'tuning_applied': False, 'error': str(e)}
    
    async def _query_cybersec_ai(self, prompt: str) -> str:
        """Query the cybersec-ai model"""
        
        try:
            response = requests.post(
                f"{self.ollama_endpoint}/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.config['llm']['temperature'],
                        "num_predict": self.config['llm']['max_tokens']
                    }
                },
                timeout=60
            )
            
            if response.status_code == 200:
                return response.json().get('response', '')
            else:
                logger.error(f"Cybersec-AI API error: {response.status_code}")
                return ""
                
        except Exception as e:
            logger.error(f"Cybersec-AI query failed: {e}")
            return ""
    
    def _parse_ai_analysis(self, ai_response: str) -> Dict:
        """Parse AI threat analysis response"""
        
        try:
            if '{' in ai_response:
                json_start = ai_response.find('{')
                json_end = ai_response.rfind('}') + 1
                json_str = ai_response[json_start:json_end]
                return json.loads(json_str)
        except Exception as e:
            logger.error(f"AI analysis parsing failed: {e}")
        
        return {
            'threat_classification': 'unknown',
            'confidence_level': 0.5,
            'threat_severity': 'medium',
            'reasoning': 'AI analysis parsing failed'
        }
    
    def _parse_correlation_analysis(self, ai_response: str) -> Dict:
        """Parse AI correlation analysis"""
        
        try:
            if '{' in ai_response:
                json_start = ai_response.find('{')
                json_end = ai_response.rfind('}') + 1
                json_str = ai_response[json_start:json_end]
                return json.loads(json_str)
        except Exception as e:
            logger.error(f"Correlation analysis parsing failed: {e}")
        
        return {'correlation_found': False, 'error': 'Parsing failed'}
    
    def _parse_threat_intelligence(self, ai_response: str) -> Dict:
        """Parse threat intelligence response"""
        
        try:
            if '{' in ai_response:
                json_start = ai_response.find('{')
                json_end = ai_response.rfind('}') + 1
                json_str = ai_response[json_start:json_end]
                return json.loads(json_str)
        except Exception as e:
            logger.error(f"Threat intelligence parsing failed: {e}")
        
        return {'intelligence_available': False, 'error': 'Parsing failed'}
    
    def _parse_threshold_tuning(self, ai_response: str) -> Dict:
        """Parse threshold tuning recommendations"""
        
        try:
            if '{' in ai_response:
                json_start = ai_response.find('{')
                json_end = ai_response.rfind('}') + 1
                json_str = ai_response[json_start:json_end]
                return json.loads(json_str)
        except Exception as e:
            logger.error(f"Threshold tuning parsing failed: {e}")
        
        return {'tuning_applied': False, 'error': 'Parsing failed'}
    
    def _get_ml_analysis(self, detection_data: Dict) -> Dict:
        """Get traditional ML analysis from existing detector"""
        
        try:
            # Use existing ML models for comparison
            if detection_data.get('type') == 'process_anomaly':
                ml_result = real_threat_detector.detect_process_anomaly(detection_data)
            elif detection_data.get('type') == 'file_threat':
                ml_result = real_threat_detector.detect_file_threat(detection_data)
            else:
                ml_result = {'threat_detected': False, 'confidence': 0.5}
            
            return {
                'ml_threat_detected': ml_result.get('threat_detected', False),
                'ml_confidence': ml_result.get('final_score', 0.5),
                'ml_reasoning': 'Traditional ML analysis'
            }
            
        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
            return {'ml_threat_detected': False, 'ml_confidence': 0.0}
    
    def _combine_analyses(self, ai_analysis: Dict, ml_analysis: Dict, 
                         detection_data: Dict) -> Dict:
        """Combine AI and ML analyses for final decision"""
        
        # Weight AI analysis higher (70%) vs ML (30%)
        ai_weight = 0.7
        ml_weight = 0.3
        
        ai_confidence = ai_analysis.get('confidence_level', 0.5)
        ml_confidence = ml_analysis.get('ml_confidence', 0.5)
        
        combined_confidence = (ai_confidence * ai_weight) + (ml_confidence * ml_weight)
        
        # Final threat determination
        ai_threat = ai_analysis.get('threat_classification') not in ['false_positive', 'unknown']
        ml_threat = ml_analysis.get('ml_threat_detected', False)
        
        final_threat_detected = ai_threat or (ml_threat and combined_confidence > 0.6)
        
        return {
            'ai_enhanced': True,
            'final_threat_detected': final_threat_detected,
            'combined_confidence': combined_confidence,
            'threat_classification': ai_analysis.get('threat_classification', 'unknown'),
            'threat_severity': ai_analysis.get('threat_severity', 'medium'),
            'mitre_techniques': ai_analysis.get('mitre_techniques', []),
            'attack_phase': ai_analysis.get('attack_phase', 'unknown'),
            'false_positive_likelihood': ai_analysis.get('false_positive_likelihood', 0.5),
            'recommended_actions': ai_analysis.get('recommended_actions', []),
            'ai_reasoning': ai_analysis.get('reasoning', 'No reasoning provided'),
            'ml_contribution': ml_analysis,
            'indicators_of_compromise': ai_analysis.get('indicators_of_compromise', []),
            'hunting_queries': ai_analysis.get('hunting_queries', []),
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_similar_threats(self, detection_data: Dict, limit: int = 5) -> List[Dict]:
        """Get similar historical threats for context"""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Simple similarity based on detection type
            detection_type = detection_data.get('type', 'unknown')
            
            cursor.execute('''
                SELECT raw_data FROM detections 
                WHERE detection_type = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (detection_type, limit))
            
            results = cursor.fetchall()
            conn.close()
            
            similar_threats = []
            for result in results:
                try:
                    threat_data = json.loads(result[0])
                    similar_threats.append(threat_data)
                except:
                    continue
            
            return similar_threats
            
        except Exception as e:
            logger.error(f"Failed to get similar threats: {e}")
            return []
    
    def _store_threat_intelligence(self, threat_data: Dict, intelligence: Dict):
        """Store generated threat intelligence"""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create threat_intelligence table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id TEXT PRIMARY KEY,
                    threat_data TEXT,
                    intelligence_data TEXT,
                    created_at TEXT,
                    confidence_level REAL
                )
            ''')
            
            intel_id = f"intel-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            cursor.execute('''
                INSERT INTO threat_intelligence 
                (id, threat_data, intelligence_data, created_at, confidence_level)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                intel_id,
                json.dumps(threat_data),
                json.dumps(intelligence),
                datetime.now().isoformat(),
                intelligence.get('confidence_assessment', 0.5)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store threat intelligence: {e}")
    
    def _apply_threshold_tuning(self, tuning: Dict):
        """Apply AI-recommended threshold tuning"""
        
        try:
            adjustments = tuning.get('threshold_adjustments', {})
            
            # Update real threat detector thresholds
            for threshold_name, new_value in adjustments.items():
                if hasattr(real_threat_detector, 'thresholds') and threshold_name in real_threat_detector.thresholds:
                    old_value = real_threat_detector.thresholds[threshold_name]
                    real_threat_detector.thresholds[threshold_name] = new_value
                    logger.info(f"🎛️ Threshold tuned: {threshold_name} {old_value} → {new_value}")
            
            logger.info("AI threshold tuning applied")
            
        except Exception as e:
            logger.error(f"Threshold tuning application failed: {e}")
    
    def _fallback_analysis(self, detection_data: Dict) -> Dict:
        """Fallback analysis when AI is unavailable"""
        
        return {
            'ai_enhanced': False,
            'final_threat_detected': detection_data.get('threat_detected', False),
            'combined_confidence': 0.5,
            'threat_classification': 'unknown',
            'threat_severity': 'medium',
            'reasoning': 'AI analysis unavailable - using fallback',
            'timestamp': datetime.now().isoformat()
        }
    
    def enable_ai(self):
        """Enable AI analysis"""
        self.ai_enabled = True
        logger.info("AI threat analysis enabled")
    
    def disable_ai(self):
        """Disable AI analysis"""
        self.ai_enabled = False
        logger.info("AI threat analysis disabled")
    
    def get_ai_status(self) -> Dict:
        """Get AI analyzer status"""
        return {
            'ai_enabled': self.ai_enabled,
            'ai_model': self.ollama_model,
            'confidence_threshold': self.confidence_threshold,
            'threat_intelligence_count': len(self.threat_intelligence),
            'attack_patterns_count': len(self.attack_patterns)
        }

# Global AI threat analyzer instance
ai_threat_analyzer = AIThreatAnalyzer()
