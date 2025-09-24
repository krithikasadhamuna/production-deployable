#!/usr/bin/env python3
"""
AI-Enhanced Threat Detector
Combines traditional ML with AI intelligence for superior threat detection
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from .real_threat_detector import real_threat_detector
from .ai_threat_analyzer import ai_threat_analyzer

logger = logging.getLogger(__name__)

class AIEnhancedThreatDetector:
    """AI-enhanced threat detector with intelligent analysis"""
    
    def __init__(self):
        self.base_detector = real_threat_detector
        self.ai_analyzer = ai_threat_analyzer
        self.ai_enabled = True
        
        # Performance tracking
        self.detection_stats = {
            'total_detections': 0,
            'ai_enhanced_detections': 0,
            'false_positives_prevented': 0,
            'threat_intelligence_generated': 0
        }
        
        logger.info("AI-Enhanced Threat Detector initialized")
    
    async def analyze_threat_intelligently(self, detection_data: Dict, 
                                         context: Dict) -> Dict:
        """Analyze threat with full AI intelligence"""
        
        self.detection_stats['total_detections'] += 1
        
        try:
            # Phase 1: Traditional ML detection
            logger.debug("Phase 1: Traditional ML detection...")
            ml_result = self._get_base_detection(detection_data)
            
            # Phase 2: AI-enhanced analysis
            if self.ai_enabled and (ml_result.get('threat_detected') or 
                                  ml_result.get('final_score', 0) > 0.4):
                
                logger.debug("Phase 2: AI threat analysis...")
                ai_result = await self.ai_analyzer.analyze_threat_with_ai(
                    detection_data, context
                )
                
                self.detection_stats['ai_enhanced_detections'] += 1
                
                # Phase 3: Generate threat intelligence if high confidence
                if (ai_result.get('combined_confidence', 0) > 0.8 and 
                    ai_result.get('final_threat_detected')):
                    
                    logger.debug("Phase 3: Generating threat intelligence...")
                    intelligence = await self.ai_analyzer.generate_threat_intelligence(
                        detection_data
                    )
                    ai_result['threat_intelligence'] = intelligence
                    
                    if intelligence.get('intelligence_available'):
                        self.detection_stats['threat_intelligence_generated'] += 1
                
                # Check for false positive prevention
                if (ml_result.get('threat_detected') and 
                    ai_result.get('false_positive_likelihood', 0) > 0.7):
                    
                    logger.info("AI prevented false positive")
                    ai_result['final_threat_detected'] = False
                    ai_result['ai_override'] = 'false_positive_prevention'
                    self.detection_stats['false_positives_prevented'] += 1
                
                return ai_result
            
            else:
                # Return enhanced ML result
                return self._enhance_ml_result(ml_result, detection_data)
            
        except Exception as e:
            logger.error(f"AI-enhanced detection failed: {e}")
            return self._enhance_ml_result(ml_result, detection_data)
    
    async def correlate_threats_intelligently(self, threat_events: List[Dict], 
                                            time_window: int = 3600) -> Dict:
        """Intelligent threat correlation using AI"""
        
        if not self.ai_enabled:
            return self._basic_correlation(threat_events)
        
        try:
            logger.info(f"AI correlating {len(threat_events)} threat events...")
            
            # AI-powered correlation
            correlation = await self.ai_analyzer.correlate_threats_with_ai(
                threat_events, time_window
            )
            
            # Enhance with traditional correlation if AI finds patterns
            if correlation.get('correlation_found'):
                traditional_correlation = self._basic_correlation(threat_events)
                correlation['traditional_correlation'] = traditional_correlation
            
            return correlation
            
        except Exception as e:
            logger.error(f"AI threat correlation failed: {e}")
            return self._basic_correlation(threat_events)
    
    async def adaptive_detection_tuning(self, detection_history: List[Dict]) -> Dict:
        """Continuously tune detection based on AI analysis"""
        
        if not self.ai_enabled:
            return {'tuning_applied': False, 'reason': 'AI disabled'}
        
        try:
            logger.info("🎛️ AI analyzing detection patterns for tuning...")
            
            # AI-powered threshold tuning
            tuning_result = await self.ai_analyzer.adaptive_threshold_tuning(
                detection_history
            )
            
            return tuning_result
            
        except Exception as e:
            logger.error(f"Adaptive tuning failed: {e}")
            return {'tuning_applied': False, 'error': str(e)}
    
    def analyze_agent_data_intelligently(self, agent_data: Dict, 
                                       agent_id: str) -> List[Dict]:
        """Comprehensive AI-enhanced analysis of agent data"""
        
        detections = []
        
        try:
            # Get context for AI analysis
            context = self._build_agent_context(agent_id, agent_data)
            
            # Process different data types
            if 'processes' in agent_data:
                for process in agent_data['processes']:
                    detection_data = {
                        'type': 'process_anomaly',
                        'data': process,
                        'agent_id': agent_id
                    }
                    
                    # AI-enhanced analysis
                    result = asyncio.run(self.analyze_threat_intelligently(
                        detection_data, context
                    ))
                    
                    if result.get('final_threat_detected'):
                        detections.append(result)
                        self._store_enhanced_detection(result, agent_id)
            
            if 'files' in agent_data:
                for file_data in agent_data['files']:
                    detection_data = {
                        'type': 'file_threat',
                        'data': file_data,
                        'agent_id': agent_id
                    }
                    
                    result = asyncio.run(self.analyze_threat_intelligently(
                        detection_data, context
                    ))
                    
                    if result.get('final_threat_detected'):
                        detections.append(result)
                        self._store_enhanced_detection(result, agent_id)
            
            if 'network' in agent_data:
                detection_data = {
                    'type': 'network_anomaly',
                    'data': agent_data['network'],
                    'agent_id': agent_id
                }
                
                result = asyncio.run(self.analyze_threat_intelligently(
                    detection_data, context
                ))
                
                if result.get('final_threat_detected'):
                    detections.append(result)
                    self._store_enhanced_detection(result, agent_id)
            
            if 'commands' in agent_data:
                for command in agent_data['commands']:
                    detection_data = {
                        'type': 'command_injection',
                        'data': command,
                        'agent_id': agent_id
                    }
                    
                    result = asyncio.run(self.analyze_threat_intelligently(
                        detection_data, context
                    ))
                    
                    if result.get('final_threat_detected'):
                        detections.append(result)
                        self._store_enhanced_detection(result, agent_id)
            
            logger.info(f"AI-enhanced analysis: {len(detections)} threats detected on {agent_id}")
            
            return detections
            
        except Exception as e:
            logger.error(f"AI-enhanced agent analysis failed: {e}")
            # Fallback to basic detection
            return self.base_detector.analyze_agent_data(agent_data, agent_id)
    
    def _get_base_detection(self, detection_data: Dict) -> Dict:
        """Get base ML detection result"""
        
        try:
            data_type = detection_data.get('type')
            data = detection_data.get('data', {})
            
            if data_type == 'process_anomaly':
                return self.base_detector.detect_process_anomaly(data)
            elif data_type == 'file_threat':
                return self.base_detector.detect_file_threat(data)
            elif data_type == 'network_anomaly':
                return self.base_detector.detect_network_anomaly(data)
            elif data_type == 'command_injection':
                return self.base_detector.detect_command_injection(data)
            else:
                return {'threat_detected': False, 'final_score': 0.0}
                
        except Exception as e:
            logger.error(f"Base detection failed: {e}")
            return {'threat_detected': False, 'final_score': 0.0}
    
    def _enhance_ml_result(self, ml_result: Dict, detection_data: Dict) -> Dict:
        """Enhance ML result with additional metadata"""
        
        enhanced = ml_result.copy()
        enhanced.update({
            'ai_enhanced': False,
            'analysis_method': 'traditional_ml',
            'timestamp': datetime.now().isoformat(),
            'detection_data': detection_data
        })
        
        return enhanced
    
    def _build_agent_context(self, agent_id: str, agent_data: Dict) -> Dict:
        """Build context for AI analysis"""
        
        import sqlite3
        
        context = {
            'agent_id': agent_id,
            'timestamp': datetime.now().isoformat(),
            'platform': 'unknown',
            'user_context': 'unknown',
            'network_segment': 'unknown'
        }
        
        try:
            # Get agent info from database
            conn = sqlite3.connect(self.base_detector.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT platform, type, hostname, ip_address FROM agents 
                WHERE id = ?
            ''', (agent_id,))
            
            result = cursor.fetchone()
            if result:
                context.update({
                    'platform': result[0] or 'unknown',
                    'agent_type': result[1] or 'unknown',
                    'hostname': result[2] or 'unknown',
                    'ip_address': result[3] or 'unknown'
                })
            
            # Get recent activity
            cursor.execute('''
                SELECT detection_type, severity, created_at FROM detections 
                WHERE agent_id = ? 
                ORDER BY created_at DESC 
                LIMIT 10
            ''', (agent_id,))
            
            recent_activity = []
            for row in cursor.fetchall():
                recent_activity.append({
                    'type': row[0],
                    'severity': row[1],
                    'timestamp': row[2]
                })
            
            context['recent_activity'] = recent_activity
            conn.close()
            
        except Exception as e:
            logger.error(f"Context building failed: {e}")
        
        return context
    
    def _basic_correlation(self, threat_events: List[Dict]) -> Dict:
        """Basic correlation fallback"""
        
        if len(threat_events) < 2:
            return {'correlation_found': False, 'reason': 'Insufficient events'}
        
        # Simple time-based correlation
        time_clustered = len([e for e in threat_events 
                            if (datetime.now() - datetime.fromisoformat(
                                e.get('timestamp', datetime.now().isoformat())
                            )).seconds < 300])  # 5 minutes
        
        correlation_found = time_clustered >= 2
        
        return {
            'correlation_found': correlation_found,
            'method': 'basic_time_clustering',
            'clustered_events': time_clustered,
            'confidence': 0.6 if correlation_found else 0.2
        }
    
    def _store_enhanced_detection(self, detection_result: Dict, agent_id: str):
        """Store AI-enhanced detection result"""
        
        try:
            # Store using base detector with enhanced data
            enhanced_result = detection_result.copy()
            enhanced_result['ai_enhanced'] = True
            enhanced_result['ai_confidence'] = detection_result.get('combined_confidence', 0.5)
            
            detection_id = self.base_detector.store_detection(
                enhanced_result, agent_id
            )
            
            # Store additional AI data if available
            if detection_result.get('threat_intelligence'):
                self._store_threat_intelligence_link(detection_id, detection_result['threat_intelligence'])
            
            return detection_id
            
        except Exception as e:
            logger.error(f"Enhanced detection storage failed: {e}")
            return None
    
    def _store_threat_intelligence_link(self, detection_id: str, intelligence: Dict):
        """Store link between detection and threat intelligence"""
        
        try:
            import sqlite3
            
            conn = sqlite3.connect(self.base_detector.db_path)
            cursor = conn.cursor()
            
            # Create detection_intelligence table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detection_intelligence (
                    detection_id TEXT,
                    intelligence_summary TEXT,
                    created_at TEXT,
                    FOREIGN KEY (detection_id) REFERENCES detections(id)
                )
            ''')
            
            cursor.execute('''
                INSERT INTO detection_intelligence 
                (detection_id, intelligence_summary, created_at)
                VALUES (?, ?, ?)
            ''', (
                detection_id,
                json.dumps(intelligence),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Threat intelligence link storage failed: {e}")
    
    def get_detection_stats(self) -> Dict:
        """Get AI-enhanced detection statistics"""
        
        ai_enhancement_rate = 0
        if self.detection_stats['total_detections'] > 0:
            ai_enhancement_rate = (
                self.detection_stats['ai_enhanced_detections'] / 
                self.detection_stats['total_detections']
            )
        
        return {
            **self.detection_stats,
            'ai_enhancement_rate': ai_enhancement_rate,
            'ai_enabled': self.ai_enabled,
            'ai_analyzer_status': self.ai_analyzer.get_ai_status()
        }
    
    def enable_ai(self):
        """Enable AI enhancement"""
        self.ai_enabled = True
        self.ai_analyzer.enable_ai()
        logger.info("AI-enhanced detection enabled")
    
    def disable_ai(self):
        """Disable AI enhancement"""
        self.ai_enabled = False
        self.ai_analyzer.disable_ai()
        logger.info("AI-enhanced detection disabled")
    
    async def run_detection_health_check(self) -> Dict:
        """Run comprehensive detection system health check"""
        
        health_check = {
            'base_detector': 'healthy',
            'ai_analyzer': 'healthy',
            'overall_status': 'healthy',
            'issues': []
        }
        
        try:
            # Test base detector
            test_data = {
                'type': 'process_anomaly',
                'data': {'name': 'test.exe', 'cmdline': 'test command'}
            }
            
            base_result = self._get_base_detection(test_data)
            if not isinstance(base_result, dict):
                health_check['base_detector'] = 'unhealthy'
                health_check['issues'].append('Base detector not responding properly')
            
            # Test AI analyzer if enabled
            if self.ai_enabled:
                try:
                    ai_status = self.ai_analyzer.get_ai_status()
                    if not ai_status.get('ai_enabled'):
                        health_check['ai_analyzer'] = 'degraded'
                        health_check['issues'].append('AI analyzer disabled')
                except Exception as e:
                    health_check['ai_analyzer'] = 'unhealthy'
                    health_check['issues'].append(f'AI analyzer error: {str(e)}')
            
            # Overall status
            if health_check['issues']:
                health_check['overall_status'] = 'degraded' if len(health_check['issues']) == 1 else 'unhealthy'
            
            return health_check
            
        except Exception as e:
            logger.error(f"Detection health check failed: {e}")
            return {
                'base_detector': 'unhealthy',
                'ai_analyzer': 'unhealthy',
                'overall_status': 'unhealthy',
                'issues': [f'Health check failed: {str(e)}']
            }

# Global AI-enhanced detector instance
ai_enhanced_detector = AIEnhancedThreatDetector()
