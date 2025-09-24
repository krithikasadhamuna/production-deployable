#!/usr/bin/env python3
"""
Real-time SIEM Monitor - Production SOC
Continuous log monitoring, event correlation, and alerting
"""

import os
import json
import time
import threading
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict, deque
import queue
import asyncio

from .real_threat_detector import real_threat_detector

logger = logging.getLogger(__name__)

class RealTimeSIEM:
    """Real-time Security Information and Event Management"""
    
    def __init__(self, db_path: str = "soc_database.db"):
        self.db_path = db_path
        self.is_running = False
        self.event_queue = queue.Queue(maxsize=10000)
        self.alert_queue = queue.Queue(maxsize=1000)
        
        # Event correlation window (5 minutes)
        self.correlation_window = 300  # seconds
        self.event_history = deque(maxlen=10000)
        
        # Alert thresholds
        self.alert_thresholds = {
            'failed_logins': 5,      # 5 failed logins in window
            'process_anomalies': 3,   # 3 anomalous processes
            'network_connections': 100, # 100+ external connections
            'file_modifications': 50,   # 50+ file changes
        }
        
        # Correlation rules
        self.correlation_rules = self._initialize_correlation_rules()
        
        # Background threads
        self.monitor_thread = None
        self.correlation_thread = None
        self.alert_thread = None
        
        logger.info("Real-time SIEM initialized")
    
    def _initialize_correlation_rules(self) -> Dict:
        """Initialize event correlation rules"""
        return {
            'apt_activity': {
                'events': ['process_anomaly', 'network_anomaly', 'file_threat'],
                'timeframe': 300,  # 5 minutes
                'threshold': 2,    # At least 2 different event types
                'severity': 'high'
            },
            'lateral_movement': {
                'events': ['failed_login', 'network_anomaly', 'process_anomaly'],
                'timeframe': 600,  # 10 minutes
                'threshold': 3,
                'severity': 'critical'
            },
            'data_exfiltration': {
                'events': ['file_access', 'network_anomaly', 'large_transfer'],
                'timeframe': 900,  # 15 minutes
                'threshold': 2,
                'severity': 'critical'
            },
            'privilege_escalation': {
                'events': ['command_injection', 'process_anomaly', 'registry_change'],
                'timeframe': 180,  # 3 minutes
                'threshold': 2,
                'severity': 'high'
            }
        }
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_running:
            logger.warning("SIEM already running")
            return
        
        self.is_running = True
        
        # Start monitoring threads
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.correlation_thread = threading.Thread(target=self._correlation_loop, daemon=True)
        self.alert_thread = threading.Thread(target=self._alert_loop, daemon=True)
        
        self.monitor_thread.start()
        self.correlation_thread.start()
        self.alert_thread.start()
        
        logger.info("Real-time SIEM monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_running = False
        logger.info("Real-time SIEM monitoring stopped")
    
    def ingest_event(self, event_data: Dict, agent_id: str):
        """Ingest a new security event"""
        try:
            # Add metadata
            event = {
                'id': f"evt-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
                'agent_id': agent_id,
                'timestamp': datetime.now().isoformat(),
                'data': event_data,
                'processed': False
            }
            
            # Add to queue for processing
            self.event_queue.put(event, timeout=1)
            
            # Add to history for correlation
            self.event_history.append(event)
            
        except queue.Full:
            logger.warning("Event queue full, dropping event")
        except Exception as e:
            logger.error(f"Event ingestion failed: {e}")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        logger.info("SIEM monitor loop started")
        
        while self.is_running:
            try:
                # Process events from queue
                try:
                    event = self.event_queue.get(timeout=1)
                    self._process_event(event)
                    self.event_queue.task_done()
                except queue.Empty:
                    continue
                
                # Periodic database polling for new agent data
                self._poll_agent_data()
                
                time.sleep(1)  # Prevent excessive CPU usage
                
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(5)
    
    def _process_event(self, event: Dict):
        """Process a single security event"""
        try:
            agent_id = event['agent_id']
            event_data = event['data']
            
            # Run threat detection
            detections = []
            
            # Analyze different data types
            if 'process' in event_data:
                result = real_threat_detector.detect_process_anomaly(event_data['process'])
                if result.get('threat_detected'):
                    detections.append(result)
            
            if 'file' in event_data:
                result = real_threat_detector.detect_file_threat(event_data['file'])
                if result.get('threat_detected'):
                    detections.append(result)
            
            if 'network' in event_data:
                result = real_threat_detector.detect_network_anomaly(event_data['network'])
                if result.get('threat_detected'):
                    detections.append(result)
            
            if 'command' in event_data:
                result = real_threat_detector.detect_command_injection(event_data['command'])
                if result.get('threat_detected'):
                    detections.append(result)
            
            # Store detections and generate alerts
            for detection in detections:
                detection_id = real_threat_detector.store_detection(detection, agent_id)
                
                # Generate alert if severity is high enough
                if detection.get('severity') in ['high', 'critical']:
                    self._generate_alert(detection, agent_id, detection_id)
            
            # Mark event as processed
            event['processed'] = True
            event['detections'] = detections
            
        except Exception as e:
            logger.error(f"Event processing failed: {e}")
    
    def _poll_agent_data(self):
        """Poll database for new agent data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get agents that have been active recently
            recent_time = (datetime.now() - timedelta(minutes=5)).isoformat()
            cursor.execute('''
                SELECT id, name, last_seen FROM agents 
                WHERE last_seen > ? AND status = 'online'
            ''', (recent_time,))
            
            active_agents = cursor.fetchall()
            
            # Simulate data collection from active agents
            for agent_id, agent_name, last_seen in active_agents:
                # In a real implementation, this would collect actual data from agents
                # For now, we'll generate sample events
                self._generate_sample_events(agent_id)
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Agent data polling failed: {e}")
    
    def _generate_sample_events(self, agent_id: str):
        """Generate sample events for testing (replace with real agent data collection)"""
        import random
        
        # Only generate events occasionally to avoid spam
        if random.random() > 0.1:  # 10% chance
            return
        
        sample_events = [
            {
                'process': {
                    'name': 'powershell.exe',
                    'cmdline': 'powershell.exe -encodedcommand dwhoami',
                    'cpu_percent': 15.5,
                    'memory_percent': 2.1,
                    'num_threads': 8,
                    'username': 'SYSTEM'
                }
            },
            {
                'file': {
                    'path': 'C:\\temp\\suspicious.exe',
                    'hash': 'd41d8cd98f00b204e9800998ecf8427e',
                    'size': 2048,
                    'action': 'created'
                }
            },
            {
                'network': {
                    'connections': [
                        {'remote_ip': '192.0.2.1', 'remote_port': 80, 'state': 'ESTABLISHED'}
                    ],
                    'dns_queries': [
                        {'domain': 'suspicious.onion', 'timestamp': datetime.now().isoformat()}
                    ]
                }
            }
        ]
        
        # Randomly select and ingest an event
        event = random.choice(sample_events)
        self.ingest_event(event, agent_id)
    
    def _correlation_loop(self):
        """Event correlation loop"""
        logger.info("SIEM correlation loop started")
        
        while self.is_running:
            try:
                self._correlate_events()
                time.sleep(30)  # Run correlation every 30 seconds
                
            except Exception as e:
                logger.error(f"Correlation loop error: {e}")
                time.sleep(60)
    
    def _correlate_events(self):
        """Correlate events to detect complex attack patterns"""
        try:
            current_time = datetime.now()
            
            # Group events by agent and time window
            agent_events = defaultdict(list)
            
            for event in self.event_history:
                event_time = datetime.fromisoformat(event['timestamp'])
                if (current_time - event_time).seconds <= self.correlation_window:
                    agent_events[event['agent_id']].append(event)
            
            # Apply correlation rules
            for agent_id, events in agent_events.items():
                for rule_name, rule in self.correlation_rules.items():
                    correlation_result = self._apply_correlation_rule(rule_name, rule, events)
                    
                    if correlation_result['triggered']:
                        self._generate_correlation_alert(rule_name, correlation_result, agent_id)
            
        except Exception as e:
            logger.error(f"Event correlation failed: {e}")
    
    def _apply_correlation_rule(self, rule_name: str, rule: Dict, events: List[Dict]) -> Dict:
        """Apply a correlation rule to events"""
        try:
            required_events = rule['events']
            timeframe = rule['timeframe']
            threshold = rule['threshold']
            
            # Filter events within timeframe
            current_time = datetime.now()
            recent_events = []
            
            for event in events:
                event_time = datetime.fromisoformat(event['timestamp'])
                if (current_time - event_time).seconds <= timeframe:
                    recent_events.append(event)
            
            # Count event types
            event_type_counts = defaultdict(int)
            for event in recent_events:
                # Determine event type from detections
                detections = event.get('detections', [])
                for detection in detections:
                    threat_type = detection.get('threat_type', 'unknown')
                    if threat_type in required_events:
                        event_type_counts[threat_type] += 1
            
            # Check if threshold is met
            matching_types = len([t for t in required_events if event_type_counts[t] > 0])
            triggered = matching_types >= threshold
            
            return {
                'triggered': triggered,
                'matching_types': matching_types,
                'event_counts': dict(event_type_counts),
                'total_events': len(recent_events),
                'timeframe': timeframe
            }
            
        except Exception as e:
            logger.error(f"Correlation rule application failed: {e}")
            return {'triggered': False, 'error': str(e)}
    
    def _generate_alert(self, detection: Dict, agent_id: str, detection_id: str):
        """Generate security alert"""
        try:
            alert = {
                'id': f"alert-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
                'organization_id': 'org-123',
                'alert_type': 'security',
                'severity': detection.get('severity', 'medium'),
                'title': f"{detection.get('threat_type', 'Unknown')} detected on {agent_id}",
                'description': f"Threat detection: {detection.get('threat_type')} with risk score {detection.get('risk_score', 0)}",
                'created_at': datetime.now().isoformat(),
                'status': 'open',
                'source_agent_id': agent_id,
                'detection_id': detection_id,
                'raw_detection': detection
            }
            
            self.alert_queue.put(alert)
            
        except Exception as e:
            logger.error(f"Alert generation failed: {e}")
    
    def _generate_correlation_alert(self, rule_name: str, correlation_result: Dict, agent_id: str):
        """Generate alert for correlated events"""
        try:
            alert = {
                'id': f"alert-corr-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
                'organization_id': 'org-123',
                'alert_type': 'correlation',
                'severity': self.correlation_rules[rule_name]['severity'],
                'title': f"Correlation Alert: {rule_name.replace('_', ' ').title()}",
                'description': f"Correlated attack pattern detected: {rule_name}",
                'created_at': datetime.now().isoformat(),
                'status': 'open',
                'source_agent_id': agent_id,
                'correlation_data': correlation_result
            }
            
            self.alert_queue.put(alert)
            logger.warning(f"Correlation alert: {rule_name} on {agent_id}")
            
        except Exception as e:
            logger.error(f"Correlation alert generation failed: {e}")
    
    def _alert_loop(self):
        """Alert processing loop"""
        logger.info("SIEM alert loop started")
        
        while self.is_running:
            try:
                # Process alerts from queue
                try:
                    alert = self.alert_queue.get(timeout=5)
                    self._process_alert(alert)
                    self.alert_queue.task_done()
                except queue.Empty:
                    continue
                
            except Exception as e:
                logger.error(f"Alert loop error: {e}")
                time.sleep(5)
    
    def _process_alert(self, alert: Dict):
        """Process and store alert"""
        try:
            # Store alert in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (
                    id, organization_id, alert_type, severity, title, 
                    description, created_at, status, source_agent_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['id'],
                alert['organization_id'],
                alert['alert_type'],
                alert['severity'],
                alert['title'],
                alert['description'],
                alert['created_at'],
                alert['status'],
                alert['source_agent_id']
            ))
            
            conn.commit()
            conn.close()
            
            # Log alert
            logger.warning(f"ALERT: {alert['title']} (Severity: {alert['severity']})")
            
            # In production, you would also:
            # - Send notifications (email, Slack, SMS)
            # - Update dashboards
            # - Trigger automated responses
            
        except Exception as e:
            logger.error(f"Alert processing failed: {e}")
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent alerts"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE created_at > ? 
                ORDER BY created_at DESC
            ''', (since_time,))
            
            columns = [desc[0] for desc in cursor.description]
            alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to get recent alerts: {e}")
            return []
    
    def get_monitoring_stats(self) -> Dict:
        """Get monitoring statistics"""
        return {
            'is_running': self.is_running,
            'events_in_queue': self.event_queue.qsize(),
            'alerts_in_queue': self.alert_queue.qsize(),
            'events_in_history': len(self.event_history),
            'correlation_rules': len(self.correlation_rules),
            'uptime_seconds': time.time() - getattr(self, 'start_time', time.time())
        }

# Global instance
realtime_siem = RealTimeSIEM()
