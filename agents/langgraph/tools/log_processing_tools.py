"""
Log Processing Tools for Detection System
Fetches, processes, and batches logs from database
"""

import sqlite3
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
import hashlib
import re

logger = logging.getLogger(__name__)

class LogFetcherTool:
    """Tool for fetching logs from database"""
    
    def __init__(self, db_path: str = "soc_database.db"):
        self.db_path = db_path
        self.name = "log_fetcher"
        self.description = "Fetch logs from database for processing"
        self.last_processed_id = None
        self.batch_size = 100
    
    def run(self, 
            batch_size: int = 100, 
            time_window: int = 5,  # minutes
            severity_filter: str = None,
            agent_filter: str = None) -> Dict[str, Any]:
        """
        Fetch unprocessed logs from database
        
        Args:
            batch_size: Number of logs to fetch
            time_window: Time window in minutes
            severity_filter: Filter by severity (critical, high, medium, low)
            agent_filter: Filter by agent ID
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Build query
            query = """
                SELECT 
                    id, agent_id, timestamp, type, severity, 
                    data, status, source_ip, target_ip, 
                    technique, description
                FROM detections
                WHERE status = 'pending'
            """
            
            params = []
            
            # Add time filter
            if time_window:
                cutoff_time = (datetime.now(timezone.utc) - timedelta(minutes=time_window)).isoformat()
                query += " AND timestamp >= ?"
                params.append(cutoff_time)
            
            # Add severity filter
            if severity_filter:
                query += " AND severity = ?"
                params.append(severity_filter)
            
            # Add agent filter
            if agent_filter:
                query += " AND agent_id = ?"
                params.append(agent_filter)
            
            # Add ordering and limit
            query += " ORDER BY timestamp DESC, severity DESC LIMIT ?"
            params.append(batch_size)
            
            cursor.execute(query, params)
            
            logs = []
            for row in cursor.fetchall():
                log_entry = {
                    'id': row['id'],
                    'agent_id': row['agent_id'],
                    'timestamp': row['timestamp'],
                    'type': row['type'],
                    'severity': row['severity'],
                    'data': json.loads(row['data']) if row['data'] else {},
                    'status': row['status'],
                    'source_ip': row['source_ip'],
                    'target_ip': row['target_ip'],
                    'technique': row['technique'],
                    'description': row['description']
                }
                logs.append(log_entry)
            
            # Get additional agent logs if available
            cursor.execute("""
                SELECT 
                    id, agent_id, timestamp, level, source, 
                    message, importance
                FROM agent_logs
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (
                (datetime.now(timezone.utc) - timedelta(minutes=time_window)).isoformat(),
                batch_size
            ))
            
            agent_logs = []
            for row in cursor.fetchall():
                agent_logs.append({
                    'id': row['id'],
                    'agent_id': row['agent_id'],
                    'timestamp': row['timestamp'],
                    'level': row['level'],
                    'source': row['source'],
                    'message': row['message'],
                    'importance': row['importance']
                })
            
            conn.close()
            
            return {
                'success': True,
                'detection_logs': logs,
                'agent_logs': agent_logs,
                'total_fetched': len(logs) + len(agent_logs),
                'time_window': time_window,
                'fetch_time': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Log fetching error: {e}")
            return {
                'success': False,
                'error': str(e),
                'detection_logs': [],
                'agent_logs': []
            }
    
    def mark_processed(self, log_ids: List[str], status: str = 'analyzed'):
        """Mark logs as processed"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for log_id in log_ids:
                cursor.execute("""
                    UPDATE detections 
                    SET status = ? 
                    WHERE id = ?
                """, (status, log_id))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            logger.error(f"Error marking logs processed: {e}")
            return False


class LogParserTool:
    """Tool for parsing and structuring log data"""
    
    def __init__(self):
        self.name = "log_parser"
        self.description = "Parse and structure various log formats"
        
        # Common log patterns
        self.patterns = {
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'file_path': r'(?:[A-Za-z]:\\|/)[^\s]+',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
            'process_name': r'[\w\-]+\.exe|[\w\-]+\.dll',
            'registry_key': r'HK[LCU][A-Z]*\\[^\s]+',
            'powershell_encoded': r'powershell\s+-[eE]nc\s+[A-Za-z0-9+/=]+',
            'base64': r'[A-Za-z0-9+/]{20,}={0,2}'
        }
    
    def run(self, logs: List[Dict]) -> List[Dict]:
        """
        Parse logs and extract structured information
        """
        parsed_logs = []
        
        for log in logs:
            parsed = log.copy()
            
            # Extract message or data field
            log_text = str(log.get('message', '')) + str(log.get('data', ''))
            
            # Extract IPs
            ips = re.findall(self.patterns['ip_address'], log_text)
            if ips:
                parsed['extracted_ips'] = list(set(ips))
            
            # Extract domains
            domains = re.findall(self.patterns['domain'], log_text)
            if domains:
                parsed['extracted_domains'] = list(set(domains))
            
            # Extract file paths
            file_paths = re.findall(self.patterns['file_path'], log_text)
            if file_paths:
                parsed['extracted_paths'] = list(set(file_paths))
            
            # Extract hashes
            md5_hashes = re.findall(self.patterns['hash_md5'], log_text)
            sha256_hashes = re.findall(self.patterns['hash_sha256'], log_text)
            if md5_hashes or sha256_hashes:
                parsed['extracted_hashes'] = {
                    'md5': list(set(md5_hashes)),
                    'sha256': list(set(sha256_hashes))
                }
            
            # Extract process names
            processes = re.findall(self.patterns['process_name'], log_text)
            if processes:
                parsed['extracted_processes'] = list(set(processes))
            
            # Check for PowerShell encoding
            if re.search(self.patterns['powershell_encoded'], log_text):
                parsed['powershell_encoded'] = True
                parsed['risk_indicators'] = parsed.get('risk_indicators', [])
                parsed['risk_indicators'].append('powershell_encoding')
            
            # Check for base64
            base64_strings = re.findall(self.patterns['base64'], log_text)
            if base64_strings:
                parsed['base64_detected'] = True
                parsed['base64_strings'] = base64_strings[:5]  # Limit to 5
            
            # Categorize log
            parsed['log_category'] = self._categorize_log(log_text)
            
            # Calculate initial risk score
            parsed['initial_risk_score'] = self._calculate_risk_score(parsed)
            
            parsed_logs.append(parsed)
        
        return parsed_logs
    
    def _categorize_log(self, log_text: str) -> str:
        """Categorize log based on content"""
        log_lower = log_text.lower()
        
        if any(word in log_lower for word in ['login', 'logon', 'authentication', 'password']):
            return 'authentication'
        elif any(word in log_lower for word in ['process', 'started', 'executed', 'spawned']):
            return 'process_activity'
        elif any(word in log_lower for word in ['connection', 'socket', 'port', 'tcp', 'udp']):
            return 'network_activity'
        elif any(word in log_lower for word in ['file', 'created', 'modified', 'deleted', 'write']):
            return 'file_activity'
        elif any(word in log_lower for word in ['registry', 'hklm', 'hkcu', 'regkey']):
            return 'registry_activity'
        elif any(word in log_lower for word in ['error', 'failed', 'denied', 'blocked']):
            return 'error_event'
        else:
            return 'general'
    
    def _calculate_risk_score(self, parsed_log: Dict) -> float:
        """Calculate initial risk score based on indicators"""
        score = 0.0
        
        # Severity-based scoring
        severity = parsed_log.get('severity', 'low')
        if severity == 'critical':
            score += 40
        elif severity == 'high':
            score += 30
        elif severity == 'medium':
            score += 20
        else:
            score += 10
        
        # Risk indicators
        if parsed_log.get('powershell_encoded'):
            score += 25
        if parsed_log.get('base64_detected'):
            score += 15
        if len(parsed_log.get('extracted_processes', [])) > 3:
            score += 10
        if parsed_log.get('log_category') == 'authentication':
            score += 5
        
        # Time-based (if outside business hours)
        try:
            timestamp = datetime.fromisoformat(parsed_log.get('timestamp', ''))
            hour = timestamp.hour
            if hour < 6 or hour > 22:  # Outside business hours
                score += 10
        except:
            pass
        
        return min(score, 100.0)  # Cap at 100


class LogAggregatorTool:
    """Tool for aggregating and correlating logs"""
    
    def __init__(self):
        self.name = "log_aggregator"
        self.description = "Aggregate and correlate related logs"
    
    def run(self, logs: List[Dict]) -> Dict[str, Any]:
        """
        Aggregate logs by various criteria
        """
        aggregated = {
            'by_agent': {},
            'by_severity': {},
            'by_category': {},
            'by_time_window': {},
            'correlations': [],
            'patterns': []
        }
        
        for log in logs:
            agent_id = log.get('agent_id')
            severity = log.get('severity', 'unknown')
            category = log.get('log_category', 'general')
            
            # Aggregate by agent
            if agent_id not in aggregated['by_agent']:
                aggregated['by_agent'][agent_id] = []
            aggregated['by_agent'][agent_id].append(log)
            
            # Aggregate by severity
            if severity not in aggregated['by_severity']:
                aggregated['by_severity'][severity] = []
            aggregated['by_severity'][severity].append(log)
            
            # Aggregate by category
            if category not in aggregated['by_category']:
                aggregated['by_category'][category] = []
            aggregated['by_category'][category].append(log)
        
        # Find correlations
        aggregated['correlations'] = self._find_correlations(logs)
        
        # Identify patterns
        aggregated['patterns'] = self._identify_patterns(aggregated)
        
        # Calculate statistics
        aggregated['statistics'] = {
            'total_logs': len(logs),
            'unique_agents': len(aggregated['by_agent']),
            'critical_count': len(aggregated['by_severity'].get('critical', [])),
            'high_count': len(aggregated['by_severity'].get('high', [])),
            'top_category': max(aggregated['by_category'], key=lambda k: len(aggregated['by_category'][k]))
            if aggregated['by_category'] else 'none'
        }
        
        return aggregated
    
    def _find_correlations(self, logs: List[Dict]) -> List[Dict]:
        """Find correlated events"""
        correlations = []
        
        # Group by time windows (5 minute windows)
        time_groups = {}
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log.get('timestamp', ''))
                window = timestamp.replace(minute=(timestamp.minute // 5) * 5, second=0, microsecond=0)
                window_key = window.isoformat()
                
                if window_key not in time_groups:
                    time_groups[window_key] = []
                time_groups[window_key].append(log)
            except:
                continue
        
        # Find correlations within time windows
        for window, window_logs in time_groups.items():
            if len(window_logs) > 1:
                # Check for related IPs
                all_ips = []
                for log in window_logs:
                    all_ips.extend(log.get('extracted_ips', []))
                
                common_ips = [ip for ip in set(all_ips) if all_ips.count(ip) > 1]
                
                if common_ips:
                    correlations.append({
                        'type': 'common_ip',
                        'time_window': window,
                        'indicators': common_ips,
                        'log_count': len(window_logs),
                        'confidence': 0.7
                    })
                
                # Check for attack progression
                categories = [log.get('log_category') for log in window_logs]
                if 'authentication' in categories and 'process_activity' in categories:
                    correlations.append({
                        'type': 'potential_attack_chain',
                        'time_window': window,
                        'pattern': 'auth_then_exec',
                        'log_count': len(window_logs),
                        'confidence': 0.6
                    })
        
        return correlations
    
    def _identify_patterns(self, aggregated: Dict) -> List[Dict]:
        """Identify patterns in aggregated logs"""
        patterns = []
        
        # Check for brute force pattern
        auth_logs = aggregated['by_category'].get('authentication', [])
        if len(auth_logs) > 10:
            failed_auth = [log for log in auth_logs if 'failed' in str(log).lower()]
            if len(failed_auth) > 5:
                patterns.append({
                    'type': 'brute_force',
                    'indicator_count': len(failed_auth),
                    'confidence': 0.8
                })
        
        # Check for scanning pattern
        network_logs = aggregated['by_category'].get('network_activity', [])
        if len(network_logs) > 20:
            unique_ports = set()
            for log in network_logs:
                # Extract ports from logs
                port_matches = re.findall(r':(\d{1,5})', str(log))
                unique_ports.update(port_matches)
            
            if len(unique_ports) > 10:
                patterns.append({
                    'type': 'port_scanning',
                    'unique_ports': len(unique_ports),
                    'confidence': 0.7
                })
        
        # Check for data exfiltration pattern
        if aggregated['statistics']['total_logs'] > 50:
            high_volume_agents = [
                agent for agent, logs in aggregated['by_agent'].items()
                if len(logs) > aggregated['statistics']['total_logs'] * 0.3
            ]
            
            if high_volume_agents:
                patterns.append({
                    'type': 'high_volume_activity',
                    'agents': high_volume_agents,
                    'confidence': 0.6
                })
        
        return patterns
