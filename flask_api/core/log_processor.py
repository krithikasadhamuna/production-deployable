"""
Comprehensive Log Processing System
Handles log receiving, parsing, storage, and AI analysis
"""

import json
import sqlite3
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Any
import hashlib

logger = logging.getLogger(__name__)

class LogProcessor:
    """Central log processing system"""
    
    def __init__(self, db_path='tenant_databases/codegrey.db'):
        self.db_path = db_path
        self.ensure_tables()
        
    def ensure_tables(self):
        """Ensure all necessary tables exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agent_logs (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                timestamp TIMESTAMP,
                log_type TEXT,
                severity TEXT,
                source TEXT,
                message TEXT,
                raw_data TEXT,
                parsed_data TEXT,
                processed INTEGER DEFAULT 0,
                threat_score REAL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
        ''')
        
        # Events/detections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                type TEXT,
                severity TEXT,
                timestamp TIMESTAMP,
                data TEXT,
                status TEXT DEFAULT 'pending',
                ai_analysis TEXT,
                threat_verdict TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_agent ON agent_logs(agent_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_processed ON agent_logs(processed)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_severity ON agent_logs(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status)')
        
        conn.commit()
        conn.close()
    
    def process_incoming_logs(self, agent_id: str, data: Dict) -> Dict:
        """
        Process logs from any agent format
        Handles both 'events' and 'logs' formats
        """
        processed_count = 0
        stored_logs = []
        
        # Handle different formats
        if 'events' in data:
            # Windows agent format
            logs = data['events']
            log_format = 'events'
        elif 'logs' in data:
            # Linux/macOS agent format
            logs = data['logs']
            log_format = 'logs'
        else:
            # Fallback: treat entire data as single log
            logs = [data]
            log_format = 'raw'
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for log_entry in logs:
            try:
                # Parse log based on format
                parsed = self.parse_log(log_entry, log_format)
                
                # Generate unique ID
                log_id = self.generate_log_id(agent_id, parsed)
                
                # Store in database
                cursor.execute('''
                    INSERT OR IGNORE INTO agent_logs 
                    (id, agent_id, timestamp, log_type, severity, source, 
                     message, raw_data, parsed_data, threat_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    log_id,
                    agent_id,
                    parsed['timestamp'],
                    parsed['type'],
                    parsed['severity'],
                    parsed['source'],
                    parsed['message'],
                    json.dumps(log_entry),
                    json.dumps(parsed),
                    parsed['threat_score']
                ))
                
                # Also store in detections if it's an event
                if parsed['severity'] in ['critical', 'high', 'medium']:
                    cursor.execute('''
                        INSERT OR IGNORE INTO detections 
                        (id, agent_id, type, severity, timestamp, data, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        log_id,
                        agent_id,
                        parsed['type'],
                        parsed['severity'],
                        parsed['timestamp'],
                        json.dumps(parsed),
                        'pending'
                    ))
                
                processed_count += 1
                stored_logs.append(log_id)
                
            except Exception as e:
                logger.error(f"Error processing log entry: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        # Trigger AI analysis if high severity logs
        high_severity_count = sum(1 for log in logs if self.get_severity(log) in ['critical', 'high'])
        if high_severity_count > 0:
            self.trigger_ai_analysis(agent_id, stored_logs)
        
        return {
            'processed': processed_count,
            'stored_logs': stored_logs,
            'high_severity': high_severity_count
        }
    
    def parse_log(self, log_entry: Any, format_type: str) -> Dict:
        """Parse log entry based on format"""
        parsed = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'type': 'unknown',
            'severity': 'info',
            'source': 'agent',
            'message': '',
            'threat_score': 0,
            'indicators': []
        }
        
        if format_type == 'events':
            # Windows event format
            if isinstance(log_entry, dict):
                parsed['timestamp'] = log_entry.get('timestamp', parsed['timestamp'])
                parsed['type'] = log_entry.get('type', 'system_event')
                parsed['severity'] = log_entry.get('severity', 'info')
                parsed['source'] = log_entry.get('source', 'windows_agent')
                parsed['message'] = log_entry.get('message', str(log_entry.get('data', '')))
                
                # Extract from data field
                if 'data' in log_entry:
                    data = log_entry['data']
                    if isinstance(data, dict):
                        parsed['message'] = data.get('description', parsed['message'])
                        if 'process' in data:
                            parsed['type'] = 'process_event'
                        elif 'network' in data:
                            parsed['type'] = 'network_event'
        
        elif format_type == 'logs':
            # Linux/macOS log format
            if isinstance(log_entry, dict):
                parsed['timestamp'] = log_entry.get('timestamp', parsed['timestamp'])
                parsed['type'] = log_entry.get('type', 'system_log')
                parsed['severity'] = log_entry.get('level', 'info')
                parsed['source'] = log_entry.get('source', 'linux_agent')
                parsed['message'] = log_entry.get('message', str(log_entry))
            elif isinstance(log_entry, str):
                # Plain text log
                parsed['message'] = log_entry
                parsed = self.parse_text_log(log_entry, parsed)
        
        # Calculate threat score
        parsed['threat_score'] = self.calculate_threat_score(parsed)
        
        # Extract indicators
        parsed['indicators'] = self.extract_indicators(parsed['message'])
        
        return parsed
    
    def parse_text_log(self, text: str, parsed: Dict) -> Dict:
        """Parse plain text log entries"""
        
        # Common log patterns
        patterns = {
            'syslog': r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
            'apache': r'^(\S+)\s+\S+\s+\S+\s+\[([\w:/]+\s[+\-]\d{4})\]\s+"(\S+\s+\S+\s+\S+)"\s+(\d{3})',
            'windows': r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+)\s+(.*)',
        }
        
        for log_type, pattern in patterns.items():
            match = re.match(pattern, text)
            if match:
                parsed['type'] = log_type
                if log_type == 'syslog':
                    parsed['timestamp'] = match.group(1)
                    parsed['source'] = match.group(3)
                    parsed['message'] = match.group(5)
                elif log_type == 'windows':
                    parsed['timestamp'] = match.group(1)
                    parsed['severity'] = match.group(2).lower()
                    parsed['source'] = match.group(3)
                    parsed['message'] = match.group(4)
                break
        
        # Check for severity keywords
        severity_keywords = {
            'critical': ['critical', 'fatal', 'emergency'],
            'high': ['error', 'alert', 'fail'],
            'medium': ['warning', 'warn'],
            'low': ['info', 'notice'],
            'debug': ['debug', 'trace']
        }
        
        message_lower = text.lower()
        for severity, keywords in severity_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                parsed['severity'] = severity
                break
        
        return parsed
    
    def calculate_threat_score(self, parsed: Dict) -> float:
        """Calculate threat score based on log content"""
        score = 0.0
        
        # Severity-based scoring
        severity_scores = {
            'critical': 0.9,
            'high': 0.7,
            'medium': 0.5,
            'low': 0.3,
            'info': 0.1
        }
        score += severity_scores.get(parsed['severity'], 0.1)
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'powershell.*-enc', 0.8),
            (r'cmd.*\/c', 0.6),
            (r'mimikatz', 0.9),
            (r'password.*failed', 0.4),
            (r'unauthorized', 0.5),
            (r'malware', 0.9),
            (r'ransomware', 0.95),
            (r'backdoor', 0.9),
            (r'reverse.*shell', 0.85),
            (r'privilege.*escalation', 0.8),
            (r'lateral.*movement', 0.75),
            (r'data.*exfiltration', 0.8),
            (r'port.*scan', 0.6),
            (r'brute.*force', 0.7)
        ]
        
        message_lower = parsed['message'].lower()
        for pattern, pattern_score in suspicious_patterns:
            if re.search(pattern, message_lower):
                score = max(score, pattern_score)
        
        return min(score, 1.0)  # Cap at 1.0
    
    def extract_indicators(self, message: str) -> List[str]:
        """Extract IOCs from log message"""
        indicators = []
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, message)
        indicators.extend([f"ip:{ip}" for ip in ips])
        
        # Domain names
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, message)
        indicators.extend([f"domain:{domain}" for domain in domains])
        
        # File hashes (MD5, SHA1, SHA256)
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        hashes = re.findall(hash_pattern, message)
        indicators.extend([f"hash:{h}" for h in hashes])
        
        # File paths
        file_pattern = r'[C-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\.[a-zA-Z]{2,4}'
        files = re.findall(file_pattern, message)
        indicators.extend([f"file:{f}" for f in files])
        
        return indicators
    
    def get_severity(self, log_entry: Any) -> str:
        """Get severity from log entry"""
        if isinstance(log_entry, dict):
            return log_entry.get('severity', log_entry.get('level', 'info'))
        return 'info'
    
    def generate_log_id(self, agent_id: str, parsed: Dict) -> str:
        """Generate unique log ID"""
        content = f"{agent_id}{parsed['timestamp']}{parsed['message']}"
        return f"log_{hashlib.md5(content.encode()).hexdigest()[:12]}"
    
    def trigger_ai_analysis(self, agent_id: str, log_ids: List[str]):
        """Trigger AI analysis for high-severity logs"""
        logger.info(f"Triggering AI analysis for {len(log_ids)} logs from agent {agent_id}")
        
        # Mark logs for AI processing
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for log_id in log_ids:
            cursor.execute('''
                UPDATE detections 
                SET status = 'analyzing' 
                WHERE id = ?
            ''', (log_id,))
        
        conn.commit()
        conn.close()
    
    def get_pending_logs_for_analysis(self, limit: int = 100) -> List[Dict]:
        """Get pending logs for AI analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, agent_id, parsed_data, raw_data, threat_score
            FROM agent_logs
            WHERE processed = 0 AND threat_score > 0.3
            ORDER BY threat_score DESC, created_at ASC
            LIMIT ?
        ''', (limit,))
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'id': row[0],
                'agent_id': row[1],
                'parsed_data': json.loads(row[2]),
                'raw_data': json.loads(row[3]),
                'threat_score': row[4]
            })
        
        conn.close()
        return logs
