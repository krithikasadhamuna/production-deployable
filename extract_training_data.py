#!/usr/bin/env python3
"""
CodeGrey SOC - Training Data Extraction Tool
Extracts sanitized logs and agent data for LLM training
"""

import sqlite3
import json
import re
import hashlib
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SOCDataExtractor:
    def __init__(self, db_path="database/soc_production.db"):
        self.db_path = db_path
        self.output_dir = "training_data"
        os.makedirs(self.output_dir, exist_ok=True)
        
    def _sanitize_sensitive_data(self, text: str) -> str:
        """Remove or hash sensitive information from text"""
        if not text:
            return text
            
        # Hash IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        text = re.sub(ip_pattern, lambda m: f"IP_{hashlib.md5(m.group().encode()).hexdigest()[:8]}", text)
        
        # Hash email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        text = re.sub(email_pattern, lambda m: f"EMAIL_{hashlib.md5(m.group().encode()).hexdigest()[:8]}", text)
        
        # Hash domain names
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        text = re.sub(domain_pattern, lambda m: f"DOMAIN_{hashlib.md5(m.group().encode()).hexdigest()[:8]}", text)
        
        # Hash file paths
        path_pattern = r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
        text = re.sub(path_pattern, lambda m: f"PATH_{hashlib.md5(m.group().encode()).hexdigest()[:8]}", text)
        
        # Hash usernames (common patterns)
        username_pattern = r'\buser[_-]?(?:name)?[:\s=]*([a-zA-Z0-9_.-]+)\b'
        text = re.sub(username_pattern, lambda m: f"USER_{hashlib.md5(m.group(1).encode()).hexdigest()[:8]}", text, flags=re.IGNORECASE)
        
        # Hash passwords (if accidentally logged)
        password_pattern = r'\bpass(?:word)?[:\s=]*([^\s]+)\b'
        text = re.sub(password_pattern, "PASS_[REDACTED]", text, flags=re.IGNORECASE)
        
        # Hash API keys/tokens
        token_pattern = r'\b(?:token|key|secret)[:\s=]*([a-zA-Z0-9_.-]{16,})\b'
        text = re.sub(token_pattern, "TOKEN_[REDACTED]", text, flags=re.IGNORECASE)
        
        return text
    
    def extract_agent_logs(self, days_back=30) -> List[Dict]:
        """Extract sanitized agent logs for training"""
        logger.info(f"Extracting agent logs from last {days_back} days...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            
            # Calculate date threshold
            date_threshold = datetime.now() - timedelta(days=days_back)
            
            # Query agent logs
            query = """
            SELECT 
                agent_id,
                log_type,
                log_data,
                timestamp,
                severity
            FROM agent_logs 
            WHERE timestamp >= ? 
            ORDER BY timestamp DESC
            """
            
            cursor = conn.execute(query, (date_threshold.isoformat(),))
            logs = []
            
            for row in cursor.fetchall():
                log_entry = {
                    "agent_id": f"AGENT_{hashlib.md5(row['agent_id'].encode()).hexdigest()[:8]}",
                    "log_type": row['log_type'],
                    "log_data": self._sanitize_sensitive_data(row['log_data']),
                    "timestamp": row['timestamp'],
                    "severity": row['severity']
                }
                logs.append(log_entry)
            
            conn.close()
            logger.info(f"Extracted {len(logs)} sanitized log entries")
            return logs
            
        except Exception as e:
            logger.error(f"Error extracting agent logs: {e}")
            return []
    
    def extract_attack_scenarios(self) -> List[Dict]:
        """Extract attack scenario data for training"""
        logger.info("Extracting attack scenario data...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            
            query = """
            SELECT 
                command_id,
                agent_id,
                command_type,
                command_data,
                result_data,
                status,
                created_at,
                completed_at
            FROM agent_commands 
            WHERE command_type LIKE '%attack%' OR command_type LIKE '%scenario%'
            ORDER BY created_at DESC
            """
            
            cursor = conn.execute(query)
            scenarios = []
            
            for row in cursor.fetchall():
                scenario = {
                    "command_id": f"CMD_{hashlib.md5(row['command_id'].encode()).hexdigest()[:8]}",
                    "agent_id": f"AGENT_{hashlib.md5(row['agent_id'].encode()).hexdigest()[:8]}",
                    "command_type": row['command_type'],
                    "command_data": self._sanitize_sensitive_data(row['command_data']),
                    "result_data": self._sanitize_sensitive_data(row['result_data']) if row['result_data'] else None,
                    "status": row['status'],
                    "created_at": row['created_at'],
                    "completed_at": row['completed_at']
                }
                scenarios.append(scenario)
            
            conn.close()
            logger.info(f"Extracted {len(scenarios)} attack scenarios")
            return scenarios
            
        except Exception as e:
            logger.error(f"Error extracting attack scenarios: {e}")
            return []
    
    def extract_detection_results(self, days_back=30) -> List[Dict]:
        """Extract detection results for training"""
        logger.info(f"Extracting detection results from last {days_back} days...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            
            date_threshold = datetime.now() - timedelta(days=days_back)
            
            # This would query from a detections table (you may need to add this to schema)
            query = """
            SELECT 
                agent_id,
                log_type,
                log_data,
                timestamp
            FROM agent_logs 
            WHERE log_type IN ('detection', 'threat', 'alert', 'malware', 'suspicious')
            AND timestamp >= ?
            ORDER BY timestamp DESC
            """
            
            cursor = conn.execute(query, (date_threshold.isoformat(),))
            detections = []
            
            for row in cursor.fetchall():
                detection = {
                    "agent_id": f"AGENT_{hashlib.md5(row['agent_id'].encode()).hexdigest()[:8]}",
                    "detection_type": row['log_type'],
                    "detection_data": self._sanitize_sensitive_data(row['log_data']),
                    "timestamp": row['timestamp']
                }
                detections.append(detection)
            
            conn.close()
            logger.info(f"Extracted {len(detections)} detection results")
            return detections
            
        except Exception as e:
            logger.error(f"Error extracting detection results: {e}")
            return []
    
    def extract_ai_reasoning_data(self, days_back=30) -> List[Dict]:
        """Extract AI reasoning and chat data for training"""
        logger.info(f"Extracting AI reasoning data from last {days_back} days...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            
            date_threshold = datetime.now() - timedelta(days=days_back)
            
            query = """
            SELECT 
                command_id,
                agent_id,
                command_data,
                result_data,
                created_at
            FROM agent_commands 
            WHERE command_type IN ('ai_chat', 'reasoning', 'analysis')
            AND created_at >= ?
            ORDER BY created_at DESC
            """
            
            cursor = conn.execute(query, (date_threshold.isoformat(),))
            reasoning_data = []
            
            for row in cursor.fetchall():
                try:
                    command_data = json.loads(row['command_data']) if row['command_data'] else {}
                    result_data = json.loads(row['result_data']) if row['result_data'] else {}
                    
                    reasoning_entry = {
                        "command_id": f"CMD_{hashlib.md5(row['command_id'].encode()).hexdigest()[:8]}",
                        "agent_id": f"AGENT_{hashlib.md5(row['agent_id'].encode()).hexdigest()[:8]}",
                        "user_query": self._sanitize_sensitive_data(command_data.get('message', '')),
                        "ai_response": self._sanitize_sensitive_data(result_data.get('response', '')),
                        "timestamp": row['created_at']
                    }
                    reasoning_data.append(reasoning_entry)
                except json.JSONDecodeError:
                    continue
            
            conn.close()
            logger.info(f"Extracted {len(reasoning_data)} AI reasoning interactions")
            return reasoning_data
            
        except Exception as e:
            logger.error(f"Error extracting AI reasoning data: {e}")
            return []
    
    def generate_training_datasets(self, days_back=30):
        """Generate complete training datasets"""
        logger.info("🚀 Starting training data extraction...")
        
        # Extract all data types
        agent_logs = self.extract_agent_logs(days_back)
        attack_scenarios = self.extract_attack_scenarios()
        detection_results = self.extract_detection_results(days_back)
        ai_reasoning = self.extract_ai_reasoning_data(days_back)
        
        # Save datasets
        datasets = {
            "agent_logs": agent_logs,
            "attack_scenarios": attack_scenarios,
            "detection_results": detection_results,
            "ai_reasoning": ai_reasoning
        }
        
        for dataset_name, data in datasets.items():
            if data:
                filename = f"{self.output_dir}/{dataset_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
                logger.info(f"✅ Saved {len(data)} records to {filename}")
        
        # Generate training summary
        summary = {
            "extraction_date": datetime.now().isoformat(),
            "days_extracted": days_back,
            "total_records": sum(len(data) for data in datasets.values()),
            "datasets": {name: len(data) for name, data in datasets.items()},
            "sanitization_applied": [
                "IP addresses hashed",
                "Email addresses hashed", 
                "Domain names hashed",
                "File paths hashed",
                "Usernames hashed",
                "Passwords redacted",
                "API keys/tokens redacted"
            ]
        }
        
        summary_file = f"{self.output_dir}/extraction_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info("🎯 Training data extraction complete!")
        logger.info(f"📊 Total records extracted: {summary['total_records']}")
        logger.info(f"📁 Files saved to: {self.output_dir}/")
        
        return summary

if __name__ == "__main__":
    extractor = SOCDataExtractor()
    
    # Extract data from last 30 days
    summary = extractor.generate_training_datasets(days_back=30)
    
    print("\n" + "="*60)
    print("🤖 LLM TRAINING DATA EXTRACTION COMPLETE")
    print("="*60)
    print(f"📊 Total Records: {summary['total_records']}")
    print(f"📅 Date Range: Last {summary['days_extracted']} days")
    print(f"📁 Output Directory: {extractor.output_dir}/")
    print("\n🔒 All sensitive data has been sanitized:")
    for item in summary['sanitization_applied']:
        print(f"  ✅ {item}")
    print("\n🎯 Ready for LLM training!")