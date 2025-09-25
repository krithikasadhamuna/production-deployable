#!/usr/bin/env python3
"""
Client Agent Log Processing API
Handles log reception, storage, and processing from client agents
No hardcoded values, fully configurable
"""

import sqlite3
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from flask import request, jsonify
from config.settings import config

logger = logging.getLogger(__name__)

class ClientAgentLogProcessor:
    """Processes logs from client agents and stores them in database"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.config = config
        
    def receive_agent_logs(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process logs received from client agent
        
        Args:
            request_data: {
                "endpoint_id": "string",
                "logs": [
                    {
                        "timestamp": "ISO_timestamp",
                        "level": "INFO|WARN|ERROR|DEBUG",
                        "source": "process_monitor|file_monitor|network_monitor|security_log",
                        "message": "log_message",
                        "metadata": {
                            "process_id": "integer",
                            "process_name": "string",
                            "file_path": "string",
                            "file_hash": "string",
                            "network_src": "ip_address",
                            "network_dst": "ip_address",
                            "network_port": "integer",
                            "user": "username",
                            "command_line": "string"
                        }
                    }
                ]
            }
            
        Returns:
            {
                "success": boolean,
                "logs_processed": integer,
                "logs_queued_for_analysis": integer,
                "processing_errors": []
            }
        """
        try:
            endpoint_id = request_data.get('endpoint_id')
            logs = request_data.get('logs', [])
            
            if not endpoint_id:
                return {
                    'success': False,
                    'error': 'endpoint_id is required',
                    'error_code': 'MISSING_ENDPOINT_ID'
                }
            
            if not logs:
                return {
                    'success': False,
                    'error': 'logs array is required',
                    'error_code': 'MISSING_LOGS'
                }
            
            # Verify endpoint exists
            if not self._verify_endpoint_exists(endpoint_id):
                return {
                    'success': False,
                    'error': 'Endpoint not registered',
                    'error_code': 'ENDPOINT_NOT_FOUND'
                }
            
            # Process and store logs
            processed_count = 0
            queued_count = 0
            processing_errors = []
            
            for log_entry in logs:
                try:
                    log_id = self._store_log_entry(endpoint_id, log_entry)
                    if log_id:
                        processed_count += 1
                        
                        # Queue for AI analysis if needed
                        if self._should_analyze_log(log_entry):
                            self._queue_for_analysis(log_id, log_entry)
                            queued_count += 1
                            
                except Exception as e:
                    processing_errors.append({
                        'log_index': logs.index(log_entry),
                        'error': str(e)
                    })
                    logger.error(f"Error processing log entry: {e}")
            
            # Update endpoint last seen
            self._update_endpoint_activity(endpoint_id)
            
            return {
                'success': True,
                'logs_processed': processed_count,
                'logs_queued_for_analysis': queued_count,
                'processing_errors': processing_errors,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in receive_agent_logs: {e}")
            return {
                'success': False,
                'error': 'Internal processing error',
                'error_code': 'INTERNAL_ERROR'
            }
    
    def _verify_endpoint_exists(self, endpoint_id: str) -> bool:
        """Verify that the endpoint is registered"""
        try:
            endpoints = self.db_manager.execute_query(
                'topology',
                'SELECT id FROM endpoints WHERE id = ?',
                (endpoint_id,)
            )
            return len(endpoints) > 0
        except Exception as e:
            logger.error(f"Error verifying endpoint: {e}")
            return False
    
    def _store_log_entry(self, endpoint_id: str, log_entry: Dict[str, Any]) -> Optional[str]:
        """Store individual log entry in database"""
        try:
            log_id = f"log_{uuid.uuid4().hex[:12]}"
            
            # Extract log data
            timestamp = log_entry.get('timestamp', datetime.now().isoformat())
            level = log_entry.get('level', 'INFO')
            source = log_entry.get('source', 'unknown')
            message = log_entry.get('message', '')
            metadata = log_entry.get('metadata', {})
            
            # Store in database
            self.db_manager.execute_insert('logs', '''
                INSERT INTO agent_logs (
                    id, endpoint_id, timestamp, log_level, source, message, 
                    raw_data, metadata, file_hash, process_id, parent_process_id,
                    command_line, network_connection
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_id,
                endpoint_id,
                timestamp,
                level,
                source,
                message,
                json.dumps(log_entry),
                json.dumps(metadata),
                metadata.get('file_hash'),
                metadata.get('process_id'),
                metadata.get('parent_process_id'),
                metadata.get('command_line'),
                json.dumps({
                    'src': metadata.get('network_src'),
                    'dst': metadata.get('network_dst'),
                    'port': metadata.get('network_port')
                }) if any(k in metadata for k in ['network_src', 'network_dst', 'network_port']) else None
            ))
            
            return log_id
            
        except Exception as e:
            logger.error(f"Error storing log entry: {e}")
            return None
    
    def _should_analyze_log(self, log_entry: Dict[str, Any]) -> bool:
        """Determine if log should be queued for AI analysis"""
        # Analysis criteria
        high_priority_sources = ['security_log', 'process_monitor']
        high_priority_levels = ['ERROR', 'WARN']
        
        source = log_entry.get('source', '')
        level = log_entry.get('level', '')
        message = log_entry.get('message', '').lower()
        
        # Always analyze security logs and errors
        if source in high_priority_sources or level in high_priority_levels:
            return True
        
        # Analyze logs with suspicious keywords
        suspicious_keywords = [
            'failed', 'error', 'denied', 'unauthorized', 'suspicious',
            'malware', 'virus', 'trojan', 'exploit', 'attack',
            'powershell', 'cmd.exe', 'wscript', 'cscript'
        ]
        
        if any(keyword in message for keyword in suspicious_keywords):
            return True
        
        # Analyze process creation logs
        if 'process' in source and 'created' in message:
            return True
        
        return False
    
    def _queue_for_analysis(self, log_id: str, log_entry: Dict[str, Any]) -> None:
        """Queue log for AI analysis"""
        try:
            queue_id = f"queue_{uuid.uuid4().hex[:12]}"
            
            # Determine priority based on log characteristics
            priority = self._calculate_analysis_priority(log_entry)
            
            self.db_manager.execute_insert('logs', '''
                INSERT INTO log_processing_queue (
                    id, log_id, priority, status, created_at
                ) VALUES (?, ?, ?, ?, ?)
            ''', (
                queue_id,
                log_id,
                priority,
                'pending',
                datetime.now().isoformat()
            ))
            
        except Exception as e:
            logger.error(f"Error queuing log for analysis: {e}")
    
    def _calculate_analysis_priority(self, log_entry: Dict[str, Any]) -> int:
        """Calculate analysis priority (1=highest, 10=lowest)"""
        level = log_entry.get('level', 'INFO')
        source = log_entry.get('source', '')
        message = log_entry.get('message', '').lower()
        
        # High priority (1-3)
        if level == 'ERROR' or 'security' in source:
            return 1
        
        if level == 'WARN' or any(word in message for word in ['failed', 'denied', 'suspicious']):
            return 2
        
        if 'process' in source or 'network' in source:
            return 3
        
        # Medium priority (4-6)
        if level == 'INFO' and any(word in message for word in ['login', 'logout', 'access']):
            return 4
        
        # Low priority (7-10)
        return 7
    
    def _update_endpoint_activity(self, endpoint_id: str) -> None:
        """Update endpoint last seen timestamp"""
        try:
            self.db_manager.execute_update('topology', '''
                UPDATE endpoints 
                SET last_seen = ?, status = 'online'
                WHERE id = ?
            ''', (datetime.now().isoformat(), endpoint_id))
            
        except Exception as e:
            logger.error(f"Error updating endpoint activity: {e}")
    
    def get_endpoint_logs(self, endpoint_id: str, limit: int = 100, 
                         level_filter: Optional[str] = None,
                         source_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Retrieve logs for specific endpoint
        
        Args:
            endpoint_id: Endpoint identifier
            limit: Maximum number of logs to return
            level_filter: Filter by log level (INFO, WARN, ERROR, DEBUG)
            source_filter: Filter by log source
            
        Returns:
            {
                "success": boolean,
                "logs": [
                    {
                        "id": "string",
                        "timestamp": "ISO_timestamp",
                        "level": "string",
                        "source": "string",
                        "message": "string",
                        "processed": boolean,
                        "threat_score": float,
                        "classification": "string"
                    }
                ],
                "total_count": integer,
                "filtered": boolean
            }
        """
        try:
            # Build query with filters
            query = '''
                SELECT id, timestamp, log_level, source, message, 
                       processed, threat_score, classification
                FROM agent_logs 
                WHERE endpoint_id = ?
            '''
            params = [endpoint_id]
            
            if level_filter:
                query += ' AND log_level = ?'
                params.append(level_filter)
            
            if source_filter:
                query += ' AND source = ?'
                params.append(source_filter)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            logs = self.db_manager.execute_query('logs', query, tuple(params))
            
            # Get total count
            count_query = 'SELECT COUNT(*) FROM agent_logs WHERE endpoint_id = ?'
            count_params = [endpoint_id]
            
            if level_filter:
                count_query += ' AND log_level = ?'
                count_params.append(level_filter)
            
            if source_filter:
                count_query += ' AND source = ?'
                count_params.append(source_filter)
            
            total_result = self.db_manager.execute_query('logs', count_query, tuple(count_params))
            total_count = total_result[0][0] if total_result else 0
            
            # Format response
            formatted_logs = []
            for log in logs:
                formatted_logs.append({
                    'id': log['id'],
                    'timestamp': log['timestamp'],
                    'level': log['log_level'],
                    'source': log['source'],
                    'message': log['message'],
                    'processed': bool(log['processed']),
                    'threat_score': log['threat_score'] or 0.0,
                    'classification': log['classification']
                })
            
            return {
                'success': True,
                'logs': formatted_logs,
                'total_count': total_count,
                'filtered': bool(level_filter or source_filter),
                'endpoint_id': endpoint_id
            }
            
        except Exception as e:
            logger.error(f"Error retrieving endpoint logs: {e}")
            return {
                'success': False,
                'error': 'Failed to retrieve logs',
                'error_code': 'RETRIEVAL_ERROR'
            }
    
    def get_processing_queue_status(self) -> Dict[str, Any]:
        """
        Get current log processing queue status
        
        Returns:
            {
                "success": boolean,
                "queue_stats": {
                    "pending": integer,
                    "processing": integer,
                    "completed": integer,
                    "failed": integer
                },
                "oldest_pending": "ISO_timestamp",
                "processing_rate": float
            }
        """
        try:
            # Get queue statistics
            stats_query = '''
                SELECT status, COUNT(*) as count
                FROM log_processing_queue
                GROUP BY status
            '''
            stats = self.db_manager.execute_query('logs', stats_query)
            
            queue_stats = {
                'pending': 0,
                'processing': 0,
                'completed': 0,
                'failed': 0
            }
            
            for stat in stats:
                queue_stats[stat['status']] = stat['count']
            
            # Get oldest pending item
            oldest_query = '''
                SELECT MIN(created_at) as oldest
                FROM log_processing_queue
                WHERE status = 'pending'
            '''
            oldest_result = self.db_manager.execute_query('logs', oldest_query)
            oldest_pending = oldest_result[0]['oldest'] if oldest_result and oldest_result[0]['oldest'] else None
            
            return {
                'success': True,
                'queue_stats': queue_stats,
                'oldest_pending': oldest_pending,
                'total_queued': sum(queue_stats.values())
            }
            
        except Exception as e:
            logger.error(f"Error getting queue status: {e}")
            return {
                'success': False,
                'error': 'Failed to get queue status',
                'error_code': 'QUEUE_STATUS_ERROR'
            }
