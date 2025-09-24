#!/usr/bin/env python3
"""
CodeGrey SOC - PostgreSQL Multi-Tenant Agent Manager
Adapted for PostgreSQL infrastructure instead of SQLite
"""

import psycopg2
import psycopg2.extras
import json
import os
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import uuid

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TenantContext:
    """Represents tenant context for multi-tenant operations"""
    def __init__(self, organization_id: str, api_key: str):
        self.organization_id = organization_id
        self.api_key = api_key

class PostgreSQLAgentManager:
    """Multi-tenant agent manager using PostgreSQL"""
    
    def __init__(self, db_config: Dict[str, str] = None):
        """Initialize with PostgreSQL connection parameters"""
        self.db_config = db_config or {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': os.getenv('DB_PORT', '5432'),
            'database': os.getenv('DB_NAME', 'codegrey_soc'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD', 'password')
        }
        
        self.lock = threading.Lock()
        self._init_database()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _get_connection(self):
        """Get PostgreSQL database connection"""
        try:
            conn = psycopg2.connect(**self.db_config)
            conn.autocommit = True
            return conn
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise
    
    def _init_database(self):
        """Initialize PostgreSQL database with schema"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Read and execute PostgreSQL schema
            schema_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'postgresql_schema.sql')
            if os.path.exists(schema_path):
                with open(schema_path, 'r') as f:
                    schema = f.read()
                
                # Execute schema
                cursor.execute(schema)
                logger.info("PostgreSQL database schema initialized successfully")
            else:
                logger.warning("PostgreSQL schema file not found, using existing database")
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL database: {e}")
            raise
    
    def validate_tenant_context(self, api_key: str) -> Optional[TenantContext]:
        """Validate API key and return tenant context"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            cursor.execute(
                "SELECT id, name FROM organizations WHERE api_key = %s AND status = 'active'",
                (api_key,)
            )
            
            org = cursor.fetchone()
            conn.close()
            
            if org:
                return TenantContext(org['id'], api_key)
            return None
            
        except Exception as e:
            logger.error(f"Error validating tenant context: {e}")
            return None
    
    def register_agent(self, tenant_context: TenantContext, agent_data: Dict[str, Any]) -> str:
        """Register a new agent for the tenant"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            agent_id = agent_data.get('id') or str(uuid.uuid4())
            
            # Extract network detection data
            network_characteristics = agent_data.get('network_characteristics', {})
            user_role_info = agent_data.get('user_role_info', {})
            
            cursor.execute("""
                INSERT INTO agents (
                    id, organization_id, name, type, hostname, ip_address, 
                    status, version, capabilities, network_element_type,
                    network_role, security_zone, subnet, element_confidence,
                    network_characteristics, detected_services, open_ports,
                    user_role_info, username, user_groups, is_admin,
                    domain_info, classified_roles, role_confidence,
                    first_seen, last_heartbeat
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (id) DO UPDATE SET
                    last_heartbeat = EXCLUDED.last_heartbeat,
                    status = EXCLUDED.status,
                    network_characteristics = EXCLUDED.network_characteristics,
                    user_role_info = EXCLUDED.user_role_info
            """, (
                agent_id,
                tenant_context.organization_id,
                agent_data.get('name', f'Agent-{agent_id[:8]}'),
                agent_data.get('type', 'unknown'),
                agent_data.get('hostname'),
                agent_data.get('ip_address'),
                'online',
                agent_data.get('version', '1.0.0'),
                json.dumps(agent_data.get('capabilities', [])),
                network_characteristics.get('network_element_type'),
                network_characteristics.get('network_role'),
                network_characteristics.get('security_zone'),
                network_characteristics.get('subnet'),
                network_characteristics.get('element_confidence', 0.0),
                json.dumps(network_characteristics),
                json.dumps(network_characteristics.get('detected_services', [])),
                json.dumps(network_characteristics.get('open_ports', [])),
                json.dumps(user_role_info),
                user_role_info.get('username'),
                json.dumps(user_role_info.get('user_groups', [])),
                user_role_info.get('is_admin', False),
                user_role_info.get('domain_info'),
                json.dumps(user_role_info.get('classified_roles', [])),
                user_role_info.get('role_confidence', 0.0),
                datetime.now(),
                datetime.now()
            ))
            
            conn.close()
            logger.info(f"Agent {agent_id} registered for tenant {tenant_context.organization_id}")
            return agent_id
            
        except Exception as e:
            logger.error(f"Error registering agent: {e}")
            raise
    
    def get_agents(self, tenant_context: TenantContext, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get all agents for the tenant with optional filters"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            query = """
                SELECT 
                    id, name, type, hostname, ip_address, status, version,
                    capabilities, network_element_type, network_role, 
                    security_zone, user_role_info, username, is_admin,
                    classified_roles, role_confidence, first_seen, last_heartbeat,
                    EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) as seconds_since_heartbeat
                FROM agents 
                WHERE organization_id = %s
            """
            params = [tenant_context.organization_id]
            
            # Apply filters
            if filters:
                if filters.get('status'):
                    query += " AND status = %s"
                    params.append(filters['status'])
                if filters.get('type'):
                    query += " AND type = %s"
                    params.append(filters['type'])
                if filters.get('hostname'):
                    query += " AND hostname ILIKE %s"
                    params.append(f"%{filters['hostname']}%")
            
            query += " ORDER BY name"
            
            cursor.execute(query, params)
            agents = cursor.fetchall()
            
            # Convert to list of dicts and add calculated fields
            result = []
            for agent in agents:
                agent_dict = dict(agent)
                
                # Parse JSON fields
                agent_dict['capabilities'] = json.loads(agent_dict['capabilities'] or '[]')
                agent_dict['user_role_info'] = json.loads(agent_dict['user_role_info'] or '{}')
                agent_dict['classified_roles'] = json.loads(agent_dict['classified_roles'] or '[]')
                
                # Calculate last activity
                seconds_ago = agent_dict.get('seconds_since_heartbeat', 0)
                if seconds_ago < 60:
                    agent_dict['lastActivity'] = "Now"
                elif seconds_ago < 3600:
                    agent_dict['lastActivity'] = f"{int(seconds_ago/60)} mins ago"
                else:
                    agent_dict['lastActivity'] = f"{int(seconds_ago/3600)} hours ago"
                
                # Add location based on network element
                network_element = agent_dict.get('network_element_type', 'unknown')
                location_map = {
                    'internet': 'External Network',
                    'dmz': 'DMZ Segment', 
                    'internal': 'Internal Network',
                    'datacenter': 'Data Center',
                    'endpoint': 'Endpoint',
                    'soc_platform': 'SOC Infrastructure',
                    'firewall': 'Network Perimeter'
                }
                agent_dict['location'] = location_map.get(network_element, 'Unknown Location')
                
                result.append(agent_dict)
            
            conn.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting agents: {e}")
            return []
    
    def get_agent_by_id(self, tenant_context: TenantContext, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get specific agent by ID"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            cursor.execute("""
                SELECT * FROM agents 
                WHERE id = %s AND organization_id = %s
            """, (agent_id, tenant_context.organization_id))
            
            agent = cursor.fetchone()
            conn.close()
            
            if agent:
                agent_dict = dict(agent)
                # Parse JSON fields
                agent_dict['capabilities'] = json.loads(agent_dict['capabilities'] or '[]')
                agent_dict['network_characteristics'] = json.loads(agent_dict['network_characteristics'] or '{}')
                agent_dict['user_role_info'] = json.loads(agent_dict['user_role_info'] or '{}')
                agent_dict['detected_services'] = json.loads(agent_dict['detected_services'] or '[]')
                agent_dict['open_ports'] = json.loads(agent_dict['open_ports'] or '[]')
                agent_dict['classified_roles'] = json.loads(agent_dict['classified_roles'] or '[]')
                agent_dict['user_groups'] = json.loads(agent_dict['user_groups'] or '[]')
                return agent_dict
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting agent {agent_id}: {e}")
            return None
    
    def store_agent_logs(self, tenant_context: TenantContext, agent_id: str, logs: List[Dict[str, Any]]) -> bool:
        """Store agent logs in PostgreSQL (critical for ML training)"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            for log_entry in logs:
                cursor.execute("""
                    INSERT INTO agent_logs (
                        organization_id, agent_id, log_type, log_data,
                        raw_log_text, timestamp, severity
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    tenant_context.organization_id,
                    agent_id,
                    log_entry.get('type', 'system'),
                    json.dumps(log_entry.get('data', {})),
                    log_entry.get('raw_text', ''),
                    log_entry.get('timestamp', datetime.now()),
                    log_entry.get('severity', 'info')
                ))
            
            conn.close()
            logger.info(f"Stored {len(logs)} log entries for agent {agent_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing agent logs: {e}")
            return False
    
    def create_command(self, tenant_context: TenantContext, agent_id: str, command_data: Dict[str, Any]) -> str:
        """Create a command for an agent"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            command_id = str(uuid.uuid4())
            
            cursor.execute("""
                INSERT INTO agent_commands (
                    id, organization_id, agent_id, command_type,
                    command_data, priority, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                command_id,
                tenant_context.organization_id,
                agent_id,
                command_data.get('type', 'unknown'),
                json.dumps(command_data),
                command_data.get('priority', 'normal'),
                'pending'
            ))
            
            conn.close()
            return command_id
            
        except Exception as e:
            logger.error(f"Error creating command: {e}")
            raise
    
    def get_statistics(self, tenant_context: TenantContext) -> Dict[str, Any]:
        """Get agent statistics for the tenant"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get basic counts
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN status = 'online' THEN 1 END) as online,
                    COUNT(CASE WHEN status = 'offline' THEN 1 END) as offline
                FROM agents WHERE organization_id = %s
            """, (tenant_context.organization_id,))
            
            basic_stats = cursor.fetchone()
            
            # Get type breakdown
            cursor.execute("""
                SELECT type, COUNT(*) as count
                FROM agents 
                WHERE organization_id = %s
                GROUP BY type
            """, (tenant_context.organization_id,))
            
            type_breakdown = {row[0]: row[1] for row in cursor.fetchall()}
            
            conn.close()
            
            return {
                "total": basic_stats[0],
                "online": basic_stats[1], 
                "offline": basic_stats[2],
                "by_type": type_breakdown,
                "by_status": {
                    "online": basic_stats[1],
                    "offline": basic_stats[2]
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        def cleanup_old_logs():
            """Clean up old logs (keep last 90 days)"""
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                cutoff_date = datetime.now() - timedelta(days=90)
                cursor.execute(
                    "DELETE FROM agent_logs WHERE timestamp < %s",
                    (cutoff_date,)
                )
                
                conn.close()
                logger.info("Cleaned up old agent logs")
                
            except Exception as e:
                logger.error(f"Error cleaning up logs: {e}")
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=cleanup_old_logs, daemon=True)
        cleanup_thread.start()

# Global instance
postgresql_agent_manager = PostgreSQLAgentManager()


