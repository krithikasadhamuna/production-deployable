#!/usr/bin/env python3
"""
Multi-Tenant Agent Manager for CodeGrey SOC Server
Handles agent registration, management, and operations with complete tenant isolation
"""

import sqlite3
import json
import uuid
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import threading
import time
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import network element detector
from .network_element_detector import network_element_detector, NetworkElement

@dataclass
class TenantContext:
    """Tenant context for all operations"""
    organization_id: str
    user_id: Optional[str] = None
    api_key_id: Optional[str] = None
    permissions: List[str] = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []

@dataclass
class Agent:
    """Agent data structure"""
    id: str
    organization_id: str
    agent_id: str
    name: str
    type: str
    hostname: str
    ip_address: str
    status: str
    last_heartbeat: datetime
    capabilities: List[str]
    metadata: Dict[str, Any]

class MultiTenantAgentManager:
    """
    Multi-tenant agent manager with complete tenant isolation
    """
    
    def __init__(self, db_path: str = "soc_multi_tenant.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _init_database(self):
        """Initialize multi-tenant database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            
            # Read and execute schema
            with open('database/multi_tenant_schema.sql', 'r') as f:
                schema = f.read()
            
            # Execute schema (handle multiple statements)
            for statement in schema.split(';'):
                statement = statement.strip()
                if statement and not statement.startswith('--'):
                    try:
                        conn.execute(statement)
                    except sqlite3.Error as e:
                        if "already exists" not in str(e):
                            logger.error(f"Schema error: {e}")
            
            conn.commit()
            conn.close()
            
            logger.info("Multi-tenant database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def _get_connection(self):
        """Get database connection with row factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    # ========================================================================
    # TENANT MANAGEMENT
    # ========================================================================
    
    def create_organization(self, name: str, domain: str = None, 
                          subdomain: str = None, settings: Dict = None,
                          limits: Dict = None) -> Dict[str, Any]:
        """Create new organization (tenant)"""
        try:
            org_id = str(uuid.uuid4())
            
            default_limits = {
                "max_agents": 100,
                "max_users": 50,
                "max_storage_gb": 10,
                "max_api_calls_per_minute": 1000
            }
            
            if limits:
                default_limits.update(limits)
            
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO organizations 
                    (id, name, domain, subdomain, settings, limits, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'active')
                """, [
                    org_id, name, domain, subdomain,
                    json.dumps(settings or {}),
                    json.dumps(default_limits)
                ])
                
                # Create default admin API key
                api_key = self._generate_api_key(org_id)
                
                conn.commit()
                
            logger.info(f"Created organization: {name} (ID: {org_id})")
            
            return {
                "organization_id": org_id,
                "name": name,
                "api_key": api_key,
                "domain": domain,
                "subdomain": subdomain,
                "limits": default_limits
            }
            
        except Exception as e:
            logger.error(f"Failed to create organization: {e}")
            raise
    
    def _generate_api_key(self, org_id: str) -> str:
        """Generate API key for organization"""
        key_id = str(uuid.uuid4())
        api_key = f"cg_{org_id[:8]}_{key_id[:8]}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO api_keys 
                (id, organization_id, key_hash, key_prefix, name, status)
                VALUES (?, ?, ?, ?, 'Default API Key', 'active')
            """, [key_id, org_id, key_hash, api_key[:10]])
            conn.commit()
        
        return api_key
    
    def validate_api_key(self, api_key: str) -> Optional[TenantContext]:
        """Validate API key and return tenant context"""
        try:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            with self._get_connection() as conn:
                result = conn.execute("""
                    SELECT ak.organization_id, ak.permissions, ak.id,
                           o.status as org_status, o.name as org_name
                    FROM api_keys ak
                    JOIN organizations o ON ak.organization_id = o.id
                    WHERE ak.key_hash = ? AND ak.status = 'active'
                    AND (ak.expires_at IS NULL OR ak.expires_at > datetime('now'))
                """, [key_hash]).fetchone()
                
                if not result:
                    return None
                
                if result['org_status'] != 'active':
                    logger.warning(f"API key used for inactive org: {result['org_name']}")
                    return None
                
                # Update last used timestamp
                conn.execute("""
                    UPDATE api_keys 
                    SET last_used = datetime('now'), usage_count = usage_count + 1
                    WHERE id = ?
                """, [result['id']])
                conn.commit()
                
                return TenantContext(
                    organization_id=result['organization_id'],
                    api_key_id=result['id'],
                    permissions=json.loads(result['permissions'] or '[]')
                )
                
        except Exception as e:
            logger.error(f"API key validation error: {e}")
            return None
    
    # ========================================================================
    # TENANT-SCOPED AGENT MANAGEMENT
    # ========================================================================
    
    async def register_agent(self, tenant_context: TenantContext, agent_data: Dict) -> str:
        """Register new agent for specific tenant with network element detection"""
        try:
            agent_id = str(uuid.uuid4())
            
            # Detect network element type
            logger.info(f"Detecting network element type for agent {agent_data.get('hostname', 'unknown')}")
            network_element = await network_element_detector.detect_network_element(agent_data)
            
            with self._get_connection() as conn:
                # Check agent limits for this tenant
                current_count = conn.execute("""
                    SELECT COUNT(*) as count FROM agents 
                    WHERE organization_id = ?
                """, [tenant_context.organization_id]).fetchone()['count']
                
                # Get tenant limits
                limits = conn.execute("""
                    SELECT limits FROM organizations 
                    WHERE id = ?
                """, [tenant_context.organization_id]).fetchone()
                
                if limits:
                    max_agents = json.loads(limits['limits']).get('max_agents', 100)
                    if current_count >= max_agents:
                        raise ValueError(f"Agent limit exceeded: {current_count}/{max_agents}")
                
                # Extract user role information
                user_role_info = agent_data.get('user_role_info', {})
                username = user_role_info.get('username')
                user_groups = user_role_info.get('groups', [])
                is_admin = user_role_info.get('is_admin', False)
                domain_info = user_role_info.get('domain_info', {})
                classified_roles = user_role_info.get('classified_roles', ['Standard_User'])
                
                # Calculate role confidence based on available data
                role_confidence = 0.5  # Default
                if domain_info and not domain_info.get('error'):
                    role_confidence += 0.3
                if user_groups:
                    role_confidence += 0.2
                role_confidence = min(role_confidence, 1.0)
                
                # Register agent with network element data and user role information
                conn.execute("""
                    INSERT INTO agents (
                        id, organization_id, agent_id, name, type, hostname, 
                        ip_address, os_info, version, status, capabilities, 
                        metadata, first_seen, last_heartbeat,
                        network_element_type, network_role, security_zone,
                        subnet, element_confidence, network_characteristics,
                        detected_services, open_ports, network_topology_level,
                        last_network_scan, user_role_info, username, user_groups,
                        is_admin, domain_info, classified_roles, role_confidence,
                        role_last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, 
                             datetime('now'), datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'),
                             ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """, [
                    agent_id,
                    tenant_context.organization_id,
                    agent_data.get('agent_id', agent_id),
                    agent_data.get('name'),
                    agent_data.get('type'),
                    agent_data.get('hostname'),
                    agent_data.get('ip_address'),
                    json.dumps(agent_data.get('os_info', {})),
                    agent_data.get('version'),
                    json.dumps(agent_data.get('capabilities', [])),
                    json.dumps(agent_data.get('metadata', {})),
                    network_element.element_type,
                    network_element.network_role,
                    network_element.security_zone,
                    network_element.subnet,
                    network_element.confidence,
                    json.dumps(network_element.characteristics),
                    json.dumps(network_element.services),
                    json.dumps(agent_data.get('open_ports', [])),
                    self._determine_topology_level(network_element.element_type),
                    json.dumps(user_role_info),
                    username,
                    json.dumps(user_groups),
                    is_admin,
                    json.dumps(domain_info),
                    json.dumps(classified_roles),
                    role_confidence
                ])
                
                conn.commit()
                
            logger.info(f"Registered agent {agent_id} as {network_element.element_type} "
                       f"(confidence: {network_element.confidence:.2f}) for tenant {tenant_context.organization_id}")
            return agent_id
            
        except Exception as e:
            logger.error(f"Failed to register agent: {e}")
            raise
    
    def _determine_topology_level(self, element_type: str) -> int:
        """Determine network topology level based on element type"""
        level_mapping = {
            "internet": 0,
            "cloud": 0,
            "firewall": 1,
            "dmz": 1,
            "soc": 2,
            "datacenter": 2,
            "domain_controller": 2,
            "internal": 2,
            "endpoint": 3,
            "workstation": 3
        }
        return level_mapping.get(element_type, 3)
    
    def get_agents(self, tenant_context: TenantContext, 
                   filters: Dict = None) -> List[Dict]:
        """Get all agents for specific tenant"""
        try:
            query = """
                SELECT * FROM agents 
                WHERE organization_id = ?
            """
            params = [tenant_context.organization_id]
            
            # Apply filters
            if filters:
                if filters.get('status'):
                    query += " AND status = ?"
                    params.append(filters['status'])
                
                if filters.get('type'):
                    query += " AND type = ?"
                    params.append(filters['type'])
                
                if filters.get('hostname'):
                    query += " AND hostname LIKE ?"
                    params.append(f"%{filters['hostname']}%")
            
            query += " ORDER BY last_heartbeat DESC"
            
            with self._get_connection() as conn:
                results = conn.execute(query, params).fetchall()
                
                agents = []
                for row in results:
                    agents.append({
                        "id": row['id'],
                        "name": row['name'] or f"{row['type']}-{row['hostname']}",
                        "type": row['type'],
                        "status": row['status'],
                        "location": row['hostname'] or "Unknown",
                        "lastActivity": self._format_last_activity(row['last_heartbeat']),
                        "capabilities": json.loads(row['capabilities'] or '[]'),
                        "hostname": row['hostname'],
                        "ip_address": row['ip_address'],
                        "os_info": json.loads(row['os_info'] or '{}'),
                        "version": row['version'],
                        "first_seen": row['first_seen'],
                        "metadata": json.loads(row['metadata'] or '{}')
                    })
                
                return agents
                
        except Exception as e:
            logger.error(f"Failed to get agents: {e}")
            return []
    
    def get_agent_by_id(self, tenant_context: TenantContext, 
                       agent_id: str) -> Optional[Dict]:
        """Get specific agent for tenant"""
        try:
            with self._get_connection() as conn:
                result = conn.execute("""
                    SELECT * FROM agents 
                    WHERE id = ? AND organization_id = ?
                """, [agent_id, tenant_context.organization_id]).fetchone()
                
                if not result:
                    return None
                
                return {
                    "id": result['id'],
                    "name": result['name'],
                    "type": result['type'],
                    "status": result['status'],
                    "location": result['hostname'],
                    "lastActivity": self._format_last_activity(result['last_heartbeat']),
                    "capabilities": json.loads(result['capabilities'] or '[]'),
                    "hostname": result['hostname'],
                    "ip_address": result['ip_address'],
                    "os_info": json.loads(result['os_info'] or '{}'),
                    "version": result['version'],
                    "first_seen": result['first_seen'],
                    "metadata": json.loads(result['metadata'] or '{}')
                }
                
        except Exception as e:
            logger.error(f"Failed to get agent {agent_id}: {e}")
            return None
    
    def update_agent_heartbeat(self, tenant_context: TenantContext, 
                              agent_id: str, activity_data: Dict = None) -> bool:
        """Update agent heartbeat (tenant-scoped)"""
        try:
            with self._get_connection() as conn:
                # Verify agent belongs to tenant
                agent = conn.execute("""
                    SELECT id FROM agents 
                    WHERE id = ? AND organization_id = ?
                """, [agent_id, tenant_context.organization_id]).fetchone()
                
                if not agent:
                    logger.warning(f"Heartbeat for unknown agent {agent_id} from tenant {tenant_context.organization_id}")
                    return False
                
                # Update heartbeat
                conn.execute("""
                    UPDATE agents 
                    SET last_heartbeat = datetime('now'), 
                        status = CASE 
                            WHEN status = 'offline' THEN 'online'
                            ELSE status
                        END
                    WHERE id = ? AND organization_id = ?
                """, [agent_id, tenant_context.organization_id])
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update heartbeat for agent {agent_id}: {e}")
            return False
    
    # ========================================================================
    # TENANT-SCOPED COMMAND MANAGEMENT
    # ========================================================================
    
    def create_command(self, tenant_context: TenantContext, 
                      agent_id: str, command_data: Dict) -> str:
        """Create command for agent (tenant-scoped)"""
        try:
            command_id = str(uuid.uuid4())
            
            with self._get_connection() as conn:
                # Verify agent belongs to tenant
                agent = conn.execute("""
                    SELECT id FROM agents 
                    WHERE id = ? AND organization_id = ?
                """, [agent_id, tenant_context.organization_id]).fetchone()
                
                if not agent:
                    raise ValueError("Agent not found or access denied")
                
                # Create command
                conn.execute("""
                    INSERT INTO agent_commands (
                        id, organization_id, agent_id, command_type, 
                        command_data, status, created_by, priority
                    ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                """, [
                    command_id,
                    tenant_context.organization_id,
                    agent_id,
                    command_data.get('type', 'execute'),
                    json.dumps(command_data),
                    tenant_context.user_id,
                    command_data.get('priority', 'normal')
                ])
                
                conn.commit()
                
            logger.info(f"Created command {command_id} for agent {agent_id}")
            return command_id
            
        except Exception as e:
            logger.error(f"Failed to create command: {e}")
            raise
    
    def get_pending_commands(self, tenant_context: TenantContext, 
                           agent_id: str) -> List[Dict]:
        """Get pending commands for agent (tenant-scoped)"""
        try:
            with self._get_connection() as conn:
                results = conn.execute("""
                    SELECT * FROM agent_commands 
                    WHERE agent_id = ? AND organization_id = ? 
                    AND status IN ('pending', 'sent')
                    ORDER BY priority DESC, created_at ASC
                """, [agent_id, tenant_context.organization_id]).fetchall()
                
                commands = []
                for row in results:
                    commands.append({
                        "id": row['id'],
                        "type": row['command_type'],
                        "data": json.loads(row['command_data']),
                        "priority": row['priority'],
                        "created_at": row['created_at'],
                        "status": row['status']
                    })
                
                return commands
                
        except Exception as e:
            logger.error(f"Failed to get pending commands: {e}")
            return []
    
    def update_command_result(self, tenant_context: TenantContext,
                            command_id: str, result_data: Dict) -> bool:
        """Update command execution result (tenant-scoped)"""
        try:
            with self._get_connection() as conn:
                # Verify command belongs to tenant
                command = conn.execute("""
                    SELECT id FROM agent_commands 
                    WHERE id = ? AND organization_id = ?
                """, [command_id, tenant_context.organization_id]).fetchone()
                
                if not command:
                    logger.warning(f"Command result for unknown command {command_id}")
                    return False
                
                # Update result
                conn.execute("""
                    UPDATE agent_commands 
                    SET status = ?, result = ?, completed_at = datetime('now'),
                        execution_time_ms = ?
                    WHERE id = ? AND organization_id = ?
                """, [
                    result_data.get('status', 'completed'),
                    json.dumps(result_data),
                    result_data.get('execution_time_ms', 0),
                    command_id,
                    tenant_context.organization_id
                ])
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update command result: {e}")
            return False
    
    # ========================================================================
    # TENANT-SCOPED LOG MANAGEMENT
    # ========================================================================
    
    def store_agent_log(self, tenant_context: TenantContext,
                       agent_id: str, log_data: Dict) -> bool:
        """Store agent log (tenant-scoped)"""
        try:
            with self._get_connection() as conn:
                # Verify agent belongs to tenant
                agent = conn.execute("""
                    SELECT id FROM agents 
                    WHERE id = ? AND organization_id = ?
                """, [agent_id, tenant_context.organization_id]).fetchone()
                
                if not agent:
                    logger.warning(f"Log from unknown agent {agent_id}")
                    return False
                
                # Store log
                log_id = str(uuid.uuid4())
                conn.execute("""
                    INSERT INTO agent_logs (
                        id, organization_id, agent_id, log_type, log_level,
                        timestamp, message, data, source, process_name,
                        process_id, user_name, file_path, event_id, raw_log
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [
                    log_id,
                    tenant_context.organization_id,
                    agent_id,
                    log_data.get('type', 'system'),
                    log_data.get('level', 'info'),
                    log_data.get('timestamp', datetime.now().isoformat()),
                    log_data.get('message'),
                    json.dumps(log_data.get('data', {})),
                    log_data.get('source'),
                    log_data.get('process_name'),
                    log_data.get('process_id'),
                    log_data.get('user_name'),
                    log_data.get('file_path'),
                    log_data.get('event_id'),
                    log_data.get('raw_log')
                ])
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to store log: {e}")
            return False
    
    # ========================================================================
    # TENANT-SCOPED STATISTICS
    # ========================================================================
    
    def get_agent_statistics(self, tenant_context: TenantContext) -> Dict:
        """Get agent statistics for tenant"""
        try:
            with self._get_connection() as conn:
                # Total agents
                total = conn.execute("""
                    SELECT COUNT(*) as count FROM agents 
                    WHERE organization_id = ?
                """, [tenant_context.organization_id]).fetchone()['count']
                
                # Online agents (heartbeat within 5 minutes)
                online = conn.execute("""
                    SELECT COUNT(*) as count FROM agents 
                    WHERE organization_id = ? 
                    AND datetime(last_heartbeat) > datetime('now', '-5 minutes')
                """, [tenant_context.organization_id]).fetchone()['count']
                
                # By status
                status_counts = {}
                status_results = conn.execute("""
                    SELECT status, COUNT(*) as count FROM agents 
                    WHERE organization_id = ? 
                    GROUP BY status
                """, [tenant_context.organization_id]).fetchall()
                
                for row in status_results:
                    status_counts[row['status']] = row['count']
                
                # By type
                type_counts = {}
                type_results = conn.execute("""
                    SELECT type, COUNT(*) as count FROM agents 
                    WHERE organization_id = ? 
                    GROUP BY type
                """, [tenant_context.organization_id]).fetchall()
                
                for row in type_results:
                    type_counts[row['type']] = row['count']
                
                return {
                    "total": total,
                    "online": online,
                    "offline": total - online,
                    "by_status": status_counts,
                    "by_type": type_counts
                }
                
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def _format_last_activity(self, timestamp_str: str) -> str:
        """Format last activity timestamp"""
        if not timestamp_str:
            return "Never"
        
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            now = datetime.now()
            diff = now - timestamp
            
            if diff.total_seconds() < 60:
                return "Now"
            elif diff.total_seconds() < 3600:
                minutes = int(diff.total_seconds() / 60)
                return f"{minutes} min{'s' if minutes != 1 else ''} ago"
            elif diff.total_seconds() < 86400:
                hours = int(diff.total_seconds() / 3600)
                return f"{hours} hour{'s' if hours != 1 else ''} ago"
            else:
                days = int(diff.total_seconds() / 86400)
                return f"{days} day{'s' if days != 1 else ''} ago"
                
        except Exception:
            return "Unknown"
    
    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        def cleanup_task():
            while True:
                try:
                    self._cleanup_old_data()
                    self._update_agent_statuses()
                    time.sleep(300)  # Run every 5 minutes
                except Exception as e:
                    logger.error(f"Background task error: {e}")
                    time.sleep(60)
        
        cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_old_data(self):
        """Clean up old data (logs, commands, etc.)"""
        try:
            with self._get_connection() as conn:
                # Delete old completed commands (30 days)
                conn.execute("""
                    DELETE FROM agent_commands 
                    WHERE status IN ('completed', 'failed', 'timeout')
                    AND datetime(completed_at) < datetime('now', '-30 days')
                """)
                
                # Delete old logs (90 days)
                conn.execute("""
                    DELETE FROM agent_logs 
                    WHERE datetime(timestamp) < datetime('now', '-90 days')
                """)
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    def _update_agent_statuses(self):
        """Update agent statuses based on heartbeat"""
        try:
            with self._get_connection() as conn:
                # Mark agents offline if no heartbeat for 10 minutes
                conn.execute("""
                    UPDATE agents 
                    SET status = 'offline'
                    WHERE status != 'offline' 
                    AND datetime(last_heartbeat) < datetime('now', '-10 minutes')
                """)
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Status update error: {e}")

# Global instance
multi_tenant_agent_manager = MultiTenantAgentManager()

if __name__ == "__main__":
    # Test the multi-tenant manager
    manager = MultiTenantAgentManager()
    
    # Create test organization
    org_data = manager.create_organization(
        name="Test Organization",
        domain="test.com",
        subdomain="test"
    )
    
    print(f"Created organization: {org_data}")
    
    # Test API key validation
    context = manager.validate_api_key(org_data['api_key'])
    print(f"Validated context: {context}")
    
    # Register test agent
    agent_data = {
        "name": "Test Agent",
        "type": "windows",
        "hostname": "test-host",
        "ip_address": "192.168.1.100",
        "capabilities": ["log_collection", "command_execution"]
    }
    
    agent_id = manager.register_agent(context, agent_data)
    print(f"Registered agent: {agent_id}")
    
    # Get agents
    agents = manager.get_agents(context)
    print(f"Agents: {json.dumps(agents, indent=2)}")
