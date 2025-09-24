#!/usr/bin/env python3
"""
CodeGrey SOC Server - Agent Management System
Tracks and manages all connected agents with real-time status
"""

import json
import time
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import threading

class AgentManager:
    """Manages all connected agents and their status"""
    
    def __init__(self, db_path="agents.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.setup_database()
        self._lock = threading.Lock()
        
        # Agent type capabilities mapping
        self.agent_capabilities = {
            "windows": [
                "Windows Event Logs",
                "PowerShell Execution", 
                "Registry Monitoring",
                "Process Injection",
                "File Download/Execute",
                "Network Reconnaissance"
            ],
            "linux": [
                "System Log Collection",
                "Shell Command Execution",
                "File System Monitoring", 
                "Network Analysis",
                "Process Monitoring",
                "Configuration Discovery"
            ],
            "macos": [
                "System Log Collection",
                "Shell Command Execution",
                "Keychain Access Testing",
                "Application Monitoring",
                "Network Analysis",
                "Security Framework Testing"
            ],
            "attack": [
                "Email Simulation",
                "Web Exploitation", 
                "Social Engineering",
                "Lateral Movement",
                "Persistence Testing",
                "Credential Harvesting"
            ],
            "detection": [
                "Threat Detection",
                "Behavioral Analysis",
                "Log Correlation",
                "IOC Matching",
                "Anomaly Detection",
                "Alert Generation"
            ]
        }
    
    def setup_database(self):
        """Initialize agent tracking database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    status TEXT DEFAULT 'offline',
                    location TEXT,
                    hostname TEXT,
                    os_info TEXT,
                    ip_address TEXT,
                    first_seen TEXT,
                    last_activity TEXT,
                    last_heartbeat TEXT,
                    capabilities TEXT,
                    agent_version TEXT,
                    config TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS agent_activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    activity_type TEXT,
                    activity_data TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (agent_id) REFERENCES agents (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            self.logger.info("Agent database initialized")
        except Exception as e:
            self.logger.error(f"Error setting up agent database: {e}")
    
    def register_agent(self, agent_data: Dict) -> bool:
        """Register a new agent or update existing one"""
        try:
            with self._lock:
                agent_id = agent_data.get('agent_id')
                hostname = agent_data.get('hostname', 'Unknown')
                os_info = agent_data.get('os', 'Unknown')
                ip_address = agent_data.get('ip_address', 'Unknown')
                agent_version = agent_data.get('version', '1.0.0')
                
                # Determine agent type based on OS
                agent_type = self._determine_agent_type(os_info)
                
                # Generate agent name
                agent_name = self._generate_agent_name(hostname, agent_type)
                
                # Determine location based on IP
                location = self._determine_location(ip_address)
                
                # Get capabilities for this agent type
                capabilities = json.dumps(self.agent_capabilities.get(agent_type, []))
                
                now = datetime.now().isoformat()
                
                conn = sqlite3.connect(self.db_path)
                
                # Check if agent exists
                cursor = conn.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
                exists = cursor.fetchone()
                
                if exists:
                    # Update existing agent
                    conn.execute('''
                        UPDATE agents SET 
                        hostname = ?, os_info = ?, ip_address = ?, 
                        last_activity = ?, last_heartbeat = ?, 
                        status = 'online', agent_version = ?
                        WHERE id = ?
                    ''', (hostname, os_info, ip_address, now, now, agent_version, agent_id))
                else:
                    # Insert new agent
                    conn.execute('''
                        INSERT INTO agents 
                        (id, name, type, status, location, hostname, os_info, 
                         ip_address, first_seen, last_activity, last_heartbeat, 
                         capabilities, agent_version)
                        VALUES (?, ?, ?, 'online', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (agent_id, agent_name, agent_type, location, hostname, 
                          os_info, ip_address, now, now, now, capabilities, agent_version))
                
                conn.commit()
                conn.close()
                
                # Log activity
                self.log_agent_activity(agent_id, "registration", agent_data)
                
                self.logger.info(f"Agent registered: {agent_name} ({agent_id})")
                return True
                
        except Exception as e:
            self.logger.error(f"Error registering agent: {e}")
            return False
    
    def update_agent_heartbeat(self, agent_id: str, activity_data: Dict = None) -> bool:
        """Update agent last heartbeat and activity"""
        try:
            with self._lock:
                now = datetime.now().isoformat()
                
                conn = sqlite3.connect(self.db_path)
                conn.execute('''
                    UPDATE agents SET 
                    last_heartbeat = ?, last_activity = ?, status = 'online'
                    WHERE id = ?
                ''', (now, now, agent_id))
                
                conn.commit()
                conn.close()
                
                # Log activity if provided
                if activity_data:
                    self.log_agent_activity(agent_id, "heartbeat", activity_data)
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error updating agent heartbeat: {e}")
            return False
    
    def update_agent_status(self, agent_id: str, status: str, activity_type: str = None, activity_data: Dict = None):
        """Update agent status (online, offline, busy, error)"""
        try:
            with self._lock:
                now = datetime.now().isoformat()
                
                conn = sqlite3.connect(self.db_path)
                conn.execute('''
                    UPDATE agents SET 
                    status = ?, last_activity = ?
                    WHERE id = ?
                ''', (status, now, agent_id))
                
                conn.commit()
                conn.close()
                
                # Log activity
                if activity_type:
                    self.log_agent_activity(agent_id, activity_type, activity_data or {})
                
                self.logger.info(f"Agent {agent_id} status updated to: {status}")
                
        except Exception as e:
            self.logger.error(f"Error updating agent status: {e}")
    
    def log_agent_activity(self, agent_id: str, activity_type: str, activity_data: Dict):
        """Log agent activity"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                INSERT INTO agent_activities (agent_id, activity_type, activity_data, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (agent_id, activity_type, json.dumps(activity_data), datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error logging agent activity: {e}")
    
    def get_all_agents(self) -> List[Dict]:
        """Get all agents in the required format"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute('''
                SELECT id, name, type, status, location, hostname, os_info, 
                       last_activity, capabilities, agent_version
                FROM agents
                ORDER BY last_activity DESC
            ''')
            
            agents = []
            for row in cursor.fetchall():
                agent_id, name, agent_type, status, location, hostname, os_info, last_activity, capabilities, version = row
                
                # Parse capabilities
                try:
                    capabilities_list = json.loads(capabilities) if capabilities else []
                except:
                    capabilities_list = []
                
                # Calculate time since last activity
                last_activity_str = self._format_last_activity(last_activity)
                
                # Determine current status
                current_status = self._determine_current_status(last_activity, status)
                
                agent = {
                    "id": agent_id,
                    "name": name,
                    "type": agent_type,
                    "status": current_status,
                    "location": location or "Unknown",
                    "lastActivity": last_activity_str,
                    "capabilities": capabilities_list,
                    "hostname": hostname,
                    "os": os_info,
                    "version": version
                }
                
                agents.append(agent)
            
            conn.close()
            return agents
            
        except Exception as e:
            self.logger.error(f"Error getting all agents: {e}")
            return []
    
    def get_agent_by_id(self, agent_id: str) -> Optional[Dict]:
        """Get specific agent by ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute('''
                SELECT id, name, type, status, location, hostname, os_info, 
                       last_activity, capabilities, agent_version, first_seen
                FROM agents WHERE id = ?
            ''', (agent_id,))
            
            row = cursor.fetchone()
            if not row:
                conn.close()
                return None
            
            agent_id, name, agent_type, status, location, hostname, os_info, last_activity, capabilities, version, first_seen = row
            
            # Parse capabilities
            try:
                capabilities_list = json.loads(capabilities) if capabilities else []
            except:
                capabilities_list = []
            
            # Get recent activities
            activity_cursor = conn.execute('''
                SELECT activity_type, activity_data, timestamp
                FROM agent_activities 
                WHERE agent_id = ?
                ORDER BY timestamp DESC
                LIMIT 10
            ''', (agent_id,))
            
            activities = []
            for activity_row in activity_cursor.fetchall():
                activity_type, activity_data, timestamp = activity_row
                try:
                    parsed_data = json.loads(activity_data) if activity_data else {}
                except:
                    parsed_data = {}
                
                activities.append({
                    "type": activity_type,
                    "data": parsed_data,
                    "timestamp": timestamp
                })
            
            conn.close()
            
            agent = {
                "id": agent_id,
                "name": name,
                "type": agent_type,
                "status": self._determine_current_status(last_activity, status),
                "location": location or "Unknown",
                "lastActivity": self._format_last_activity(last_activity),
                "capabilities": capabilities_list,
                "hostname": hostname,
                "os": os_info,
                "version": version,
                "firstSeen": first_seen,
                "recentActivities": activities
            }
            
            return agent
            
        except Exception as e:
            self.logger.error(f"Error getting agent {agent_id}: {e}")
            return None
    
    def get_agents_by_status(self, status: str) -> List[Dict]:
        """Get agents filtered by status"""
        all_agents = self.get_all_agents()
        return [agent for agent in all_agents if agent['status'] == status]
    
    def get_agents_by_type(self, agent_type: str) -> List[Dict]:
        """Get agents filtered by type"""
        all_agents = self.get_all_agents()
        return [agent for agent in all_agents if agent['type'] == agent_type]
    
    def cleanup_offline_agents(self, offline_threshold_minutes: int = 5):
        """Mark agents as offline if they haven't sent heartbeat recently"""
        try:
            threshold_time = datetime.now() - timedelta(minutes=offline_threshold_minutes)
            threshold_str = threshold_time.isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute('''
                UPDATE agents SET status = 'offline'
                WHERE last_heartbeat < ? AND status != 'offline'
            ''', (threshold_str,))
            
            updated_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if updated_count > 0:
                self.logger.info(f"Marked {updated_count} agents as offline")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up offline agents: {e}")
    
    def _determine_agent_type(self, os_info: str) -> str:
        """Determine agent type based on OS information"""
        os_lower = os_info.lower()
        if 'windows' in os_lower:
            return 'windows'
        elif 'linux' in os_lower:
            return 'linux'
        elif 'darwin' in os_lower or 'macos' in os_lower:
            return 'macos'
        else:
            return 'unknown'
    
    def _generate_agent_name(self, hostname: str, agent_type: str) -> str:
        """Generate a friendly name for the agent"""
        type_names = {
            'windows': 'Windows Agent',
            'linux': 'Linux Agent', 
            'macos': 'macOS Agent',
            'attack': 'Attack Agent',
            'detection': 'Detection Agent'
        }
        
        base_name = type_names.get(agent_type, 'Unknown Agent')
        return f"{base_name} ({hostname})"
    
    def _determine_location(self, ip_address: str) -> str:
        """Determine location based on IP address"""
        if ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.'):
            return "Internal Network"
        elif ip_address.startswith('127.'):
            return "Localhost"
        else:
            return "External Network"
    
    def _format_last_activity(self, last_activity: str) -> str:
        """Format last activity time as human readable"""
        try:
            last_time = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
            now = datetime.now()
            diff = now - last_time.replace(tzinfo=None)
            
            if diff.total_seconds() < 60:
                return f"{int(diff.total_seconds())} secs ago"
            elif diff.total_seconds() < 3600:
                return f"{int(diff.total_seconds() // 60)} mins ago"
            elif diff.total_seconds() < 86400:
                return f"{int(diff.total_seconds() // 3600)} hours ago"
            else:
                return f"{int(diff.total_seconds() // 86400)} days ago"
                
        except Exception:
            return "Unknown"
    
    def _determine_current_status(self, last_activity: str, stored_status: str) -> str:
        """Determine current status based on last activity"""
        try:
            last_time = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
            now = datetime.now()
            diff = now - last_time.replace(tzinfo=None)
            
            # If last activity was more than 5 minutes ago, mark as offline
            if diff.total_seconds() > 300:  # 5 minutes
                return "offline"
            elif diff.total_seconds() > 120:  # 2 minutes
                return "idle"
            else:
                return stored_status if stored_status in ['online', 'busy', 'error'] else "online"
                
        except Exception:
            return "offline"
    
    def get_agent_statistics(self) -> Dict:
        """Get overall agent statistics"""
        try:
            agents = self.get_all_agents()
            
            stats = {
                "total": len(agents),
                "online": len([a for a in agents if a['status'] == 'online']),
                "offline": len([a for a in agents if a['status'] == 'offline']),
                "idle": len([a for a in agents if a['status'] == 'idle']),
                "busy": len([a for a in agents if a['status'] == 'busy']),
                "error": len([a for a in agents if a['status'] == 'error']),
                "by_type": {
                    "windows": len([a for a in agents if a['type'] == 'windows']),
                    "linux": len([a for a in agents if a['type'] == 'linux']),
                    "macos": len([a for a in agents if a['type'] == 'macos']),
                    "attack": len([a for a in agents if a['type'] == 'attack']),
                    "detection": len([a for a in agents if a['type'] == 'detection'])
                }
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting agent statistics: {e}")
            return {
                "total": 0,
                "online": 0,
                "offline": 0,
                "idle": 0,
                "busy": 0,
                "error": 0,
                "by_type": {}
            }

# Example usage and testing
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Create agent manager
    manager = AgentManager()
    
    # Example: Register some test agents
    test_agents = [
        {
            "agent_id": "agent_001",
            "hostname": "DESKTOP-WIN01",
            "os": "Windows 10",
            "ip_address": "192.168.1.100",
            "version": "2.1.0"
        },
        {
            "agent_id": "agent_002", 
            "hostname": "ubuntu-server",
            "os": "Linux Ubuntu 20.04",
            "ip_address": "192.168.1.101",
            "version": "2.1.0"
        },
        {
            "agent_id": "agent_003",
            "hostname": "MacBook-Pro",
            "os": "Darwin 21.6.0",
            "ip_address": "192.168.1.102",
            "version": "2.1.0"
        }
    ]
    
    # Register test agents
    for agent_data in test_agents:
        manager.register_agent(agent_data)
    
    # Get all agents
    agents = manager.get_all_agents()
    print("All Agents:")
    print(json.dumps(agents, indent=2))
    
    # Get statistics
    stats = manager.get_agent_statistics()
    print("\nAgent Statistics:")
    print(json.dumps(stats, indent=2))

