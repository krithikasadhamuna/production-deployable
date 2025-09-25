"""
Network Discovery and Management Tools for LangGraph
"""

import sqlite3
import json
import logging
from typing import Dict, List, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class NetworkDiscoveryTool:
    """Tool for discovering network topology and agent status"""
    
    def __init__(self, db_path: str = "soc_database.db"):
        self.db_path = db_path
        self.name = "network_discovery"
        self.description = "Discover network topology, online/offline agents, and their configurations"
    
    def run(self, query: str = "all") -> Dict[str, Any]:
        """
        Execute network discovery
        Args:
            query: Type of discovery - "all", "online", "offline", "critical"
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Base query
            sql = """
                SELECT 
                    id, hostname, ip_address, platform, status,
                    last_heartbeat, capabilities, configuration,
                    endpoint_importance, user_role, role_confidence,
                    security_zone
                FROM agents
            """
            
            # Apply filters
            if query == "online":
                sql += " WHERE status = 'online'"
            elif query == "offline":
                sql += " WHERE status = 'offline'"
            elif query == "critical":
                sql += " WHERE endpoint_importance IN ('critical', 'high')"
            
            sql += " ORDER BY endpoint_importance DESC, hostname ASC"
            
            cursor.execute(sql)
            
            agents = []
            for row in cursor.fetchall():
                agent = {
                    'id': row['id'],
                    'hostname': row['hostname'],
                    'ip_address': row['ip_address'],
                    'platform': row['platform'],
                    'status': row['status'],
                    'last_seen': row['last_heartbeat'],
                    'capabilities': json.loads(row['capabilities']) if row['capabilities'] else [],
                    'configuration': json.loads(row['configuration']) if row['configuration'] else {},
                    'importance': row['endpoint_importance'] or 'medium',
                    'user_role': row['user_role'] or 'employee',
                    'role_confidence': row['role_confidence'] or 0.5,
                    'security_zone': row['security_zone'] or 'internal'
                }
                agents.append(agent)
            
            # Get network statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online,
                    SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline,
                    SUM(CASE WHEN endpoint_importance = 'critical' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN endpoint_importance = 'high' THEN 1 ELSE 0 END) as high_value
                FROM agents
            """)
            
            stats = cursor.fetchone()
            
            conn.close()
            
            return {
                'success': True,
                'agents': agents,
                'statistics': {
                    'total': stats['total'] or 0,
                    'online': stats['online'] or 0,
                    'offline': stats['offline'] or 0,
                    'critical_assets': stats['critical'] or 0,
                    'high_value_targets': stats['high_value'] or 0
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Network discovery error: {e}")
            return {
                'success': False,
                'error': str(e),
                'agents': [],
                'statistics': {}
            }


class VulnerabilityAnalysisTool:
    """Tool for analyzing vulnerabilities in discovered endpoints"""
    
    def __init__(self):
        self.name = "vulnerability_analysis"
        self.description = "Analyze endpoints for potential vulnerabilities and attack vectors"
    
    def run(self, agents: List[Dict]) -> Dict[str, Any]:
        """
        Analyze agents for vulnerabilities
        """
        vulnerabilities = []
        
        for agent in agents:
            agent_vulns = []
            
            # Check platform vulnerabilities
            platform = agent.get('platform', '').lower()
            if 'windows' in platform:
                agent_vulns.append({
                    'type': 'OS',
                    'name': 'SMB/EternalBlue',
                    'cve': 'CVE-2017-0144',
                    'severity': 'critical',
                    'technique': 'T1210'
                })
                agent_vulns.append({
                    'type': 'Privilege',
                    'name': 'UAC Bypass',
                    'severity': 'high',
                    'technique': 'T1548.002'
                })
            
            # Check for database services
            if any('database' in str(cap).lower() for cap in agent.get('capabilities', [])):
                agent_vulns.append({
                    'type': 'Service',
                    'name': 'SQL Injection',
                    'severity': 'high',
                    'technique': 'T1190'
                })
            
            # Check for web services
            if any('web' in str(cap).lower() for cap in agent.get('capabilities', [])):
                agent_vulns.append({
                    'type': 'Service',
                    'name': 'Web Application Vulnerabilities',
                    'severity': 'medium',
                    'technique': 'T1190'
                })
            
            # Check importance-based vulnerabilities
            if agent.get('importance') == 'critical':
                agent_vulns.append({
                    'type': 'Target',
                    'name': 'High-Value Target',
                    'severity': 'critical',
                    'technique': 'T1078'
                })
            
            if agent_vulns:
                vulnerabilities.append({
                    'agent_id': agent['id'],
                    'hostname': agent['hostname'],
                    'vulnerabilities': agent_vulns,
                    'risk_score': len(agent_vulns) * 25,  # Simple risk scoring
                    'recommended_techniques': list(set(v['technique'] for v in agent_vulns))
                })
        
        return {
            'success': True,
            'total_vulnerabilities': sum(len(v['vulnerabilities']) for v in vulnerabilities),
            'affected_agents': len(vulnerabilities),
            'vulnerability_details': vulnerabilities,
            'high_risk_targets': [v for v in vulnerabilities if v['risk_score'] >= 75]
        }


class AttackScenarioTool:
    """Tool for generating attack scenarios based on network and vulnerabilities"""
    
    def __init__(self):
        self.name = "attack_scenario_generator"
        self.description = "Generate realistic attack scenarios based on network topology"
    
    def run(self, network_data: Dict, vulnerability_data: Dict) -> List[Dict]:
        """
        Generate attack scenarios
        """
        scenarios = []
        
        # Analyze network for scenario generation
        online_agents = [a for a in network_data.get('agents', []) if a['status'] == 'online']
        critical_agents = [a for a in online_agents if a['importance'] == 'critical']
        high_value = [a for a in online_agents if a['importance'] == 'high']
        
        # Scenario 1: APT-style attack
        if len(online_agents) >= 5 and critical_agents:
            scenarios.append({
                'id': 'apt_advanced',
                'name': 'Advanced Persistent Threat',
                'description': 'Stealthy, long-term attack targeting critical assets',
                'phases': [
                    {
                        'name': 'Initial Compromise',
                        'targets': [a['id'] for a in online_agents if a['importance'] == 'low'][:2],
                        'techniques': ['T1566', 'T1078'],
                        'duration': 30
                    },
                    {
                        'name': 'Establish Foothold',
                        'targets': [a['id'] for a in online_agents if a['importance'] == 'low'][:2],
                        'techniques': ['T1053', 'T1547'],
                        'duration': 20
                    },
                    {
                        'name': 'Privilege Escalation',
                        'targets': [a['id'] for a in online_agents if a['importance'] == 'medium'][:2],
                        'techniques': ['T1055', 'T1134'],
                        'duration': 30
                    },
                    {
                        'name': 'Lateral Movement',
                        'targets': [a['id'] for a in high_value][:3],
                        'techniques': ['T1021', 'T1570'],
                        'duration': 45
                    },
                    {
                        'name': 'Data Exfiltration',
                        'targets': [a['id'] for a in critical_agents],
                        'techniques': ['T1005', 'T1048'],
                        'duration': 60
                    }
                ],
                'total_duration': 185,
                'sophistication': 'advanced',
                'objectives': ['persistence', 'exfiltration']
            })
        
        # Scenario 2: Ransomware attack
        if len(online_agents) >= 3:
            scenarios.append({
                'id': 'ransomware_fast',
                'name': 'Rapid Ransomware',
                'description': 'Fast-moving ransomware with encryption',
                'phases': [
                    {
                        'name': 'Initial Access',
                        'targets': [a['id'] for a in online_agents][:1],
                        'techniques': ['T1566', 'T1189'],
                        'duration': 15
                    },
                    {
                        'name': 'Execution & Escalation',
                        'targets': [a['id'] for a in online_agents][:2],
                        'techniques': ['T1055', 'T1548'],
                        'duration': 20
                    },
                    {
                        'name': 'Rapid Spread',
                        'targets': [a['id'] for a in online_agents],
                        'techniques': ['T1021', 'T1080'],
                        'duration': 30
                    },
                    {
                        'name': 'Encryption',
                        'targets': [a['id'] for a in online_agents],
                        'techniques': ['T1486', 'T1490'],
                        'duration': 15
                    }
                ],
                'total_duration': 80,
                'sophistication': 'medium',
                'objectives': ['impact', 'financial']
            })
        
        # Scenario 3: Data theft
        if high_value or critical_agents:
            targets = (critical_agents + high_value)[:5]
            scenarios.append({
                'id': 'data_theft',
                'name': 'Targeted Data Theft',
                'description': 'Focused attack on high-value data',
                'phases': [
                    {
                        'name': 'Reconnaissance',
                        'targets': [],
                        'techniques': ['T1595', 'T1592'],
                        'duration': 20
                    },
                    {
                        'name': 'Initial Access',
                        'targets': [targets[0]['id']] if targets else [],
                        'techniques': ['T1078', 'T1133'],
                        'duration': 15
                    },
                    {
                        'name': 'Discovery',
                        'targets': [t['id'] for t in targets[:2]],
                        'techniques': ['T1057', 'T1083'],
                        'duration': 25
                    },
                    {
                        'name': 'Collection',
                        'targets': [t['id'] for t in targets],
                        'techniques': ['T1005', 'T1074'],
                        'duration': 40
                    },
                    {
                        'name': 'Exfiltration',
                        'targets': [t['id'] for t in targets[:2]],
                        'techniques': ['T1048', 'T1071'],
                        'duration': 30
                    }
                ],
                'total_duration': 130,
                'sophistication': 'medium',
                'objectives': ['collection', 'exfiltration']
            })
        
        return scenarios


class CommandExecutionTool:
    """Tool for executing attack commands on agents"""
    
    def __init__(self, db_path: str = "soc_database.db"):
        self.db_path = db_path
        self.name = "command_execution"
        self.description = "Queue and execute commands on target agents"
    
    def run(self, agent_id: str, technique: str, parameters: Dict = None) -> Dict:
        """
        Queue command for execution on agent
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if agent is online
            cursor.execute("SELECT status FROM agents WHERE id = ?", (agent_id,))
            agent = cursor.fetchone()
            
            if not agent:
                conn.close()
                return {'success': False, 'error': 'Agent not found'}
            
            if agent[0] != 'online':
                conn.close()
                return {'success': False, 'error': 'Agent is offline'}
            
            # Create command
            import uuid
            command_id = f"cmd_{uuid.uuid4().hex[:12]}"
            
            cursor.execute("""
                INSERT INTO commands 
                (id, agent_id, type, parameters, status, created_at, priority)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                command_id,
                agent_id,
                f"attack_{technique}",
                json.dumps(parameters or {}),
                'queued',
                datetime.now(timezone.utc).isoformat(),
                'high'
            ))
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'command_id': command_id,
                'agent_id': agent_id,
                'technique': technique,
                'status': 'queued'
            }
            
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return {'success': False, 'error': str(e)}
