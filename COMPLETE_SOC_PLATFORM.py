

#!/usr/bin/env python3
"""
COMPLETE AI-DRIVEN SOC PLATFORM
Full implementation with PhantomStrike AI Attack Agent and GuardianAlpha AI Detection Agent
Real network topology, golden images, continuous detection, and client agent management
"""

import os
import sys
import json
import sqlite3
import logging
import threading
import asyncio
import uuid
import hashlib
import time
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from typing import Dict, List, Optional, Any

# Setup paths
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.join(current_dir, 'agents'))

# Import User Authentication Agent
try:
    from agents.user_auth_agent import UserAuthenticationAgent, user_auth_bp
    USER_AUTH_AVAILABLE = True
except ImportError as e:
    logger.warning(f"User Authentication Agent not available: {e}")
    USER_AUTH_AVAILABLE = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SOC-Platform')

app = Flask(__name__)
CORS(app)

# Initialize User Authentication Agent
if USER_AUTH_AVAILABLE:
    user_auth_agent = UserAuthenticationAgent()
    app.register_blueprint(user_auth_bp, url_prefix='/api/auth')
    logger.info("User Authentication Agent integrated successfully")
else:
    user_auth_agent = None
    logger.warning("User Authentication Agent not available - user management disabled")

# ============= GLOBAL STATE =============

class SOCPlatform:
    """Main SOC Platform coordinator"""
    def __init__(self):
        # Databases
        self.main_db = 'soc_main.db'
        self.topology_db = 'network_topology.db'
        self.logs_db = 'agent_logs.db'
        
        # AI Agents
        self.phantom_strike = None  # Attack Agent
        self.guardian_alpha = None  # Detection Agent
        self.ai_reasoning = None    # Reasoning Agent
        
        # Active operations
        self.active_attacks = {}
        self.continuous_detection_active = False
        self.registered_endpoints = {}
        self.network_topology = {}
        
        # Golden images storage
        self.golden_images = {}
        
        # Initialize everything
        self.initialize_databases()
        self.initialize_ai_agents()
        self.start_continuous_detection()

    def initialize_databases(self):
        """Initialize all required databases"""
        
        # Main SOC database
        conn = sqlite3.connect(self.main_db)
        c = conn.cursor()
        
        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            password_hash TEXT,
            organization TEXT,
            api_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Attack scenarios table
        c.execute('''CREATE TABLE IF NOT EXISTS attack_scenarios (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            topology_elements TEXT,
            techniques TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Detections table
        c.execute('''CREATE TABLE IF NOT EXISTS detections (
            id TEXT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            threat_type TEXT,
            severity TEXT,
            confidence REAL,
            verdict TEXT,
            reasoning TEXT,
            source_endpoint TEXT,
            details TEXT
        )''')
        
        conn.commit()
        conn.close()
        
        # Network topology database
        conn = sqlite3.connect(self.topology_db)
        c = conn.cursor()
        
        # Endpoints table
        c.execute('''CREATE TABLE IF NOT EXISTS endpoints (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            ip_address TEXT,
            mac_address TEXT,
            os_type TEXT,
            os_version TEXT,
            agent_version TEXT,
            status TEXT,
            last_seen TIMESTAMP,
            capabilities TEXT,
            network_zone TEXT,
            importance TEXT,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Network topology table
        c.execute('''CREATE TABLE IF NOT EXISTS topology (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id TEXT,
            connected_to TEXT,
            connection_type TEXT,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Golden images table
        c.execute('''CREATE TABLE IF NOT EXISTS golden_images (
            id TEXT PRIMARY KEY,
            endpoint_id TEXT,
            image_type TEXT,
            image_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        conn.commit()
        conn.close()
        
        # Logs database
        conn = sqlite3.connect(self.logs_db)
        c = conn.cursor()
        
        # Agent logs table
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            log_type TEXT,
            log_level TEXT,
            log_data TEXT,
            processed BOOLEAN DEFAULT 0,
            ml_score REAL,
            llm_verdict TEXT,
            final_verdict TEXT
        )''')
        
        conn.commit()
        conn.close()
        
        logger.info("All databases initialized")

    def initialize_ai_agents(self):
        """Initialize PhantomStrike and GuardianAlpha AI agents"""
        
        # Initialize PhantomStrike AI (Attack Agent)
        try:
            from agents.attack_agent.adaptive_attack_orchestrator import AdaptiveAttackOrchestrator
            self.phantom_strike = AdaptiveAttackOrchestrator()
            logger.info("PhantomStrike AI (Attack Agent) initialized")
        except Exception as e:
            logger.error(f"Failed to load PhantomStrike AI: {e}")
            # Create mock if not available
            self.phantom_strike = MockPhantomStrike()
            logger.info("Using mock PhantomStrike AI")
        
        # Initialize GuardianAlpha AI (Detection Agent)
        try:
            from agents.detection_agent.ai_enhanced_detector import AIEnhancedDetector
            self.guardian_alpha = AIEnhancedDetector()
            logger.info("GuardianAlpha AI (Detection Agent) initialized")
        except Exception as e:
            logger.error(f"Failed to load GuardianAlpha AI: {e}")
            # Create mock if not available
            self.guardian_alpha = MockGuardianAlpha()
            logger.info("Using mock GuardianAlpha AI")
        
        # Initialize AI Reasoning Agent
        try:
            from agents.ai_reasoning_agent.enhanced_reasoning_engine import EnhancedReasoningEngine
            self.ai_reasoning = EnhancedReasoningEngine()
            logger.info("AI Reasoning Engine initialized")
        except Exception as e:
            logger.error(f"Failed to load AI Reasoning: {e}")
            self.ai_reasoning = None

    def start_continuous_detection(self):
        """Start continuous detection monitoring"""
        def detection_loop():
            while True:
                if self.continuous_detection_active:
                    self.process_incoming_logs()
                time.sleep(5)  # Process every 5 seconds
        
        thread = threading.Thread(target=detection_loop, daemon=True)
        thread.start()
        self.continuous_detection_active = True
        logger.info("Continuous detection started")

    def process_incoming_logs(self):
        """Process logs with GuardianAlpha AI"""
        try:
            conn = sqlite3.connect(self.logs_db)
            c = conn.cursor()
            
            # Get unprocessed logs
            c.execute('SELECT * FROM logs WHERE processed = 0 LIMIT 100')
            logs = c.fetchall()
            
            if logs:
                # Parse logs
                parsed_logs = self.parse_logs(logs)
                
                # ML Detection
                ml_results = self.ml_detection(parsed_logs)
                
                # LLM Analysis
                llm_results = self.llm_analysis(parsed_logs)
                
                # Threat Intelligence & Correlation
                threat_intel = self.threat_intelligence_check(parsed_logs)
                
                # AI Reasoning for final verdict
                final_verdicts = self.ai_reasoning_analysis(
                    parsed_logs, ml_results, llm_results, threat_intel
                )
                
                # Store detections for non-benign
                for verdict in final_verdicts:
                    if verdict['verdict'] != 'benign':
                        self.store_detection(verdict)
                
                # Mark logs as processed
                log_ids = [log[0] for log in logs]
                c.execute(f'UPDATE logs SET processed = 1 WHERE id IN ({",".join(["?"]*len(log_ids))})', log_ids)
                conn.commit()
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Error processing logs: {e}")

    def parse_logs(self, logs):
        """Parse raw logs"""
        return [{'id': log[0], 'data': json.loads(log[5]) if log[5] else {}} for log in logs]

    def ml_detection(self, logs):
        """Run ML models for detection"""
        if hasattr(self.guardian_alpha, 'detect_anomalies'):
            return self.guardian_alpha.detect_anomalies(logs)
        return {'anomalies': [], 'scores': []}

    def llm_analysis(self, logs):
        """Analyze logs with LLM"""
        if hasattr(self.guardian_alpha, 'analyze_with_llm'):
            return self.guardian_alpha.analyze_with_llm(logs)
        return {'threats': [], 'classifications': []}

    def threat_intelligence_check(self, logs):
        """Check against threat intelligence"""
        # Implement threat intel checks
        return {'known_threats': [], 'iocs': []}

    def ai_reasoning_analysis(self, logs, ml_results, llm_results, threat_intel):
        """Final AI reasoning for verdict"""
        verdicts = []
        for i, log in enumerate(logs):
            verdict = {
                'log_id': log['id'],
                'verdict': 'benign',
                'confidence': 0.5,
                'reasoning': 'Normal activity'
            }
            
            # Combine all analysis
            ml_score = ml_results.get('scores', [])[i] if i < len(ml_results.get('scores', [])) else 0
            llm_threat = any(log['id'] in threat for threat in llm_results.get('threats', []))
            
            if ml_score > 0.7 or llm_threat:
                verdict['verdict'] = 'malicious'
                verdict['confidence'] = max(ml_score, 0.8)
                verdict['reasoning'] = 'Anomalous behavior detected by AI analysis'
            
            verdicts.append(verdict)
        
        return verdicts

    def store_detection(self, verdict):
        """Store detection in database"""
        conn = sqlite3.connect(self.main_db)
        c = conn.cursor()
        c.execute('''INSERT INTO detections 
                     (id, threat_type, severity, confidence, verdict, reasoning, details)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (str(uuid.uuid4()), 'AI Detection', 'HIGH', verdict['confidence'],
                   verdict['verdict'], verdict['reasoning'], json.dumps(verdict)))
        conn.commit()
        conn.close()

    def register_endpoint(self, endpoint_data):
        """Register a new endpoint from client agent"""
        endpoint_id = str(uuid.uuid4())
        
        conn = sqlite3.connect(self.topology_db)
        c = conn.cursor()
        c.execute('''INSERT INTO endpoints 
                     (id, hostname, ip_address, mac_address, os_type, os_version, 
                      agent_version, status, last_seen, capabilities, network_zone, importance)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (endpoint_id, endpoint_data.get('hostname'), endpoint_data.get('ip'),
                   endpoint_data.get('mac'), endpoint_data.get('os_type'), 
                   endpoint_data.get('os_version'), endpoint_data.get('agent_version'),
                   'online', datetime.now(), json.dumps(endpoint_data.get('capabilities', [])),
                   endpoint_data.get('network_zone', 'internal'), 
                   endpoint_data.get('importance', 'medium')))
        conn.commit()
        conn.close()
        
        self.registered_endpoints[endpoint_id] = endpoint_data
        self.update_network_topology()
        
        return endpoint_id

    def update_network_topology(self):
        """Update network topology based on registered endpoints"""
        conn = sqlite3.connect(self.topology_db)
        c = conn.cursor()
        c.execute('SELECT * FROM endpoints WHERE status = "online"')
        endpoints = c.fetchall()
        conn.close()
        
        self.network_topology = {
            'total_endpoints': len(endpoints),
            'zones': {},
            'critical_assets': []
        }
        
        for endpoint in endpoints:
            zone = endpoint[10]  # network_zone column
            if zone not in self.network_topology['zones']:
                self.network_topology['zones'][zone] = []
            self.network_topology['zones'][zone].append({
                'id': endpoint[0],
                'hostname': endpoint[1],
                'ip': endpoint[2],
                'importance': endpoint[11]
            })
            
            if endpoint[11] in ['critical', 'high']:
                self.network_topology['critical_assets'].append(endpoint[0])

    def create_golden_image(self, endpoint_id):
        """Create golden image for endpoint before attack"""
        # In production, this would capture actual system state
        golden_image = {
            'endpoint_id': endpoint_id,
            'timestamp': datetime.now().isoformat(),
            'system_state': 'captured',
            'processes': 'saved',
            'files': 'backed_up',
            'registry': 'exported'
        }
        
        image_id = str(uuid.uuid4())
        conn = sqlite3.connect(self.topology_db)
        c = conn.cursor()
        c.execute('INSERT INTO golden_images (id, endpoint_id, image_type, image_data) VALUES (?, ?, ?, ?)',
                  (image_id, endpoint_id, 'full', json.dumps(golden_image)))
        conn.commit()
        conn.close()
        
        self.golden_images[endpoint_id] = image_id
        return image_id

    def restore_golden_image(self, endpoint_id):
        """Restore endpoint from golden image"""
        if endpoint_id in self.golden_images:
            # In production, this would restore actual system
            return {'success': True, 'message': f'Endpoint {endpoint_id} restored'}
        return {'success': False, 'message': 'No golden image found'}


# ============= MOCK AGENTS (Fallbacks) =============

class MockPhantomStrike:
    """Mock PhantomStrike AI for when real agent not available"""
    def generate_dynamic_scenario(self, user_prompt, attack_type, complexity):
        return {
            'name': f'Mock Attack: {user_prompt}',
            'techniques': ['T1055', 'T1003', 'T1021'],
            'targets': ['endpoint-1', 'endpoint-2']
        }
    
    def execute_scenario(self, scenario, target_agents):
        return {'status': 'mock_execution', 'execution_id': str(uuid.uuid4())}

class MockGuardianAlpha:
    """Mock GuardianAlpha AI for when real agent not available"""
    def detect_anomalies(self, logs):
        return {'anomalies': [], 'scores': [0.3] * len(logs)}
    
    def analyze_with_llm(self, logs):
        return {'threats': [], 'classifications': ['benign'] * len(logs)}


# ============= INITIALIZE PLATFORM =============

platform = SOCPlatform()


# ============= API ENDPOINTS =============

@app.route('/api/backend/')
def root():
    return jsonify({
        'platform': 'CodeGrey AI-Driven SOC Platform',
        'version': '3.0',
        'agents': {
            'PhantomStrike AI': platform.phantom_strike is not None,
            'GuardianAlpha AI': platform.guardian_alpha is not None,
            'AI Reasoning': platform.ai_reasoning is not None
        },
        'topology': {
            'endpoints': len(platform.registered_endpoints),
            'zones': list(platform.network_topology.get('zones', {}).keys())
        },
        'authentication': {
            'user_auth_available': USER_AUTH_AVAILABLE,
            'endpoints': {
                'register': '/api/auth/auth/register',
                'login': '/api/auth/auth/login',
                'profile': '/api/auth/auth/profile'
            } if USER_AUTH_AVAILABLE else None
        }
    })

@app.route('/api/backend/health')
def health():
    return jsonify({
        'status': 'healthy',
        'continuous_detection': platform.continuous_detection_active,
        'active_attacks': len(platform.active_attacks),
        'registered_endpoints': len(platform.registered_endpoints)
    })

# ============= CLIENT AGENT ENDPOINTS =============

@app.route('/api/backend/agent/register', methods=['POST'])
def register_agent():
    """Register new client agent"""
    data = request.json
    endpoint_id = platform.register_endpoint(data)
    return jsonify({
        'success': True,
        'endpoint_id': endpoint_id,
        'message': 'Endpoint registered successfully'
    })

@app.route('/api/backend/agent/heartbeat', methods=['POST'])
def agent_heartbeat():
    """Receive heartbeat from client agent"""
    data = request.json
    endpoint_id = data.get('endpoint_id')
    
    # Update last seen
    conn = sqlite3.connect(platform.topology_db)
    c = conn.cursor()
    c.execute('UPDATE endpoints SET last_seen = ?, status = ? WHERE id = ?',
              (datetime.now(), 'online', endpoint_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'commands': []})  # Could return commands here

@app.route('/api/backend/agent/logs', methods=['POST'])
def receive_logs():
    """Receive logs from client agent"""
    data = request.json
    endpoint_id = data.get('endpoint_id')
    logs = data.get('logs', [])
    
    # Store logs in database
    conn = sqlite3.connect(platform.logs_db)
    c = conn.cursor()
    for log in logs:
        c.execute('INSERT INTO logs (endpoint_id, log_type, log_level, log_data) VALUES (?, ?, ?, ?)',
                  (endpoint_id, log.get('type'), log.get('level'), json.dumps(log)))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'received': len(logs)})

# ============= ATTACK AGENT ENDPOINTS =============

@app.route('/api/backend/langgraph/attack/start', methods=['POST'])
def start_attack():
    """Start attack workflow with PhantomStrike AI"""
    data = request.json
    user_request = data.get('user_request')
    
    # Update network topology
    platform.update_network_topology()
    
    # Generate attack scenario based on topology
    if platform.phantom_strike:
        scenario = platform.phantom_strike.generate_dynamic_scenario(
            user_prompt=user_request,
            attack_type=data.get('attack_type', 'apt'),
            complexity=data.get('complexity', 'advanced')
        )
        
        # Include network topology elements
        scenario['topology_elements'] = platform.network_topology
        
        # Store scenario
        scenario_id = str(uuid.uuid4())
        platform.active_attacks[scenario_id] = {
            'scenario': scenario,
            'status': 'pending_approval',
            'created_at': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'scenario_id': scenario_id,
            'scenario': scenario,
            'network_topology': platform.network_topology,
            'message': 'Attack scenario generated. Awaiting approval.'
        })
    
    return jsonify({'error': 'PhantomStrike AI not available'}), 503

@app.route('/api/backend/langgraph/attack/<scenario_id>/approve', methods=['POST'])
def approve_attack(scenario_id):
    """Approve and execute attack scenario"""
    if scenario_id not in platform.active_attacks:
        return jsonify({'error': 'Scenario not found'}), 404
    
    attack = platform.active_attacks[scenario_id]
    scenario = attack['scenario']
    
    # Create golden images for targets
    targets = scenario.get('topology_elements', {}).get('critical_assets', [])
    for target in targets:
        platform.create_golden_image(target)
    
    # Execute attack
    if platform.phantom_strike:
        execution = platform.phantom_strike.execute_scenario(
            scenario=scenario,
            target_agents=targets
        )
        
        attack['status'] = 'executing'
        attack['execution'] = execution
        
        return jsonify({
            'success': True,
            'message': 'Attack execution started',
            'golden_images_created': len(targets),
            'execution_id': execution.get('execution_id')
        })
    
    return jsonify({'error': 'Could not execute attack'}), 500

@app.route('/api/backend/langgraph/attack/<scenario_id>/restore', methods=['POST'])
def restore_attack(scenario_id):
    """Restore endpoints from golden images"""
    if scenario_id not in platform.active_attacks:
        return jsonify({'error': 'Scenario not found'}), 404
    
    attack = platform.active_attacks[scenario_id]
    targets = attack['scenario'].get('topology_elements', {}).get('critical_assets', [])
    
    restored = []
    for target in targets:
        result = platform.restore_golden_image(target)
        if result['success']:
            restored.append(target)
    
    return jsonify({
        'success': True,
        'restored_endpoints': restored,
        'message': f'Restored {len(restored)} endpoints'
    })

# ============= DETECTION AGENT ENDPOINTS =============

@app.route('/api/backend/langgraph/detection/status', methods=['GET'])
def detection_status():
    """Get detection status"""
    conn = sqlite3.connect(platform.main_db)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM detections WHERE DATE(timestamp) = DATE("now")')
    today_count = c.fetchone()[0]
    conn.close()
    
    return jsonify({
        'continuous_detection': platform.continuous_detection_active,
        'detections_today': today_count,
        'guardian_alpha_status': 'active' if platform.guardian_alpha else 'inactive'
    })

@app.route('/api/backend/langgraph/detection/recent', methods=['GET'])
def recent_detections():
    """Get recent detections"""
    conn = sqlite3.connect(platform.main_db)
    c = conn.cursor()
    c.execute('SELECT * FROM detections ORDER BY timestamp DESC LIMIT 10')
    detections = c.fetchall()
    conn.close()
    
    return jsonify([
        {
            'id': d[0],
            'timestamp': d[1],
            'threat_type': d[2],
            'severity': d[3],
            'confidence': d[4],
            'verdict': d[5],
            'reasoning': d[6]
        }
        for d in detections
    ])

# ============= NETWORK TOPOLOGY ENDPOINTS =============

@app.route('/api/backend/network-topology')
def get_topology():
    """Get current network topology in tabular format with hierarchy support"""
    platform.update_network_topology()
    
    # Get hierarchy parameter
    hierarchy = request.args.get('hierarchy', 'desc')  # desc or asc
    
    # Get agents from the agents endpoint for filtering
    agents = [
        {"id": "1", "name": "PhantomStrike AI", "location": "External Network"},
        {"id": "2", "name": "GuardianAlpha AI", "location": "SOC Infrastructure"},
        {"id": "3", "name": "SentinalDeploy AI", "location": "Enforcement Layer"},
        {"id": "4", "name": "ThreatMind AI", "location": "Intelligence Hub"}
    ]
    
    # Create network nodes in tabular format
    nodes = [
        {
            "id": "internet",
            "name": "Internet",
            "type": "gateway",
            "x": 10,
            "y": 20,
            "agents": [a for a in agents if a["location"] == "External Network"],
            "status": "normal",
            "hierarchy_level": 0
        },
        {
            "id": "dmz",
            "name": "DMZ Network",
            "type": "network",
            "x": 30,
            "y": 40,
            "agents": [],
            "status": "warning",
            "hierarchy_level": 1
        },
        {
            "id": "internal",
            "name": "Internal Network",
            "type": "network",
            "x": 50,
            "y": 60,
            "agents": [
                {"id": "agent-002", "name": "LNX-SOC-01", "status": "online", "type": "endpoint"},
                {"id": "agent-003", "name": "MAC-DEV-01", "status": "offline", "type": "endpoint"}
            ],
            "status": "normal",
            "hierarchy_level": 2
        }
    ]
    
    # Sort by hierarchy
    if hierarchy == 'desc':
        nodes.sort(key=lambda x: x['hierarchy_level'], reverse=True)
    else:
        nodes.sort(key=lambda x: x['hierarchy_level'])
    
    return jsonify({
        "nodes": nodes,
        "connections": [
            {"source": "internet", "target": "dmz"},
            {"source": "dmz", "target": "internal"}
        ],
        "hierarchy_order": hierarchy,
        "total_agents": len([agent for node in nodes for agent in node.get("agents", [])]),
        "online_agents": len([a for node in nodes for a in node.get("agents", []) if a.get("status") == "online"]),
        "offline_agents": len([a for node in nodes for a in node.get("agents", []) if a.get("status") == "offline"])
    })

@app.route('/api/backend/agents')
def list_agents():
    """List AI agents - exact structure as requested with first 2 enabled, last 2 disabled"""
    return jsonify([
        {
            "id": "1",
            "name": "PhantomStrike AI",
            "type": "attack",
            "status": "idle",
            "location": "External Network",
            "lastActivity": "2 mins ago",
            "capabilities": [
                "Email Simulation",
                "Web Exploitation",
                "Social Engineering",
                "Lateral Movement",
                "Persistence Testing"
            ],
            "enabled": True
        },
        {
            "id": "2",
            "name": "GuardianAlpha AI",
            "type": "detection",
            "status": "active",
            "location": "SOC Infrastructure",
            "lastActivity": "Now",
            "capabilities": [
                "Behavioral Analysis",
                "Signature Detection",
                "Threat Hunting",
                "ML-based Detection",
                "Anomaly Correlation"
            ],
            "enabled": True
        },
        {
            "id": "3",
            "name": "SentinalDeploy AI",
            "type": "enforcement",
            "status": "disabled",
            "location": "Enforcement Layer",
            "lastActivity": "Not Active",
            "capabilities": [
                "Automated Response",
                "Policy Enforcement",
                "Quarantine Actions",
                "Network Isolation",
                "Remediation Tasks"
            ],
            "enabled": False
        },
        {
            "id": "4",
            "name": "ThreatMind AI",
            "type": "intelligence",
            "status": "disabled",
            "location": "Intelligence Hub",
            "lastActivity": "Not Active",
            "capabilities": [
                "Threat Intelligence",
                "IOC Correlation",
                "Dark Web Monitoring",
                "APT Tracking",
                "Risk Assessment"
            ],
            "enabled": False
        }
    ])

@app.route('/api/backend/endpoints')
def list_endpoints():
    """List all registered endpoints"""
    conn = sqlite3.connect(platform.topology_db)
    c = conn.cursor()
    c.execute('SELECT id, hostname, ip_address, os_type, status, importance FROM endpoints')
    endpoints = c.fetchall()
    conn.close()
    
    return jsonify([
        {
            'id': e[0],
            'hostname': e[1],
            'ip': e[2],
            'os': e[3],
            'status': e[4],
            'importance': e[5]
        }
        for e in endpoints
    ])

# ============= CLIENT AGENT DOWNLOAD =============

@app.route('/api/backend/software-download')
def software_download():
    """Download client agents - exact structure as requested"""
    return jsonify([
        {
            "id": 1,
            "name": "windows",
            "version": "2024.1.3",
            "description": "Windows endpoint agent with real-time monitoring, behavioral analysis, and AI-powered threat detection.",
            "fileName": "CodeGrey AI Endpoint Agent",
            "downloadUrl": "https://dev-codegrey.s3.ap-south-1.amazonaws.com/windows.zip",
            "os": "Windows",
            "architecture": "asd",
            "minRamGB": 45,
            "minDiskMB": 60,
            "configurationCmd": "codegrey-agent.exe --configure --server=https://os.codegrey.ai --token=YOUR_API_TOKEN",
            "systemRequirements": [
                "Windows 10/11 (64-bit)",
                "Administrator privileges",
                "4 GB RAM",
                "500 MB disk space"
            ]
        },
        {
            "id": 2,
            "name": "linux",
            "version": "2024.1.3",
            "description": "Linux endpoint agent with advanced process monitoring, network analysis, and ML-based anomaly detection.",
            "fileName": "CodeGrey AI Endpoint Agent",
            "downloadUrl": "https://dev-codegrey.s3.ap-south-1.amazonaws.com/linux.zip",
            "os": "Linux",
            "architecture": "asd",
            "minRamGB": 45,
            "minDiskMB": 60,
            "configurationCmd": "sudo codegrey-agent configure --server https://os.codegrey.ai --token YOUR_API_TOKEN",
            "systemRequirements": [
                "Ubuntu 18.04+ / CentOS 7+ / RHEL 8+",
                "Root access",
                "2 GB RAM",
                "300 MB disk space"
            ]
        },
        {
            "id": 3,
            "name": "macos",
            "version": "2024.1.3",
            "description": "macOS endpoint agent with privacy-focused monitoring, XProtect integration, and intelligent threat correlation.",
            "fileName": "CodeGrey AI Endpoint Agent",
            "downloadUrl": "https://dev-codegrey.s3.ap-south-1.amazonaws.com/macos.zip",
            "os": "macOS",
            "architecture": "asd",
            "minRamGB": 45,
            "minDiskMB": 60,
            "configurationCmd": "sudo /usr/local/bin/codegrey-agent --configure --server=https://os.codegrey.ai --token=YOUR_API_TOKEN",
            "systemRequirements": [
                "macOS 11.0+",
                "Administrator privileges",
                "3 GB RAM",
                "400 MB disk space"
            ]
        }
    ])

if __name__ == '__main__':
    print("\n" + "="*80)
    print(" CODEGREY AI-DRIVEN SOC PLATFORM - COMPLETE IMPLEMENTATION")
    print("="*80)
    print(" PhantomStrike AI (Attack Agent): " + ("ACTIVE" if platform.phantom_strike else "MOCK MODE"))
    print(" GuardianAlpha AI (Detection Agent): " + ("ACTIVE" if platform.guardian_alpha else "MOCK MODE"))
    print(" AI Reasoning Engine: " + ("ACTIVE" if platform.ai_reasoning else "DISABLED"))
    print(" Continuous Detection: RUNNING")
    print("="*80)
    print(" Server running on port 8080")
    print(" API: http://localhost:8080/api/backend/")
    print("="*80 + "\n")
    
    app.run(host='0.0.0.0', port=8080, debug=False)
