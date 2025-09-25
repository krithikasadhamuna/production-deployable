#!/usr/bin/env python3
"""
SOC PLATFORM BACKEND - PROFESSIONAL ORCHESTRATION
Enterprise-grade AI-driven SOC Platform with proper architecture
Built with 5+ years backend development experience principles
"""

import os
import sys
import asyncio
import logging
import signal
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Setup paths
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))

# Import core components
from config.settings import config_manager, config
from core.database_manager import DatabaseManager
from core.service_orchestrator import ServiceOrchestrator

# Flask and API components
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from functools import wraps
import threading
import time

# Setup professional logging
def setup_logging():
    """Setup comprehensive logging system"""
    log_dir = Path(config.storage.logs_path)
    log_dir.mkdir(exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'soc_platform.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set specific log levels
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    return logging.getLogger('SOC-Platform')

logger = setup_logging()

class SOCPlatformBackend:
    """Main SOC Platform Backend Application"""
    
    def __init__(self):
        self.config = config
        self.db_manager = None
        self.service_orchestrator = None
        self.flask_app = None
        self.running = False
        self.startup_time = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info(f"SOC Platform Backend initializing...")
        logger.info(f"Environment: {self.config.environment}")
        logger.info(f"Version: {self.config.version}")
    
    async def initialize(self) -> bool:
        """Initialize all platform components"""
        try:
            logger.info("Initializing SOC Platform components...")
            
            # 1. Initialize Database Manager
            logger.info("Initializing Database Manager...")
            self.db_manager = DatabaseManager(self.config)
            logger.info("Database Manager initialized successfully")
            
            # 2. Initialize Service Orchestrator
            logger.info("Initializing Service Orchestrator...")
            self.service_orchestrator = ServiceOrchestrator(self.config, self.db_manager)
            logger.info("Service Orchestrator initialized successfully")
            
            # 3. Initialize Flask Application
            logger.info("Initializing Flask Application...")
            self.flask_app = self._create_flask_app()
            logger.info("Flask Application initialized successfully")
            
            # 4. Create required directories
            self._create_directories()
            
            logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize platform: {e}")
            return False
    
    def _create_directories(self):
        """Create required directories"""
        directories = [
            self.config.storage.golden_images_path,
            self.config.storage.logs_path,
            self.config.storage.checkpoints_path,
            "backups",
            "config"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created directory: {directory}")
    
    def _create_flask_app(self) -> Flask:
        """Create and configure Flask application"""
        app = Flask(__name__)
        CORS(app)
        
        # Configure Flask
        app.config['MAX_CONTENT_LENGTH'] = self.config.server.max_content_length
        app.config['JSON_SORT_KEYS'] = False
        
        # Register blueprints and routes
        self._register_routes(app)
        
        # Register error handlers
        self._register_error_handlers(app)
        
        # Register middleware
        self._register_middleware(app)
        
        return app
    
    def _register_routes(self, app: Flask):
        """Register all API routes"""
        
        # ============= CORE PLATFORM ROUTES =============
        
        @app.route('/api/backend/', methods=['GET'])
        def root():
            """Platform information and status"""
            return jsonify({
                'platform': self.config.platform_name,
                'version': self.config.version,
                'environment': self.config.environment,
                'status': 'operational' if self.running else 'starting',
                'uptime': (datetime.now() - self.startup_time).total_seconds() if self.startup_time else 0,
                'services': self.service_orchestrator.get_service_status() if self.service_orchestrator else {},
                'endpoints': {
                    'health': '/api/backend/health',
                    'services': '/api/backend/services',
                    'agents': '/api/backend/agents',
                    'network_topology': '/api/backend/network-topology',
                    'software_download': '/api/backend/software-download',
                    'attack': '/api/backend/attack',
                    'detection': '/api/backend/detection'
                },
                'authentication': {
                    'user_auth_available': True,
                    'endpoints': {
                        'register': '/api/auth/auth/register',
                        'login': '/api/auth/auth/login',
                        'profile': '/api/auth/auth/profile'
                    }
                }
            })
        
        @app.route('/api/backend/health', methods=['GET'])
        def health():
            """Comprehensive health check"""
            try:
                # Get service status
                service_status = self.service_orchestrator.get_service_status() if self.service_orchestrator else {}
                
                # Get database stats
                db_stats = self.db_manager.get_database_stats() if self.db_manager else {}
                
                # Calculate overall health
                all_services_healthy = all(
                    service['health']['status'] in ['running', 'stopped'] 
                    for service in service_status.values()
                )
                
                return jsonify({
                    'status': 'healthy' if all_services_healthy else 'degraded',
                    'timestamp': datetime.now().isoformat(),
                    'uptime': (datetime.now() - self.startup_time).total_seconds() if self.startup_time else 0,
                    'services': service_status,
                    'database': db_stats,
                    'environment': self.config.environment,
                    'version': self.config.version
                })
                
            except Exception as e:
                logger.error(f"Health check error: {e}")
                return jsonify({
                    'status': 'error',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }), 500
        
        @app.route('/api/backend/services', methods=['GET'])
        def get_services():
            """Get detailed service information"""
            if not self.service_orchestrator:
                return jsonify({'error': 'Service orchestrator not available'}), 503
            
            return jsonify({
                'services': self.service_orchestrator.get_service_status(),
                'total_services': len(self.service_orchestrator.services),
                'timestamp': datetime.now().isoformat()
            })
        
        @app.route('/api/backend/services/<service_name>/restart', methods=['POST'])
        async def restart_service(service_name):
            """Restart a specific service"""
            if not self.service_orchestrator:
                return jsonify({'error': 'Service orchestrator not available'}), 503
            
            success = await self.service_orchestrator.restart_service(service_name)
            
            if success:
                return jsonify({
                    'success': True,
                    'message': f'Service {service_name} restarted successfully'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Failed to restart service {service_name}'
                }), 500
        
        # ============= CLIENT AGENT MANAGEMENT =============
        
        @app.route('/api/backend/agent/register', methods=['POST'])
        def register_agent():
            """Register new client agent endpoint"""
            try:
                data = request.get_json()
                
                if not data:
                    return jsonify({'error': 'Request body required'}), 400
                
                # Validate required fields
                required_fields = ['hostname', 'ip_address', 'os_type']
                for field in required_fields:
                    if field not in data:
                        return jsonify({'error': f'Missing required field: {field}'}), 400
                
                # Generate endpoint ID
                import uuid
                endpoint_id = f"ep_{uuid.uuid4().hex[:8]}"
                
                # Insert into database
                self.db_manager.execute_insert('topology', '''
                    INSERT INTO endpoints (
                        id, hostname, ip_address, mac_address, os_type, os_version,
                        agent_version, network_zone, importance, user_id, organization_id, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    endpoint_id,
                    data['hostname'],
                    data['ip_address'],
                    data.get('mac_address'),
                    data['os_type'],
                    data.get('os_version'),
                    data.get('agent_version', '1.0.0'),
                    data.get('network_zone', 'internal'),
                    data.get('importance', 'medium'),
                    data.get('user_id'),
                    data.get('organization_id'),
                    str(data.get('metadata', {}))
                ))
                
                logger.info(f"Registered new endpoint: {endpoint_id} ({data['hostname']})")
                
                return jsonify({
                    'success': True,
                    'endpoint_id': endpoint_id,
                    'message': 'Endpoint registered successfully'
                }), 201
                
            except Exception as e:
                logger.error(f"Error registering agent: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @app.route('/api/backend/agent/heartbeat', methods=['POST'])
        def agent_heartbeat():
            """Receive heartbeat from client agent"""
            try:
                data = request.get_json()
                endpoint_id = data.get('endpoint_id')
                
                if not endpoint_id:
                    return jsonify({'error': 'endpoint_id required'}), 400
                
                # Update last seen timestamp
                self.db_manager.execute_update('topology', '''
                    UPDATE endpoints 
                    SET last_seen = CURRENT_TIMESTAMP, status = ?
                    WHERE id = ?
                ''', ('online', endpoint_id))
                
                return jsonify({
                    'success': True,
                    'message': 'Heartbeat received',
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error processing heartbeat: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @app.route('/api/backend/agent/logs', methods=['POST'])
        def receive_logs():
            """Receive logs from client agent for analysis"""
            try:
                from api_client_agent_logs import ClientAgentLogProcessor
                from api_structures import APIStructures
                
                data = request.get_json()
                if not data:
                    return jsonify(APIStructures.create_standard_response(
                        success=False,
                        error="No data provided",
                        error_code="MISSING_DATA"
                    )), 400
                
                # Initialize log processor
                log_processor = ClientAgentLogProcessor(self.db_manager)
                
                # Process logs
                result = log_processor.receive_agent_logs(data)
                
                # Return appropriate HTTP status
                if result['success']:
                    return jsonify(result), 200
                else:
                    status_code = 400 if 'MISSING' in result.get('error_code', '') else 500
                    return jsonify(result), status_code
                
            except Exception as e:
                logger.error(f"Error receiving logs: {e}")
                return jsonify(APIStructures.create_standard_response(
                    success=False,
                    error="Internal server error",
                    error_code="INTERNAL_ERROR"
                )), 500
        
        # ============= NETWORK TOPOLOGY =============
        
        @app.route('/api/backend/network-topology', methods=['GET'])
        def get_network_topology():
            """Get current network topology"""
            try:
                hierarchy = request.args.get('hierarchy', 'desc')
                
                # Get endpoints from database
                endpoints = self.db_manager.execute_query('topology', '''
                    SELECT id, hostname, ip_address, os_type, status, network_zone, importance, last_seen
                    FROM endpoints
                    ORDER BY last_seen DESC
                ''')
                
                # Create network nodes
                nodes = []
                for endpoint in endpoints:
                    nodes.append({
                        'id': endpoint['id'],
                        'name': endpoint['hostname'],
                        'type': 'endpoint',
                        'ip': endpoint['ip_address'],
                        'os': endpoint['os_type'],
                        'status': endpoint['status'],
                        'zone': endpoint['network_zone'],
                        'importance': endpoint['importance'],
                        'last_seen': endpoint['last_seen'],
                        'hierarchy_level': self._get_hierarchy_level(endpoint['network_zone'])
                    })
                
                # Sort by hierarchy
                if hierarchy == 'desc':
                    nodes.sort(key=lambda x: x['hierarchy_level'], reverse=True)
                else:
                    nodes.sort(key=lambda x: x['hierarchy_level'])
                
                # Get connections
                connections = self.db_manager.execute_query('topology', '''
                    SELECT source_endpoint, target_endpoint, connection_type, port, protocol
                    FROM network_topology
                    WHERE status = 'active'
                ''')
                
                return jsonify({
                    'nodes': nodes,
                    'connections': [
                        {
                            'source': conn['source_endpoint'],
                            'target': conn['target_endpoint'],
                            'type': conn['connection_type'],
                            'port': conn['port'],
                            'protocol': conn['protocol']
                        }
                        for conn in connections
                    ],
                    'hierarchy_order': hierarchy,
                    'total_endpoints': len(nodes),
                    'online_endpoints': len([n for n in nodes if n['status'] == 'online']),
                    'offline_endpoints': len([n for n in nodes if n['status'] == 'offline']),
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error getting network topology: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @app.route('/api/backend/endpoints', methods=['GET'])
        def list_endpoints():
            """List all registered endpoints"""
            try:
                endpoints = self.db_manager.execute_query('topology', '''
                    SELECT id, hostname, ip_address, os_type, status, importance, last_seen, network_zone
                    FROM endpoints
                    ORDER BY last_seen DESC
                ''')
                
                return jsonify([
                    {
                        'id': ep['id'],
                        'hostname': ep['hostname'],
                        'ip': ep['ip_address'],
                        'os': ep['os_type'],
                        'status': ep['status'],
                        'importance': ep['importance'],
                        'last_seen': ep['last_seen'],
                        'zone': ep['network_zone']
                    }
                    for ep in endpoints
                ])
                
            except Exception as e:
                logger.error(f"Error listing endpoints: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        # ============= SOFTWARE DOWNLOADS =============
        
        @app.route('/api/backend/software-download', methods=['GET'])
        def software_download():
            """Get available client agents for download"""
            from api_structures import SoftwareDownload
            from dataclasses import asdict
            
            # Get software configurations from config
            software_configs = [
                {
                    "id": 1,
                    "name": "windows",
                    "os": "Windows",
                    "architecture": "x64",
                    "min_ram_gb": 4,
                    "min_disk_mb": 500,
                    "system_requirements": [
                        "Windows 10/11 (64-bit)",
                        "Administrator privileges",
                        "4 GB RAM",
                        "500 MB disk space"
                    ]
                },
                {
                    "id": 2,
                    "name": "linux",
                    "os": "Linux", 
                    "architecture": "x64",
                    "min_ram_gb": 2,
                    "min_disk_mb": 300,
                    "system_requirements": [
                        "Ubuntu 18.04+ / CentOS 7+ / RHEL 8+",
                        "Root access",
                        "2 GB RAM",
                        "300 MB disk space"
                    ]
                },
                {
                    "id": 3,
                    "name": "macos",
                    "os": "macOS",
                    "architecture": "universal",
                    "min_ram_gb": 3,
                    "min_disk_mb": 400,
                    "system_requirements": [
                        "macOS 11.0+",
                        "Administrator privileges", 
                        "3 GB RAM",
                        "400 MB disk space"
                    ]
                }
            ]
            
            downloads = []
            for sw_config in software_configs:
                download = SoftwareDownload(
                    id=sw_config["id"],
                    name=sw_config["name"],
                    version=self.config.version,
                    description=f"{sw_config['os']} endpoint agent with real-time monitoring, behavioral analysis, and AI-powered threat detection.",
                    file_name=f"{self.config.platform_name} Endpoint Agent",
                    download_url=f"{config.external_services.download_base_url}/{sw_config['name']}.zip",
                    os=sw_config["os"],
                    architecture=sw_config["architecture"],
                    min_ram_gb=sw_config["min_ram_gb"],
                    min_disk_mb=sw_config["min_disk_mb"],
                    configuration_cmd=f"codegrey-agent --configure --server={config.external_services.client_server_url} --token=YOUR_API_TOKEN",
                    system_requirements=sw_config["system_requirements"]
                )
                downloads.append(asdict(download))
            
            return jsonify(downloads)
        
        # ============= AI AGENTS =============
        
        @app.route('/api/backend/agents', methods=['GET'])
        def list_agents():
            """List AI agents with current status"""
            service_status = self.service_orchestrator.get_service_status() if self.service_orchestrator else {}
            
            agents = [
                {
                    "id": "1",
                    "name": "PhantomStrike AI",
                    "type": "attack",
                    "status": service_status.get('phantom_strike', {}).get('status', 'stopped'),
                    "location": "External Network",
                    "lastActivity": "2 mins ago" if service_status.get('phantom_strike', {}).get('status') == 'running' else "Not Active",
                    "capabilities": [
                        "Email Simulation",
                        "Web Exploitation", 
                        "Social Engineering",
                        "Lateral Movement",
                        "Persistence Testing"
                    ],
                    "enabled": service_status.get('phantom_strike', {}).get('status') == 'running'
                },
                {
                    "id": "2",
                    "name": "GuardianAlpha AI",
                    "type": "detection",
                    "status": service_status.get('guardian_alpha', {}).get('status', 'stopped'),
                    "location": "SOC Infrastructure",
                    "lastActivity": "Now" if service_status.get('guardian_alpha', {}).get('status') == 'running' else "Not Active",
                    "capabilities": [
                        "Behavioral Analysis",
                        "Signature Detection",
                        "Threat Hunting",
                        "ML-based Detection",
                        "Anomaly Correlation"
                    ],
                    "enabled": service_status.get('guardian_alpha', {}).get('status') == 'running'
                },
                {
                    "id": "3",
                    "name": "Network Scanner",
                    "type": "scanner",
                    "status": service_status.get('network_scanner', {}).get('status', 'stopped'),
                    "location": "Network Infrastructure",
                    "lastActivity": "5 mins ago" if service_status.get('network_scanner', {}).get('status') == 'running' else "Not Active",
                    "capabilities": [
                        "Network Discovery",
                        "Port Scanning",
                        "Service Detection",
                        "Topology Mapping",
                        "Vulnerability Assessment"
                    ],
                    "enabled": service_status.get('network_scanner', {}).get('status') == 'running'
                }
            ]
            
            return jsonify(agents)
    
    def _get_hierarchy_level(self, zone: str) -> int:
        """Get hierarchy level for network zone"""
        zone_levels = {
            'external': 0,
            'dmz': 1,
            'internal': 2,
            'management': 3
        }
        return zone_levels.get(zone, 1)
    
    def _register_error_handlers(self, app: Flask):
        """Register error handlers"""
        
        @app.errorhandler(404)
        def not_found(error):
            return jsonify({
                'error': 'Endpoint not found',
                'message': 'The requested endpoint does not exist',
                'status_code': 404
            }), 404
        
        @app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal server error: {error}")
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred',
                'status_code': 500
            }), 500
        
        @app.errorhandler(Exception)
        def handle_exception(e):
            logger.error(f"Unhandled exception: {e}")
            return jsonify({
                'error': 'Unexpected error',
                'message': str(e),
                'status_code': 500
            }), 500
    
    def _register_middleware(self, app: Flask):
        """Register middleware"""
        
        @app.before_request
        def before_request():
            """Before request middleware"""
            g.request_start_time = time.time()
            g.request_id = f"req_{int(time.time() * 1000)}"
        
        @app.after_request
        def after_request(response):
            """After request middleware"""
            if hasattr(g, 'request_start_time'):
                response_time = time.time() - g.request_start_time
                response.headers['X-Response-Time'] = f"{response_time:.3f}s"
                response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')
            
            return response
    
    async def start(self) -> bool:
        """Start the SOC Platform"""
        try:
            logger.info("Starting SOC Platform Backend...")
            self.startup_time = datetime.now()
            
            # Initialize platform
            if not await self.initialize():
                return False
            
            # Start all services
            if not await self.service_orchestrator.start_all_services():
                logger.error("Failed to start services")
                return False
            
            self.running = True
            
            # Start Flask app in a separate thread
            flask_thread = threading.Thread(
                target=self._run_flask_app,
                daemon=True
            )
            flask_thread.start()
            
            logger.info("="*80)
            logger.info(f" {self.config.platform_name}")
            logger.info("="*80)
            logger.info(f" Environment: {self.config.environment}")
            logger.info(f" Version: {self.config.version}")
            logger.info(f" Server: http://{self.config.server.host}:{self.config.server.port}")
            logger.info(f" API Base: http://{self.config.server.host}:{self.config.server.port}/api/backend/")
            logger.info("="*80)
            logger.info(" Services Status:")
            
            service_status = self.service_orchestrator.get_service_status()
            for name, status in service_status.items():
                logger.info(f"   {name}: {status['status'].upper()}")
            
            logger.info("="*80)
            logger.info(" SOC Platform Backend started successfully!")
            logger.info("="*80)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start SOC Platform: {e}")
            return False
    
    def _run_flask_app(self):
        """Run Flask application"""
        try:
            self.flask_app.run(
                host=self.config.server.host,
                port=self.config.server.port,
                debug=self.config.server.debug,
                threaded=True,
                use_reloader=False
            )
        except Exception as e:
            logger.error(f"Flask app error: {e}")
    
    async def stop(self):
        """Stop the SOC Platform"""
        try:
            logger.info("Stopping SOC Platform Backend...")
            
            self.running = False
            
            # Stop services
            if self.service_orchestrator:
                await self.service_orchestrator.stop_all_services()
            
            # Close database connections
            if self.db_manager:
                self.db_manager.close()
            
            logger.info("SOC Platform Backend stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping platform: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(self.stop())
        sys.exit(0)

# ============= MAIN ENTRY POINT =============

async def main():
    """Main entry point"""
    try:
        # Create and start SOC Platform
        platform = SOCPlatformBackend()
        
        success = await platform.start()
        if not success:
            logger.error("Failed to start SOC Platform")
            sys.exit(1)
        
        # Keep running
        try:
            while platform.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutdown requested by user")
        finally:
            await platform.stop()
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    # Save default configuration
    config_manager.save_config()
    
    # Run the platform
    asyncio.run(main())
