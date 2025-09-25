#!/usr/bin/env python3
"""
Production Database Creation Script
Creates all required databases with proper schema and minimal dummy data
Only users table will have dummy values for testing - all other tables empty
"""

import sqlite3
import json
import hashlib
import uuid
import secrets
from datetime import datetime
from pathlib import Path
import bcrypt
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProductionDatabaseCreator:
    """Creates production-ready databases with proper schema"""
    
    def __init__(self):
        self.databases = {
            'soc_main.db': self._create_main_database,
            'network_topology.db': self._create_topology_database,
            'agent_logs.db': self._create_logs_database,
            'soc_users.db': self._create_users_database
        }
        
    def create_all_databases(self):
        """Create all production databases"""
        logger.info("Creating production databases...")
        
        for db_name, create_func in self.databases.items():
            logger.info(f"Creating {db_name}...")
            create_func(db_name)
            logger.info(f"✓ {db_name} created successfully")
        
        logger.info("All production databases created successfully!")
        self._print_database_info()
    
    def _create_main_database(self, db_path: str):
        """Create main SOC database with attack scenarios, detections, etc."""
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Attack scenarios table
        c.execute('''
            CREATE TABLE IF NOT EXISTS attack_scenarios (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                topology_elements TEXT,
                techniques TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT,
                approved_by TEXT,
                approved_at TIMESTAMP,
                executed_at TIMESTAMP,
                completed_at TIMESTAMP,
                results TEXT,
                target_endpoints TEXT,
                attack_type TEXT,
                complexity TEXT DEFAULT 'medium',
                estimated_duration INTEGER DEFAULT 3600
            )
        ''')
        
        # Detections table
        c.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                verdict TEXT NOT NULL,
                reasoning TEXT,
                source_endpoint TEXT,
                details TEXT,
                status TEXT DEFAULT 'new',
                assigned_to TEXT,
                resolved_at TIMESTAMP,
                resolution_notes TEXT,
                ml_model_used TEXT,
                processing_time REAL,
                false_positive BOOLEAN DEFAULT 0
            )
        ''')
        
        # Golden images table
        c.execute('''
            CREATE TABLE IF NOT EXISTS golden_images (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                scenario_id TEXT,
                image_path TEXT NOT NULL,
                image_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT,
                size_bytes INTEGER,
                compression_type TEXT DEFAULT 'gzip',
                backup_type TEXT DEFAULT 'full',
                restore_tested BOOLEAN DEFAULT 0
            )
        ''')
        
        # System events table
        c.execute('''
            CREATE TABLE IF NOT EXISTS system_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                severity TEXT DEFAULT 'info',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                session_id TEXT,
                ip_address TEXT,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        # Incident response table
        c.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                assigned_to TEXT,
                resolved_at TIMESTAMP,
                resolution_summary TEXT,
                related_detections TEXT,
                impact_assessment TEXT,
                lessons_learned TEXT
            )
        ''')
        
        # Create indexes for performance
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_attack_scenarios_status ON attack_scenarios(status)',
            'CREATE INDEX IF NOT EXISTS idx_attack_scenarios_created_at ON attack_scenarios(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity)',
            'CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status)',
            'CREATE INDEX IF NOT EXISTS idx_detections_verdict ON detections(verdict)',
            'CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type)',
            'CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)',
            'CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)'
        ]
        
        for index in indexes:
            c.execute(index)
        
        conn.commit()
        conn.close()
    
    def _create_topology_database(self, db_path: str):
        """Create network topology database"""
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Endpoints table
        c.execute('''
            CREATE TABLE IF NOT EXISTS endpoints (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                os_type TEXT NOT NULL,
                os_version TEXT,
                agent_version TEXT,
                status TEXT DEFAULT 'offline',
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                capabilities TEXT,
                network_zone TEXT DEFAULT 'internal',
                importance TEXT DEFAULT 'medium',
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                organization_id TEXT,
                metadata TEXT,
                vulnerability_score REAL DEFAULT 0.0,
                patch_level TEXT,
                security_tools TEXT
            )
        ''')
        
        # Network topology connections
        c.execute('''
            CREATE TABLE IF NOT EXISTS network_topology (
                id TEXT PRIMARY KEY,
                source_endpoint TEXT NOT NULL,
                target_endpoint TEXT NOT NULL,
                connection_type TEXT NOT NULL,
                port INTEGER,
                protocol TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                metadata TEXT,
                bandwidth_usage REAL DEFAULT 0.0,
                latency_ms REAL DEFAULT 0.0
            )
        ''')
        
        # Network zones
        c.execute('''
            CREATE TABLE IF NOT EXISTS network_zones (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                cidr_range TEXT,
                security_level TEXT DEFAULT 'medium',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                policies TEXT,
                metadata TEXT,
                monitoring_enabled BOOLEAN DEFAULT 1,
                isolation_rules TEXT
            )
        ''')
        
        # Network services
        c.execute('''
            CREATE TABLE IF NOT EXISTS network_services (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                service_name TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                version TEXT,
                status TEXT DEFAULT 'running',
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                vulnerabilities TEXT,
                configuration TEXT,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints (id)
            )
        ''')
        
        # Insert default network zones (empty tables, but zones are configuration)
        default_zones = [
            ('zone_internal', 'internal', 'Internal corporate network', '10.0.0.0/8', 'high'),
            ('zone_dmz', 'dmz', 'Demilitarized zone', '192.168.1.0/24', 'medium'),
            ('zone_external', 'external', 'External/Internet facing', '0.0.0.0/0', 'low'),
            ('zone_management', 'management', 'Management network', '172.16.0.0/12', 'critical')
        ]
        
        for zone_id, name, description, cidr, security_level in default_zones:
            c.execute('''
                INSERT OR IGNORE INTO network_zones (id, name, description, cidr_range, security_level)
                VALUES (?, ?, ?, ?, ?)
            ''', (zone_id, name, description, cidr, security_level))
        
        # Create indexes
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status)',
            'CREATE INDEX IF NOT EXISTS idx_endpoints_zone ON endpoints(network_zone)',
            'CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen)',
            'CREATE INDEX IF NOT EXISTS idx_endpoints_ip ON endpoints(ip_address)',
            'CREATE INDEX IF NOT EXISTS idx_topology_source ON network_topology(source_endpoint)',
            'CREATE INDEX IF NOT EXISTS idx_topology_target ON network_topology(target_endpoint)',
            'CREATE INDEX IF NOT EXISTS idx_services_endpoint ON network_services(endpoint_id)',
            'CREATE INDEX IF NOT EXISTS idx_services_port ON network_services(port)'
        ]
        
        for index in indexes:
            c.execute(index)
        
        conn.commit()
        conn.close()
    
    def _create_logs_database(self, db_path: str):
        """Create agent logs database"""
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Agent logs table
        c.execute('''
            CREATE TABLE IF NOT EXISTS agent_logs (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                log_level TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                raw_data TEXT,
                processed BOOLEAN DEFAULT 0,
                threat_score REAL DEFAULT 0.0,
                classification TEXT,
                metadata TEXT,
                file_hash TEXT,
                process_id INTEGER,
                parent_process_id INTEGER,
                command_line TEXT,
                network_connection TEXT
            )
        ''')
        
        # Detection results table
        c.execute('''
            CREATE TABLE IF NOT EXISTS detection_results (
                id TEXT PRIMARY KEY,
                log_id TEXT NOT NULL,
                detection_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                verdict TEXT NOT NULL,
                reasoning TEXT,
                model_used TEXT,
                processing_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                mitre_techniques TEXT,
                iocs_extracted TEXT,
                risk_score REAL DEFAULT 0.0,
                FOREIGN KEY (log_id) REFERENCES agent_logs (id)
            )
        ''')
        
        # Log processing queue
        c.execute('''
            CREATE TABLE IF NOT EXISTS log_processing_queue (
                id TEXT PRIMARY KEY,
                log_id TEXT NOT NULL,
                priority INTEGER DEFAULT 5,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT,
                retry_count INTEGER DEFAULT 0,
                worker_id TEXT,
                processing_time REAL,
                FOREIGN KEY (log_id) REFERENCES agent_logs (id)
            )
        ''')
        
        # ML model performance tracking
        c.execute('''
            CREATE TABLE IF NOT EXISTS ml_model_performance (
                id TEXT PRIMARY KEY,
                model_name TEXT NOT NULL,
                version TEXT NOT NULL,
                accuracy REAL,
                precision_score REAL,
                recall REAL,
                f1_score REAL,
                false_positive_rate REAL,
                evaluation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                dataset_size INTEGER,
                notes TEXT
            )
        ''')
        
        # Create indexes
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_agent_logs_endpoint ON agent_logs(endpoint_id)',
            'CREATE INDEX IF NOT EXISTS idx_agent_logs_timestamp ON agent_logs(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_agent_logs_processed ON agent_logs(processed)',
            'CREATE INDEX IF NOT EXISTS idx_agent_logs_threat_score ON agent_logs(threat_score)',
            'CREATE INDEX IF NOT EXISTS idx_detection_results_log ON detection_results(log_id)',
            'CREATE INDEX IF NOT EXISTS idx_detection_results_verdict ON detection_results(verdict)',
            'CREATE INDEX IF NOT EXISTS idx_queue_status ON log_processing_queue(status)',
            'CREATE INDEX IF NOT EXISTS idx_queue_priority ON log_processing_queue(priority)'
        ]
        
        for index in indexes:
            c.execute(index)
        
        conn.commit()
        conn.close()
    
    def _create_users_database(self, db_path: str):
        """Create users database with dummy SOC personnel"""
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # SOC users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS soc_users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT,
                role TEXT DEFAULT 'analyst',
                organization TEXT NOT NULL,
                department TEXT,
                api_key TEXT UNIQUE NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                created_by TEXT,
                metadata TEXT,
                phone TEXT,
                timezone TEXT DEFAULT 'UTC',
                preferences TEXT
            )
        ''')
        
        # User sessions table
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                jwt_token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                is_active BOOLEAN DEFAULT 1,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                device_fingerprint TEXT,
                FOREIGN KEY (user_id) REFERENCES soc_users (id)
            )
        ''')
        
        # User roles table
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_roles (
                id TEXT PRIMARY KEY,
                role_name TEXT UNIQUE NOT NULL,
                permissions TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                hierarchy_level INTEGER DEFAULT 1
            )
        ''')
        
        # API key usage tracking
        c.execute('''
            CREATE TABLE IF NOT EXISTS api_key_usage (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                api_key TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                success BOOLEAN DEFAULT 1,
                response_time REAL,
                request_size INTEGER,
                response_size INTEGER,
                FOREIGN KEY (user_id) REFERENCES soc_users (id)
            )
        ''')
        
        # User audit log
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_audit_log (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                success BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES soc_users (id)
            )
        ''')
        
        # Insert default roles
        default_roles = [
            ('role_admin', 'admin', '["user_management", "attack_control", "detection_control", "system_config", "view_all_data", "manage_agents", "audit_access"]', 'Full system administrator', 5),
            ('role_soc_manager', 'soc_manager', '["attack_control", "detection_control", "view_all_data", "manage_team", "incident_response", "report_generation"]', 'SOC Manager with team oversight', 4),
            ('role_senior_analyst', 'senior_analyst', '["attack_control", "detection_control", "incident_response", "view_team_data", "advanced_analysis", "threat_hunting"]', 'Senior SOC Analyst', 3),
            ('role_analyst', 'analyst', '["detection_view", "incident_response", "basic_analysis", "log_analysis"]', 'SOC Analyst', 2),
            ('role_viewer', 'viewer', '["detection_view", "dashboard_view", "report_view"]', 'Read-only access', 1)
        ]
        
        for role_id, role_name, permissions, description, level in default_roles:
            c.execute('''
                INSERT OR IGNORE INTO user_roles (id, role_name, permissions, description, hierarchy_level)
                VALUES (?, ?, ?, ?, ?)
            ''', (role_id, role_name, permissions, description, level))
        
        # Create dummy SOC users for testing
        dummy_users = [
            {
                'email': 'admin@codegrey.ai',
                'password': 'SecureAdmin123!',
                'first_name': 'System',
                'last_name': 'Administrator',
                'role': 'admin',
                'organization': 'CodeGrey Inc',
                'department': 'IT Security'
            },
            {
                'email': 'soc.manager@codegrey.ai',
                'password': 'SOCManager456!',
                'first_name': 'Sarah',
                'last_name': 'Johnson',
                'role': 'soc_manager',
                'organization': 'CodeGrey Inc',
                'department': 'SOC Operations'
            },
            {
                'email': 'senior.analyst@codegrey.ai',
                'password': 'SeniorAnalyst789!',
                'first_name': 'Michael',
                'last_name': 'Chen',
                'role': 'senior_analyst',
                'organization': 'CodeGrey Inc',
                'department': 'Threat Analysis'
            },
            {
                'email': 'analyst@codegrey.ai',
                'password': 'Analyst123!',
                'first_name': 'Emma',
                'last_name': 'Davis',
                'role': 'analyst',
                'organization': 'CodeGrey Inc',
                'department': 'SOC Operations'
            },
            {
                'email': 'viewer@codegrey.ai',
                'password': 'Viewer456!',
                'first_name': 'John',
                'last_name': 'Smith',
                'role': 'viewer',
                'organization': 'CodeGrey Inc',
                'department': 'Management'
            }
        ]
        
        for user_data in dummy_users:
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            api_key = f"soc_{secrets.token_urlsafe(32)}"
            
            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(
                user_data['password'].encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            
            c.execute('''
                INSERT OR IGNORE INTO soc_users (
                    id, email, password_hash, first_name, last_name,
                    role, organization, department, api_key, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                user_data['email'],
                password_hash,
                user_data['first_name'],
                user_data['last_name'],
                user_data['role'],
                user_data['organization'],
                user_data['department'],
                api_key,
                'system_init'
            ))
        
        # Create indexes
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_users_email ON soc_users(email)',
            'CREATE INDEX IF NOT EXISTS idx_users_api_key ON soc_users(api_key)',
            'CREATE INDEX IF NOT EXISTS idx_users_role ON soc_users(role)',
            'CREATE INDEX IF NOT EXISTS idx_users_active ON soc_users(is_active)',
            'CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(is_active)',
            'CREATE INDEX IF NOT EXISTS idx_api_usage_user ON api_key_usage(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_key_usage(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_audit_user ON user_audit_log(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON user_audit_log(timestamp)'
        ]
        
        for index in indexes:
            c.execute(index)
        
        conn.commit()
        conn.close()
    
    def _print_database_info(self):
        """Print information about created databases"""
        print("\n" + "="*80)
        print(" PRODUCTION DATABASES CREATED")
        print("="*80)
        
        for db_name in self.databases.keys():
            if Path(db_name).exists():
                size_mb = Path(db_name).stat().st_size / (1024 * 1024)
                print(f" • {db_name:<25} - {size_mb:.2f} MB")
        
        print("\n" + "="*80)
        print(" DUMMY USERS CREATED (for testing only)")
        print("="*80)
        
        # Show dummy users
        conn = sqlite3.connect('soc_users.db')
        c = conn.cursor()
        c.execute('SELECT email, role, first_name, last_name FROM soc_users ORDER BY role DESC')
        users = c.fetchall()
        conn.close()
        
        for email, role, first_name, last_name in users:
            print(f" • {email:<30} - {role:<15} ({first_name} {last_name})")
        
        print("\n" + "="*80)
        print(" READY FOR PRODUCTION DEPLOYMENT")
        print("="*80)
        print(" • All databases have proper schema")
        print(" • Only users table has dummy data for testing")
        print(" • All other tables are empty and ready for real data")
        print(" • Indexes created for optimal performance")
        print("="*80 + "\n")

def main():
    """Main function to create production databases"""
    print("Creating Production Databases for SOC Platform...")
    print("This will create empty databases with proper schema")
    print("Only the users database will have dummy data for testing\n")
    
    creator = ProductionDatabaseCreator()
    creator.create_all_databases()
    
    print("Database creation completed successfully!")
    print("You can now migrate these databases to your server.")

if __name__ == '__main__':
    main()
