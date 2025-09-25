"""
Database Manager
Centralized database management for SOC Platform
Professional database handling with connection pooling, migrations, and backup
"""

import sqlite3
import logging
import threading
import time
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class DatabaseSchema:
    """Database schema definition"""
    name: str
    tables: Dict[str, str]
    indexes: List[str] = None
    version: str = "1.0.0"

class DatabaseManager:
    """Centralized database management system"""
    
    def __init__(self, config):
        self.config = config
        self.connections = {}
        self.connection_locks = {}
        self.schemas = self._define_schemas()
        self.backup_thread = None
        self.backup_running = False
        
        # Initialize databases
        self._initialize_all_databases()
        
        # Start backup thread if configured
        if config.database.backup_interval > 0:
            self._start_backup_thread()
    
    def _define_schemas(self) -> Dict[str, DatabaseSchema]:
        """Define all database schemas"""
        return {
            'main': DatabaseSchema(
                name='main',
                tables={
                    'attack_scenarios': '''
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
                            results TEXT
                        )
                    ''',
                    'detections': '''
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
                            resolution_notes TEXT
                        )
                    ''',
                    'golden_images': '''
                        CREATE TABLE IF NOT EXISTS golden_images (
                            id TEXT PRIMARY KEY,
                            endpoint_id TEXT NOT NULL,
                            scenario_id TEXT,
                            image_path TEXT NOT NULL,
                            image_hash TEXT NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            metadata TEXT,
                            size_bytes INTEGER,
                            compression_type TEXT DEFAULT 'gzip'
                        )
                    ''',
                    'system_events': '''
                        CREATE TABLE IF NOT EXISTS system_events (
                            id TEXT PRIMARY KEY,
                            event_type TEXT NOT NULL,
                            source TEXT NOT NULL,
                            message TEXT NOT NULL,
                            details TEXT,
                            severity TEXT DEFAULT 'info',
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            user_id TEXT,
                            session_id TEXT
                        )
                    '''
                },
                indexes=[
                    'CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp)',
                    'CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity)',
                    'CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status)',
                    'CREATE INDEX IF NOT EXISTS idx_attack_scenarios_status ON attack_scenarios(status)',
                    'CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp)',
                    'CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type)'
                ]
            ),
            
            'topology': DatabaseSchema(
                name='topology',
                tables={
                    'endpoints': '''
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
                            metadata TEXT
                        )
                    ''',
                    'network_topology': '''
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
                            metadata TEXT
                        )
                    ''',
                    'network_zones': '''
                        CREATE TABLE IF NOT EXISTS network_zones (
                            id TEXT PRIMARY KEY,
                            name TEXT UNIQUE NOT NULL,
                            description TEXT,
                            cidr_range TEXT,
                            security_level TEXT DEFAULT 'medium',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            policies TEXT,
                            metadata TEXT
                        )
                    '''
                },
                indexes=[
                    'CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status)',
                    'CREATE INDEX IF NOT EXISTS idx_endpoints_zone ON endpoints(network_zone)',
                    'CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen)',
                    'CREATE INDEX IF NOT EXISTS idx_topology_source ON network_topology(source_endpoint)',
                    'CREATE INDEX IF NOT EXISTS idx_topology_target ON network_topology(target_endpoint)'
                ]
            ),
            
            'logs': DatabaseSchema(
                name='logs',
                tables={
                    'agent_logs': '''
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
                            metadata TEXT
                        )
                    ''',
                    'detection_results': '''
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
                            FOREIGN KEY (log_id) REFERENCES agent_logs (id)
                        )
                    ''',
                    'log_processing_queue': '''
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
                            FOREIGN KEY (log_id) REFERENCES agent_logs (id)
                        )
                    '''
                },
                indexes=[
                    'CREATE INDEX IF NOT EXISTS idx_agent_logs_endpoint ON agent_logs(endpoint_id)',
                    'CREATE INDEX IF NOT EXISTS idx_agent_logs_timestamp ON agent_logs(timestamp)',
                    'CREATE INDEX IF NOT EXISTS idx_agent_logs_processed ON agent_logs(processed)',
                    'CREATE INDEX IF NOT EXISTS idx_detection_results_log ON detection_results(log_id)',
                    'CREATE INDEX IF NOT EXISTS idx_queue_status ON log_processing_queue(status)'
                ]
            ),
            
            'users': DatabaseSchema(
                name='users',
                tables={
                    'soc_users': '''
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
                            metadata TEXT
                        )
                    ''',
                    'user_sessions': '''
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
                            FOREIGN KEY (user_id) REFERENCES soc_users (id)
                        )
                    ''',
                    'user_roles': '''
                        CREATE TABLE IF NOT EXISTS user_roles (
                            id TEXT PRIMARY KEY,
                            role_name TEXT UNIQUE NOT NULL,
                            permissions TEXT NOT NULL,
                            description TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            is_active BOOLEAN DEFAULT 1
                        )
                    ''',
                    'api_key_usage': '''
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
                            FOREIGN KEY (user_id) REFERENCES soc_users (id)
                        )
                    '''
                },
                indexes=[
                    'CREATE INDEX IF NOT EXISTS idx_users_email ON soc_users(email)',
                    'CREATE INDEX IF NOT EXISTS idx_users_api_key ON soc_users(api_key)',
                    'CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)',
                    'CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(is_active)',
                    'CREATE INDEX IF NOT EXISTS idx_api_usage_user ON api_key_usage(user_id)'
                ]
            )
        }
    
    def _initialize_all_databases(self):
        """Initialize all databases with their schemas"""
        for db_name, schema in self.schemas.items():
            self._initialize_database(db_name, schema)
    
    def _initialize_database(self, db_name: str, schema: DatabaseSchema):
        """Initialize a single database"""
        try:
            db_path = getattr(self.config.database, f"{db_name}_db")
            
            # Create connection lock
            self.connection_locks[db_name] = threading.Lock()
            
            with self.get_connection(db_name) as conn:
                cursor = conn.cursor()
                
                # Create tables
                for table_name, table_sql in schema.tables.items():
                    cursor.execute(table_sql)
                    logger.debug(f"Created/verified table {table_name} in {db_name} database")
                
                # Create indexes
                if schema.indexes:
                    for index_sql in schema.indexes:
                        cursor.execute(index_sql)
                        logger.debug(f"Created/verified index in {db_name} database")
                
                # Insert default data if needed
                self._insert_default_data(db_name, cursor)
                
                conn.commit()
                logger.info(f"Database {db_name} initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing database {db_name}: {e}")
            raise
    
    def _insert_default_data(self, db_name: str, cursor):
        """Insert default data for specific databases"""
        if db_name == 'users':
            # Insert default roles
            default_roles = [
                ('admin', '["user_management", "attack_control", "detection_control", "system_config", "view_all_data", "manage_agents"]', 'Full system administrator'),
                ('soc_manager', '["attack_control", "detection_control", "view_all_data", "manage_team", "incident_response"]', 'SOC Manager with team oversight'),
                ('senior_analyst', '["attack_control", "detection_control", "incident_response", "view_team_data", "advanced_analysis"]', 'Senior SOC Analyst'),
                ('analyst', '["detection_view", "incident_response", "basic_analysis"]', 'SOC Analyst'),
                ('viewer', '["detection_view", "dashboard_view"]', 'Read-only access')
            ]
            
            for role_name, permissions, description in default_roles:
                cursor.execute('''
                    INSERT OR IGNORE INTO user_roles (id, role_name, permissions, description)
                    VALUES (?, ?, ?, ?)
                ''', (f"role_{role_name}", role_name, permissions, description))
        
        elif db_name == 'topology':
            # Insert default network zones
            default_zones = [
                ('internal', 'Internal corporate network', '10.0.0.0/8', 'high'),
                ('dmz', 'Demilitarized zone', '192.168.1.0/24', 'medium'),
                ('external', 'External/Internet facing', '0.0.0.0/0', 'low'),
                ('management', 'Management network', '172.16.0.0/12', 'critical')
            ]
            
            for name, description, cidr, security_level in default_zones:
                cursor.execute('''
                    INSERT OR IGNORE INTO network_zones (id, name, description, cidr_range, security_level)
                    VALUES (?, ?, ?, ?, ?)
                ''', (f"zone_{name}", name, description, cidr, security_level))
    
    @contextmanager
    def get_connection(self, db_name: str):
        """Get database connection with proper locking"""
        if db_name not in self.schemas:
            raise ValueError(f"Unknown database: {db_name}")
        
        db_path = getattr(self.config.database, f"{db_name}_db")
        
        with self.connection_locks[db_name]:
            conn = sqlite3.connect(db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            
            try:
                yield conn
            finally:
                conn.close()
    
    def execute_query(self, db_name: str, query: str, params: tuple = None) -> List[sqlite3.Row]:
        """Execute a SELECT query and return results"""
        with self.get_connection(db_name) as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor.fetchall()
    
    def execute_insert(self, db_name: str, query: str, params: tuple = None) -> str:
        """Execute an INSERT query and return the last row ID"""
        with self.get_connection(db_name) as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            conn.commit()
            return cursor.lastrowid
    
    def execute_update(self, db_name: str, query: str, params: tuple = None) -> int:
        """Execute an UPDATE/DELETE query and return affected rows"""
        with self.get_connection(db_name) as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            conn.commit()
            return cursor.rowcount
    
    def backup_database(self, db_name: str, backup_path: Optional[str] = None) -> str:
        """Create a backup of the specified database"""
        if db_name not in self.schemas:
            raise ValueError(f"Unknown database: {db_name}")
        
        db_path = getattr(self.config.database, f"{db_name}_db")
        
        if backup_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"backups/{db_name}_{timestamp}.db"
        
        # Ensure backup directory exists
        Path(backup_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create backup
        shutil.copy2(db_path, backup_path)
        logger.info(f"Database {db_name} backed up to {backup_path}")
        
        return backup_path
    
    def backup_all_databases(self) -> List[str]:
        """Create backups of all databases"""
        backup_paths = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for db_name in self.schemas.keys():
            backup_path = f"backups/{db_name}_{timestamp}.db"
            backup_paths.append(self.backup_database(db_name, backup_path))
        
        return backup_paths
    
    def _start_backup_thread(self):
        """Start automatic backup thread"""
        def backup_worker():
            while self.backup_running:
                try:
                    time.sleep(self.config.database.backup_interval)
                    if self.backup_running:
                        self.backup_all_databases()
                        logger.info("Automatic database backup completed")
                except Exception as e:
                    logger.error(f"Error in automatic backup: {e}")
        
        self.backup_running = True
        self.backup_thread = threading.Thread(target=backup_worker, daemon=True)
        self.backup_thread.start()
        logger.info("Automatic backup thread started")
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get statistics for all databases"""
        stats = {}
        
        for db_name in self.schemas.keys():
            try:
                with self.get_connection(db_name) as conn:
                    cursor = conn.cursor()
                    
                    # Get table counts
                    table_stats = {}
                    for table_name in self.schemas[db_name].tables.keys():
                        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                        count = cursor.fetchone()[0]
                        table_stats[table_name] = count
                    
                    # Get database size
                    db_path = getattr(self.config.database, f"{db_name}_db")
                    size_bytes = Path(db_path).stat().st_size if Path(db_path).exists() else 0
                    
                    stats[db_name] = {
                        'tables': table_stats,
                        'size_bytes': size_bytes,
                        'size_mb': round(size_bytes / (1024 * 1024), 2)
                    }
                    
            except Exception as e:
                logger.error(f"Error getting stats for database {db_name}: {e}")
                stats[db_name] = {'error': str(e)}
        
        return stats
    
    def cleanup_old_data(self):
        """Clean up old data based on retention policies"""
        try:
            # Clean up old logs
            cutoff_date = datetime.now() - timedelta(days=self.config.storage.log_retention_days)
            
            with self.get_connection('logs') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM agent_logs 
                    WHERE timestamp < ? AND processed = 1
                ''', (cutoff_date.isoformat(),))
                deleted_logs = cursor.rowcount
                conn.commit()
            
            # Clean up old sessions
            with self.get_connection('users') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM user_sessions 
                    WHERE expires_at < ? OR (is_active = 0 AND created_at < ?)
                ''', (datetime.now().isoformat(), cutoff_date.isoformat()))
                deleted_sessions = cursor.rowcount
                conn.commit()
            
            logger.info(f"Cleanup completed: {deleted_logs} logs, {deleted_sessions} sessions removed")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def close(self):
        """Close all connections and stop background threads"""
        self.backup_running = False
        
        if self.backup_thread and self.backup_thread.is_alive():
            self.backup_thread.join(timeout=5)
        
        logger.info("Database manager closed")
