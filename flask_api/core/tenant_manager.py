"""
Multi-Tenancy Manager for SOC Platform
Handles tenant isolation, database routing, and context management
"""

import os
import sqlite3
import json
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Any, List
from functools import wraps
import jwt
import logging

logger = logging.getLogger(__name__)

class TenantManager:
    """Core tenant management system"""
    
    def __init__(self, master_db_path: str = "master_platform.db"):
        self.master_db_path = master_db_path
        self.tenant_connections = {}
        self.current_tenant = None
        
        # Initialize master database
        self._init_master_database()
    
    def _init_master_database(self):
        """Initialize master platform database"""
        conn = sqlite3.connect(self.master_db_path)
        cursor = conn.cursor()
        
        # Tenants table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                domain TEXT UNIQUE,
                subscription_tier TEXT DEFAULT 'starter',
                status TEXT DEFAULT 'active',
                database_name TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                
                -- Subscription limits
                max_users INTEGER DEFAULT 10,
                max_agents INTEGER DEFAULT 100,
                max_log_retention_days INTEGER DEFAULT 90,
                max_api_calls_per_day INTEGER DEFAULT 10000,
                max_storage_gb INTEGER DEFAULT 100,
                
                -- Features (JSON)
                features TEXT DEFAULT '{}',
                
                -- Contact info
                admin_email TEXT,
                billing_email TEXT,
                technical_contact TEXT,
                
                -- Metadata
                metadata TEXT DEFAULT '{}'
            )
        ''')
        
        # Platform admins
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS platform_admins (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'platform_admin',
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Platform audit log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS platform_audit_log (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                action TEXT,
                resource TEXT,
                user_id TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT,
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)
            )
        ''')
        
        # Tenant usage tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tenant_usage (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                date DATE NOT NULL,
                api_calls INTEGER DEFAULT 0,
                storage_used_mb INTEGER DEFAULT 0,
                active_users INTEGER DEFAULT 0,
                active_agents INTEGER DEFAULT 0,
                logs_processed INTEGER DEFAULT 0,
                alerts_generated INTEGER DEFAULT 0,
                FOREIGN KEY (tenant_id) REFERENCES tenants(id),
                UNIQUE(tenant_id, date)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_tenant(self, tenant_data: Dict) -> Dict[str, Any]:
        """Create a new tenant"""
        try:
            import uuid
            tenant_id = tenant_data.get('id', f"tenant_{uuid.uuid4().hex[:12]}")
            
            # Create tenant record in master DB
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            database_name = f"soc_tenant_{tenant_id}.db"
            
            # Set subscription defaults
            subscription_limits = self._get_subscription_limits(
                tenant_data.get('subscription_tier', 'starter')
            )
            
            cursor.execute('''
                INSERT INTO tenants (
                    id, name, domain, subscription_tier, status, database_name,
                    max_users, max_agents, max_log_retention_days, 
                    max_api_calls_per_day, max_storage_gb,
                    features, admin_email, billing_email, technical_contact,
                    metadata, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                tenant_id,
                tenant_data['name'],
                tenant_data.get('domain'),
                tenant_data.get('subscription_tier', 'starter'),
                'active',
                database_name,
                subscription_limits['max_users'],
                subscription_limits['max_agents'],
                subscription_limits['max_log_retention_days'],
                subscription_limits['max_api_calls_per_day'],
                subscription_limits['max_storage_gb'],
                json.dumps(subscription_limits['features']),
                tenant_data.get('admin_email'),
                tenant_data.get('billing_email'),
                tenant_data.get('technical_contact'),
                json.dumps(tenant_data.get('metadata', {})),
                tenant_data.get('expires_at')
            ))
            
            conn.commit()
            conn.close()
            
            # Create tenant database
            self._create_tenant_database(tenant_id, database_name)
            
            # Create default admin user
            if tenant_data.get('admin_email'):
                self._create_default_admin(tenant_id, tenant_data['admin_email'])
            
            # Log creation
            self._log_platform_action(
                tenant_id, 'tenant_created', 'tenant', None, 
                tenant_data.get('created_by_ip')
            )
            
            return {
                'success': True,
                'tenant_id': tenant_id,
                'database_name': database_name,
                'message': 'Tenant created successfully'
            }
            
        except Exception as e:
            logger.error(f"Error creating tenant: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_subscription_limits(self, tier: str) -> Dict:
        """Get limits based on subscription tier"""
        tiers = {
            'starter': {
                'max_users': 10,
                'max_agents': 50,
                'max_log_retention_days': 30,
                'max_api_calls_per_day': 10000,
                'max_storage_gb': 50,
                'features': {
                    'ml_detection': True,
                    'llm_analysis': True,
                    'ai_attack': False,
                    'advanced_reporting': False,
                    'sso': False,
                    'api_access': True
                }
            },
            'professional': {
                'max_users': 50,
                'max_agents': 500,
                'max_log_retention_days': 90,
                'max_api_calls_per_day': 100000,
                'max_storage_gb': 500,
                'features': {
                    'ml_detection': True,
                    'llm_analysis': True,
                    'ai_attack': True,
                    'advanced_reporting': True,
                    'sso': False,
                    'api_access': True
                }
            },
            'enterprise': {
                'max_users': -1,  # Unlimited
                'max_agents': -1,
                'max_log_retention_days': 365,
                'max_api_calls_per_day': -1,
                'max_storage_gb': -1,
                'features': {
                    'ml_detection': True,
                    'llm_analysis': True,
                    'ai_attack': True,
                    'advanced_reporting': True,
                    'sso': True,
                    'api_access': True,
                    'custom_ml_models': True,
                    'white_label': True
                }
            }
        }
        
        return tiers.get(tier, tiers['starter'])
    
    def _create_tenant_database(self, tenant_id: str, database_name: str):
        """Create and initialize tenant-specific database"""
        db_path = os.path.join('tenant_databases', database_name)
        os.makedirs('tenant_databases', exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                role TEXT NOT NULL,
                permissions TEXT,
                mfa_enabled BOOLEAN DEFAULT FALSE,
                mfa_secret TEXT,
                status TEXT DEFAULT 'active',
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT,
                updated_at TIMESTAMP,
                preferences TEXT,
                api_key TEXT UNIQUE,
                api_key_expires TIMESTAMP
            )
        ''')
        
        # Roles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS roles (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                permissions TEXT NOT NULL,
                is_custom BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tenant_id, name)
            )
        ''')
        
        # Insert default roles
        default_roles = [
            ('admin', 'Administrator', json.dumps(['*']), False),
            ('analyst', 'Security Analyst', json.dumps([
                'view_logs', 'create_alerts', 'run_detection', 'view_reports'
            ]), False),
            ('responder', 'Incident Responder', json.dumps([
                'view_alerts', 'manage_incidents', 'execute_response', 'view_logs'
            ]), False),
            ('viewer', 'Viewer', json.dumps(['view_dashboard', 'view_reports']), False)
        ]
        
        for role_name, desc, perms, is_custom in default_roles:
            cursor.execute('''
                INSERT INTO roles (id, tenant_id, name, description, permissions, is_custom)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (f"role_{role_name}_{tenant_id}", tenant_id, role_name, desc, perms, is_custom))
        
        # User sessions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                revoked BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Teams
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        ''')
        
        # Team members
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS team_members (
                team_id TEXT,
                user_id TEXT,
                role TEXT DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (team_id, user_id),
                FOREIGN KEY (team_id) REFERENCES teams(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Audit log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                user_id TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT,
                status TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Copy other necessary tables from template
        self._create_tenant_soc_tables(cursor, tenant_id)
        
        conn.commit()
        conn.close()
    
    def _create_tenant_soc_tables(self, cursor, tenant_id: str):
        """Create SOC-specific tables for tenant"""
        # Agents table with tenant context
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT DEFAULT 'offline',
                hostname TEXT,
                ip_address TEXT,
                platform TEXT,
                assigned_user_id TEXT,
                assigned_team_id TEXT,
                department TEXT,
                location TEXT,
                tags TEXT,
                capabilities TEXT,
                version TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_heartbeat TIMESTAMP,
                endpoint_importance TEXT,
                user_role TEXT,
                configuration TEXT,
                FOREIGN KEY (assigned_user_id) REFERENCES users(id),
                FOREIGN KEY (assigned_team_id) REFERENCES teams(id)
            )
        ''')
        
        # Detections with tenant context
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                agent_id TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                type TEXT,
                severity TEXT,
                data TEXT,
                status TEXT DEFAULT 'pending',
                assigned_to TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents(id),
                FOREIGN KEY (assigned_to) REFERENCES users(id)
            )
        ''')
        
        # Alerts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,
                status TEXT DEFAULT 'open',
                assigned_to TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP,
                resolved_at TIMESTAMP,
                description TEXT,
                affected_agents TEXT,
                FOREIGN KEY (assigned_to) REFERENCES users(id)
            )
        ''')
    
    def _create_default_admin(self, tenant_id: str, admin_email: str):
        """Create default admin user for tenant"""
        try:
            import uuid
            import bcrypt
            
            # Generate temporary password
            temp_password = secrets.token_urlsafe(16)
            password_hash = bcrypt.hashpw(temp_password.encode(), bcrypt.gensalt()).decode()
            
            # Get tenant database
            db_path = self.get_tenant_database_path(tenant_id)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            
            cursor.execute('''
                INSERT INTO users (
                    id, tenant_id, email, username, password_hash,
                    first_name, last_name, role, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, tenant_id, admin_email, admin_email.split('@')[0],
                password_hash, 'Admin', 'User', 'admin', 'active'
            ))
            
            conn.commit()
            conn.close()
            
            # In production, send email with temp password
            logger.info(f"Created default admin for tenant {tenant_id}: {admin_email}")
            logger.info(f"Temporary password: {temp_password}")  # Remove in production
            
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")
    
    def get_tenant_database_path(self, tenant_id: str) -> str:
        """Get database path for tenant"""
        conn = sqlite3.connect(self.master_db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT database_name FROM tenants WHERE id = ?", (tenant_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return os.path.join('tenant_databases', result[0])
        return None
    
    def get_tenant_connection(self, tenant_id: str):
        """Get database connection for tenant"""
        if tenant_id not in self.tenant_connections:
            db_path = self.get_tenant_database_path(tenant_id)
            if db_path:
                self.tenant_connections[tenant_id] = sqlite3.connect(db_path)
                self.tenant_connections[tenant_id].row_factory = sqlite3.Row
        
        return self.tenant_connections.get(tenant_id)
    
    def validate_tenant(self, tenant_id: str) -> bool:
        """Validate if tenant exists and is active"""
        conn = sqlite3.connect(self.master_db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT status FROM tenants WHERE id = ? AND status = 'active'",
            (tenant_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def check_tenant_limit(self, tenant_id: str, resource: str, current_count: int) -> bool:
        """Check if tenant has reached resource limit"""
        conn = sqlite3.connect(self.master_db_path)
        cursor = conn.cursor()
        
        limit_column = f"max_{resource}"
        cursor.execute(
            f"SELECT {limit_column} FROM tenants WHERE id = ?",
            (tenant_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            limit = result[0]
            if limit == -1:  # Unlimited
                return True
            return current_count < limit
        
        return False
    
    def track_usage(self, tenant_id: str, metric: str, value: int = 1):
        """Track tenant usage metrics"""
        try:
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            import uuid
            today = datetime.now(timezone.utc).date()
            
            # Try to update existing record
            cursor.execute(f'''
                UPDATE tenant_usage 
                SET {metric} = {metric} + ?
                WHERE tenant_id = ? AND date = ?
            ''', (value, tenant_id, today))
            
            if cursor.rowcount == 0:
                # Create new record
                cursor.execute('''
                    INSERT INTO tenant_usage (id, tenant_id, date, {})
                    VALUES (?, ?, ?, ?)
                '''.format(metric), (
                    f"usage_{uuid.uuid4().hex[:12]}",
                    tenant_id, today, value
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error tracking usage: {e}")
    
    def _log_platform_action(self, tenant_id: str, action: str, 
                            resource: str, user_id: str = None, 
                            ip_address: str = None):
        """Log platform-level actions"""
        try:
            import uuid
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO platform_audit_log 
                (id, tenant_id, action, resource, user_id, ip_address)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                f"audit_{uuid.uuid4().hex[:12]}",
                tenant_id, action, resource, user_id, ip_address
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging platform action: {e}")
    
    def close_all_connections(self):
        """Close all tenant database connections"""
        for conn in self.tenant_connections.values():
            conn.close()
        self.tenant_connections.clear()


# Middleware for Flask
def require_tenant(f):
    """Decorator to require tenant context"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, jsonify
        
        # Extract tenant from request
        tenant_id = None
        
        # Try subdomain
        if '.' in request.host:
            subdomain = request.host.split('.')[0]
            if subdomain not in ['www', 'api']:
                tenant_id = subdomain
        
        # Try header
        if not tenant_id:
            tenant_id = request.headers.get('X-Tenant-ID')
        
        # Try JWT token
        if not tenant_id:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                try:
                    token = auth_header.split(' ')[1]
                    payload = jwt.decode(token, 'SECRET_KEY', algorithms=['HS256'])
                    tenant_id = payload.get('tenant_id')
                except:
                    pass
        
        if not tenant_id:
            return jsonify({'error': 'Tenant context required'}), 400
        
        # Validate tenant
        tenant_manager = TenantManager()
        if not tenant_manager.validate_tenant(tenant_id):
            return jsonify({'error': 'Invalid or inactive tenant'}), 403
        
        # Set tenant context
        request.tenant_id = tenant_id
        request.tenant_db = tenant_manager.get_tenant_connection(tenant_id)
        
        return f(*args, **kwargs)
    
    return decorated_function


# Singleton instance
tenant_manager = TenantManager()
