"""
Multi-Tenant Authentication System for CodeGrey SOC Platform
Uses JWT tokens and path-based tenant isolation (no subdomains required)
"""

import os
import sqlite3
import json
import hashlib
import secrets
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Any, List, Tuple
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'codegrey-soc-platform-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24
REFRESH_TOKEN_DAYS = 30

class MultiTenantAuth:
    """
    Multi-tenant authentication without subdomains
    Uses path-based routing: dev.codegrey.ai/t/{tenant_id}/...
    """
    
    def __init__(self, master_db_path: str = "master_platform.db"):
        self.master_db_path = master_db_path
        self.tenant_connections = {}
        self._init_master_database()
    
    def _init_master_database(self):
        """Initialize master database with tenant and auth tables"""
        conn = sqlite3.connect(self.master_db_path)
        cursor = conn.cursor()
        
        # Enhanced tenants table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT UNIQUE NOT NULL,  -- URL-friendly identifier
                status TEXT DEFAULT 'active',
                database_name TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- Subscription
                subscription_tier TEXT DEFAULT 'starter',
                subscription_status TEXT DEFAULT 'active',
                trial_ends_at TIMESTAMP,
                subscription_ends_at TIMESTAMP,
                
                -- Limits
                max_users INTEGER DEFAULT 10,
                max_agents INTEGER DEFAULT 100,
                max_api_calls_daily INTEGER DEFAULT 10000,
                
                -- Settings
                settings TEXT DEFAULT '{}',  -- JSON
                features TEXT DEFAULT '{}',  -- JSON
                
                -- Branding (for white-label)
                logo_url TEXT,
                primary_color TEXT DEFAULT '#1a73e8',
                custom_domain TEXT,  -- Future use
                
                -- Contact
                admin_email TEXT,
                admin_name TEXT,
                company_website TEXT,
                industry TEXT,
                company_size TEXT
            )
        ''')
        
        # Global users table (users can belong to multiple tenants)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS global_users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                phone TEXT,
                
                -- Global settings
                preferred_language TEXT DEFAULT 'en',
                timezone TEXT DEFAULT 'UTC',
                
                -- Security
                mfa_enabled BOOLEAN DEFAULT FALSE,
                mfa_secret TEXT,
                email_verified BOOLEAN DEFAULT FALSE,
                phone_verified BOOLEAN DEFAULT FALSE,
                
                -- Status
                is_active BOOLEAN DEFAULT TRUE,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        # User-Tenant relationships
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_tenants (
                user_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                permissions TEXT DEFAULT '[]',  -- JSON array
                
                -- Status in this tenant
                status TEXT DEFAULT 'active',
                invited_by TEXT,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_access TIMESTAMP,
                
                -- Tenant-specific settings
                preferences TEXT DEFAULT '{}',  -- JSON
                
                PRIMARY KEY (user_id, tenant_id),
                FOREIGN KEY (user_id) REFERENCES global_users(id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)
            )
        ''')
        
        # Authentication tokens
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                tenant_id TEXT,  -- Can be NULL for tenant selection
                token_type TEXT NOT NULL,  -- 'access', 'refresh', 'api_key'
                token_hash TEXT NOT NULL UNIQUE,
                
                -- Metadata
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                last_used TIMESTAMP,
                revoked BOOLEAN DEFAULT FALSE,
                revoked_at TIMESTAMP,
                
                -- Device/Session info
                ip_address TEXT,
                user_agent TEXT,
                device_id TEXT,
                
                FOREIGN KEY (user_id) REFERENCES global_users(id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)
            )
        ''')
        
        # Login attempts tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                tenant_id TEXT,
                success BOOLEAN,
                ip_address TEXT,
                user_agent TEXT,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                failure_reason TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def register_tenant(self, tenant_data: Dict) -> Tuple[bool, Dict]:
        """
        Register a new tenant organization
        """
        try:
            import uuid
            
            tenant_id = f"org_{uuid.uuid4().hex[:12]}"
            slug = tenant_data.get('slug', tenant_data['name'].lower().replace(' ', '-'))
            database_name = f"tenant_{slug}.db"
            
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            # Check if slug is unique
            cursor.execute("SELECT id FROM tenants WHERE slug = ?", (slug,))
            if cursor.fetchone():
                return False, {'error': 'Organization slug already exists'}
            
            # Create tenant record
            cursor.execute('''
                INSERT INTO tenants (
                    id, name, slug, database_name,
                    subscription_tier, admin_email, admin_name,
                    company_website, industry, company_size,
                    settings, features
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                tenant_id,
                tenant_data['name'],
                slug,
                database_name,
                tenant_data.get('subscription_tier', 'starter'),
                tenant_data['admin_email'],
                tenant_data.get('admin_name'),
                tenant_data.get('company_website'),
                tenant_data.get('industry'),
                tenant_data.get('company_size'),
                json.dumps(tenant_data.get('settings', {})),
                json.dumps(self._get_features_for_tier(tenant_data.get('subscription_tier', 'starter')))
            ))
            
            # Set trial period for new tenants
            if tenant_data.get('subscription_tier') != 'enterprise':
                trial_days = 14
                trial_ends = datetime.now(timezone.utc) + timedelta(days=trial_days)
                cursor.execute(
                    "UPDATE tenants SET trial_ends_at = ? WHERE id = ?",
                    (trial_ends.isoformat(), tenant_id)
                )
            
            conn.commit()
            conn.close()
            
            # Create tenant database
            self._create_tenant_database(tenant_id, database_name)
            
            # Create admin user account
            admin_user = self.register_user({
                'email': tenant_data['admin_email'],
                'password': tenant_data.get('admin_password', secrets.token_urlsafe(16)),
                'first_name': tenant_data.get('admin_name', 'Admin').split()[0],
                'last_name': tenant_data.get('admin_name', 'User').split()[-1] if len(tenant_data.get('admin_name', '').split()) > 1 else 'User'
            })
            
            if admin_user[0]:
                # Add admin to tenant with admin role
                self.add_user_to_tenant(
                    admin_user[1]['user_id'],
                    tenant_id,
                    'admin'
                )
            
            return True, {
                'tenant_id': tenant_id,
                'slug': slug,
                'admin_email': tenant_data['admin_email'],
                'admin_password': tenant_data.get('admin_password', '[Sent via email]'),
                'login_url': f"https://dev.codegrey.ai/t/{slug}/login"
            }
            
        except Exception as e:
            logger.error(f"Error registering tenant: {e}")
            return False, {'error': str(e)}
    
    def register_user(self, user_data: Dict) -> Tuple[bool, Dict]:
        """
        Register a new user (can belong to multiple tenants)
        """
        try:
            import uuid
            
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT id FROM global_users WHERE email = ?", (user_data['email'],))
            if cursor.fetchone():
                conn.close()
                return False, {'error': 'User already exists'}
            
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            password_hash = bcrypt.hashpw(
                user_data['password'].encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            
            cursor.execute('''
                INSERT INTO global_users (
                    id, email, password_hash, first_name, last_name,
                    phone, preferred_language, timezone
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                user_data['email'],
                password_hash,
                user_data.get('first_name'),
                user_data.get('last_name'),
                user_data.get('phone'),
                user_data.get('language', 'en'),
                user_data.get('timezone', 'UTC')
            ))
            
            conn.commit()
            conn.close()
            
            return True, {
                'user_id': user_id,
                'email': user_data['email']
            }
            
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return False, {'error': str(e)}
    
    def authenticate_user(self, email: str, password: str, tenant_slug: str = None) -> Tuple[bool, Dict]:
        """
        Authenticate user and generate JWT token
        """
        try:
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            # Get user
            cursor.execute("""
                SELECT id, email, password_hash, first_name, last_name, mfa_enabled
                FROM global_users 
                WHERE email = ? AND is_active = TRUE
            """, (email,))
            
            user = cursor.fetchone()
            if not user:
                self._log_login_attempt(email, None, False, "User not found")
                conn.close()
                return False, {'error': 'Invalid credentials'}
            
            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                self._log_login_attempt(email, None, False, "Invalid password")
                conn.close()
                return False, {'error': 'Invalid credentials'}
            
            user_id = user[0]
            
            # If tenant specified, verify user has access
            tenant_id = None
            user_role = None
            user_permissions = []
            
            if tenant_slug:
                cursor.execute("SELECT id FROM tenants WHERE slug = ? AND status = 'active'", (tenant_slug,))
                tenant = cursor.fetchone()
                if tenant:
                    tenant_id = tenant[0]
                    
                    # Check user access to tenant
                    cursor.execute("""
                        SELECT role, permissions, status
                        FROM user_tenants
                        WHERE user_id = ? AND tenant_id = ? AND status = 'active'
                    """, (user_id, tenant_id))
                    
                    access = cursor.fetchone()
                    if not access:
                        conn.close()
                        return False, {'error': 'No access to this organization'}
                    
                    user_role = access[0]
                    user_permissions = json.loads(access[1] or '[]')
            
            # Get user's tenants if no specific tenant
            if not tenant_id:
                cursor.execute("""
                    SELECT t.id, t.name, t.slug, ut.role
                    FROM user_tenants ut
                    JOIN tenants t ON ut.tenant_id = t.id
                    WHERE ut.user_id = ? AND ut.status = 'active' AND t.status = 'active'
                """, (user_id,))
                
                user_tenants = cursor.fetchall()
                
                # If user has only one tenant, auto-select it
                if len(user_tenants) == 1:
                    tenant_id = user_tenants[0][0]
                    tenant_slug = user_tenants[0][2]
                    user_role = user_tenants[0][3]
            
            # Generate JWT token
            token_payload = {
                'user_id': user_id,
                'email': user[1],
                'first_name': user[3],
                'last_name': user[4],
                'tenant_id': tenant_id,
                'tenant_slug': tenant_slug,
                'role': user_role,
                'permissions': user_permissions,
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
            }
            
            access_token = jwt.encode(token_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            
            # Generate refresh token
            refresh_payload = {
                'user_id': user_id,
                'type': 'refresh',
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_DAYS)
            }
            
            refresh_token = jwt.encode(refresh_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            
            # Store tokens
            self._store_token(user_id, tenant_id, 'access', access_token)
            self._store_token(user_id, tenant_id, 'refresh', refresh_token)
            
            # Update last login
            cursor.execute(
                "UPDATE global_users SET last_login = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), user_id)
            )
            
            if tenant_id:
                cursor.execute(
                    "UPDATE user_tenants SET last_access = ? WHERE user_id = ? AND tenant_id = ?",
                    (datetime.now(timezone.utc).isoformat(), user_id, tenant_id)
                )
            
            conn.commit()
            conn.close()
            
            # Log successful login
            self._log_login_attempt(email, tenant_id, True, None)
            
            response = {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': {
                    'id': user_id,
                    'email': user[1],
                    'first_name': user[3],
                    'last_name': user[4],
                    'role': user_role
                }
            }
            
            # Add tenant info if available
            if tenant_id:
                response['tenant'] = {
                    'id': tenant_id,
                    'slug': tenant_slug
                }
            else:
                # Return list of available tenants
                cursor.execute("""
                    SELECT t.id, t.name, t.slug, ut.role
                    FROM user_tenants ut
                    JOIN tenants t ON ut.tenant_id = t.id
                    WHERE ut.user_id = ? AND ut.status = 'active' AND t.status = 'active'
                """, (user_id,))
                
                tenants = []
                for t in cursor.fetchall():
                    tenants.append({
                        'id': t[0],
                        'name': t[1],
                        'slug': t[2],
                        'role': t[3],
                        'login_url': f"https://dev.codegrey.ai/t/{t[2]}/dashboard"
                    })
                
                response['available_tenants'] = tenants
            
            return True, response
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, {'error': 'Authentication failed'}
    
    def add_user_to_tenant(self, user_id: str, tenant_id: str, role: str = 'viewer', invited_by: str = None):
        """
        Add user to a tenant with specific role
        """
        try:
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            # Get role permissions
            permissions = self._get_role_permissions(role)
            
            cursor.execute('''
                INSERT OR REPLACE INTO user_tenants 
                (user_id, tenant_id, role, permissions, status, invited_by)
                VALUES (?, ?, ?, ?, 'active', ?)
            ''', (user_id, tenant_id, role, json.dumps(permissions), invited_by))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding user to tenant: {e}")
            return False
    
    def switch_tenant(self, user_id: str, tenant_slug: str) -> Tuple[bool, Dict]:
        """
        Switch user's active tenant context
        """
        try:
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            # Get tenant
            cursor.execute("SELECT id FROM tenants WHERE slug = ? AND status = 'active'", (tenant_slug,))
            tenant = cursor.fetchone()
            if not tenant:
                conn.close()
                return False, {'error': 'Tenant not found'}
            
            tenant_id = tenant[0]
            
            # Verify user has access
            cursor.execute("""
                SELECT role, permissions
                FROM user_tenants
                WHERE user_id = ? AND tenant_id = ? AND status = 'active'
            """, (user_id, tenant_id))
            
            access = cursor.fetchone()
            if not access:
                conn.close()
                return False, {'error': 'No access to this organization'}
            
            # Generate new token with tenant context
            cursor.execute("""
                SELECT email, first_name, last_name
                FROM global_users
                WHERE id = ?
            """, (user_id,))
            
            user = cursor.fetchone()
            
            token_payload = {
                'user_id': user_id,
                'email': user[0],
                'first_name': user[1],
                'last_name': user[2],
                'tenant_id': tenant_id,
                'tenant_slug': tenant_slug,
                'role': access[0],
                'permissions': json.loads(access[1] or '[]'),
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
            }
            
            access_token = jwt.encode(token_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            
            # Update last access
            cursor.execute(
                "UPDATE user_tenants SET last_access = ? WHERE user_id = ? AND tenant_id = ?",
                (datetime.now(timezone.utc).isoformat(), user_id, tenant_id)
            )
            
            conn.commit()
            conn.close()
            
            return True, {
                'access_token': access_token,
                'tenant': {
                    'id': tenant_id,
                    'slug': tenant_slug
                }
            }
            
        except Exception as e:
            logger.error(f"Error switching tenant: {e}")
            return False, {'error': 'Failed to switch organization'}
    
    def verify_token(self, token: str) -> Tuple[bool, Dict]:
        """
        Verify JWT token and return user/tenant info
        """
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            # Check if token is expired (JWT handles this but double-check)
            if datetime.fromtimestamp(payload['exp'], tz=timezone.utc) < datetime.now(timezone.utc):
                return False, {'error': 'Token expired'}
            
            return True, payload
            
        except jwt.ExpiredSignatureError:
            return False, {'error': 'Token expired'}
        except jwt.InvalidTokenError as e:
            return False, {'error': f'Invalid token: {e}'}
    
    def _get_features_for_tier(self, tier: str) -> Dict:
        """Get features based on subscription tier"""
        tiers = {
            'starter': {
                'ml_detection': True,
                'ai_detection': True,
                'basic_reporting': True,
                'api_access': True,
                'max_api_calls': 10000
            },
            'professional': {
                'ml_detection': True,
                'ai_detection': True,
                'ai_attack_simulation': True,
                'advanced_reporting': True,
                'api_access': True,
                'max_api_calls': 100000,
                'custom_alerts': True,
                'integrations': True
            },
            'enterprise': {
                'ml_detection': True,
                'ai_detection': True,
                'ai_attack_simulation': True,
                'advanced_reporting': True,
                'api_access': True,
                'max_api_calls': -1,  # Unlimited
                'custom_alerts': True,
                'integrations': True,
                'sso': True,
                'white_label': True,
                'custom_ml_models': True,
                'dedicated_support': True
            }
        }
        return tiers.get(tier, tiers['starter'])
    
    def _get_role_permissions(self, role: str) -> List[str]:
        """Get default permissions for role"""
        roles = {
            'admin': ['*'],  # All permissions
            'analyst': [
                'view_dashboard', 'view_logs', 'view_alerts', 'create_alerts',
                'run_detection', 'view_reports', 'manage_incidents'
            ],
            'responder': [
                'view_dashboard', 'view_alerts', 'manage_incidents',
                'execute_response', 'view_logs', 'create_reports'
            ],
            'viewer': [
                'view_dashboard', 'view_reports', 'view_alerts'
            ]
        }
        return roles.get(role, roles['viewer'])
    
    def _create_tenant_database(self, tenant_id: str, database_name: str):
        """Create isolated database for tenant"""
        db_path = os.path.join('tenant_databases', database_name)
        os.makedirs('tenant_databases', exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create all necessary tables for tenant
        # (agents, detections, alerts, etc.)
        # ... [Previous table creation code]
        
        conn.commit()
        conn.close()
    
    def _store_token(self, user_id: str, tenant_id: str, token_type: str, token: str):
        """Store authentication token"""
        try:
            import uuid
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            cursor.execute('''
                INSERT INTO auth_tokens (id, user_id, tenant_id, token_type, token_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                f"token_{uuid.uuid4().hex[:12]}",
                user_id, tenant_id, token_type, token_hash
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing token: {e}")
    
    def _log_login_attempt(self, email: str, tenant_id: str, success: bool, failure_reason: str = None):
        """Log login attempt"""
        try:
            import uuid
            conn = sqlite3.connect(self.master_db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO login_attempts (id, email, tenant_id, success, failure_reason)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                f"attempt_{uuid.uuid4().hex[:12]}",
                email, tenant_id, success, failure_reason
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging login attempt: {e}")


# Flask middleware for multi-tenant authentication
def require_auth(f):
    """Decorator to require authentication and tenant context"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, jsonify
        
        # Get token from header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        
        # Verify token
        auth = MultiTenantAuth()
        valid, payload = auth.verify_token(token)
        
        if not valid:
            return jsonify({'error': payload.get('error', 'Invalid token')}), 401
        
        # Set request context
        request.user_id = payload['user_id']
        request.user_email = payload['email']
        request.tenant_id = payload.get('tenant_id')
        request.tenant_slug = payload.get('tenant_slug')
        request.user_role = payload.get('role')
        request.user_permissions = payload.get('permissions', [])
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify
            
            # Check if user has permission
            if permission != '*' and permission not in request.user_permissions:
                # Check for admin override
                if '*' not in request.user_permissions:
                    return jsonify({'error': f'Permission denied: {permission} required'}), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# Singleton instance
multi_tenant_auth = MultiTenantAuth()
