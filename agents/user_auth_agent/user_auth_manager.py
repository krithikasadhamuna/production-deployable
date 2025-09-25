"""
User Authentication Agent
Dedicated service for SOC personnel user management, authentication, and API key management
Separate from endpoint registration - this is for human users of the SOC platform
"""

import sqlite3
import hashlib
import uuid
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple, Optional, List
import logging
import json
import secrets

logger = logging.getLogger('UserAuthAgent')

class UserAuthenticationAgent:
    """
    Dedicated User Authentication Agent for SOC Platform
    Handles all user management separate from client endpoint registration
    """
    
    def __init__(self, db_path: str = "soc_users.db"):
        self.db_path = db_path
        self.jwt_secret = self._get_or_create_jwt_secret()
        self.initialize_user_database()
        logger.info("User Authentication Agent initialized")
    
    def _get_or_create_jwt_secret(self) -> str:
        """Get or create JWT secret key"""
        try:
            with open('.jwt_secret', 'r') as f:
                return f.read().strip()
        except FileNotFoundError:
            secret = secrets.token_urlsafe(64)
            with open('.jwt_secret', 'w') as f:
                f.write(secret)
            return secret
    
    def initialize_user_database(self):
        """Initialize user authentication database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # SOC Users table
        c.execute('''CREATE TABLE IF NOT EXISTS soc_users (
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
            created_by TEXT
        )''')
        
        # User sessions table
        c.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            jwt_token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES soc_users (id)
        )''')
        
        # API key usage tracking
        c.execute('''CREATE TABLE IF NOT EXISTS api_key_usage (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            api_key TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            success BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES soc_users (id)
        )''')
        
        # User roles and permissions
        c.execute('''CREATE TABLE IF NOT EXISTS user_roles (
            id TEXT PRIMARY KEY,
            role_name TEXT UNIQUE NOT NULL,
            permissions TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Initialize default roles
        self._create_default_roles(c)
        
        conn.commit()
        conn.close()
        logger.info("User authentication database initialized")
    
    def _create_default_roles(self, cursor):
        """Create default SOC roles"""
        default_roles = [
            {
                'role_name': 'admin',
                'permissions': json.dumps([
                    'user_management', 'attack_control', 'detection_control',
                    'system_config', 'view_all_data', 'manage_agents'
                ]),
                'description': 'Full system administrator'
            },
            {
                'role_name': 'soc_manager',
                'permissions': json.dumps([
                    'attack_control', 'detection_control', 'view_all_data',
                    'manage_team', 'incident_response'
                ]),
                'description': 'SOC Manager with team oversight'
            },
            {
                'role_name': 'senior_analyst',
                'permissions': json.dumps([
                    'attack_control', 'detection_control', 'incident_response',
                    'view_team_data', 'advanced_analysis'
                ]),
                'description': 'Senior SOC Analyst'
            },
            {
                'role_name': 'analyst',
                'permissions': json.dumps([
                    'detection_view', 'incident_response', 'basic_analysis'
                ]),
                'description': 'SOC Analyst'
            },
            {
                'role_name': 'viewer',
                'permissions': json.dumps([
                    'detection_view', 'dashboard_view'
                ]),
                'description': 'Read-only access'
            }
        ]
        
        for role in default_roles:
            cursor.execute('''
                INSERT OR IGNORE INTO user_roles (id, role_name, permissions, description)
                VALUES (?, ?, ?, ?)
            ''', (
                f"role_{uuid.uuid4().hex[:8]}",
                role['role_name'],
                role['permissions'],
                role['description']
            ))
    
    def register_user(self, user_data: Dict) -> Tuple[bool, Dict]:
        """
        Register new SOC personnel user
        """
        try:
            # Validate required fields
            required_fields = ['email', 'password', 'first_name', 'organization']
            for field in required_fields:
                if field not in user_data:
                    return False, {'error': f'Missing required field: {field}'}
            
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Check if user already exists
            c.execute('SELECT id FROM soc_users WHERE email = ?', (user_data['email'],))
            if c.fetchone():
                conn.close()
                return False, {'error': 'User with this email already exists'}
            
            # Generate user ID and API key
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            api_key = f"soc_{secrets.token_urlsafe(32)}"
            
            # Hash password
            password_hash = bcrypt.hashpw(
                user_data['password'].encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            
            # Insert user
            c.execute('''
                INSERT INTO soc_users (
                    id, email, password_hash, first_name, last_name,
                    role, organization, department, api_key, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                user_data['email'],
                password_hash,
                user_data['first_name'],
                user_data.get('last_name', ''),
                user_data.get('role', 'analyst'),
                user_data['organization'],
                user_data.get('department', ''),
                api_key,
                user_data.get('created_by', 'system')
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"User registered successfully: {user_data['email']}")
            
            return True, {
                'user_id': user_id,
                'api_key': api_key,
                'message': 'User registered successfully'
            }
            
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return False, {'error': str(e)}
    
    def authenticate_user(self, email: str, password: str) -> Tuple[bool, Dict]:
        """
        Authenticate SOC user and generate JWT token
        """
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Get user
            c.execute('''
                SELECT id, email, password_hash, first_name, last_name, role, 
                       organization, api_key, is_active, login_attempts, locked_until
                FROM soc_users WHERE email = ?
            ''', (email,))
            
            user = c.fetchone()
            if not user:
                conn.close()
                return False, {'error': 'Invalid credentials'}
            
            user_id, user_email, password_hash, first_name, last_name, role, organization, api_key, is_active, login_attempts, locked_until = user
            
            # Check if account is locked
            if locked_until and datetime.fromisoformat(locked_until) > datetime.now():
                conn.close()
                return False, {'error': 'Account temporarily locked due to failed login attempts'}
            
            # Check if account is active
            if not is_active:
                conn.close()
                return False, {'error': 'Account is deactivated'}
            
            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                # Increment login attempts
                new_attempts = login_attempts + 1
                locked_until_time = None
                
                if new_attempts >= 5:
                    locked_until_time = (datetime.now() + timedelta(minutes=30)).isoformat()
                
                c.execute('''
                    UPDATE soc_users 
                    SET login_attempts = ?, locked_until = ?
                    WHERE id = ?
                ''', (new_attempts, locked_until_time, user_id))
                conn.commit()
                conn.close()
                
                return False, {'error': 'Invalid credentials'}
            
            # Reset login attempts on successful login
            c.execute('''
                UPDATE soc_users 
                SET login_attempts = 0, locked_until = NULL, last_login = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), user_id))
            
            # Generate JWT token
            token_payload = {
                'user_id': user_id,
                'email': user_email,
                'role': role,
                'organization': organization,
                'exp': datetime.utcnow() + timedelta(hours=8),
                'iat': datetime.utcnow()
            }
            
            jwt_token = jwt.encode(token_payload, self.jwt_secret, algorithm='HS256')
            
            # Store session
            session_id = f"session_{uuid.uuid4().hex[:16]}"
            c.execute('''
                INSERT INTO user_sessions (
                    id, user_id, jwt_token, expires_at
                ) VALUES (?, ?, ?, ?)
            ''', (
                session_id,
                user_id,
                jwt_token,
                (datetime.now() + timedelta(hours=8)).isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"User authenticated successfully: {email}")
            
            return True, {
                'user_id': user_id,
                'email': user_email,
                'first_name': first_name,
                'last_name': last_name,
                'role': role,
                'organization': organization,
                'api_key': api_key,
                'jwt_token': jwt_token,
                'session_id': session_id,
                'expires_at': token_payload['exp'].isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
            return False, {'error': str(e)}
    
    def validate_api_key(self, api_key: str) -> Tuple[bool, Dict]:
        """
        Validate API key and return user info
        """
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                SELECT id, email, first_name, last_name, role, organization, is_active
                FROM soc_users WHERE api_key = ? AND is_active = 1
            ''', (api_key,))
            
            user = c.fetchone()
            if not user:
                conn.close()
                return False, {'error': 'Invalid API key'}
            
            user_id, email, first_name, last_name, role, organization, is_active = user
            
            # Log API key usage
            c.execute('''
                INSERT INTO api_key_usage (
                    id, user_id, api_key, endpoint, method
                ) VALUES (?, ?, ?, ?, ?)
            ''', (
                f"usage_{uuid.uuid4().hex[:12]}",
                user_id,
                api_key,
                'validation',
                'GET'
            ))
            
            conn.commit()
            conn.close()
            
            return True, {
                'user_id': user_id,
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'role': role,
                'organization': organization
            }
            
        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return False, {'error': str(e)}
    
    def validate_jwt_token(self, token: str) -> Tuple[bool, Dict]:
        """
        Validate JWT token
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            
            # Check if session is still active
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                SELECT is_active FROM user_sessions 
                WHERE user_id = ? AND jwt_token = ? AND expires_at > ?
            ''', (
                payload['user_id'],
                token,
                datetime.now().isoformat()
            ))
            
            session = c.fetchone()
            conn.close()
            
            if not session or not session[0]:
                return False, {'error': 'Session expired or invalid'}
            
            return True, payload
            
        except jwt.ExpiredSignatureError:
            return False, {'error': 'Token expired'}
        except jwt.InvalidTokenError:
            return False, {'error': 'Invalid token'}
        except Exception as e:
            logger.error(f"Error validating JWT token: {e}")
            return False, {'error': str(e)}
    
    def get_user_permissions(self, user_id: str) -> List[str]:
        """
        Get user permissions based on role
        """
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                SELECT ur.permissions 
                FROM soc_users u
                JOIN user_roles ur ON u.role = ur.role_name
                WHERE u.id = ?
            ''', (user_id,))
            
            result = c.fetchone()
            conn.close()
            
            if result:
                return json.loads(result[0])
            return []
            
        except Exception as e:
            logger.error(f"Error getting user permissions: {e}")
            return []
    
    def regenerate_api_key(self, user_id: str) -> Tuple[bool, str]:
        """
        Regenerate API key for user
        """
        try:
            new_api_key = f"soc_{secrets.token_urlsafe(32)}"
            
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                UPDATE soc_users SET api_key = ? WHERE id = ?
            ''', (new_api_key, user_id))
            
            conn.commit()
            conn.close()
            
            logger.info(f"API key regenerated for user: {user_id}")
            return True, new_api_key
            
        except Exception as e:
            logger.error(f"Error regenerating API key: {e}")
            return False, str(e)
    
    def logout_user(self, session_id: str) -> bool:
        """
        Logout user by deactivating session
        """
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                UPDATE user_sessions SET is_active = 0 WHERE id = ?
            ''', (session_id,))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error logging out user: {e}")
            return False
    
    def get_user_stats(self) -> Dict:
        """
        Get user statistics for admin dashboard
        """
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Total users
            c.execute('SELECT COUNT(*) FROM soc_users')
            total_users = c.fetchone()[0]
            
            # Active users
            c.execute('SELECT COUNT(*) FROM soc_users WHERE is_active = 1')
            active_users = c.fetchone()[0]
            
            # Users by role
            c.execute('SELECT role, COUNT(*) FROM soc_users GROUP BY role')
            users_by_role = dict(c.fetchall())
            
            # Recent logins (last 24 hours)
            c.execute('''
                SELECT COUNT(*) FROM soc_users 
                WHERE last_login > datetime('now', '-1 day')
            ''')
            recent_logins = c.fetchone()[0]
            
            conn.close()
            
            return {
                'total_users': total_users,
                'active_users': active_users,
                'users_by_role': users_by_role,
                'recent_logins': recent_logins
            }
            
        except Exception as e:
            logger.error(f"Error getting user stats: {e}")
            return {}
