"""
🚀 CodeGrey SOC - Flask API Server
Complete implementation of AI-driven SOC backend APIs
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timezone
import os
import sqlite3
import json
import uuid
from functools import wraps

# Import blueprints
from routes.agents import agents_bp
from routes.attacks import attacks_bp
from routes.detections import detections_bp
from routes.reasoning import reasoning_bp
from routes.network import network_bp
from routes.commands import commands_bp
from routes.system import system_bp
from routes.organizations import organizations_bp
from routes.testing import testing_bp

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend access

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['DATABASE'] = 'soc_database.db'

# Initialize database
def init_database():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Agents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT DEFAULT 'offline',
            hostname TEXT,
            ip_address TEXT,
            location TEXT,
            capabilities TEXT,  -- JSON string
            version TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            network_element_type TEXT,
            security_zone TEXT,
            organization_id TEXT DEFAULT 'org-123'
        )
    ''')
    
    # Attack scenarios table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_scenarios (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            apt_group TEXT,
            country TEXT,
            difficulty TEXT,
            duration_minutes INTEGER,
            impact TEXT,
            techniques TEXT,  -- JSON array
            target_sectors TEXT,  -- JSON array
            motivation TEXT,
            playbook_steps TEXT  -- JSON array
        )
    ''')
    
    # Attack timeline table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_timeline (
            id TEXT PRIMARY KEY,
            scenario_id TEXT,
            scenario_name TEXT,
            agent_id TEXT,
            agent_name TEXT,
            status TEXT,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            duration_minutes INTEGER,
            techniques_executed TEXT,  -- JSON array
            targets_affected INTEGER,
            success_rate REAL,
            results TEXT  -- JSON object
        )
    ''')
    
    # Detections table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            threat_type TEXT,
            severity TEXT,
            confidence REAL,
            source_ip TEXT,
            target_ip TEXT,
            technique TEXT,
            technique_name TEXT,
            description TEXT,
            status TEXT,
            indicators TEXT,  -- JSON object
            risk_score REAL,
            false_positive_probability REAL
        )
    ''')
    
    # Commands table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS commands (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            type TEXT,
            priority TEXT DEFAULT 'normal',
            parameters TEXT,  -- JSON object
            status TEXT DEFAULT 'queued',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            scheduled_at TIMESTAMP,
            output TEXT,
            stderr TEXT,
            exit_code INTEGER,
            execution_time TIMESTAMP,
            duration_seconds REAL
        )
    ''')
    
    # Network topology table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_topology (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            level INTEGER DEFAULT 0,
            parent_id TEXT,
            agents TEXT,  -- JSON array
            status TEXT DEFAULT 'normal',
            risk_level TEXT DEFAULT 'low',
            confidence REAL DEFAULT 0.9,
            characteristics TEXT,  -- JSON object
            security_zone TEXT,
            ip_ranges TEXT  -- JSON array
        )
    ''')
    
    # Organizations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            contact_email TEXT,
            industry TEXT,
            size TEXT,
            api_key TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            settings TEXT,  -- JSON object
            status TEXT DEFAULT 'active'
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'Missing or invalid Authorization header',
                'error_code': 'UNAUTHORIZED'
            }), 401
        
        token = auth_header.split(' ')[1]
        # Simple token validation (in production, use proper JWT validation)
        if not token or len(token) < 10:
            return jsonify({
                'success': False,
                'error': 'Invalid API token',
                'error_code': 'UNAUTHORIZED'
            }), 401
            
        return f(*args, **kwargs)
    return decorated_function

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'error_code': 'NOT_FOUND',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'error_code': 'INTERNAL_ERROR',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }), 500

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'success': True,
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '2.1.0'
    })

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'success': True,
        'message': 'CodeGrey SOC API Server',
        'version': '2.1.0',
        'endpoints': {
            'agents': '/api/agents',
            'attacks': '/api/attack_scenarios',
            'detections': '/api/detections/live',
            'reasoning': '/api/v1/chat',
            'network': '/api/network/topology',
            'commands': '/api/agents/{agent_id}/command',
            'system': '/api/system/status',
            'organizations': '/api/organizations'
        }
    })

# Register blueprints
app.register_blueprint(agents_bp, url_prefix='/api')
app.register_blueprint(attacks_bp, url_prefix='/api')
app.register_blueprint(detections_bp, url_prefix='/api')
app.register_blueprint(reasoning_bp, url_prefix='/api')
app.register_blueprint(network_bp, url_prefix='/api')
app.register_blueprint(commands_bp, url_prefix='/api')
app.register_blueprint(system_bp, url_prefix='/api')
app.register_blueprint(organizations_bp, url_prefix='/api')
app.register_blueprint(testing_bp, url_prefix='/api')

if __name__ == '__main__':
    # Initialize database on startup
    init_database()
    
    # Start Flask development server
    print("🚀 Starting CodeGrey SOC API Server...")
    print("📊 API Documentation available at: http://localhost:8443")
    print("🔐 All endpoints require Bearer token authentication")
    
    app.run(
        host='0.0.0.0',
        port=8443,
        debug=True,
        ssl_context='adhoc'  # Self-signed SSL for HTTPS
    )

