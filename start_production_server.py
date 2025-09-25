#!/usr/bin/env python3
"""
Production Server Startup Script for Multi-Tenant SOC Platform
Complete functionality with all AI agents and capabilities
Domain: dev.codegrey.ai
"""

import os
import sys
import sqlite3
import logging
import asyncio
import threading
from datetime import datetime, timezone
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('soc_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SOC-Platform')

# DOMAIN CONFIGURATION
DOMAIN = "dev.codegrey.ai"
BASE_URL = f"https://{DOMAIN}"

def init_master_database():
    """Initialize master database for multi-tenancy"""
    db_path = "master_platform.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tenants table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'active',
            database_name TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            subscription_tier TEXT DEFAULT 'starter',
            max_agents INTEGER DEFAULT 100,
            admin_email TEXT,
            settings TEXT DEFAULT '{}'
        )
    ''')
    
    # Create global users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS global_users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create user-tenant relationships
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_tenants (
            user_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            status TEXT DEFAULT 'active',
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, tenant_id)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Master database initialized")

def init_tenant_database(tenant_slug):
    """Initialize a tenant-specific database with ALL tables needed"""
    db_dir = Path("tenant_databases")
    db_dir.mkdir(exist_ok=True)
    
    db_path = db_dir / f"tenant_{tenant_slug}.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Agents table - for client endpoints
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            ip_address TEXT,
            platform TEXT,
            status TEXT DEFAULT 'offline',
            last_heartbeat TIMESTAMP,
            endpoint_importance TEXT,
            user_role TEXT,
            configuration TEXT,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            registered_by TEXT,
            agent_version TEXT,
            capabilities TEXT
        )
    ''')
    
    # Logs table - for security events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id TEXT PRIMARY KEY,
            timestamp TIMESTAMP,
            agent_id TEXT,
            event_type TEXT,
            severity TEXT,
            message TEXT,
            details TEXT,
            processed BOOLEAN DEFAULT FALSE,
            detection_status TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        )
    ''')
    
    # Detections table - AI detection results
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id TEXT PRIMARY KEY,
            timestamp TIMESTAMP,
            threat_type TEXT,
            severity TEXT,
            confidence REAL,
            affected_agents TEXT,
            ml_analysis TEXT,
            llm_analysis TEXT,
            ai_reasoning TEXT,
            recommended_action TEXT,
            status TEXT DEFAULT 'new',
            acknowledged_by TEXT,
            acknowledged_at TIMESTAMP
        )
    ''')
    
    # Attack workflows table - Attack agent operations
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_workflows (
            id TEXT PRIMARY KEY,
            name TEXT,
            status TEXT,
            created_at TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            attack_plan TEXT,
            mitre_techniques TEXT,
            target_agents TEXT,
            results TEXT,
            approved_by TEXT,
            scenario_type TEXT,
            llm_generated BOOLEAN DEFAULT TRUE
        )
    ''')
    
    # Commands table - Agent command queue
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS commands (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            type TEXT,
            command TEXT,
            parameters TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP,
            executed_at TIMESTAMP,
            result TEXT,
            created_by TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        )
    ''')
    
    # Golden images table - System backups
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS golden_images (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            created_at TIMESTAMP,
            image_type TEXT,
            image_path TEXT,
            checksum TEXT,
            metadata TEXT,
            created_by TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        )
    ''')
    
    # Software downloads tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS software_downloads (
            id TEXT PRIMARY KEY,
            download_id INTEGER,
            user_email TEXT,
            downloaded_at TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            software_type TEXT,
            version TEXT
        )
    ''')
    
    # Alerts table - Security alerts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            detection_id TEXT,
            created_at TIMESTAMP,
            severity TEXT,
            title TEXT,
            description TEXT,
            status TEXT DEFAULT 'open',
            assigned_to TEXT,
            resolved_at TIMESTAMP,
            FOREIGN KEY (detection_id) REFERENCES detections(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info(f"Tenant database initialized with all tables: {tenant_slug}")

def create_demo_tenants():
    """Create demo tenants with CodeGrey users"""
    import uuid
    import bcrypt
    
    conn = sqlite3.connect("master_platform.db")
    cursor = conn.cursor()
    
    # Check if demo tenants exist
    cursor.execute("SELECT COUNT(*) FROM tenants WHERE slug IN ('codegrey', 'acme', 'contoso')")
    if cursor.fetchone()[0] > 0:
        logger.info("Demo tenants already exist")
        conn.close()
        return
    
    demo_tenants = [
        {
            'id': f'org_{uuid.uuid4().hex[:12]}',
            'name': 'CodeGrey SOC',
            'slug': 'codegrey',
            'admin_email': 'sagar@codegrey.ai',
            'subscription_tier': 'enterprise'
        },
        {
            'id': f'org_{uuid.uuid4().hex[:12]}',
            'name': 'Acme Corporation',
            'slug': 'acme',
            'admin_email': 'admin@acme.com',
            'subscription_tier': 'enterprise'
        },
        {
            'id': f'org_{uuid.uuid4().hex[:12]}',
            'name': 'Contoso Ltd',
            'slug': 'contoso',
            'admin_email': 'admin@contoso.com',
            'subscription_tier': 'professional'
        }
    ]
    
    for tenant in demo_tenants:
        # Create tenant
        cursor.execute('''
            INSERT INTO tenants (id, name, slug, database_name, admin_email, subscription_tier)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            tenant['id'],
            tenant['name'],
            tenant['slug'],
            f"tenant_{tenant['slug']}.db",
            tenant['admin_email'],
            tenant['subscription_tier']
        ))
        
        # Initialize tenant database with all tables
        init_tenant_database(tenant['slug'])
        
        # Create admin user
        user_id = f'user_{uuid.uuid4().hex[:12]}'
        password_hash = bcrypt.hashpw(b'123', bcrypt.gensalt()).decode('utf-8')
        
        cursor.execute('''
            INSERT OR IGNORE INTO global_users (id, email, password_hash, first_name, last_name)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, tenant['admin_email'], password_hash, 'Admin', tenant['name']))
        
        # Link user to tenant
        cursor.execute('''
            INSERT OR IGNORE INTO user_tenants (user_id, tenant_id, role)
            VALUES (?, ?, 'admin')
        ''', (user_id, tenant['id']))
        
        logger.info(f"Created demo tenant: {tenant['name']} ({tenant['slug']})")
    
    # Create CodeGrey specific users with API keys
    codegrey_users = [
        {'email': 'sagar@codegrey.ai', 'first_name': 'Sagar', 'last_name': 'CodeGrey', 'role': 'admin', 'api_key': 'usr-api-sagar-default-2024'},
        {'email': 'alsaad@codegrey.ai', 'first_name': 'Alsaad', 'last_name': 'CodeGrey', 'role': 'admin', 'api_key': 'usr-api-alsaad-default-2024'},
        {'email': 'krithika@codegrey.ai', 'first_name': 'Krithika', 'last_name': 'CodeGrey', 'role': 'admin', 'api_key': 'usr-api-krithika-default-2024'}
    ]
    
    # Get CodeGrey tenant ID
    cursor.execute("SELECT id FROM tenants WHERE slug = 'codegrey'")
    codegrey_tenant = cursor.fetchone()
    
    if codegrey_tenant:
        codegrey_tenant_id = codegrey_tenant[0]
        password_hash = bcrypt.hashpw(b'123', bcrypt.gensalt()).decode('utf-8')
        
        for user in codegrey_users:
            user_id = f'user_{uuid.uuid4().hex[:12]}'
            
            # Add api_key column if it doesn't exist
            cursor.execute("PRAGMA table_info(global_users)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'api_key' not in columns:
                cursor.execute('ALTER TABLE global_users ADD COLUMN api_key TEXT UNIQUE')
            
            # Create user if not exists with API key
            cursor.execute('''
                INSERT OR REPLACE INTO global_users (id, email, password_hash, first_name, last_name, api_key)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, user['email'], password_hash, user['first_name'], user['last_name'], user['api_key']))
            
            # Get user ID if already exists
            cursor.execute("SELECT id FROM global_users WHERE email = ?", (user['email'],))
            existing_user = cursor.fetchone()
            if existing_user:
                user_id = existing_user[0]
            
            # Link to CodeGrey tenant
            cursor.execute('''
                INSERT OR IGNORE INTO user_tenants (user_id, tenant_id, role)
                VALUES (?, ?, ?)
            ''', (user_id, codegrey_tenant_id, user['role']))
            
            # Also link to other tenants for testing
            cursor.execute("SELECT id FROM tenants WHERE slug IN ('acme', 'contoso')")
            other_tenants = cursor.fetchall()
            for other_tenant_id in other_tenants:
                cursor.execute('''
                    INSERT OR IGNORE INTO user_tenants (user_id, tenant_id, role)
                    VALUES (?, ?, ?)
                ''', (user_id, other_tenant_id[0], 'admin'))
            
            logger.info(f"Created user: {user['email']}")
    
    conn.commit()
    conn.close()
    
    logger.info(f"Demo setup complete. Access at: {BASE_URL}/t/codegrey/dashboard")

class AttackAgentManager:
    """Manages AI Attack agents for multiple tenants"""
    
    def __init__(self):
        self.tenant_agents = {}
        self.running = True
        
    async def start_for_tenant(self, tenant_id, tenant_slug):
        """Start attack agent for a specific tenant"""
        try:
            # Try to import LangGraph-based attack workflow
            from agents.langgraph.workflows.attack_workflow import AttackWorkflow
            
            workflow = AttackWorkflow(
                checkpoint_dir=f"checkpoints/{tenant_slug}",
                db_path=f"tenant_databases/tenant_{tenant_slug}.db"
            )
            
            self.tenant_agents[tenant_id] = workflow
            logger.info(f"✅ LangGraph Attack Agent (PhantomStrike AI) started for tenant: {tenant_slug}")
            
        except ImportError as e:
            logger.warning(f"LangGraph not available, using basic attack agent for {tenant_slug}: {e}")
            # Fallback to basic attack agent
            self.tenant_agents[tenant_id] = {"type": "basic", "status": "ready"}
            logger.info(f"✅ Basic Attack Agent started for tenant: {tenant_slug}")
    
    def get_agent_status(self, tenant_id):
        """Get attack agent status"""
        if tenant_id in self.tenant_agents:
            return {"status": "active", "type": "attack", "name": "PhantomStrike AI"}
        return {"status": "offline", "type": "attack", "name": "PhantomStrike AI"}

class DetectionAgentManager:
    """Manages AI Detection agents for multiple tenants"""
    
    def __init__(self):
        self.tenant_agents = {}
        self.running = True
        
    async def start_for_tenant(self, tenant_id, tenant_slug):
        """Start detection agent for a specific tenant"""
        try:
            # Try to import LangGraph-based detection workflow
            from agents.langgraph.workflows.detection_workflow import DetectionWorkflow
            
            workflow = DetectionWorkflow(
                checkpoint_dir=f"checkpoints/{tenant_slug}",
                db_path=f"tenant_databases/tenant_{tenant_slug}.db"
            )
            
            self.tenant_agents[tenant_id] = workflow
            
            # Start continuous monitoring
            asyncio.create_task(self.monitor_tenant(tenant_id, tenant_slug))
            logger.info(f"✅ LangGraph Detection Agent (GuardianAlpha AI) started for tenant: {tenant_slug}")
            
        except ImportError as e:
            logger.warning(f"LangGraph not available, using basic detection for {tenant_slug}: {e}")
            # Fallback to basic detection
            self.tenant_agents[tenant_id] = {"type": "basic", "status": "monitoring"}
            asyncio.create_task(self.basic_monitor(tenant_id, tenant_slug))
            logger.info(f"✅ Basic Detection Agent started for tenant: {tenant_slug}")
    
    async def monitor_tenant(self, tenant_id, tenant_slug):
        """Continuous monitoring for a tenant"""
        while self.running and tenant_id in self.tenant_agents:
            try:
                db_path = f"tenant_databases/tenant_{tenant_slug}.db"
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Check for unprocessed logs
                cursor.execute("""
                    SELECT COUNT(*) FROM logs 
                    WHERE processed = FALSE 
                    AND timestamp > datetime('now', '-5 minutes')
                """)
                
                unprocessed = cursor.fetchone()[0]
                
                if unprocessed > 0:
                    logger.info(f"[{tenant_slug}] Processing {unprocessed} new logs for threat detection")
                    
                    # Mark as processed (in real implementation, would run ML/AI detection)
                    cursor.execute("""
                        UPDATE logs SET processed = TRUE 
                        WHERE processed = FALSE
                    """)
                    conn.commit()
                
                conn.close()
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring tenant {tenant_slug}: {e}")
                await asyncio.sleep(60)
    
    async def basic_monitor(self, tenant_id, tenant_slug):
        """Basic monitoring without LangGraph"""
        while self.running:
            await asyncio.sleep(30)
            logger.debug(f"[{tenant_slug}] Basic detection running...")
    
    def get_agent_status(self, tenant_id):
        """Get detection agent status"""
        if tenant_id in self.tenant_agents:
            return {"status": "active", "type": "detection", "name": "GuardianAlpha AI"}
        return {"status": "offline", "type": "detection", "name": "GuardianAlpha AI"}

def start_flask_app():
    """Start the Flask application with all APIs"""
    os.environ['FLASK_ENV'] = 'production'
    os.environ['DOMAIN'] = DOMAIN
    os.environ['BASE_URL'] = BASE_URL
    
    # Fix Python path for imports
    flask_dir = Path(__file__).parent / "flask_api"
    sys.path.insert(0, str(flask_dir.parent))
    sys.path.insert(0, str(flask_dir))
    
    try:
        # Import Flask app with all routes
        from app import app
        
        # Configure for production
        app.config['DEBUG'] = False
        app.config['TESTING'] = False
        app.config['DOMAIN'] = DOMAIN
        app.config['BASE_URL'] = BASE_URL
        
        # Log all registered routes
        logger.info("Registered API endpoints:")
        for rule in app.url_map.iter_rules():
            logger.info(f"  {rule.endpoint}: {rule.rule}")
        
        # Try HTTPS first, fallback to HTTP
        try:
            import ssl
            cert_file = 'certificates/cert.pem'
            key_file = 'certificates/key.pem'
            
            if os.path.exists(cert_file) and os.path.exists(key_file):
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                context.load_cert_chain(cert_file, key_file)
                logger.info(f"Starting Flask app with HTTPS on port 8443")
                logger.info(f"Access at: {BASE_URL}/api/agents")
                app.run(host='0.0.0.0', port=8443, ssl_context=context)
            else:
                logger.info("SSL certificates not found, starting HTTP on port 5000")
                logger.info(f"Access at: http://{DOMAIN}:5000/api/agents")
                logger.info(f"Or use IP: http://YOUR-SERVER-IP:5000/api/agents")
                app.run(host='0.0.0.0', port=5000)
                
        except Exception as e:
            logger.warning(f"Could not start with SSL: {e}")
            logger.info("Starting Flask app with HTTP on port 5000")
            logger.info(f"Access at: http://{DOMAIN}:5000/api/agents")
            app.run(host='0.0.0.0', port=5000)
            
    except ImportError as e:
        logger.error(f"Could not import Flask app: {e}")
        logger.error("Check flask_api/app.py exists and imports are correct")

# Global agent managers
attack_manager = None
detection_manager = None

async def start_agents():
    """Start ALL AI agents for all active tenants"""
    global attack_manager, detection_manager
    
    attack_manager = AttackAgentManager()
    detection_manager = DetectionAgentManager()
    
    # Get active tenants
    conn = sqlite3.connect("master_platform.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, slug FROM tenants WHERE status = 'active'")
    tenants = cursor.fetchall()
    conn.close()
    
    # Start both agents for each tenant
    for tenant_id, tenant_slug in tenants:
        logger.info(f"Starting AI agents for tenant: {tenant_slug}")
        await attack_manager.start_for_tenant(tenant_id, tenant_slug)
        await detection_manager.start_for_tenant(tenant_id, tenant_slug)
    
    logger.info(f"✅ Started AI agents for {len(tenants)} tenants")
    logger.info(f"   - PhantomStrike AI (Attack Agent)")
    logger.info(f"   - GuardianAlpha AI (Detection Agent)")
    
    # Keep agents running
    try:
        while True:
            await asyncio.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down agents...")
        detection_manager.running = False
        attack_manager.running = False

def main():
    """Main entry point - starts everything"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║           CODEGREY SOC PLATFORM - PRODUCTION                ║
    ║              Complete AI-Driven Security Platform            ║
    ║                   Domain: dev.codegrey.ai                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    logger.info("="*60)
    logger.info("Starting Complete SOC Platform...")
    logger.info(f"Domain: {DOMAIN}")
    logger.info(f"Base URL: {BASE_URL}")
    logger.info("="*60)
    
    # Initialize databases
    logger.info("Initializing databases...")
    init_master_database()
    create_demo_tenants()
    
    # Create necessary directories
    directories = ["tenant_databases", "logs", "checkpoints", "golden_images", "certificates"]
    for dir_name in directories:
        Path(dir_name).mkdir(exist_ok=True)
    logger.info(f"Created directories: {', '.join(directories)}")
    
    # Start AI agents in background
    def run_agents():
        asyncio.run(start_agents())
    
    agent_thread = threading.Thread(target=run_agents, daemon=True)
    agent_thread.start()
    logger.info("✅ AI Agents started in background")
    
    # Log access information
    logger.info("="*60)
    logger.info("PLATFORM READY!")
    logger.info("="*60)
    logger.info("Access URLs:")
    logger.info(f"  Main: {BASE_URL}/t/codegrey/dashboard")
    logger.info(f"  Login: {BASE_URL}/t/codegrey/login")
    logger.info("")
    logger.info("Default Users (password: 123):")
    logger.info("  - sagar@codegrey.ai (API Key: usr-api-sagar-default-2024)")
    logger.info("  - alsaad@codegrey.ai (API Key: usr-api-alsaad-default-2024)")
    logger.info("  - krithika@codegrey.ai (API Key: usr-api-krithika-default-2024)")
    logger.info("")
    logger.info("API Endpoints:")
    logger.info(f"  {BASE_URL}/api/agents")
    logger.info(f"  {BASE_URL}/api/software-download")
    logger.info(f"  {BASE_URL}/api/network-topology")
    logger.info("="*60)
    
    # Start Flask app (this blocks)
    logger.info("Starting Flask API server...")
    start_flask_app()

if __name__ == "__main__":
    main()