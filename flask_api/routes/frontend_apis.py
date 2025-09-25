"""
Frontend-specific APIs for Software Download, Agent Listing, and Network Topology
Provides exact data structures requested by frontend team
"""

from flask import Blueprint, jsonify, request
import sqlite3
import json
from datetime import datetime, timezone, timedelta
import uuid

frontend_bp = Blueprint('frontend', __name__)

def get_db_connection(tenant_slug='codegrey'):
    """Get database connection for tenant"""
    db_path = f"tenant_databases/tenant_{tenant_slug}.db"
    return sqlite3.connect(db_path)

@frontend_bp.route('/api/software-download', methods=['GET'])
def get_software_downloads():
    """
    Get available software downloads
    Frontend: app/profile/software-downloads/page.tsx
    """
    downloads = [
        {
            "id": 1,
            "name": "windows",
            "version": "2024.1.3",
            "description": "Windows endpoint agent with real-time monitoring, behavioral analysis, and AI-powered threat detection.",
            "fileName": "CodeGrey AI Endpoint Agent",
            "downloadUrl": "/api/download/agent/windows",  # This triggers API key generation
            "os": "Windows",
            "architecture": "x64",
            "minRamGB": 4,
            "minDiskMB": 500,
            "configurationCmd": "codegrey-agent.exe --configure --server=https://dev.codegrey.ai --token=YOUR_API_TOKEN",
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
            "architecture": "x64",
            "minRamGB": 2,
            "minDiskMB": 300,
            "configurationCmd": "sudo codegrey-agent configure --server https://dev.codegrey.ai --token YOUR_API_TOKEN",
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
            "architecture": "arm64",
            "minRamGB": 3,
            "minDiskMB": 400,
            "configurationCmd": "sudo /usr/local/bin/codegrey-agent --configure --server=https://dev.codegrey.ai --token=YOUR_API_TOKEN",
            "systemRequirements": [
                "macOS 11.0+",
                "Administrator privileges",
                "3 GB RAM",
                "400 MB disk space"
            ]
        }
    ]
    
    return jsonify(downloads)

@frontend_bp.route('/api/agents', methods=['GET'])
def list_agents():
    """
    List AI agents (Attack and Detection agents)
    Frontend: components/AgentEcoSystemBanner.tsx
    Returns exact structure requested by frontend
    """
    agents = [
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
    ]
    
    # Check actual status from database if available
    try:
        tenant_slug = request.args.get('tenant', 'codegrey')
        conn = get_db_connection(tenant_slug)
        cursor = conn.cursor()
        
        # Check for recent attack workflows
        cursor.execute("""
            SELECT status, started_at 
            FROM attack_workflows 
            WHERE created_at > datetime('now', '-1 hour')
            ORDER BY created_at DESC LIMIT 1
        """)
        attack_workflow = cursor.fetchone()
        
        if attack_workflow and attack_workflow[0] == 'running':
            agents[0]['status'] = 'active'
            agents[0]['lastActivity'] = 'Now'
        
        # Check for recent detections
        cursor.execute("""
            SELECT COUNT(*) 
            FROM detections 
            WHERE timestamp > datetime('now', '-5 minutes')
        """)
        recent_detections = cursor.fetchone()[0]
        
        if recent_detections > 0:
            agents[1]['status'] = 'active'
            agents[1]['lastActivity'] = 'Now'
        
        conn.close()
    except:
        pass  # Use default values if DB not available
    
    return jsonify(agents)

@frontend_bp.route('/api/network-topology', methods=['GET'])
def get_network_topology():
    """
    Get network topology in tabular form
    Supports hierarchy/order flags as requested
    """
    # Get query parameters
    order = request.args.get('order', 'hierarchy')  # hierarchy or desc
    show_offline = request.args.get('show_offline', 'true').lower() == 'true'
    tenant_slug = request.args.get('tenant', 'codegrey')
    
    try:
        conn = get_db_connection(tenant_slug)
        cursor = conn.cursor()
        
        # Fetch all agents (client endpoints)
        cursor.execute("""
            SELECT 
                id, hostname, ip_address, platform, status,
                endpoint_importance, user_role, last_heartbeat,
                configuration
            FROM agents
            ORDER BY 
                CASE endpoint_importance
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                hostname
        """)
        
        agents = cursor.fetchall()
        conn.close()
        
        # Format for tabular display
        network_nodes = []
        
        for agent in agents:
            # Skip offline if not showing
            if not show_offline and agent[4] != 'online':
                continue
            
            # Parse configuration for details
            config = json.loads(agent[8] or '{}')
            
            # Determine hierarchy level based on importance
            hierarchy_level = {
                'critical': 1,
                'high': 2,
                'medium': 3,
                'low': 4
            }.get(agent[5], 5)
            
            node = {
                "id": agent[0],
                "hostname": agent[1],
                "ipAddress": agent[2],
                "platform": agent[3],
                "status": agent[4],
                "importance": agent[5] or 'unknown',
                "role": agent[6] or 'endpoint',
                "lastSeen": agent[7] or datetime.now(timezone.utc).isoformat(),
                "hierarchyLevel": hierarchy_level,
                "details": {
                    "version": config.get('version', 'Unknown'),
                    "updateInterval": config.get('update_interval', 60),
                    "capabilities": config.get('capabilities', [])
                }
            }
            
            # Add status indicator
            if agent[4] == 'online':
                last_heartbeat = datetime.fromisoformat(agent[7]) if agent[7] else None
                if last_heartbeat:
                    time_diff = datetime.now(timezone.utc) - last_heartbeat
                    if time_diff < timedelta(minutes=1):
                        node['statusIndicator'] = 'green'
                        node['statusText'] = 'Online'
                    elif time_diff < timedelta(minutes=5):
                        node['statusIndicator'] = 'yellow'
                        node['statusText'] = 'Warning'
                    else:
                        node['statusIndicator'] = 'red'
                        node['statusText'] = 'Offline'
                else:
                    node['statusIndicator'] = 'gray'
                    node['statusText'] = 'Unknown'
            else:
                node['statusIndicator'] = 'red'
                node['statusText'] = 'Offline'
            
            network_nodes.append(node)
        
        # Sort based on requested order
        if order == 'desc':
            # Descending order by hostname
            network_nodes.sort(key=lambda x: x['hostname'], reverse=True)
        else:
            # Hierarchy order (already sorted by importance)
            pass
        
        # Create response with metadata
        response = {
            "nodes": network_nodes,
            "metadata": {
                "totalNodes": len(network_nodes),
                "onlineNodes": sum(1 for n in network_nodes if n['statusIndicator'] in ['green', 'yellow']),
                "offlineNodes": sum(1 for n in network_nodes if n['statusIndicator'] == 'red'),
                "criticalNodes": sum(1 for n in network_nodes if n['importance'] == 'critical'),
                "lastUpdated": datetime.now(timezone.utc).isoformat(),
                "orderBy": order
            },
            "hierarchyLevels": [
                {"level": 1, "name": "Critical Infrastructure", "color": "#ff0000"},
                {"level": 2, "name": "High Value Assets", "color": "#ff9900"},
                {"level": 3, "name": "Standard Systems", "color": "#ffcc00"},
                {"level": 4, "name": "Low Priority", "color": "#00cc00"}
            ]
        }
        
        return jsonify(response)
        
    except Exception as e:
        # Return sample data if database not available
        sample_response = {
            "nodes": [
                {
                    "id": "agent_dc01",
                    "hostname": "DC01-PRIMARY",
                    "ipAddress": "192.168.1.10",
                    "platform": "Windows Server 2019",
                    "status": "online",
                    "importance": "critical",
                    "role": "domain_controller",
                    "lastSeen": datetime.now(timezone.utc).isoformat(),
                    "hierarchyLevel": 1,
                    "statusIndicator": "green",
                    "statusText": "Online",
                    "details": {
                        "version": "3.0.0",
                        "updateInterval": 60,
                        "capabilities": ["active_directory", "dns", "dhcp"]
                    }
                },
                {
                    "id": "agent_sql01",
                    "hostname": "SQL01-PROD",
                    "ipAddress": "192.168.1.20",
                    "platform": "Windows Server 2016",
                    "status": "online",
                    "importance": "critical",
                    "role": "database_server",
                    "lastSeen": datetime.now(timezone.utc).isoformat(),
                    "hierarchyLevel": 1,
                    "statusIndicator": "green",
                    "statusText": "Online",
                    "details": {
                        "version": "3.0.0",
                        "updateInterval": 60,
                        "capabilities": ["sql_server", "data_storage"]
                    }
                },
                {
                    "id": "agent_web01",
                    "hostname": "WEB01-PUBLIC",
                    "ipAddress": "10.0.0.50",
                    "platform": "Ubuntu 20.04",
                    "status": "online",
                    "importance": "medium",
                    "role": "web_server",
                    "lastSeen": datetime.now(timezone.utc).isoformat(),
                    "hierarchyLevel": 3,
                    "statusIndicator": "green",
                    "statusText": "Online",
                    "details": {
                        "version": "3.0.0",
                        "updateInterval": 60,
                        "capabilities": ["web_hosting", "api_gateway"]
                    }
                },
                {
                    "id": "agent_user01",
                    "hostname": "USER-PC-001",
                    "ipAddress": "192.168.4.100",
                    "platform": "Windows 10",
                    "status": "online",
                    "importance": "low",
                    "role": "employee",
                    "lastSeen": datetime.now(timezone.utc).isoformat(),
                    "hierarchyLevel": 4,
                    "statusIndicator": "yellow",
                    "statusText": "Warning",
                    "details": {
                        "version": "3.0.0",
                        "updateInterval": 60,
                        "capabilities": ["email", "web_browsing"]
                    }
                }
            ],
            "metadata": {
                "totalNodes": 4,
                "onlineNodes": 4,
                "offlineNodes": 0,
                "criticalNodes": 2,
                "lastUpdated": datetime.now(timezone.utc).isoformat(),
                "orderBy": order
            },
            "hierarchyLevels": [
                {"level": 1, "name": "Critical Infrastructure", "color": "#ff0000"},
                {"level": 2, "name": "High Value Assets", "color": "#ff9900"},
                {"level": 3, "name": "Standard Systems", "color": "#ffcc00"},
                {"level": 4, "name": "Low Priority", "color": "#00cc00"}
            ]
        }
        
        return jsonify(sample_response)

@frontend_bp.route('/api/software-download/<int:download_id>', methods=['POST'])
def track_download(download_id):
    """
    Track software download by user and generate deployment API key
    SOC analysts download pre-configured agents with embedded API keys
    """
    try:
        data = request.get_json()
        user_email = data.get('user_email', 'unknown')
        tenant_slug = data.get('tenant', 'codegrey')
        
        # Generate unique deployment API key for this download
        deployment_api_key = f"soc-dep-{uuid.uuid4().hex}"
        
        # Get deployment configuration
        endpoint_type = data.get('endpoint_type', 'employee')
        department = data.get('department', 'general')
        num_licenses = data.get('num_licenses', 1)
        
        # Get platform from download_id
        platform_map = {
            1: 'Windows',
            2: 'Linux', 
            3: 'macOS'
        }
        platform = platform_map.get(download_id, 'Unknown')
        
        # Log the download with deployment info
        conn = get_db_connection(tenant_slug)
        cursor = conn.cursor()
        
        # Create enhanced downloads table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS software_downloads (
                id TEXT PRIMARY KEY,
                download_id INTEGER,
                deployment_api_key TEXT UNIQUE,
                user_email TEXT,
                platform TEXT,
                endpoint_type TEXT,
                department TEXT,
                num_licenses INTEGER,
                deployed_count INTEGER DEFAULT 0,
                downloaded_at TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        deployment_id = f"dep_{uuid.uuid4().hex[:12]}"
        
        cursor.execute('''
            INSERT INTO software_downloads 
            (id, download_id, deployment_api_key, user_email, platform, 
             endpoint_type, department, num_licenses, downloaded_at, 
             ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            deployment_id,
            download_id,
            deployment_api_key,
            user_email,
            platform,
            endpoint_type,
            department,
            num_licenses,
            datetime.now(timezone.utc).isoformat(),
            request.remote_addr,
            request.headers.get('User-Agent', 'Unknown')
        ))
        
        # Also store the API key in agents table for authentication
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agent_api_keys (
                api_key TEXT PRIMARY KEY,
                deployment_id TEXT,
                created_by TEXT,
                created_at TIMESTAMP,
                tenant TEXT,
                status TEXT DEFAULT 'active',
                FOREIGN KEY (deployment_id) REFERENCES software_downloads(id)
            )
        ''')
        
        cursor.execute('''
            INSERT INTO agent_api_keys (api_key, deployment_id, created_by, created_at, tenant)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            deployment_api_key,
            deployment_id,
            user_email,
            datetime.now(timezone.utc).isoformat(),
            tenant_slug
        ))
        
        conn.commit()
        conn.close()
        
        # Generate installation commands with embedded API key
        install_commands = {
            'Windows': f'''
# Windows PowerShell (Run as Administrator)
$config = @{{
    "server_url" = "https://dev.codegrey.ai"
    "api_key" = "{deployment_api_key}"
    "tenant" = "{tenant_slug}"
}} | ConvertTo-Json
New-Item -Path "C:\\ProgramData\\CodeGrey" -ItemType Directory -Force
$config | Out-File "C:\\ProgramData\\CodeGrey\\agent.conf"
python windows_agent.py --install
''',
            'Linux': f'''
# Linux Bash (Run as root)
mkdir -p /etc/codegrey
cat > /etc/codegrey/agent.conf << EOF
{{
  "server_url": "https://dev.codegrey.ai",
  "api_key": "{deployment_api_key}",
  "tenant": "{tenant_slug}"
}}
EOF
chmod 600 /etc/codegrey/agent.conf
python3 linux_agent.py --install
''',
            'macOS': f'''
# macOS Terminal (Run with sudo)
mkdir -p "/Library/Application Support/CodeGrey"
cat > "/Library/Application Support/CodeGrey/agent.conf" << EOF
{{
  "server_url": "https://dev.codegrey.ai",
  "api_key": "{deployment_api_key}",
  "tenant": "{tenant_slug}"
}}
EOF
chmod 600 "/Library/Application Support/CodeGrey/agent.conf"
sudo python3 macos_agent.py --install
'''
        }
        
        return jsonify({
            "success": True,
            "message": "Agent package generated with embedded configuration",
            "deployment": {
                "id": deployment_id,
                "api_key": deployment_api_key,
                "platform": platform,
                "endpoint_type": endpoint_type,
                "department": department,
                "licenses": num_licenses
            },
            "configuration": {
                "server_url": "https://dev.codegrey.ai",
                "api_key": deployment_api_key,
                "tenant": tenant_slug
            },
            "installation_command": install_commands.get(platform, "# Platform not supported"),
            "download_url": f"https://dev.codegrey.ai/downloads/{deployment_id}/agent-{platform.lower()}.zip"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# Additional helper endpoint for agent status updates
@frontend_bp.route('/api/agents/status', methods=['GET'])
def get_agents_status():
    """
    Get real-time status of all agents (both AI and client agents)
    """
    tenant_slug = request.args.get('tenant', 'codegrey')
    
    response = {
        "aiAgents": [
            {
                "name": "PhantomStrike AI",
                "type": "attack",
                "status": "idle",
                "lastActivity": datetime.now(timezone.utc).isoformat()
            },
            {
                "name": "GuardianAlpha AI", 
                "type": "detection",
                "status": "active",
                "lastActivity": datetime.now(timezone.utc).isoformat()
            }
        ],
        "clientAgents": {
            "total": 0,
            "online": 0,
            "offline": 0,
            "warning": 0
        },
        "lastUpdated": datetime.now(timezone.utc).isoformat()
    }
    
    try:
        conn = get_db_connection(tenant_slug)
        cursor = conn.cursor()
        
        # Count client agents by status
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online,
                SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline
            FROM agents
        """)
        
        result = cursor.fetchone()
        if result:
            response['clientAgents']['total'] = result[0]
            response['clientAgents']['online'] = result[1] or 0
            response['clientAgents']['offline'] = result[2] or 0
        
        conn.close()
        
    except:
        pass  # Return default values
    
    return jsonify(response)
