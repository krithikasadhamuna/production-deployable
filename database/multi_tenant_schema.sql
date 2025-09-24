-- CodeGrey SOC Multi-Tenant Database Schema
-- This schema supports complete tenant isolation for multiple organizations

-- ============================================================================
-- TENANT MANAGEMENT TABLES
-- ============================================================================

-- Organizations (Tenants)
CREATE TABLE organizations (
    id VARCHAR(36) PRIMARY KEY,                    -- UUID
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE,                    -- company.com
    subdomain VARCHAR(100) UNIQUE,                 -- company.codegrey.ai
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'suspended', 'trial', 'expired') DEFAULT 'active',
    settings JSON,                                 -- Tenant-specific settings
    limits JSON,                                   -- Resource limits
    billing_info JSON,                             -- Billing details
    contact_email VARCHAR(255),
    phone VARCHAR(50),
    address TEXT,
    
    INDEX idx_domain (domain),
    INDEX idx_subdomain (subdomain),
    INDEX idx_status (status)
);

-- Tenant Users
CREATE TABLE tenant_users (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role ENUM('super_admin', 'admin', 'analyst', 'viewer') DEFAULT 'analyst',
    permissions JSON,                              -- Granular permissions
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    login_count INT DEFAULT 0,
    status ENUM('active', 'inactive', 'locked') DEFAULT 'active',
    email_verified BOOLEAN DEFAULT FALSE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP,
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    UNIQUE KEY unique_email_per_org (organization_id, email),
    INDEX idx_org_email (organization_id, email),
    INDEX idx_org_role (organization_id, role),
    INDEX idx_status (status)
);

-- API Keys (Tenant-scoped)
CREATE TABLE api_keys (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,         -- Hashed API key
    key_prefix VARCHAR(20),                        -- First few chars for identification
    name VARCHAR(255),                             -- Human-readable name
    description TEXT,
    permissions JSON,                              -- API permissions
    rate_limit_per_minute INT DEFAULT 100,
    created_by VARCHAR(36),                        -- User who created it
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_used TIMESTAMP,
    usage_count INT DEFAULT 0,
    status ENUM('active', 'revoked', 'expired') DEFAULT 'active',
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES tenant_users(id) ON DELETE SET NULL,
    INDEX idx_key_hash (key_hash),
    INDEX idx_org_status (organization_id, status)
);

-- ============================================================================
-- TENANT-SCOPED AGENT MANAGEMENT
-- ============================================================================

-- Agents (Tenant-scoped)
CREATE TABLE agents (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,          -- TENANT ISOLATION KEY
    agent_id VARCHAR(255) NOT NULL,                -- Agent's self-reported ID
    name VARCHAR(255),
    type ENUM('windows', 'linux', 'macos', 'android', 'attack', 'detection') NOT NULL,
    hostname VARCHAR(255),
    ip_address VARCHAR(45),
    public_ip VARCHAR(45),
    mac_address VARCHAR(17),
    os_info JSON,                                  -- OS details
    hardware_info JSON,                            -- Hardware specs
    network_info JSON,                             -- Network configuration
    version VARCHAR(50),                           -- Agent version
    status ENUM('online', 'offline', 'idle', 'busy', 'error', 'maintenance') DEFAULT 'offline',
    last_heartbeat TIMESTAMP,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    capabilities JSON,                             -- Agent capabilities
    configuration JSON,                            -- Agent configuration
    metadata JSON,                                 -- Additional metadata
    tags JSON,                                     -- User-defined tags
    location VARCHAR(255),                         -- Physical/logical location
    department VARCHAR(100),                       -- Department/team
    environment ENUM('production', 'staging', 'development', 'test') DEFAULT 'production',
    criticality ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    
    -- Network Element Classification Fields
    network_element_type VARCHAR(100) DEFAULT 'endpoint',     -- firewall, dmz, datacenter, endpoint, soc, cloud, etc.
    network_role VARCHAR(100) DEFAULT 'user',                 -- security, infrastructure, user, external
    security_zone VARCHAR(100) DEFAULT 'internal',            -- external, dmz, internal, secure, perimeter
    subnet VARCHAR(45) DEFAULT 'unknown',                     -- Network subnet (e.g., 192.168.1.0/24)
    element_confidence DECIMAL(3,2) DEFAULT 0.5,              -- Detection confidence (0.0-1.0)
    network_characteristics JSON,                             -- Detected characteristics
    detected_services JSON,                                   -- Services detected on this element
    open_ports JSON,                                          -- Open ports discovered
    network_topology_level INT DEFAULT 3,                     -- Hierarchy level (0=internet, 1=perimeter, 2=internal, 3=endpoints)
    parent_network_element VARCHAR(36),                       -- Parent element in network hierarchy
    child_network_elements JSON,                              -- Child elements
    last_network_scan TIMESTAMP,                              -- Last network discovery scan
    
    -- User Role Information (NEW: Secure role detection)
    user_role_info JSON,                                      -- Complete user role information from agent
    username VARCHAR(255),                                    -- Current logged-in user
    user_groups JSON,                                         -- User's group memberships
    is_admin BOOLEAN DEFAULT FALSE,                           -- Whether user has admin privileges
    domain_info JSON,                                         -- AD/LDAP information if available
    classified_roles JSON,                                    -- Final role classifications (Executive, Admin, Manager, etc.)
    role_confidence DECIMAL(3,2) DEFAULT 0.5,                -- Confidence in role classification (0.0-1.0)
    role_last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,    -- When role info was last updated
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_network_element) REFERENCES agents(id) ON DELETE SET NULL,
    UNIQUE KEY unique_agent_per_org (organization_id, agent_id),
    INDEX idx_org_type (organization_id, type),
    INDEX idx_org_status (organization_id, status),
    INDEX idx_org_heartbeat (organization_id, last_heartbeat),
    INDEX idx_hostname (hostname),
    INDEX idx_ip_address (ip_address),
    INDEX idx_network_element_type (network_element_type),
    INDEX idx_security_zone (security_zone),
    INDEX idx_network_role (network_role),
    INDEX idx_topology_level (network_topology_level),
    INDEX idx_org_network_type (organization_id, network_element_type),
    INDEX idx_username (username),
    INDEX idx_is_admin (is_admin),
    INDEX idx_org_admin (organization_id, is_admin),
    INDEX idx_role_confidence (role_confidence)
);

-- Agent Commands (Tenant-scoped)
CREATE TABLE agent_commands (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,          -- TENANT ISOLATION KEY
    agent_id VARCHAR(36) NOT NULL,
    command_type VARCHAR(100) NOT NULL,
    command_data JSON NOT NULL,
    priority ENUM('low', 'normal', 'high', 'urgent') DEFAULT 'normal',
    status ENUM('pending', 'sent', 'executing', 'completed', 'failed', 'timeout', 'cancelled') DEFAULT 'pending',
    created_by VARCHAR(36),                        -- User who created command
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP,
    executed_at TIMESTAMP,
    completed_at TIMESTAMP,
    timeout_seconds INT DEFAULT 300,
    retry_count INT DEFAULT 0,
    max_retries INT DEFAULT 3,
    result JSON,                                   -- Command execution result
    error_message TEXT,
    execution_time_ms INT,
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES tenant_users(id) ON DELETE SET NULL,
    INDEX idx_org_agent (organization_id, agent_id),
    INDEX idx_org_status (organization_id, status),
    INDEX idx_org_created (organization_id, created_at),
    INDEX idx_agent_status (agent_id, status)
);

-- Agent Logs (Tenant-scoped)
CREATE TABLE agent_logs (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,          -- TENANT ISOLATION KEY
    agent_id VARCHAR(36) NOT NULL,
    log_type VARCHAR(100) NOT NULL,                -- system, security, application, etc.
    log_level ENUM('debug', 'info', 'warning', 'error', 'critical') DEFAULT 'info',
    timestamp TIMESTAMP NOT NULL,
    message TEXT,
    data JSON,                                     -- Structured log data
    source VARCHAR(255),                           -- Log source
    process_name VARCHAR(255),
    process_id INT,
    user_name VARCHAR(255),
    file_path VARCHAR(500),
    event_id VARCHAR(100),
    raw_log TEXT,                                  -- Original log entry
    indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed BOOLEAN DEFAULT FALSE,
    threat_score DECIMAL(3,2) DEFAULT 0.0,        -- AI threat scoring
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    INDEX idx_org_agent_timestamp (organization_id, agent_id, timestamp),
    INDEX idx_org_log_type (organization_id, log_type),
    INDEX idx_org_log_level (organization_id, log_level),
    INDEX idx_timestamp (timestamp),
    INDEX idx_threat_score (threat_score),
    INDEX idx_processed (processed)
);

-- ============================================================================
-- TENANT-SCOPED THREAT INTELLIGENCE
-- ============================================================================

-- Threats (Tenant-scoped)
CREATE TABLE threats (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,          -- TENANT ISOLATION KEY
    threat_type VARCHAR(100) NOT NULL,
    threat_name VARCHAR(255),
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    confidence DECIMAL(3,2) DEFAULT 0.0,           -- 0.0 to 1.0
    status ENUM('open', 'investigating', 'contained', 'resolved', 'false_positive') DEFAULT 'open',
    source_agent_id VARCHAR(36),
    source_log_id VARCHAR(36),
    detection_timestamp TIMESTAMP NOT NULL,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details JSON,                                  -- Threat details
    indicators JSON,                               -- IOCs
    mitre_techniques JSON,                         -- MITRE ATT&CK techniques
    kill_chain_phase VARCHAR(100),
    affected_assets JSON,                          -- List of affected systems
    network_connections JSON,                      -- Network activity
    file_hashes JSON,                              -- File indicators
    registry_keys JSON,                            -- Registry modifications
    processes JSON,                                -- Process information
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(36),
    resolution_notes TEXT,
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (source_agent_id) REFERENCES agents(id) ON DELETE SET NULL,
    FOREIGN KEY (source_log_id) REFERENCES agent_logs(id) ON DELETE SET NULL,
    FOREIGN KEY (resolved_by) REFERENCES tenant_users(id) ON DELETE SET NULL,
    INDEX idx_org_severity (organization_id, severity),
    INDEX idx_org_status (organization_id, status),
    INDEX idx_org_detection_time (organization_id, detection_timestamp),
    INDEX idx_threat_type (threat_type),
    INDEX idx_confidence (confidence)
);

-- Alerts (Tenant-scoped)
CREATE TABLE alerts (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,          -- TENANT ISOLATION KEY
    threat_id VARCHAR(36),
    rule_id VARCHAR(36),                           -- Detection rule that triggered
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    status ENUM('open', 'acknowledged', 'investigating', 'resolved', 'closed') DEFAULT 'open',
    assigned_to VARCHAR(36),
    escalated_to VARCHAR(36),
    priority ENUM('low', 'normal', 'high', 'urgent') DEFAULT 'normal',
    tags JSON,
    source_data JSON,                              -- Original detection data
    context JSON,                                  -- Additional context
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMP,
    acknowledged_by VARCHAR(36),
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(36),
    resolution_notes TEXT,
    escalation_count INT DEFAULT 0,
    false_positive BOOLEAN DEFAULT FALSE,
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to) REFERENCES tenant_users(id) ON DELETE SET NULL,
    FOREIGN KEY (escalated_to) REFERENCES tenant_users(id) ON DELETE SET NULL,
    FOREIGN KEY (acknowledged_by) REFERENCES tenant_users(id) ON DELETE SET NULL,
    FOREIGN KEY (resolved_by) REFERENCES tenant_users(id) ON DELETE SET NULL,
    INDEX idx_org_severity (organization_id, severity),
    INDEX idx_org_status (organization_id, status),
    INDEX idx_org_created (organization_id, created_at),
    INDEX idx_assigned_to (assigned_to),
    INDEX idx_priority (priority)
);

-- ============================================================================
-- TENANT-SCOPED ANALYTICS & REPORTING
-- ============================================================================

-- Tenant Usage Metrics
CREATE TABLE tenant_usage_metrics (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    metric_type VARCHAR(100) NOT NULL,             -- agents, logs, threats, api_calls, storage
    metric_date DATE NOT NULL,
    metric_hour TINYINT,                           -- 0-23 for hourly metrics
    value_count BIGINT DEFAULT 0,
    value_size_bytes BIGINT DEFAULT 0,
    value_decimal DECIMAL(10,2) DEFAULT 0.0,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    UNIQUE KEY unique_org_metric_time (organization_id, metric_type, metric_date, metric_hour),
    INDEX idx_org_type_date (organization_id, metric_type, metric_date),
    INDEX idx_metric_date (metric_date)
);

-- Audit Logs (Tenant-scoped)
CREATE TABLE audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36),
    api_key_id VARCHAR(36),
    action VARCHAR(100) NOT NULL,                  -- login, create_agent, send_command, etc.
    resource_type VARCHAR(100),                    -- agent, command, threat, alert
    resource_id VARCHAR(36),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSON,
    result ENUM('success', 'failure', 'error') DEFAULT 'success',
    error_message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES tenant_users(id) ON DELETE SET NULL,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL,
    INDEX idx_org_timestamp (organization_id, timestamp),
    INDEX idx_org_action (organization_id, action),
    INDEX idx_org_user (organization_id, user_id),
    INDEX idx_timestamp (timestamp)
);

-- ============================================================================
-- DETECTION RULES (Tenant-scoped)
-- ============================================================================

-- Detection Rules
CREATE TABLE detection_rules (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,          -- TENANT ISOLATION KEY
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type ENUM('signature', 'behavioral', 'statistical', 'ml') NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    status ENUM('active', 'inactive', 'testing') DEFAULT 'active',
    rule_logic JSON NOT NULL,                      -- Rule definition
    mitre_techniques JSON,
    tags JSON,
    created_by VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_triggered TIMESTAMP,
    trigger_count INT DEFAULT 0,
    false_positive_count INT DEFAULT 0,
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES tenant_users(id) ON DELETE SET NULL,
    INDEX idx_org_status (organization_id, status),
    INDEX idx_org_type (organization_id, rule_type),
    INDEX idx_org_severity (organization_id, severity)
);

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Create default super admin organization (for system management)
INSERT INTO organizations (id, name, domain, subdomain, status, settings, limits) VALUES (
    'sys_admin_org',
    'CodeGrey System Administration',
    'admin.codegrey.ai',
    'admin',
    'active',
    '{"system_admin": true, "multi_tenant_admin": true}',
    '{"max_agents": 9999, "max_users": 100, "max_storage_gb": 1000}'
);

-- Create system admin user
INSERT INTO tenant_users (id, organization_id, email, role, status, email_verified) VALUES (
    'sys_admin_user',
    'sys_admin_org',
    'admin@codegrey.ai',
    'super_admin',
    'active',
    TRUE
);

-- Create system admin API key
INSERT INTO api_keys (id, organization_id, key_hash, key_prefix, name, permissions, created_by, rate_limit_per_minute) VALUES (
    'sys_admin_key',
    'sys_admin_org',
    SHA2('cg_sys_admin_key_12345', 256),
    'cg_sys_',
    'System Admin Key',
    '["*"]',
    'sys_admin_user',
    1000
);

-- ============================================================================
-- VIEWS FOR EASY QUERYING
-- ============================================================================

-- Agent Summary View
CREATE VIEW agent_summary AS
SELECT 
    a.id,
    a.organization_id,
    o.name as organization_name,
    a.agent_id,
    a.name,
    a.type,
    a.hostname,
    a.status,
    a.last_heartbeat,
    a.first_seen,
    TIMESTAMPDIFF(SECOND, a.last_heartbeat, NOW()) as seconds_since_heartbeat,
    JSON_LENGTH(a.capabilities) as capability_count
FROM agents a
JOIN organizations o ON a.organization_id = o.id
WHERE o.status = 'active';

-- Threat Summary View  
CREATE VIEW threat_summary AS
SELECT 
    t.id,
    t.organization_id,
    o.name as organization_name,
    t.threat_type,
    t.severity,
    t.status,
    t.detection_timestamp,
    a.name as source_agent_name,
    a.hostname as source_hostname,
    TIMESTAMPDIFF(HOUR, t.detection_timestamp, NOW()) as hours_since_detection
FROM threats t
JOIN organizations o ON t.organization_id = o.id
LEFT JOIN agents a ON t.source_agent_id = a.id
WHERE o.status = 'active';

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Additional performance indexes
CREATE INDEX idx_agents_org_heartbeat_status ON agents(organization_id, last_heartbeat, status);
CREATE INDEX idx_logs_org_timestamp_type ON agent_logs(organization_id, timestamp, log_type);
CREATE INDEX idx_threats_org_detection_severity ON threats(organization_id, detection_timestamp, severity);
CREATE INDEX idx_alerts_org_created_status ON alerts(organization_id, created_at, status);
CREATE INDEX idx_commands_org_created_status ON agent_commands(organization_id, created_at, status);

-- Full-text search indexes
CREATE FULLTEXT INDEX ft_agents_search ON agents(name, hostname, location, department);
CREATE FULLTEXT INDEX ft_threats_search ON threats(threat_name, details);
CREATE FULLTEXT INDEX ft_alerts_search ON alerts(title, description);

-- ============================================================================
-- TRIGGERS FOR AUTOMATION
-- ============================================================================

-- Update organization updated_at when agents change
DELIMITER //
CREATE TRIGGER update_org_timestamp_on_agent_change
    AFTER UPDATE ON agents
    FOR EACH ROW
BEGIN
    UPDATE organizations 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.organization_id;
END//
DELIMITER ;

-- Auto-resolve old threats
DELIMITER //
CREATE TRIGGER auto_resolve_old_threats
    BEFORE UPDATE ON threats
    FOR EACH ROW
BEGIN
    IF NEW.status = 'open' AND 
       TIMESTAMPDIFF(DAY, NEW.detection_timestamp, NOW()) > 30 THEN
        SET NEW.status = 'resolved';
        SET NEW.resolved_at = CURRENT_TIMESTAMP;
        SET NEW.resolution_notes = 'Auto-resolved: No activity for 30 days';
    END IF;
END//
DELIMITER ;
