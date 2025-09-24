-- CodeGrey SOC - PostgreSQL Schema
-- Multi-tenant SOC database schema for PostgreSQL

-- ============================================================================
-- ORGANIZATIONS (Multi-tenancy)
-- ============================================================================

CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    contact_email VARCHAR(255) NOT NULL,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active',
    settings JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_org_api_key ON organizations(api_key);
CREATE INDEX idx_org_status ON organizations(status);

-- ============================================================================
-- AGENTS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    hostname VARCHAR(255),
    ip_address INET,
    status VARCHAR(50) DEFAULT 'offline',
    version VARCHAR(50),
    capabilities JSONB DEFAULT '[]'::jsonb,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Network element classification
    network_element_type VARCHAR(100),
    network_role VARCHAR(100),
    security_zone VARCHAR(100),
    subnet VARCHAR(100),
    element_confidence DECIMAL(5,2) DEFAULT 0.0,
    network_characteristics JSONB DEFAULT '{}'::jsonb,
    detected_services JSONB DEFAULT '[]'::jsonb,
    open_ports JSONB DEFAULT '[]'::jsonb,
    network_topology_level INTEGER DEFAULT 0,
    parent_network_element VARCHAR(255),
    child_network_elements JSONB DEFAULT '[]'::jsonb,
    last_network_scan TIMESTAMP,
    
    -- User role information
    user_role_info JSONB DEFAULT '{}'::jsonb,
    username VARCHAR(255),
    user_groups JSONB DEFAULT '[]'::jsonb,
    is_admin BOOLEAN DEFAULT FALSE,
    domain_info VARCHAR(255),
    classified_roles JSONB DEFAULT '[]'::jsonb,
    role_confidence DECIMAL(5,2) DEFAULT 0.0,
    role_last_updated TIMESTAMP,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_agents_org ON agents(organization_id);
CREATE INDEX idx_agents_type ON agents(type);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_hostname ON agents(hostname);
CREATE INDEX idx_agents_network_element ON agents(network_element_type);
CREATE INDEX idx_username ON agents(username);
CREATE INDEX idx_is_admin ON agents(is_admin);
CREATE INDEX idx_role_confidence ON agents(role_confidence);

-- ============================================================================
-- AGENT COMMANDS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_commands (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id VARCHAR(255) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    command_type VARCHAR(100) NOT NULL,
    command_data JSONB,
    priority VARCHAR(20) DEFAULT 'normal',
    status VARCHAR(50) DEFAULT 'pending',
    result_data JSONB,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX idx_commands_org ON agent_commands(organization_id);
CREATE INDEX idx_commands_agent ON agent_commands(agent_id);
CREATE INDEX idx_commands_status ON agent_commands(status);
CREATE INDEX idx_commands_type ON agent_commands(command_type);
CREATE INDEX idx_commands_created ON agent_commands(created_at);

-- ============================================================================
-- AGENT LOGS (Multi-tenant) - Critical for ML/AI Training
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_logs (
    id SERIAL PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id VARCHAR(255) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    log_type VARCHAR(100) NOT NULL,
    log_data JSONB NOT NULL,
    raw_log_text TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) DEFAULT 'info',
    processed BOOLEAN DEFAULT FALSE,
    ml_features JSONB DEFAULT '{}'::jsonb,
    threat_score DECIMAL(5,2) DEFAULT 0.0,
    classification VARCHAR(100),
    
    -- S3 storage reference for large logs
    s3_bucket VARCHAR(255),
    s3_key VARCHAR(500),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_logs_org ON agent_logs(organization_id);
CREATE INDEX idx_logs_agent ON agent_logs(agent_id);
CREATE INDEX idx_logs_type ON agent_logs(log_type);
CREATE INDEX idx_logs_timestamp ON agent_logs(timestamp);
CREATE INDEX idx_logs_severity ON agent_logs(severity);
CREATE INDEX idx_logs_processed ON agent_logs(processed);
CREATE INDEX idx_logs_threat_score ON agent_logs(threat_score);

-- ============================================================================
-- ML MODEL METADATA (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS ml_models (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    model_name VARCHAR(255) NOT NULL,
    model_type VARCHAR(100) NOT NULL, -- 'detection', 'classification', 'anomaly'
    version VARCHAR(50) NOT NULL,
    s3_bucket VARCHAR(255),
    s3_model_path VARCHAR(500),
    accuracy DECIMAL(5,2),
    precision_score DECIMAL(5,2),
    recall DECIMAL(5,2),
    f1_score DECIMAL(5,2),
    training_date TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active', -- 'active', 'training', 'deprecated'
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_models_org ON ml_models(organization_id);
CREATE INDEX idx_models_type ON ml_models(model_type);
CREATE INDEX idx_models_status ON ml_models(status);

-- ============================================================================
-- THREAT DETECTIONS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS threat_detections (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id VARCHAR(255) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    log_id INTEGER REFERENCES agent_logs(id),
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence DECIMAL(5,2) NOT NULL,
    mitre_technique VARCHAR(20),
    mitre_tactic VARCHAR(100),
    source_ip INET,
    target_ip INET,
    description TEXT,
    indicators JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(50) DEFAULT 'active', -- 'active', 'investigating', 'resolved', 'false_positive'
    ml_model_used VARCHAR(255),
    detection_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    false_positive BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_detections_org ON threat_detections(organization_id);
CREATE INDEX idx_detections_agent ON threat_detections(agent_id);
CREATE INDEX idx_detections_type ON threat_detections(threat_type);
CREATE INDEX idx_detections_severity ON threat_detections(severity);
CREATE INDEX idx_detections_timestamp ON threat_detections(detection_timestamp);
CREATE INDEX idx_detections_status ON threat_detections(status);

-- ============================================================================
-- ATTACK SCENARIOS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack_scenarios (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    apt_group VARCHAR(255),
    difficulty VARCHAR(50),
    duration_minutes INTEGER,
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    target_sectors JSONB DEFAULT '[]'::jsonb,
    playbook_steps JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active'
);

CREATE INDEX idx_scenarios_org ON attack_scenarios(organization_id);
CREATE INDEX idx_scenarios_difficulty ON attack_scenarios(difficulty);

-- ============================================================================
-- ATTACK EXECUTIONS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack_executions (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scenario_id VARCHAR(255) NOT NULL REFERENCES attack_scenarios(id),
    agent_id VARCHAR(255) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'queued',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_minutes INTEGER,
    success_rate DECIMAL(5,2),
    targets_affected INTEGER DEFAULT 0,
    techniques_executed JSONB DEFAULT '[]'::jsonb,
    results JSONB DEFAULT '{}'::jsonb,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_executions_org ON attack_executions(organization_id);
CREATE INDEX idx_executions_scenario ON attack_executions(scenario_id);
CREATE INDEX idx_executions_agent ON attack_executions(agent_id);
CREATE INDEX idx_executions_status ON attack_executions(status);
CREATE INDEX idx_executions_started ON attack_executions(started_at);

-- ============================================================================
-- NETWORK TOPOLOGY (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_topology (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    node_id VARCHAR(255) NOT NULL,
    node_name VARCHAR(255) NOT NULL,
    node_type VARCHAR(100) NOT NULL,
    parent_node_id VARCHAR(255),
    level_hierarchy INTEGER DEFAULT 0,
    ip_ranges JSONB DEFAULT '[]'::jsonb,
    security_zone VARCHAR(100),
    risk_level VARCHAR(20),
    agent_count INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'active',
    characteristics JSONB DEFAULT '{}'::jsonb,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_topology_org ON network_topology(organization_id);
CREATE INDEX idx_topology_node_type ON network_topology(node_type);
CREATE INDEX idx_topology_parent ON network_topology(parent_node_id);
CREATE INDEX idx_topology_level ON network_topology(level_hierarchy);

-- ============================================================================
-- TRAINING DATA EXPORTS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS training_data_exports (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    export_type VARCHAR(100) NOT NULL, -- 'agent_logs', 'detections', 'attack_scenarios'
    date_range_start TIMESTAMP,
    date_range_end TIMESTAMP,
    record_count INTEGER,
    s3_bucket VARCHAR(255),
    s3_export_path VARCHAR(500),
    sanitization_applied JSONB DEFAULT '[]'::jsonb,
    export_status VARCHAR(50) DEFAULT 'processing',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX idx_exports_org ON training_data_exports(organization_id);
CREATE INDEX idx_exports_type ON training_data_exports(export_type);
CREATE INDEX idx_exports_status ON training_data_exports(export_status);

-- ============================================================================
-- SAMPLE DATA INSERTION
-- ============================================================================

-- Insert default organization
INSERT INTO organizations (id, name, contact_email, api_key, status) 
VALUES ('org-default-001', 'Default Organization', 'admin@codegrey.ai', 'ak_default_key_change_in_production', 'active')
ON CONFLICT (id) DO NOTHING;

-- Create sample network topology
INSERT INTO network_topology (id, organization_id, node_id, node_name, node_type, level_hierarchy, security_zone, risk_level, status)
VALUES 
    ('topo-001', 'org-default-001', 'internet', 'Internet', 'gateway', 0, 'untrusted', 'medium', 'active'),
    ('topo-002', 'org-default-001', 'firewall', 'Corporate Firewall', 'security_device', 1, 'perimeter', 'low', 'active'),
    ('topo-003', 'org-default-001', 'dmz', 'DMZ Segment', 'network_segment', 2, 'dmz', 'high', 'active'),
    ('topo-004', 'org-default-001', 'internal', 'Internal Network', 'network_segment', 2, 'trusted', 'low', 'active'),
    ('topo-005', 'org-default-001', 'datacenter', 'Data Center', 'datacenter', 3, 'secure', 'medium', 'active'),
    ('topo-006', 'org-default-001', 'endpoints', 'Endpoints', 'endpoint_group', 3, 'trusted', 'medium', 'active'),
    ('topo-007', 'org-default-001', 'soc_platform', 'SOC Platform', 'soc_platform', 1, 'secure', 'low', 'active')
ON CONFLICT (id) DO NOTHING;

-- Update parent relationships
UPDATE network_topology SET parent_node_id = 'internet' WHERE node_id IN ('firewall', 'soc_platform');
UPDATE network_topology SET parent_node_id = 'firewall' WHERE node_id IN ('dmz', 'internal');
UPDATE network_topology SET parent_node_id = 'internal' WHERE node_id IN ('datacenter', 'endpoints');

COMMIT;



