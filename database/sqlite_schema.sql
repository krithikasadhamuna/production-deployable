-- CodeGrey SOC - SQLite Schema
-- Simplified multi-tenant SOC database schema for SQLite

-- ============================================================================
-- ORGANIZATIONS (Multi-tenancy)
-- ============================================================================

CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active',
    settings TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_org_api_key ON organizations(api_key);
CREATE INDEX IF NOT EXISTS idx_org_status ON organizations(status);

-- ============================================================================
-- AGENTS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    hostname TEXT,
    ip_address TEXT,
    status TEXT DEFAULT 'offline',
    version TEXT,
    capabilities TEXT DEFAULT '[]',
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Network element classification
    network_element_type TEXT,
    network_role TEXT,
    security_zone TEXT,
    subnet TEXT,
    element_confidence REAL DEFAULT 0.0,
    network_characteristics TEXT DEFAULT '{}',
    detected_services TEXT DEFAULT '[]',
    open_ports TEXT DEFAULT '[]',
    network_topology_level INTEGER DEFAULT 0,
    parent_network_element TEXT,
    child_network_elements TEXT DEFAULT '[]',
    last_network_scan DATETIME,
    
    -- User role information
    user_role_info TEXT DEFAULT '{}',
    username TEXT,
    user_groups TEXT DEFAULT '[]',
    is_admin INTEGER DEFAULT 0,
    domain_info TEXT,
    classified_roles TEXT DEFAULT '[]',
    role_confidence REAL DEFAULT 0.0,
    role_last_updated DATETIME,
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_agents_org ON agents(organization_id);
CREATE INDEX IF NOT EXISTS idx_agents_type ON agents(type);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(hostname);
CREATE INDEX IF NOT EXISTS idx_agents_network_element ON agents(network_element_type);
CREATE INDEX IF NOT EXISTS idx_username ON agents(username);
CREATE INDEX IF NOT EXISTS idx_is_admin ON agents(is_admin);
CREATE INDEX IF NOT EXISTS idx_role_confidence ON agents(role_confidence);

-- ============================================================================
-- AGENT COMMANDS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_commands (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    command_type TEXT NOT NULL,
    command_data TEXT,
    priority TEXT DEFAULT 'normal',
    status TEXT DEFAULT 'pending',
    result_data TEXT,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_commands_org ON agent_commands(organization_id);
CREATE INDEX IF NOT EXISTS idx_commands_agent ON agent_commands(agent_id);
CREATE INDEX IF NOT EXISTS idx_commands_status ON agent_commands(status);
CREATE INDEX IF NOT EXISTS idx_commands_type ON agent_commands(command_type);
CREATE INDEX IF NOT EXISTS idx_commands_created ON agent_commands(created_at);

-- ============================================================================
-- AGENT LOGS (Multi-tenant) - Critical for ML/AI Training
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    log_type TEXT NOT NULL,
    log_data TEXT NOT NULL,
    raw_log_text TEXT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity TEXT DEFAULT 'info',
    processed INTEGER DEFAULT 0,
    ml_features TEXT DEFAULT '{}',
    threat_score REAL DEFAULT 0.0,
    classification TEXT,
    
    -- S3 storage reference for large logs
    s3_bucket TEXT,
    s3_key TEXT,
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_logs_org ON agent_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_logs_agent ON agent_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_logs_type ON agent_logs(log_type);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON agent_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_severity ON agent_logs(severity);
CREATE INDEX IF NOT EXISTS idx_logs_processed ON agent_logs(processed);
CREATE INDEX IF NOT EXISTS idx_logs_threat_score ON agent_logs(threat_score);

-- ============================================================================
-- THREAT DETECTIONS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS threat_detections (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    log_id INTEGER REFERENCES agent_logs(id),
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    mitre_technique TEXT,
    mitre_tactic TEXT,
    source_ip TEXT,
    target_ip TEXT,
    description TEXT,
    indicators TEXT DEFAULT '{}',
    status TEXT DEFAULT 'active',
    ml_model_used TEXT,
    detection_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    false_positive INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_detections_org ON threat_detections(organization_id);
CREATE INDEX IF NOT EXISTS idx_detections_agent ON threat_detections(agent_id);
CREATE INDEX IF NOT EXISTS idx_detections_type ON threat_detections(threat_type);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON threat_detections(severity);
CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON threat_detections(detection_timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_status ON threat_detections(status);

-- ============================================================================
-- ATTACK SCENARIOS (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack_scenarios (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    apt_group TEXT,
    difficulty TEXT,
    duration_minutes INTEGER,
    mitre_techniques TEXT DEFAULT '[]',
    target_sectors TEXT DEFAULT '[]',
    playbook_steps TEXT DEFAULT '[]',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_scenarios_org ON attack_scenarios(organization_id);
CREATE INDEX IF NOT EXISTS idx_scenarios_difficulty ON attack_scenarios(difficulty);

-- ============================================================================
-- SAMPLE DATA INSERTION
-- ============================================================================

-- Insert default organization
INSERT OR IGNORE INTO organizations (id, name, contact_email, api_key, status) 
VALUES ('org-default-001', 'Default Organization', 'admin@codegrey.ai', 'ak_default_key_change_in_production', 'active');

-- Insert sample agents for demo
INSERT OR IGNORE INTO agents (id, organization_id, name, type, hostname, ip_address, status, capabilities, network_element_type, security_zone) 
VALUES 
    ('agent-001', 'org-default-001', 'PhantomStrike AI', 'attack', 'phantom-ai-01', '192.168.1.100', 'active', '["Email Simulation", "Web Exploitation", "Social Engineering", "Lateral Movement", "Persistence Testing"]', 'endpoint', 'trusted'),
    ('agent-002', 'org-default-001', 'CyberGuard Detector', 'detection', 'cyberguard-01', '192.168.1.101', 'active', '["Log Analysis", "Anomaly Detection", "Threat Classification", "Real-time Monitoring"]', 'soc', 'secure'),
    ('agent-003', 'org-default-001', 'AI Reasoning Engine', 'reasoning', 'reasoning-01', '192.168.1.102', 'active', '["Incident Analysis", "Root Cause Analysis", "Mitigation Recommendations", "AI Chat"]', 'soc', 'secure');

-- Insert sample attack scenarios for demo
INSERT OR IGNORE INTO attack_scenarios (id, organization_id, name, description, apt_group, difficulty, duration_minutes, mitre_techniques, status)
VALUES 
    ('scenario-001', 'org-default-001', 'Advanced Persistent Threat Simulation', 'Multi-stage APT attack simulation with lateral movement', 'APT29', 'Advanced', 120, '["T1566.001", "T1059.001", "T1055", "T1021.001"]', 'active'),
    ('scenario-002', 'org-default-001', 'Ransomware Attack Chain', 'Simulated ransomware deployment and encryption', 'Conti', 'Intermediate', 60, '["T1566.002", "T1204.002", "T1486", "T1490"]', 'active'),
    ('scenario-003', 'org-default-001', 'Insider Threat Simulation', 'Privileged user abuse and data exfiltration', 'Custom', 'Beginner', 45, '["T1078", "T1005", "T1041", "T1048.003"]', 'active');

-- Insert sample threat detections for demo
INSERT OR IGNORE INTO threat_detections (id, organization_id, agent_id, threat_type, severity, confidence, mitre_technique, description, status)
VALUES 
    ('detection-001', 'org-default-001', 'agent-002', 'Malware', 'High', 95.5, 'T1055', 'Process injection detected in critical system process', 'active'),
    ('detection-002', 'org-default-001', 'agent-002', 'Network Anomaly', 'Medium', 78.2, 'T1041', 'Unusual outbound network traffic detected', 'investigating'),
    ('detection-003', 'org-default-001', 'agent-002', 'Privilege Escalation', 'High', 88.9, 'T1078', 'Suspicious privilege escalation attempt detected', 'resolved');



