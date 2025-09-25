# SOC Platform Database Setup Guide

## Overview

This guide covers the production database setup for the AI-driven SOC Platform. The databases are designed to be **empty and ready for production** with only dummy users for testing.

## Database Structure

### 1. **soc_main.db** - Core SOC Operations
**Purpose**: Attack scenarios, detections, incidents, system events

**Tables**:
- `attack_scenarios` - Attack scenario definitions and execution tracking
- `detections` - Threat detections from AI agents
- `golden_images` - Endpoint backup images for attack recovery
- `system_events` - Platform system events and audit logs
- `incidents` - Security incident management

**Status**: **EMPTY** - Ready for production data

### 2. **network_topology.db** - Network Infrastructure
**Purpose**: Network topology, endpoints, zones, services

**Tables**:
- `endpoints` - Registered client endpoints
- `network_topology` - Network connections and relationships
- `network_zones` - Network security zones (DMZ, Internal, etc.)
- `network_services` - Services running on endpoints

**Status**: **EMPTY** - Only default network zones configured

### 3. **agent_logs.db** - Log Processing
**Purpose**: Agent logs, detection results, ML model performance

**Tables**:
- `agent_logs` - Raw logs from client agents
- `detection_results` - AI detection analysis results
- `log_processing_queue` - Log processing workflow
- `ml_model_performance` - ML model accuracy tracking

**Status**: **EMPTY** - Ready for real log data

### 4. **soc_users.db** - User Management
**Purpose**: SOC personnel authentication and authorization

**Tables**:
- `soc_users` - SOC personnel accounts
- `user_sessions` - Active user sessions
- `user_roles` - Role definitions and permissions
- `api_key_usage` - API usage tracking
- `user_audit_log` - User activity audit trail

**Status**: **CONTAINS DUMMY USERS** - 5 test accounts for development

## Dummy Users (Testing Only)

| Email | Password | Role | Description |
|-------|----------|------|-------------|
| `admin@codegrey.ai` | `SecureAdmin123!` | admin | Full system administrator |
| `soc.manager@codegrey.ai` | `SOCManager456!` | soc_manager | SOC team manager |
| `senior.analyst@codegrey.ai` | `SeniorAnalyst789!` | senior_analyst | Senior threat analyst |
| `analyst@codegrey.ai` | `Analyst123!` | analyst | SOC analyst |
| `viewer@codegrey.ai` | `Viewer456!` | viewer | Read-only dashboard access |

## Role Permissions

### Admin
- User management
- Attack control
- Detection control
- System configuration
- View all data
- Manage agents
- Audit access

### SOC Manager
- Attack control
- Detection control
- View all data
- Manage team
- Incident response
- Report generation

### Senior Analyst
- Attack control
- Detection control
- Incident response
- View team data
- Advanced analysis
- Threat hunting

### Analyst
- Detection view
- Incident response
- Basic analysis
- Log analysis

### Viewer
- Detection view
- Dashboard view
- Report view

## Database Creation

### Step 1: Create Databases Locally
```bash
python create_production_databases.py
```

This creates:
- All 4 database files with proper schema
- Indexes for optimal performance
- Empty tables ready for production
- 5 dummy users for testing

### Step 2: Migrate to Server

**For Linux/Mac**:
```bash
chmod +x migrate_databases_to_server.sh
./migrate_databases_to_server.sh
```

**For Windows**:
```powershell
.\migrate_databases_to_server.ps1
```

The migration script will:
1. Backup existing databases on server
2. Transfer new databases via SCP
3. Set proper permissions
4. Verify database integrity
5. Test connectivity

## Production Deployment

### 1. Database Files Location
```
/home/krithika/soc-platform-production/
├── soc_main.db
├── network_topology.db
├── agent_logs.db
└── soc_users.db
```

### 2. Start SOC Platform
```bash
python SOC_PLATFORM_BACKEND.py
```

### 3. Test Authentication
```bash
curl -X POST http://localhost:8080/api/auth/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@codegrey.ai",
    "password": "SecureAdmin123!"
  }'
```

### 4. Register First Real Endpoint
```bash
curl -X POST http://localhost:8080/api/backend/agent/register \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "hostname": "PROD-SERVER-01",
    "ip_address": "10.0.1.100",
    "os_type": "Linux",
    "importance": "critical"
  }'
```

## Database Maintenance

### Backup Strategy
```bash
# Automated backups are created in:
/home/krithika/soc-platform-production/database_backups/

# Manual backup:
cp *.db backup_$(date +%Y%m%d_%H%M%S)/
```

### Performance Monitoring
- All tables have proper indexes
- Query performance is optimized
- Connection pooling is implemented
- Automatic cleanup of old data

### Security
- Database files have restricted permissions (644)
- User passwords are bcrypt hashed
- API keys are cryptographically secure
- Session tokens have expiration
- Audit logging is enabled

## Production Checklist

- [ ] Databases created locally
- [ ] Databases migrated to server
- [ ] SOC Platform started successfully
- [ ] Dummy user login tested
- [ ] First real endpoint registered
- [ ] Network topology populated
- [ ] Log processing verified
- [ ] Detection system active

## Troubleshooting

### Database Connection Issues
```bash
# Check database files exist
ls -la *.db

# Test database connectivity
python3 -c "import sqlite3; conn = sqlite3.connect('soc_users.db'); print('OK')"
```

### Permission Issues
```bash
# Fix database permissions
chmod 644 *.db
chown krithika:krithika *.db
```

### Migration Issues
```bash
# Check SSH connectivity
ssh krithika@your-server-ip "echo 'SSH OK'"

# Check SCP functionality
scp test.txt krithika@your-server-ip:/tmp/
```

## Next Steps

1. **Replace Dummy Users**: Create real SOC personnel accounts
2. **Register Endpoints**: Begin registering production endpoints
3. **Configure Monitoring**: Set up log collection from real systems
4. **Test Attack Scenarios**: Validate attack simulation capabilities
5. **Tune Detection**: Calibrate AI detection models with real data

## Support

For database issues:
- Check logs in `logs/soc_platform.log`
- Verify database schema with provided scripts
- Ensure proper permissions and connectivity
- Contact system administrator for server access issues

---

**Database Status**: Ready for Production Deployment
**Last Updated**: 2025-09-25
**Version**: 3.0.0
