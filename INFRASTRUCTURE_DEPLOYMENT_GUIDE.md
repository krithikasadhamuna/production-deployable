# 🏗️ CodeGrey SOC - Infrastructure Deployment Guide

**Your Setup:** App Server + PostgreSQL DB Server + S3 + Infra Person  
**SOC Requirements:** AI/ML Models + Real-time Processing + Multi-tenant Database

---

## 🎯 **Deployment Strategy Overview**

### **✅ What Works with Your Current Infrastructure:**
- **App Server** - Perfect for SOC application
- **PostgreSQL** - Excellent for multi-tenant data (better than SQLite!)
- **S3** - Perfect for ML models, logs, and training data storage
- **Infra Person** - Can handle the deployment process

### **🔧 What Needs to be Added:**
- **ML/AI Models** - Threat detection and classification models
- **Real-time Processing** - Background AI agent threads
- **Model Storage** - S3 integration for ML models

---

## 📋 **Step-by-Step Deployment Process**

### **Step 1: Prepare Your Infrastructure**

#### **Database Server (PostgreSQL):**
```sql
-- Create SOC database
CREATE DATABASE codegrey_soc;
CREATE USER codegrey_soc_user WITH PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE codegrey_soc TO codegrey_soc_user;
```

#### **S3 Bucket Setup:**
```bash
# Create S3 bucket for ML models and data
aws s3 mb s3://your-company-soc-models
aws s3 mb s3://your-company-soc-logs

# Set up bucket structure
aws s3api put-object --bucket your-company-soc-models --key ml_models/
aws s3api put-object --bucket your-company-soc-logs --key training_data/
aws s3api put-object --bucket your-company-soc-logs --key agent_logs/
```

### **Step 2: Environment Configuration**

#### **Create Production Environment File:**
```bash
# /opt/codegrey-soc/.env
SOC_HOST=0.0.0.0
SOC_PORT=8443
SOC_DEBUG=false

# Database Configuration (PostgreSQL)
DB_HOST=your-db-server.internal
DB_PORT=5432
DB_NAME=codegrey_soc
DB_USER=codegrey_soc_user
DB_PASSWORD=secure_password_here

# S3 Configuration
S3_BUCKET=your-company-soc-models
S3_LOGS_BUCKET=your-company-soc-logs
AWS_REGION=us-east-1

# Security
SOC_SECRET_KEY=your-super-secure-production-key-change-this

# AI/ML Settings
ML_MODELS_ENABLED=true
ML_RETRAIN_INTERVAL_HOURS=24
THREAT_DETECTION_THRESHOLD=0.7

# Multi-tenant Settings
SOC_MAX_AGENTS_PER_TENANT=1000
SOC_MAX_COMMANDS_PER_MINUTE=100
```

### **Step 3: File Upload Structure**

#### **What Your Infra Person Needs to Upload:**
```
/opt/codegrey-soc/
├── app.py                              # Main application
├── requirements.txt                    # Dependencies (includes ML libraries)
├── .env                               # Environment configuration
├── api/                               # API endpoints
│   ├── multi_tenant_api.py
│   └── network_topology_api.py
├── agents/                            # AI Agent engines
│   ├── postgresql_agent_manager.py    # PostgreSQL adapter
│   ├── attack_agent/                  # Attack AI Agent
│   ├── detection_agent/               # Detection AI Agent  
│   └── ai_reasoning_agent/            # AI Reasoning Agent
├── ml_models/                         # ML/AI Models
│   ├── threat_detection_models.py     # Core ML models
│   └── saved_models/                  # Model files directory
├── database/
│   └── postgresql_schema.sql          # Database schema
└── logs/                              # Log directory
```

### **Step 4: Dependencies Installation**

#### **Updated requirements.txt for ML/AI:**
```bash
# Your infra person runs this on the app server
pip install -r requirements.txt

# Key additions for ML/AI:
# - scikit-learn (ML models)
# - numpy, pandas (data processing)
# - psycopg2 (PostgreSQL connector)
# - boto3 (S3 integration)
```

### **Step 5: Database Schema Deployment**

#### **Run PostgreSQL Schema:**
```bash
# Your infra person runs this
psql -h your-db-server -U codegrey_soc_user -d codegrey_soc -f database/postgresql_schema.sql
```

### **Step 6: Application Startup**

#### **Production Startup Script:**
```bash
#!/bin/bash
# /opt/codegrey-soc/start_production.sh

echo "🚀 Starting CodeGrey SOC Production Server..."

# Set environment
export PYTHONPATH=/opt/codegrey-soc
cd /opt/codegrey-soc

# Check database connection
python -c "
import psycopg2
import os
try:
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST'),
        port=os.getenv('DB_PORT'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD')
    )
    print('✅ Database connection successful')
    conn.close()
except Exception as e:
    print(f'❌ Database connection failed: {e}')
    exit(1)
"

# Check S3 access
python -c "
import boto3
import os
try:
    s3 = boto3.client('s3')
    s3.head_bucket(Bucket=os.getenv('S3_BUCKET'))
    print('✅ S3 access successful')
except Exception as e:
    print(f'❌ S3 access failed: {e}')
    exit(1)
"

# Start the SOC server
echo "🎯 Starting SOC Server with AI Agents..."
python app.py
```

---

## 🤖 **ML/AI Integration Details**

### **✅ YES - ML/AI Models are Fully Integrated!**

#### **What's Included in Production:**

**1. Core ML Models:**
- **Anomaly Detection** - Isolation Forest for detecting unusual log patterns
- **Threat Classification** - Random Forest for malicious vs normal classification  
- **Feature Extraction** - TF-IDF vectorization for log text analysis
- **Risk Scoring** - Combined anomaly + threat scores

**2. Real-time AI Processing:**
- **Detection Pipeline** - Processes logs every 10 seconds with ML analysis
- **Threat Scoring** - Each log gets risk score (0-10) and severity (low/medium/high/critical)
- **Model Updates** - Models retrain automatically with new data

**3. S3 Model Storage:**
- **Model Persistence** - Trained models saved to S3
- **Version Control** - Model versioning and performance tracking
- **Distributed Deployment** - Models downloaded from S3 on server startup

### **How ML/AI Works in Your SOC:**

```python
# Real-time log analysis flow:
1. Agent sends log → PostgreSQL storage
2. Detection Pipeline picks up log
3. ML models analyze:
   - Is this log anomalous? (Isolation Forest)
   - Is this log malicious? (Random Forest)
   - What's the risk score? (Combined algorithm)
4. Results stored in threat_detections table
5. Frontend shows real-time threats
```

---

## 🔄 **Deployment Process for Your Infra Person**

### **Phase 1: Infrastructure Prep (Day 1)**
```bash
# 1. Database Setup
psql -h db-server -U postgres -c "CREATE DATABASE codegrey_soc;"

# 2. S3 Bucket Creation  
aws s3 mb s3://yourcompany-soc-models
aws s3 mb s3://yourcompany-soc-logs

# 3. App Server Prep
mkdir -p /opt/codegrey-soc
chown -R appuser:appgroup /opt/codegrey-soc
```

### **Phase 2: File Upload (Day 1)**
```bash
# Upload PRODUCTION_DEPLOYMENT folder contents
scp -r PRODUCTION_DEPLOYMENT/* appuser@app-server:/opt/codegrey-soc/

# Set permissions
chmod +x /opt/codegrey-soc/start_production.sh
chmod 600 /opt/codegrey-soc/.env
```

### **Phase 3: Dependencies & Schema (Day 1)**
```bash
# Install Python dependencies
ssh appuser@app-server
cd /opt/codegrey-soc
pip install -r requirements.txt

# Deploy database schema
psql -h db-server -U codegrey_soc_user -d codegrey_soc -f database/postgresql_schema.sql
```

### **Phase 4: Testing & Launch (Day 2)**
```bash
# Test configuration
./start_production.sh

# Check health endpoint
curl http://app-server:8443/api/system/status

# Create sample data
curl -X POST http://app-server:8443/api/test/create-sample-agents \
     -H "Authorization: Bearer ak_default_key_change_in_production"
```

---

## 📊 **Monitoring & Maintenance**

### **Health Checks:**
```bash
# Database health
curl http://app-server:8443/api/system/status | jq '.status.database_status'

# ML Models health  
curl http://app-server:8443/api/system/status | jq '.status.ai_agents'

# S3 connectivity
aws s3 ls s3://yourcompany-soc-models/ml_models/
```

### **Log Monitoring:**
```bash
# SOC application logs
tail -f /opt/codegrey-soc/logs/soc_server.log

# ML model performance
grep "Model accuracy" /opt/codegrey-soc/logs/soc_server.log

# Database performance
psql -h db-server -U codegrey_soc_user -d codegrey_soc -c "
SELECT COUNT(*) as total_logs FROM agent_logs;
SELECT COUNT(*) as total_threats FROM threat_detections;
"
```

### **Backup Strategy:**
```bash
# Database backup
pg_dump -h db-server -U codegrey_soc_user codegrey_soc > backup_$(date +%Y%m%d).sql

# S3 model backup
aws s3 sync s3://yourcompany-soc-models/ ./model_backups/

# Application backup
tar -czf soc_app_backup_$(date +%Y%m%d).tar.gz /opt/codegrey-soc/
```

---

## 🎯 **Key Advantages of This Setup**

### **✅ PostgreSQL vs SQLite:**
- **Better Performance** - Handles thousands of agents and millions of logs
- **Concurrent Access** - Multiple AI agents can write simultaneously
- **Advanced Features** - JSON columns, full-text search, advanced indexing
- **Scalability** - Can handle enterprise-scale SOC operations

### **✅ S3 Integration:**
- **Model Storage** - ML models stored in S3, downloaded on startup
- **Log Archival** - Old logs can be moved to S3 for cost-effective storage
- **Training Data** - Sanitized training data exported to S3 for LLM training
- **Disaster Recovery** - Complete backup and restore capability

### **✅ Production-Ready AI:**
- **Real ML Models** - Not just mock data, actual threat detection
- **Continuous Learning** - Models retrain with new data automatically
- **Performance Tracking** - Model accuracy and performance monitoring
- **Scalable Architecture** - Can handle high-volume log processing

---

## 🚨 **Critical Success Factors**

### **1. Database Performance:**
```sql
-- Ensure these indexes exist for performance
CREATE INDEX CONCURRENTLY idx_agent_logs_timestamp ON agent_logs(timestamp);
CREATE INDEX CONCURRENTLY idx_threat_detections_severity ON threat_detections(severity);
```

### **2. S3 Permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::yourcompany-soc-models/*",
        "arn:aws:s3:::yourcompany-soc-logs/*"
      ]
    }
  ]
}
```

### **3. Resource Requirements:**
- **CPU:** 4+ cores (ML processing is CPU-intensive)
- **RAM:** 8+ GB (ML models + data processing)
- **Storage:** 100+ GB (logs, models, temporary data)
- **Network:** High bandwidth for S3 transfers

---

## 🎉 **Summary**

**Your infrastructure is PERFECT for the SOC product:**

✅ **PostgreSQL** - Better than SQLite for enterprise SOC  
✅ **S3** - Perfect for ML models and training data  
✅ **App Server** - Can handle AI processing  
✅ **Infra Person** - Can deploy following this guide  

**What you get:**
- **Complete AI SOC Platform** with real ML threat detection
- **Multi-tenant Architecture** supporting multiple organizations  
- **Real-time Processing** with background AI agents
- **Scalable Database** handling millions of logs
- **Cloud Storage** for models and training data
- **Production Monitoring** and health checks

**Your SOC product will be fully operational with integrated AI/ML capabilities!** 🚀



