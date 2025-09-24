# ✅ CodeGrey SOC - Deployment Checklist for Infra Team

**Target Infrastructure:** App Server + PostgreSQL + S3  
**Deployment Time:** ~2-3 hours  
**Complexity:** Medium (standard web app deployment)

---

## 📋 **Pre-Deployment Checklist**

### **Infrastructure Requirements:**
- [ ] App server with 4+ CPU cores, 8+ GB RAM
- [ ] PostgreSQL database server (existing)
- [ ] S3 bucket access (existing)
- [ ] Network connectivity between app server and DB server
- [ ] Firewall rules allowing port 8443

### **Access Requirements:**
- [ ] SSH access to app server
- [ ] PostgreSQL admin credentials
- [ ] AWS credentials for S3 access
- [ ] Sudo/admin privileges on app server

---

## 🚀 **Deployment Steps**

### **Step 1: Database Setup (5 minutes)**
```sql
-- Run on PostgreSQL server
CREATE DATABASE codegrey_soc;
CREATE USER codegrey_soc_user WITH PASSWORD 'CHANGE_THIS_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE codegrey_soc TO codegrey_soc_user;
```
- [ ] Database created
- [ ] User created with secure password
- [ ] Permissions granted

### **Step 2: S3 Bucket Setup (5 minutes)**
```bash
# Create buckets (if not existing)
aws s3 mb s3://yourcompany-soc-models
aws s3 mb s3://yourcompany-soc-logs

# Verify access
aws s3 ls s3://yourcompany-soc-models/
```
- [ ] S3 buckets accessible
- [ ] AWS credentials configured
- [ ] Bucket permissions verified

### **Step 3: App Server Setup (10 minutes)**
```bash
# Create application directory
sudo mkdir -p /opt/codegrey-soc
sudo chown -R $USER:$USER /opt/codegrey-soc
cd /opt/codegrey-soc

# Upload PRODUCTION_DEPLOYMENT files
# (Use your preferred method: scp, rsync, git, etc.)
```
- [ ] Directory created
- [ ] Files uploaded
- [ ] Permissions set correctly

### **Step 4: Environment Configuration (5 minutes)**
```bash
# Create .env file
cp env.example .env

# Edit .env with your settings:
# - Database connection details
# - S3 bucket names  
# - Security keys
# - AWS region
```
- [ ] .env file created
- [ ] Database credentials configured
- [ ] S3 settings configured
- [ ] Security keys set

### **Step 5: Dependencies Installation (15 minutes)**
```bash
# Install Python dependencies
pip install -r requirements.txt

# Note: This includes ML libraries (scikit-learn, numpy, pandas)
# Installation may take 10-15 minutes
```
- [ ] All dependencies installed successfully
- [ ] No error messages during installation
- [ ] Python version 3.8+ confirmed

### **Step 6: Database Schema Deployment (2 minutes)**
```bash
# Deploy PostgreSQL schema
psql -h YOUR_DB_HOST -U codegrey_soc_user -d codegrey_soc -f database/postgresql_schema.sql
```
- [ ] Schema deployed successfully
- [ ] Tables created
- [ ] Sample data inserted

### **Step 7: Application Testing (10 minutes)**
```bash
# Start the application
python app.py

# In another terminal, test endpoints:
curl http://localhost:8443/api/system/status
curl -X POST http://localhost:8443/api/test/create-sample-agents \
     -H "Authorization: Bearer ak_default_key_change_in_production"
```
- [ ] Application starts without errors
- [ ] Health check returns success
- [ ] Sample agents created
- [ ] AI agents initialized (check logs)

### **Step 8: Production Configuration (5 minutes)**
```bash
# Set up as systemd service (optional but recommended)
sudo cp scripts/codegrey-soc.service /etc/systemd/system/
sudo systemctl enable codegrey-soc
sudo systemctl start codegrey-soc
```
- [ ] Service configured (if using systemd)
- [ ] Auto-start enabled
- [ ] Service running

---

## 🔍 **Verification Checklist**

### **Application Health:**
- [ ] Server responds on port 8443
- [ ] `/api/system/status` returns healthy status
- [ ] AI agents show as "active" in status
- [ ] Database connection successful

### **ML/AI Integration:**
- [ ] ML models loaded successfully (check logs)
- [ ] Threat detection models initialized
- [ ] S3 model storage working
- [ ] Log analysis pipeline active

### **Database Integration:**
- [ ] PostgreSQL connection working
- [ ] All tables created successfully
- [ ] Sample data visible in database
- [ ] Multi-tenant isolation working

### **API Functionality:**
- [ ] Agent management APIs working
- [ ] Attack scenario APIs responding
- [ ] Detection APIs returning data
- [ ] AI chat API functional

---

## 🚨 **Common Issues & Solutions**

### **Database Connection Issues:**
```bash
# Check connection
psql -h DB_HOST -U codegrey_soc_user -d codegrey_soc -c "SELECT 1;"

# Common fixes:
# - Verify hostname/IP in .env
# - Check firewall rules
# - Confirm user permissions
```

### **S3 Access Issues:**
```bash
# Test S3 access
aws s3 ls s3://yourcompany-soc-models/

# Common fixes:
# - Check AWS credentials
# - Verify bucket permissions
# - Confirm region settings
```

### **ML Model Loading Issues:**
```bash
# Check ML model initialization in logs
grep "ML models" logs/soc_server.log

# Common fixes:
# - Ensure scikit-learn installed
# - Check available memory (8GB+ recommended)
# - Verify S3 bucket access
```

### **Port/Firewall Issues:**
```bash
# Check if port is listening
netstat -tlnp | grep 8443

# Common fixes:
# - Open port 8443 in firewall
# - Check if another service is using the port
# - Verify binding to 0.0.0.0 not just localhost
```

---

## 📊 **Post-Deployment Monitoring**

### **Log Monitoring:**
```bash
# Application logs
tail -f /opt/codegrey-soc/logs/soc_server.log

# Look for these success messages:
# "✅ All AI Agent Engines initialized successfully!"
# "🔄 Background agent processes started"
# "Multi-tenant database initialized successfully"
```

### **Performance Monitoring:**
```bash
# Check system resources
htop
df -h
free -h

# Check database performance
psql -h DB_HOST -U codegrey_soc_user -d codegrey_soc -c "
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del 
FROM pg_stat_user_tables;
"
```

### **API Health Checks:**
```bash
# Set up monitoring (add to cron)
*/5 * * * * curl -f http://localhost:8443/api/system/status || echo "SOC Down" | mail admin@company.com
```

---

## 🎯 **Success Criteria**

### **Deployment is successful when:**
- [ ] Application starts and runs without errors
- [ ] All 28 API endpoints respond correctly
- [ ] AI agents (Attack, Detection, Reasoning) are active
- [ ] ML models loaded and processing logs
- [ ] Database storing agent data and logs
- [ ] S3 integration working for model storage
- [ ] Multi-tenant isolation functional
- [ ] Real-time threat detection operational

### **Performance Benchmarks:**
- [ ] API response time < 500ms
- [ ] ML log analysis < 1 second per log
- [ ] Database queries < 100ms average
- [ ] Memory usage < 70% of available RAM
- [ ] CPU usage < 80% under normal load

---

## 📞 **Support Information**

### **Log Locations:**
- **Application:** `/opt/codegrey-soc/logs/soc_server.log`
- **ML Models:** Check for "ML" or "Model" in application logs
- **Database:** PostgreSQL server logs

### **Configuration Files:**
- **Main Config:** `/opt/codegrey-soc/.env`
- **Database Schema:** `/opt/codegrey-soc/database/postgresql_schema.sql`
- **Dependencies:** `/opt/codegrey-soc/requirements.txt`

### **Key Processes:**
- **Main Application:** `python app.py`
- **Background AI Agents:** Threads within main process
- **ML Model Processing:** Background threads

---

## 🎉 **Deployment Complete!**

**Once all checkboxes are completed, you have:**

✅ **Fully Operational AI SOC Platform**  
✅ **Real-time Threat Detection with ML**  
✅ **Multi-tenant Architecture**  
✅ **PostgreSQL Database Integration**  
✅ **S3 Cloud Storage Integration**  
✅ **28 API Endpoints for Frontend**  
✅ **Attack, Detection, and Reasoning AI Agents**  

**Your SOC product is now production-ready and serving real AI-driven security operations!** 🚀

**Estimated Total Deployment Time: 60-90 minutes**



