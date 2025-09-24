# 🚀 **SERVER DEPLOYMENT CHECKLIST**

## **BEFORE HANDING TO FRONTEND TEAM**

### ✅ **Step 1: Transfer Files to Server**
```bash
# From your local machine
scp -r CLEAN_DEPLOYMENT_PACKAGE/ krithika@15.207.6.45:/home/krithika/soc-production/

# OR use Git
git init
git add .
git commit -m "Production deployment package"
git push origin main
```

### ✅ **Step 2: SSH into Server**
```bash
ssh krithika@15.207.6.45
cd /home/krithika/soc-production/CLEAN_DEPLOYMENT_PACKAGE
```

### ✅ **Step 3: Install Dependencies**
```bash
# Create virtual environment
python3 -m venv soc_env
source soc_env/bin/activate

# Install requirements
pip install -r requirements.txt

# Install Ollama if not installed
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull cybersec-ai
```

### ✅ **Step 4: Configure Environment**
```bash
# Create production environment file
cp production.env .env

# Edit configuration
nano .env
```

Update these values:
```env
SOC_HOST=0.0.0.0
SOC_PORT=443
SOC_API_KEY=soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs
DATABASE_PATH=/home/krithika/soc-production/soc_database.db
OLLAMA_URL=http://localhost:11434
```

### ✅ **Step 5: Initialize Database**
```bash
# Create fresh database with all tables
python -c "from flask_api.app import init_database; init_database()"

# Verify database
sqlite3 soc_database.db ".tables"
```

### ✅ **Step 6: Configure SSL (for HTTPS)**
```bash
# Option A: Self-signed (for testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Option B: Let's Encrypt (for production)
sudo certbot certonly --standalone -d dev.codegrey.ai
```

### ✅ **Step 7: Configure Firewall**
```bash
# Allow HTTPS
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload

# If using port 8443 instead
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

### ✅ **Step 8: Start Server**
```bash
# For port 443 (requires sudo)
sudo /home/krithika/soc_env/bin/python start_server.py

# OR for port 8443 (no sudo needed)
SOC_PORT=8443 python start_server.py

# OR run in background with nohup
nohup python start_server.py > soc_server.log 2>&1 &
```

### ✅ **Step 9: Verify APIs Are Working**
```bash
# Test from server itself
curl -k https://localhost:443/api/system/status \
  -H "Authorization: Bearer soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs"

# Test agent listing
curl -k https://localhost:443/api/agents/list?format=table \
  -H "Authorization: Bearer soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs"

# Test network topology
curl -k https://localhost:443/api/network/topology?format=table \
  -H "Authorization: Bearer soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs"
```

### ✅ **Step 10: Test from External**
```bash
# From your local machine
curl https://dev.codegrey.ai:443/api/system/status \
  -H "Authorization: Bearer soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs"
```

---

## 🔍 **VERIFICATION CHECKLIST**

Before telling frontend team it's ready:

- [ ] Server is running on port 443 or 8443
- [ ] All APIs respond with 200 OK
- [ ] Database has all required tables
- [ ] SSL certificate is working
- [ ] Firewall allows incoming connections
- [ ] Domain `dev.codegrey.ai` resolves correctly
- [ ] Authentication with Bearer token works
- [ ] JSON responses match documentation

---

## 🚨 **COMMON ISSUES & FIXES**

### **Port 443 Permission Denied**
```bash
# Use port 8443 instead
SOC_PORT=8443 python start_server.py

# OR use sudo
sudo $(which python) start_server.py
```

### **Module Not Found Errors**
```bash
# Make sure virtual env is activated
source soc_env/bin/activate
pip install -r requirements.txt
```

### **Database Errors**
```bash
# Recreate database
rm soc_database.db
python -c "from flask_api.app import init_database; init_database()"
```

### **SSL Certificate Issues**
```bash
# For testing, use HTTP on port 5000
SOC_PORT=5000 python start_server.py
# Then update frontend to use http://dev.codegrey.ai:5000
```

---

## 📧 **WHAT TO SEND TO FRONTEND TEAM**

Once deployed and verified:

```
Subject: Backend APIs Ready for Integration

Hi Team,

The backend APIs are now deployed and ready for integration:

🔗 Base URL: https://dev.codegrey.ai:443/api
🔑 Auth Token: Bearer soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs

✅ Software Download API: Working
✅ Agent Listing API: Working  
✅ Network Canvas API: Working

Test these endpoints:
- GET https://dev.codegrey.ai:443/api/agents/list?format=table
- GET https://dev.codegrey.ai:443/api/network/topology?format=table
- POST https://dev.codegrey.ai:443/api/agents/track-download

Full documentation: [Attached FINAL_API_CONTRACT_FOR_FRONTEND.md]

The server is live and you can start integration immediately.
Let me know if you face any issues.

Thanks!
```

---

## 🎯 **DEPLOYMENT COMMANDS SUMMARY**

```bash
# Quick deployment (copy & paste)
ssh krithika@15.207.6.45
cd /home/krithika
git clone [your-repo-url] soc-production
cd soc-production/CLEAN_DEPLOYMENT_PACKAGE
python3 -m venv soc_env
source soc_env/bin/activate
pip install -r requirements.txt
python -c "from flask_api.app import init_database; init_database()"
sudo $(which python) start_server.py
```

---

## ✅ **READY TO DEPLOY!**

1. Deploy to server first ✅
2. Verify all APIs work ✅
3. Then send to frontend team ✅

This ensures they can actually test and integrate with live endpoints!
