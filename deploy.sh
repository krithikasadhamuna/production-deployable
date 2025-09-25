#!/bin/bash

echo "=========================================="
echo " DEPLOYING CODEGREY SOC PLATFORM"
echo " PhantomStrike AI + GuardianAlpha AI"
echo "=========================================="

# 1. Install dependencies
echo "Installing dependencies..."
pip3 install --user -r requirements.txt

# 2. Create necessary directories
echo "Creating directories..."
mkdir -p tenant_databases
mkdir -p golden_images
mkdir -p logs
mkdir -p checkpoints

# 3. Initialize databases
echo "Initializing databases..."
python3 << 'EOF'
import sqlite3
from datetime import datetime

# Create master database
conn = sqlite3.connect('master_platform.db')
c = conn.cursor()

# Create tables for multitenancy
c.execute('''CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE,
    organization TEXT,
    api_key TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')

# Add default tenant
c.execute("INSERT OR IGNORE INTO tenants (id, name, organization, api_key) VALUES (?, ?, ?, ?)",
          ('tenant_001', 'codegrey', 'CodeGrey Inc', 'api_codegrey_2024'))

conn.commit()
conn.close()

print("Databases initialized")
EOF

# 4. Start the platform
echo "Starting SOC Platform..."
nohup python3 COMPLETE_SOC_PLATFORM.py > platform.log 2>&1 &
PID=$!

# 5. Configure NGINX
echo "Configuring NGINX..."
sudo tee /etc/nginx/conf.d/soc_platform.conf << 'EOF' > /dev/null
server {
    listen 80;
    server_name dev.codegrey.ai;
    
    location /api/backend/ {
        proxy_pass http://127.0.0.1:8080/api/backend/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        
        # CORS
        add_header Access-Control-Allow-Origin * always;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
    }
}
EOF

sudo nginx -t && sudo systemctl reload nginx

# 6. Wait and test
sleep 5

echo ""
echo "=========================================="
echo " DEPLOYMENT COMPLETE!"
echo "=========================================="
echo ""
echo "Platform Details:"
echo "  PID: $PID"
echo "  Port: 8080"
echo "  Log: tail -f platform.log"
echo ""
echo "Test endpoints:"
echo "  curl http://localhost:8080/api/backend/health"
echo "  curl http://localhost:8080/api/backend/agents"
echo ""
echo "Attack API:"
echo "  curl -X POST http://localhost:8080/api/backend/langgraph/attack/start \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"user_request\":\"Execute APT simulation\"}'"
echo ""
echo "=========================================="
