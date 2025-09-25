#!/bin/bash

# SOC Platform Backend Deployment Script
# This script deploys the Flask backend with /api/backend/ routing

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     SOC Platform Backend Deployment (/api/backend/)         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running on Linux/Unix
if [[ "$OSTYPE" != "linux-gnu"* ]] && [[ "$OSTYPE" != "darwin"* ]]; then
    echo "ERROR: This script is for Linux/Unix systems only"
    echo "   For Windows, use deploy_backend.ps1"
    exit 1
fi

# Variables
FLASK_PORT=5000
NGINX_CONFIG="nginx_backend_config.conf"
DOMAIN="dev.codegrey.ai"

echo "Deployment Configuration:"
echo "   Domain: $DOMAIN"
echo "   Flask Port: $FLASK_PORT"
echo "   API Base: http://$DOMAIN/api/backend/"
echo ""

# Step 1: Install Python dependencies
echo "📦 Installing Python dependencies..."
if [ -f "requirements_optimized.txt" ]; then
    pip3 install -r requirements_optimized.txt
elif [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
else
    echo "WARNING: No requirements file found"
fi

# Step 2: Stop existing Flask processes
echo "Stopping existing Flask processes on port $FLASK_PORT..."
sudo lsof -ti:$FLASK_PORT | xargs kill -9 2>/dev/null || true

# Step 3: Setup NGINX configuration
echo "Setting up NGINX configuration..."
if [ -f "$NGINX_CONFIG" ]; then
    # Copy to NGINX sites-available
    sudo cp $NGINX_CONFIG /etc/nginx/sites-available/soc-backend.conf
    
    # Enable the site
    sudo ln -sf /etc/nginx/sites-available/soc-backend.conf /etc/nginx/sites-enabled/
    
    # Test NGINX configuration
    sudo nginx -t
    if [ $? -eq 0 ]; then
        echo "SUCCESS: NGINX configuration valid"
        sudo systemctl reload nginx
        echo "SUCCESS: NGINX reloaded"
    else
        echo "ERROR: NGINX configuration error"
        exit 1
    fi
else
    echo "WARNING: NGINX config file not found: $NGINX_CONFIG"
fi

# Step 4: Create necessary directories
echo "Creating necessary directories..."
mkdir -p logs
mkdir -p tenant_databases
mkdir -p certificates
mkdir -p checkpoints
mkdir -p golden_images

# Step 5: Start Flask application
echo "Starting Flask application..."
cd flask_api

# Create startup script
cat > start_backend.sh << 'EOF'
#!/bin/bash
export FLASK_ENV=production
export FLASK_APP=app.py
export DOMAIN=dev.codegrey.ai

# Start Flask with gunicorn for production
if command -v gunicorn &> /dev/null; then
    echo "Starting with Gunicorn (production)..."
    gunicorn -w 4 -b 0.0.0.0:5000 --timeout 300 --log-file ../logs/gunicorn.log app:app &
else
    echo "Starting with Flask development server..."
    python3 app.py > ../logs/flask.log 2>&1 &
fi
EOF

chmod +x start_backend.sh
./start_backend.sh

cd ..

# Step 6: Wait for Flask to start
echo "Waiting for Flask to start..."
sleep 5

# Step 7: Test the endpoints
echo "Testing backend endpoints..."
python3 test_backend_apis.py

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "DEPLOYMENT COMPLETE!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Backend APIs are now available at:"
echo "   http://$DOMAIN/api/backend/"
echo ""
echo "Example endpoints:"
echo "   • http://$DOMAIN/api/backend/health"
echo "   • http://$DOMAIN/api/backend/agents"
echo "   • http://$DOMAIN/api/backend/software-download"
echo "   • http://$DOMAIN/api/backend/attack/scenario"
echo "   • http://$DOMAIN/api/backend/detection/analyze"
echo ""
echo "Logs:"
echo "   • Flask logs: logs/flask.log"
echo "   • NGINX logs: /var/log/nginx/soc-platform-*.log"
echo ""
echo "Management commands:"
echo "   • View Flask logs: tail -f logs/flask.log"
echo "   • Restart Flask: ./flask_api/start_backend.sh"
echo "   • Check status: systemctl status nginx"
echo "   • Test endpoints: python3 test_backend_apis.py"
echo ""
