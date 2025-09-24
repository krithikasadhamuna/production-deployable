#!/bin/bash
# CodeGrey SOC Server - Quick Start Script

echo "🚀 CodeGrey SOC Server - Production Deployment"
echo "=============================================="

# Check if Docker is available
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo "✅ Docker found - Using containerized deployment"
    
    # Create .env if it doesn't exist
    if [ ! -f .env ]; then
        echo "📝 Creating .env file from template..."
        cp env.example .env
        echo "⚠️  Please edit .env file with your settings before production use!"
    fi
    
    # Start with Docker Compose
    echo "🐳 Starting with Docker Compose..."
    docker-compose up -d
    
    echo "✅ Server should be running on port 8443"
    echo "🔍 Check status: curl http://localhost:8443/api/system/status"
    echo "📊 View logs: docker-compose logs -f soc-server"
    
elif command -v python3 &> /dev/null; then
    echo "🐍 Python found - Using direct deployment"
    
    # Install dependencies
    echo "📦 Installing dependencies..."
    pip3 install -r requirements.txt
    
    # Create .env if it doesn't exist
    if [ ! -f .env ]; then
        echo "📝 Creating .env file from template..."
        cp env.example .env
        echo "⚠️  Please edit .env file with your settings!"
    fi
    
    # Create directories
    mkdir -p logs database
    
    # Start server
    echo "🚀 Starting server..."
    python3 app.py
    
else
    echo "❌ Neither Docker nor Python3 found!"
    echo "Please install Docker or Python 3.8+ to continue."
    exit 1
fi



