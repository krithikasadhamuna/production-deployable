#!/usr/bin/env python3
"""
🚀 CodeGrey SOC API Server Startup Script
Initializes and starts the Flask API server with all endpoints
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def check_requirements():
    """Check if required packages are installed"""
    try:
        import flask
        import flask_cors
        import psutil
        print("✅ All required packages are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing required package: {e}")
        print("📦 Installing requirements...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("✅ Requirements installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("❌ Failed to install requirements")
            return False

def main():
    """Main startup function"""
    print("🚀 CodeGrey SOC - Flask API Server")
    print("=" * 50)
    
    # Change to flask_api directory
    os.chdir(Path(__file__).parent)
    
    # Check requirements
    if not check_requirements():
        print("❌ Cannot start server due to missing requirements")
        return 1
    
    # Import and run the Flask app
    try:
        from app import app
        
        print("\n📊 API Endpoints Available:")
        print("├── Agent Management: /api/agents")
        print("├── Attack Operations: /api/attack_scenarios")
        print("├── Detection Results: /api/detections/live") 
        print("├── AI Reasoning: /api/v1/chat")
        print("├── Network Topology: /api/network/topology")
        print("├── Command & Control: /api/agents/{id}/command")
        print("├── System Monitoring: /api/system/status")
        print("├── Organizations: /api/organizations")
        print("└── Testing: /api/test/create-sample-agents")
        
        print("\n🔐 Authentication:")
        print("├── All endpoints require Bearer token")
        print("├── Header: Authorization: Bearer <your-token>")
        print("└── Sample token: ak_demo_token_12345")
        
        print("\n🌐 Server Information:")
        print(f"├── Host: https://localhost:8443")
        print(f"├── Protocol: HTTPS (self-signed certificate)")
        print(f"├── Database: SQLite (soc_database.db)")
        print(f"└── CORS: Enabled for frontend access")
        
        print("\n🧪 Quick Test:")
        print("curl -k -H 'Authorization: Bearer ak_demo_token_12345' https://localhost:8443/api/agents")
        
        print("\n" + "=" * 50)
        print("🚀 Starting Flask API Server...")
        print("📝 Press Ctrl+C to stop the server")
        print("=" * 50 + "\n")
        
        # Start the server
        app.run(
            host='0.0.0.0',
            port=443,
            debug=True,
            ssl_context='adhoc'
        )
        
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
        return 0
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())


