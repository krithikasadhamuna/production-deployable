#!/usr/bin/env python3
"""
CodeGrey SOC Platform - Production Server
Start with: python start_server.py
"""

import os
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import and run Flask app
from flask_api.app import app, init_database

if __name__ == "__main__":
    print("🚀 Starting CodeGrey SOC Production Server...")
    print("=" * 50)
    
    # Initialize database
    init_database()
    
    # Configuration
    HOST = os.getenv("SOC_HOST", "0.0.0.0")
    PORT = int(os.getenv("SOC_PORT", 443))
    
    # SSL Configuration (for production)
    ssl_context = None
    if PORT == 443:
        # For production, use proper SSL certificates
        cert_path = os.getenv("SSL_CERT_PATH", "cert.pem")
        key_path = os.getenv("SSL_KEY_PATH", "key.pem")
        if os.path.exists(cert_path) and os.path.exists(key_path):
            ssl_context = (cert_path, key_path)
        else:
            print("⚠️ SSL certificates not found, using adhoc certificates")
            ssl_context = "adhoc"
    
    print(f"📡 Server: https://{HOST}:{PORT}" if ssl_context else f"http://{HOST}:{PORT}")
    print(f"🔐 API Key Required: Yes")
    print("=" * 50)
    
    # Run server
    app.run(
        host=HOST,
        port=PORT,
        debug=False,  # Never use debug in production
        ssl_context=ssl_context
    )
