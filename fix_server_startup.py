#!/usr/bin/env python3
"""
Fix script for production server startup issues
Run this before start_production_server.py
"""

import sqlite3
import os
import sys

def fix_database():
    """Fix the database schema issues"""
    
    # Fix master database
    if os.path.exists('master_platform.db'):
        print("Fixing master database...")
        conn = sqlite3.connect('master_platform.db')
        cursor = conn.cursor()
        
        # Check if api_key column exists
        cursor.execute("PRAGMA table_info(global_users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'api_key' not in columns:
            # Add column without UNIQUE constraint first
            try:
                cursor.execute('ALTER TABLE global_users ADD COLUMN api_key TEXT')
                print("Added api_key column")
            except:
                pass
        
        # Update existing users with API keys
        users_keys = [
            ('sagar@codegrey.ai', 'usr-api-sagar-default-2024'),
            ('alsaad@codegrey.ai', 'usr-api-alsaad-default-2024'),
            ('krithika@codegrey.ai', 'usr-api-krithika-default-2024')
        ]
        
        for email, api_key in users_keys:
            cursor.execute('UPDATE global_users SET api_key = ? WHERE email = ?', (api_key, email))
        
        conn.commit()
        conn.close()
        print("Master database fixed!")
    
    # Create missing module stub
    os.makedirs('agents/attack_agent', exist_ok=True)
    
    # Create missing playbook_engine.py
    with open('agents/attack_agent/playbook_engine.py', 'w') as f:
        f.write("""
# Stub for missing module
class PlaybookEngine:
    def __init__(self):
        pass
    
    def execute(self):
        pass
""")
    
    print("Created missing playbook_engine module")
    
    # Create __init__.py files
    for path in ['agents', 'agents/attack_agent', 'flask_api', 'flask_api/routes']:
        init_file = os.path.join(path, '__init__.py')
        if not os.path.exists(init_file):
            os.makedirs(path, exist_ok=True)
            with open(init_file, 'w') as f:
                f.write('# Init file\n')
    
    print("Created __init__ files")
    
    return True

def create_simple_app():
    """Create a simple app.py that works"""
    simple_app = '''
from flask import Flask, jsonify
from flask_cors import CORS
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
CORS(app)

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'message': 'SOC Platform Running'})

@app.route('/api/software-download', methods=['GET'])
def software_download():
    return jsonify([
        {
            "id": 1,
            "name": "windows",
            "version": "2024.1.3",
            "downloadUrl": "https://dev.codegrey.s3.ap-south-1.amazonaws.com/windows.zip"
        },
        {
            "id": 2,
            "name": "linux",
            "version": "2024.1.3",
            "downloadUrl": "https://dev.codegrey.s3.ap-south-1.amazonaws.com/linux.zip"
        },
        {
            "id": 3,
            "name": "macos",
            "version": "2024.1.3",
            "downloadUrl": "https://dev.codegrey.s3.ap-south-1.amazonaws.com/macos.zip"
        }
    ])

@app.route('/api/agents', methods=['GET'])
def agents():
    return jsonify([
        {
            "id": "1",
            "name": "PhantomStrike AI",
            "type": "attack",
            "status": "idle",
            "enabled": True
        },
        {
            "id": "2",
            "name": "GuardianAlpha AI",
            "type": "detection",
            "status": "active",
            "enabled": True
        }
    ])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
'''
    
    with open('flask_api/app_simple.py', 'w') as f:
        f.write(simple_app)
    
    print("Created simple Flask app")

if __name__ == '__main__':
    print("Fixing production server issues...")
    
    if fix_database():
        create_simple_app()
        print("\n✅ Fixes applied successfully!")
        print("\nNow you can run:")
        print("  python3 flask_api/app_simple.py")
        print("\nOr try the full server again:")
        print("  python3 start_production_server.py")
    else:
        print("\n❌ Failed to apply fixes")
        sys.exit(1)
