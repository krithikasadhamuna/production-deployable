"""
🏢 Organization Management APIs
Implements organization and tenant management endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import uuid
import secrets
from functools import wraps

organizations_bp = Blueprint('organizations', __name__)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'Missing or invalid Authorization header',
                'error_code': 'UNAUTHORIZED'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

@organizations_bp.route('/organizations', methods=['POST'])
@require_auth
def create_organization():
    """
    POST /api/organizations
    Create a new organization
    """
    try:
        data = request.get_json()
        
        if not data or 'name' not in data or 'contact_email' not in data:
            return jsonify({
                "success": False,
                "error": "Missing required fields: name, contact_email",
                "error_code": "INVALID_PARAMETERS"
            }), 400
        
        name = data['name']
        contact_email = data['contact_email']
        industry = data.get('industry', 'Technology')
        size = data.get('size', 'medium')
        settings = data.get('settings', {
            "max_agents": 100,
            "retention_days": 90,
            "alert_threshold": "medium"
        })
        
        # Generate organization ID and API key
        org_id = f"org-{uuid.uuid4().hex[:12]}"
        api_key = f"ak_{secrets.token_hex(16)}"
        
        conn = get_db_connection()
        
        # Check if organization name already exists
        cursor = conn.execute("SELECT id FROM organizations WHERE name = ?", (name,))
        if cursor.fetchone():
            conn.close()
            return jsonify({
                "success": False,
                "error": "Organization name already exists",
                "error_code": "DUPLICATE_ORGANIZATION"
            }), 409
        
        # Insert new organization
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            INSERT INTO organizations 
            (id, name, contact_email, industry, size, api_key, created_at, settings, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            org_id, name, contact_email, industry, size, api_key, now, 
            json.dumps(settings), 'active'
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "organization": {
                "id": org_id,
                "name": name,
                "contact_email": contact_email,
                "api_key": api_key,
                "created_at": now,
                "settings": settings,
                "status": "active"
            },
            "message": "Organization created successfully"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@organizations_bp.route('/organizations', methods=['GET'])
@require_auth
def get_organizations():
    """
    GET /api/organizations
    List all organizations (admin only)
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM organizations ORDER BY created_at DESC")
        orgs_raw = cursor.fetchall()
        conn.close()
        
        organizations = []
        for org in orgs_raw:
            org_data = {
                "id": org['id'],
                "name": org['name'],
                "contact_email": org['contact_email'],
                "industry": org['industry'],
                "size": org['size'],
                "created_at": org['created_at'],
                "settings": json.loads(org['settings']) if org['settings'] else {},
                "status": org['status']
                # Note: API key is not returned for security
            }
            organizations.append(org_data)
        
        return jsonify({
            "success": True,
            "organizations": organizations,
            "total": len(organizations)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500

@organizations_bp.route('/organizations/<org_id>', methods=['GET'])
@require_auth
def get_organization(org_id):
    """
    GET /api/organizations/{org_id}
    Get specific organization details
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM organizations WHERE id = ?", (org_id,))
        org = cursor.fetchone()
        conn.close()
        
        if not org:
            return jsonify({
                "success": False,
                "error": "Organization not found",
                "error_code": "ORGANIZATION_NOT_FOUND"
            }), 404
        
        org_data = {
            "id": org['id'],
            "name": org['name'],
            "contact_email": org['contact_email'],
            "industry": org['industry'],
            "size": org['size'],
            "created_at": org['created_at'],
            "settings": json.loads(org['settings']) if org['settings'] else {},
            "status": org['status']
        }
        
        return jsonify({
            "success": True,
            "organization": org_data
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "INTERNAL_ERROR"
        }), 500


