"""
User Authentication API
Flask API endpoints for SOC personnel user management
Separate from main SOC platform - dedicated authentication service
"""

from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
from functools import wraps
import logging
from .user_auth_manager import UserAuthenticationAgent

logger = logging.getLogger('UserAuthAPI')

# Create blueprint for user authentication
user_auth_bp = Blueprint('user_auth', __name__)

# Initialize User Authentication Agent
auth_agent = UserAuthenticationAgent()

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({
                'success': False,
                'error': 'API key required',
                'error_code': 'MISSING_API_KEY'
            }), 401
        
        # Validate API key
        valid, user_info = auth_agent.validate_api_key(api_key)
        if not valid:
            return jsonify({
                'success': False,
                'error': 'Invalid API key',
                'error_code': 'INVALID_API_KEY'
            }), 401
        
        # Add user info to request context
        request.user = user_info
        return f(*args, **kwargs)
    
    return decorated_function

def require_jwt_token(f):
    """Decorator to require JWT token authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'JWT token required',
                'error_code': 'MISSING_TOKEN'
            }), 401
        
        token = auth_header.split(' ')[1]
        valid, payload = auth_agent.validate_jwt_token(token)
        
        if not valid:
            return jsonify({
                'success': False,
                'error': payload.get('error', 'Invalid token'),
                'error_code': 'INVALID_TOKEN'
            }), 401
        
        # Add user info to request context
        request.user = payload
        return f(*args, **kwargs)
    
    return decorated_function

def require_permission(permission):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'user'):
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'error_code': 'AUTHENTICATION_REQUIRED'
                }), 401
            
            user_permissions = auth_agent.get_user_permissions(request.user['user_id'])
            
            if permission not in user_permissions:
                return jsonify({
                    'success': False,
                    'error': f'Permission required: {permission}',
                    'error_code': 'INSUFFICIENT_PERMISSIONS'
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============= USER AUTHENTICATION ENDPOINTS =============

@user_auth_bp.route('/auth/register', methods=['POST'])
def register_user():
    """
    Register new SOC personnel user
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Request body required',
                'error_code': 'MISSING_DATA'
            }), 400
        
        success, result = auth_agent.register_user(data)
        
        if success:
            return jsonify({
                'success': True,
                'message': result['message'],
                'user_id': result['user_id'],
                'api_key': result['api_key']
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': result['error'],
                'error_code': 'REGISTRATION_FAILED'
            }), 400
            
    except Exception as e:
        logger.error(f"Error in register_user: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@user_auth_bp.route('/auth/login', methods=['POST'])
def login_user():
    """
    Authenticate SOC user and return JWT token
    """
    try:
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({
                'success': False,
                'error': 'Email and password required',
                'error_code': 'MISSING_CREDENTIALS'
            }), 400
        
        success, result = auth_agent.authenticate_user(data['email'], data['password'])
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'user_id': result['user_id'],
                    'email': result['email'],
                    'first_name': result['first_name'],
                    'last_name': result['last_name'],
                    'role': result['role'],
                    'organization': result['organization']
                },
                'auth': {
                    'jwt_token': result['jwt_token'],
                    'api_key': result['api_key'],
                    'session_id': result['session_id'],
                    'expires_at': result['expires_at']
                }
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': result['error'],
                'error_code': 'LOGIN_FAILED'
            }), 401
            
    except Exception as e:
        logger.error(f"Error in login_user: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@user_auth_bp.route('/auth/logout', methods=['POST'])
@require_jwt_token
def logout_user():
    """
    Logout user by deactivating session
    """
    try:
        data = request.get_json()
        session_id = data.get('session_id') if data else None
        
        if not session_id:
            return jsonify({
                'success': False,
                'error': 'Session ID required',
                'error_code': 'MISSING_SESSION_ID'
            }), 400
        
        success = auth_agent.logout_user(session_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Logout successful'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Logout failed',
                'error_code': 'LOGOUT_FAILED'
            }), 400
            
    except Exception as e:
        logger.error(f"Error in logout_user: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@user_auth_bp.route('/auth/validate', methods=['GET'])
@require_api_key
def validate_api_key():
    """
    Validate API key and return user info
    """
    try:
        return jsonify({
            'success': True,
            'message': 'API key valid',
            'user': request.user
        }), 200
        
    except Exception as e:
        logger.error(f"Error in validate_api_key: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@user_auth_bp.route('/auth/profile', methods=['GET'])
@require_jwt_token
def get_user_profile():
    """
    Get current user profile
    """
    try:
        user_permissions = auth_agent.get_user_permissions(request.user['user_id'])
        
        return jsonify({
            'success': True,
            'user': {
                'user_id': request.user['user_id'],
                'email': request.user['email'],
                'role': request.user['role'],
                'organization': request.user['organization'],
                'permissions': user_permissions
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error in get_user_profile: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@user_auth_bp.route('/auth/regenerate-api-key', methods=['POST'])
@require_jwt_token
def regenerate_api_key():
    """
    Regenerate API key for current user
    """
    try:
        success, new_api_key = auth_agent.regenerate_api_key(request.user['user_id'])
        
        if success:
            return jsonify({
                'success': True,
                'message': 'API key regenerated successfully',
                'new_api_key': new_api_key
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': new_api_key,  # Error message
                'error_code': 'REGENERATION_FAILED'
            }), 400
            
    except Exception as e:
        logger.error(f"Error in regenerate_api_key: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

# ============= ADMIN ENDPOINTS =============

@user_auth_bp.route('/admin/users', methods=['GET'])
@require_jwt_token
@require_permission('user_management')
def list_all_users():
    """
    List all users (admin only)
    """
    try:
        # This would be implemented in the auth agent
        return jsonify({
            'success': True,
            'message': 'Admin endpoint - list all users',
            'users': []  # Placeholder
        }), 200
        
    except Exception as e:
        logger.error(f"Error in list_all_users: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@user_auth_bp.route('/admin/stats', methods=['GET'])
@require_jwt_token
@require_permission('user_management')
def get_user_stats():
    """
    Get user statistics (admin only)
    """
    try:
        stats = auth_agent.get_user_stats()
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Error in get_user_stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

# ============= HEALTH CHECK =============

@user_auth_bp.route('/auth/health', methods=['GET'])
def auth_health():
    """
    User authentication service health check
    """
    try:
        stats = auth_agent.get_user_stats()
        
        return jsonify({
            'service': 'User Authentication Agent',
            'status': 'healthy',
            'version': '1.0.0',
            'database': 'connected',
            'stats': {
                'total_users': stats.get('total_users', 0),
                'active_users': stats.get('active_users', 0)
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error in auth_health: {e}")
        return jsonify({
            'service': 'User Authentication Agent',
            'status': 'error',
            'error': str(e)
        }), 500

# ============= STANDALONE FLASK APP =============

def create_auth_app():
    """
    Create standalone Flask app for user authentication
    """
    app = Flask(__name__)
    CORS(app)
    
    # Register blueprint
    app.register_blueprint(user_auth_bp, url_prefix='/api/auth')
    
    # Root endpoint
    @app.route('/')
    def root():
        return jsonify({
            'service': 'SOC Platform - User Authentication Agent',
            'version': '1.0.0',
            'endpoints': {
                'register': '/api/auth/auth/register',
                'login': '/api/auth/auth/login',
                'logout': '/api/auth/auth/logout',
                'validate': '/api/auth/auth/validate',
                'profile': '/api/auth/auth/profile',
                'health': '/api/auth/auth/health'
            }
        })
    
    return app

if __name__ == '__main__':
    # Run as standalone service
    app = create_auth_app()
    app.run(host='0.0.0.0', port=5002, debug=False)
