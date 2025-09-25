#!/usr/bin/env python3
"""
Standalone User Authentication Service
Dedicated service for SOC personnel user management
Runs on separate port from main SOC platform
"""

import os
import sys
import logging

# Setup paths
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from agents.user_auth_agent import create_auth_app

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('user_auth_service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('UserAuthService')

def main():
    """Start the User Authentication Service"""
    logger.info("Starting SOC Platform User Authentication Service...")
    
    # Create Flask app
    app = create_auth_app()
    
    # Run the service
    logger.info("User Authentication Service starting on port 5002")
    logger.info("Available endpoints:")
    logger.info("  - POST /api/auth/auth/register - Register new SOC user")
    logger.info("  - POST /api/auth/auth/login - Login SOC user")
    logger.info("  - POST /api/auth/auth/logout - Logout SOC user")
    logger.info("  - GET /api/auth/auth/validate - Validate API key")
    logger.info("  - GET /api/auth/auth/profile - Get user profile")
    logger.info("  - GET /api/auth/auth/health - Service health check")
    
    try:
        app.run(
            host='0.0.0.0',
            port=5002,
            debug=False,
            threaded=True
        )
    except KeyboardInterrupt:
        logger.info("User Authentication Service stopped by user")
    except Exception as e:
        logger.error(f"Error starting User Authentication Service: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
