"""
Production configuration for CodeGrey SOC Server
"""
import os

class ProductionConfig:
    """Production configuration settings"""
    
    # Server settings
    HOST = os.getenv('SOC_HOST', '0.0.0.0')
    PORT = int(os.getenv('SOC_PORT', '443'))
    DEBUG = False
    TESTING = False
    
    # Database settings
    DATABASE_PATH = os.getenv('SOC_DATABASE_PATH', 'database/soc_production.db')
    
    # Security settings
    SECRET_KEY = os.getenv('SOC_SECRET_KEY', 'your-production-secret-key-change-this')
    
    # API settings
    API_RATE_LIMIT = os.getenv('SOC_API_RATE_LIMIT', '1000 per hour')
    
    # Logging settings
    LOG_LEVEL = os.getenv('SOC_LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('SOC_LOG_FILE', 'logs/soc_server.log')
    
    # Multi-tenant settings
    MAX_AGENTS_PER_TENANT = int(os.getenv('SOC_MAX_AGENTS_PER_TENANT', '100'))
    MAX_COMMANDS_PER_MINUTE = int(os.getenv('SOC_MAX_COMMANDS_PER_MINUTE', '60'))
    
    @staticmethod
    def init_app(app):
        """Initialize Flask app with production settings"""
        pass

# Environment-specific configurations
config = {
    'production': ProductionConfig,
    'default': ProductionConfig
}



