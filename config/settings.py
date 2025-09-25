"""
SOC Platform Configuration Management
Professional configuration system with environment support
"""

import os
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class DatabaseConfig:
    """Database configuration"""
    main_db: str = "soc_main.db"
    topology_db: str = "network_topology.db"
    logs_db: str = "agent_logs.db"
    users_db: str = "soc_users.db"
    backup_interval: int = 3600  # seconds
    
@dataclass
class ServerConfig:
    """Server configuration"""
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    workers: int = 4
    max_content_length: int = 16 * 1024 * 1024  # 16MB
    
@dataclass
class SecurityConfig:
    """Security configuration"""
    jwt_secret_key: str = ""
    api_key_length: int = 32
    session_timeout: int = 28800  # 8 hours
    max_login_attempts: int = 5
    lockout_duration: int = 1800  # 30 minutes
    
@dataclass
class AIAgentConfig:
    """AI Agent configuration"""
    ollama_host: str = "http://localhost:11434"
    default_model: str = "cybersec-ai"
    fallback_model: str = "llama3.2:3b"
    max_tokens: int = 2048
    temperature: float = 0.7
    
@dataclass
class NetworkConfig:
    """Network and topology configuration"""
    scan_interval: int = 300  # 5 minutes
    heartbeat_timeout: int = 300  # 5 minutes
    max_endpoints: int = 10000
    topology_update_interval: int = 60  # 1 minute
    
@dataclass
class StorageConfig:
    """Storage configuration"""
    golden_images_path: str = "golden_images"
    logs_path: str = "logs"
    checkpoints_path: str = "checkpoints"
    max_log_size: int = 100 * 1024 * 1024  # 100MB
    log_retention_days: int = 30
    
@dataclass
class ExternalServicesConfig:
    """External services configuration"""
    s3_bucket: str = "dev-codegrey"
    s3_region: str = "ap-south-1"
    download_base_url: str = "https://dev-codegrey.s3.ap-south-1.amazonaws.com"
    client_server_url: str = "https://os.codegrey.ai"
    
@dataclass
class SOCPlatformConfig:
    """Main SOC Platform configuration"""
    environment: str = "development"
    platform_name: str = "CodeGrey AI-Driven SOC Platform"
    version: str = "3.0.0"
    
    # Sub-configurations
    database: DatabaseConfig = None
    server: ServerConfig = None
    security: SecurityConfig = None
    ai_agents: AIAgentConfig = None
    network: NetworkConfig = None
    storage: StorageConfig = None
    external_services: ExternalServicesConfig = None
    
    def __post_init__(self):
        """Initialize sub-configurations if not provided"""
        if self.database is None:
            self.database = DatabaseConfig()
        if self.server is None:
            self.server = ServerConfig()
        if self.security is None:
            self.security = SecurityConfig()
        if self.ai_agents is None:
            self.ai_agents = AIAgentConfig()
        if self.network is None:
            self.network = NetworkConfig()
        if self.storage is None:
            self.storage = StorageConfig()
        if self.external_services is None:
            self.external_services = ExternalServicesConfig()

class ConfigManager:
    """Configuration manager with environment support"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "config/soc_platform.json"
        self.config = self._load_config()
        self._apply_environment_overrides()
    
    def _load_config(self) -> SOCPlatformConfig:
        """Load configuration from file or create default"""
        config_path = Path(self.config_file)
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                return self._dict_to_config(config_data)
            except Exception as e:
                print(f"Warning: Could not load config file {self.config_file}: {e}")
                print("Using default configuration")
        
        return SOCPlatformConfig()
    
    def _dict_to_config(self, data: Dict[str, Any]) -> SOCPlatformConfig:
        """Convert dictionary to configuration object"""
        config = SOCPlatformConfig()
        
        # Update main config
        for key, value in data.items():
            if hasattr(config, key) and not isinstance(getattr(config, key), (DatabaseConfig, ServerConfig, SecurityConfig, AIAgentConfig, NetworkConfig, StorageConfig, ExternalServicesConfig)):
                setattr(config, key, value)
        
        # Update sub-configurations
        if 'database' in data:
            config.database = DatabaseConfig(**data['database'])
        if 'server' in data:
            config.server = ServerConfig(**data['server'])
        if 'security' in data:
            config.security = SecurityConfig(**data['security'])
        if 'ai_agents' in data:
            config.ai_agents = AIAgentConfig(**data['ai_agents'])
        if 'network' in data:
            config.network = NetworkConfig(**data['network'])
        if 'storage' in data:
            config.storage = StorageConfig(**data['storage'])
        if 'external_services' in data:
            config.external_services = ExternalServicesConfig(**data['external_services'])
        
        return config
    
    def _apply_environment_overrides(self):
        """Apply environment variable overrides"""
        env_mappings = {
            'SOC_ENVIRONMENT': ('environment',),
            'SOC_HOST': ('server', 'host'),
            'SOC_PORT': ('server', 'port'),
            'SOC_DEBUG': ('server', 'debug'),
            'SOC_JWT_SECRET': ('security', 'jwt_secret_key'),
            'SOC_OLLAMA_HOST': ('ai_agents', 'ollama_host'),
            'SOC_DEFAULT_MODEL': ('ai_agents', 'default_model'),
            'SOC_S3_BUCKET': ('external_services', 's3_bucket'),
            'SOC_DOWNLOAD_URL': ('external_services', 'download_base_url'),
            'SOC_CLIENT_SERVER_URL': ('external_services', 'client_server_url'),
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                self._set_nested_config(config_path, value)
    
    def _set_nested_config(self, path: tuple, value: str):
        """Set nested configuration value"""
        obj = self.config
        for key in path[:-1]:
            obj = getattr(obj, key)
        
        # Type conversion
        final_key = path[-1]
        current_value = getattr(obj, final_key)
        
        if isinstance(current_value, bool):
            value = value.lower() in ('true', '1', 'yes', 'on')
        elif isinstance(current_value, int):
            value = int(value)
        elif isinstance(current_value, float):
            value = float(value)
        
        setattr(obj, final_key, value)
    
    def save_config(self, file_path: Optional[str] = None):
        """Save current configuration to file"""
        file_path = file_path or self.config_file
        
        # Ensure directory exists
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dictionary
        config_dict = asdict(self.config)
        
        with open(file_path, 'w') as f:
            json.dump(config_dict, f, indent=2)
    
    def get_database_url(self, db_name: str) -> str:
        """Get database URL for given database"""
        db_mapping = {
            'main': self.config.database.main_db,
            'topology': self.config.database.topology_db,
            'logs': self.config.database.logs_db,
            'users': self.config.database.users_db,
        }
        return db_mapping.get(db_name, db_name)
    
    def get_download_url(self, filename: str) -> str:
        """Get download URL for client agent"""
        return f"{self.config.external_services.download_base_url}/{filename}"
    
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.config.environment.lower() == 'production'
    
    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.config.environment.lower() == 'development'

# Global configuration instance
config_manager = ConfigManager()
config = config_manager.config
