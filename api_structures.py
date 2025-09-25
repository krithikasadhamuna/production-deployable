#!/usr/bin/env python3
"""
API Structure Definitions
Clean API structures without hardcoded values or dummy data
All structures are configurable and production-ready
"""

from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

# Enums for consistent values
class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LogSource(Enum):
    PROCESS_MONITOR = "process_monitor"
    FILE_MONITOR = "file_monitor"
    NETWORK_MONITOR = "network_monitor"
    SECURITY_LOG = "security_log"
    SYSTEM_LOG = "system_log"
    APPLICATION_LOG = "application_log"

class EndpointStatus(Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    ERROR = "error"

class ThreatVerdict(Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

class UserRole(Enum):
    ADMIN = "admin"
    SOC_MANAGER = "soc_manager"
    SENIOR_ANALYST = "senior_analyst"
    ANALYST = "analyst"
    VIEWER = "viewer"

# API Request Structures
@dataclass
class AgentRegistrationRequest:
    """Client agent registration request structure"""
    hostname: str
    ip_address: str
    os_type: str
    mac_address: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    network_zone: Optional[str] = None
    importance: Optional[str] = None
    capabilities: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class LogEntry:
    """Individual log entry structure"""
    timestamp: str
    level: str  # LogLevel enum value
    source: str  # LogSource enum value
    message: str
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class AgentLogsRequest:
    """Agent logs submission request structure"""
    endpoint_id: str
    logs: List[LogEntry]
    batch_id: Optional[str] = None
    agent_version: Optional[str] = None

@dataclass
class HeartbeatRequest:
    """Agent heartbeat request structure"""
    endpoint_id: str
    status: str  # EndpointStatus enum value
    timestamp: str
    system_metrics: Optional[Dict[str, Any]] = None
    agent_health: Optional[Dict[str, Any]] = None

@dataclass
class UserLoginRequest:
    """User login request structure"""
    email: str
    password: str
    remember_me: Optional[bool] = False
    device_info: Optional[Dict[str, Any]] = None

@dataclass
class UserRegistrationRequest:
    """User registration request structure"""
    email: str
    password: str
    first_name: str
    last_name: Optional[str] = None
    role: str  # UserRole enum value
    organization: str
    department: Optional[str] = None
    phone: Optional[str] = None

@dataclass
class AttackScenarioRequest:
    """Attack scenario creation request structure"""
    name: str
    description: str
    attack_type: str
    target_endpoints: List[str]
    techniques: List[str]
    complexity: Optional[str] = None
    estimated_duration: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None

# API Response Structures
@dataclass
class StandardResponse:
    """Standard API response structure"""
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    timestamp: Optional[str] = None

@dataclass
class AgentRegistrationResponse(StandardResponse):
    """Agent registration response structure"""
    endpoint_id: Optional[str] = None
    api_key: Optional[str] = None
    configuration: Optional[Dict[str, Any]] = None

@dataclass
class LogsProcessingResponse(StandardResponse):
    """Logs processing response structure"""
    logs_processed: Optional[int] = None
    logs_queued_for_analysis: Optional[int] = None
    processing_errors: Optional[List[Dict[str, Any]]] = None

@dataclass
class UserAuthResponse(StandardResponse):
    """User authentication response structure"""
    user: Optional[Dict[str, Any]] = None
    auth: Optional[Dict[str, Any]] = None

@dataclass
class EndpointInfo:
    """Endpoint information structure"""
    id: str
    hostname: str
    ip_address: str
    os_type: str
    status: str
    last_seen: str
    network_zone: str
    importance: str
    agent_version: Optional[str] = None
    capabilities: Optional[List[str]] = None

@dataclass
class DetectionResult:
    """Detection result structure"""
    id: str
    timestamp: str
    threat_type: str
    severity: str
    confidence: float
    verdict: str  # ThreatVerdict enum value
    reasoning: str
    source_endpoint: str
    details: Optional[Dict[str, Any]] = None

@dataclass
class NetworkTopologyNode:
    """Network topology node structure"""
    id: str
    name: str
    type: str
    status: str
    metadata: Optional[Dict[str, Any]] = None
    agents: Optional[List[Dict[str, Any]]] = None
    hierarchy_level: Optional[int] = None

@dataclass
class NetworkTopologyResponse(StandardResponse):
    """Network topology response structure"""
    nodes: Optional[List[NetworkTopologyNode]] = None
    connections: Optional[List[Dict[str, str]]] = None
    hierarchy_order: Optional[str] = None
    statistics: Optional[Dict[str, int]] = None

@dataclass
class AgentInfo:
    """AI Agent information structure"""
    id: str
    name: str
    type: str
    status: str
    location: str
    last_activity: str
    capabilities: List[str]
    enabled: bool
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class SoftwareDownload:
    """Software download information structure"""
    id: int
    name: str
    version: str
    description: str
    file_name: str
    download_url: str
    os: str
    architecture: str
    min_ram_gb: int
    min_disk_mb: int
    configuration_cmd: str
    system_requirements: List[str]
    checksum: Optional[str] = None
    size_bytes: Optional[int] = None

# API Structure Factory Functions
class APIStructures:
    """Factory class for creating API structures"""
    
    @staticmethod
    def create_standard_response(success: bool, message: str = None, 
                               error: str = None, error_code: str = None) -> Dict[str, Any]:
        """Create standard API response"""
        response = StandardResponse(
            success=success,
            message=message,
            error=error,
            error_code=error_code,
            timestamp=datetime.now().isoformat()
        )
        return asdict(response)
    
    @staticmethod
    def create_agent_registration_response(success: bool, endpoint_id: str = None,
                                         api_key: str = None, message: str = None,
                                         error: str = None) -> Dict[str, Any]:
        """Create agent registration response"""
        response = AgentRegistrationResponse(
            success=success,
            endpoint_id=endpoint_id,
            api_key=api_key,
            message=message,
            error=error,
            timestamp=datetime.now().isoformat()
        )
        return asdict(response)
    
    @staticmethod
    def create_logs_processing_response(success: bool, logs_processed: int = None,
                                      logs_queued: int = None, errors: List = None,
                                      message: str = None, error: str = None) -> Dict[str, Any]:
        """Create logs processing response"""
        response = LogsProcessingResponse(
            success=success,
            logs_processed=logs_processed,
            logs_queued_for_analysis=logs_queued,
            processing_errors=errors or [],
            message=message,
            error=error,
            timestamp=datetime.now().isoformat()
        )
        return asdict(response)
    
    @staticmethod
    def create_user_auth_response(success: bool, user_data: Dict = None,
                                auth_data: Dict = None, message: str = None,
                                error: str = None, error_code: str = None) -> Dict[str, Any]:
        """Create user authentication response"""
        response = UserAuthResponse(
            success=success,
            user=user_data,
            auth=auth_data,
            message=message,
            error=error,
            error_code=error_code,
            timestamp=datetime.now().isoformat()
        )
        return asdict(response)
    
    @staticmethod
    def create_network_topology_response(success: bool, nodes: List = None,
                                       connections: List = None, hierarchy: str = None,
                                       stats: Dict = None, error: str = None) -> Dict[str, Any]:
        """Create network topology response"""
        response = NetworkTopologyResponse(
            success=success,
            nodes=nodes or [],
            connections=connections or [],
            hierarchy_order=hierarchy,
            statistics=stats or {},
            error=error,
            timestamp=datetime.now().isoformat()
        )
        return asdict(response)
    
    @staticmethod
    def validate_log_entry(log_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate log entry structure"""
        required_fields = ['timestamp', 'level', 'source', 'message']
        
        for field in required_fields:
            if field not in log_data:
                return False, f"Missing required field: {field}"
        
        # Validate enum values
        if log_data['level'] not in [level.value for level in LogLevel]:
            return False, f"Invalid log level: {log_data['level']}"
        
        if log_data['source'] not in [source.value for source in LogSource]:
            return False, f"Invalid log source: {log_data['source']}"
        
        return True, "Valid"
    
    @staticmethod
    def validate_agent_registration(reg_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate agent registration structure"""
        required_fields = ['hostname', 'ip_address', 'os_type']
        
        for field in required_fields:
            if field not in reg_data:
                return False, f"Missing required field: {field}"
        
        # Validate IP address format (basic check)
        ip = reg_data['ip_address']
        if not all(0 <= int(part) <= 255 for part in ip.split('.') if part.isdigit()):
            return False, "Invalid IP address format"
        
        return True, "Valid"
    
    @staticmethod
    def validate_user_login(login_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate user login structure"""
        required_fields = ['email', 'password']
        
        for field in required_fields:
            if field not in login_data:
                return False, f"Missing required field: {field}"
        
        # Basic email validation
        email = login_data['email']
        if '@' not in email or '.' not in email:
            return False, "Invalid email format"
        
        return True, "Valid"

# Error Code Constants
class ErrorCodes:
    """Standard error codes for API responses"""
    
    # Authentication errors
    MISSING_API_KEY = "MISSING_API_KEY"
    INVALID_API_KEY = "INVALID_API_KEY"
    MISSING_TOKEN = "MISSING_TOKEN"
    INVALID_TOKEN = "INVALID_TOKEN"
    INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
    
    # Validation errors
    MISSING_DATA = "MISSING_DATA"
    INVALID_DATA = "INVALID_DATA"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    
    # Resource errors
    ENDPOINT_NOT_FOUND = "ENDPOINT_NOT_FOUND"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"
    
    # Processing errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    DATABASE_ERROR = "DATABASE_ERROR"
    PROCESSING_ERROR = "PROCESSING_ERROR"
    QUEUE_FULL = "QUEUE_FULL"
    
    # Business logic errors
    ENDPOINT_ALREADY_REGISTERED = "ENDPOINT_ALREADY_REGISTERED"
    USER_ALREADY_EXISTS = "USER_ALREADY_EXISTS"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"

# HTTP Status Code Constants
class HTTPStatus:
    """HTTP status codes for API responses"""
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    INTERNAL_SERVER_ERROR = 500
    SERVICE_UNAVAILABLE = 503
