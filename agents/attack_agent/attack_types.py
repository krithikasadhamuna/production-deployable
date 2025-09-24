"""
Common types and enums for attack tools
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

class PlaybookStatus(Enum):
    DRAFT = "draft"
    APPROVED = "approved" 
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class AttackCategory(Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

@dataclass
class AttackStep:
    name: str
    description: str
    mitre_technique: str
    target_systems: Optional[List[str]] = None
    commands: Optional[List[str]] = None
    expected_results: Optional[str] = None
    prerequisites: Optional[List[str]] = None
    estimated_duration: int = 5
    risk_level: str = "medium"
    os_compatibility: Optional[List[str]] = None
    step_id: Optional[str] = None
    
    def __post_init__(self):
        if self.target_systems is None:
            self.target_systems = []
        if self.commands is None:
            self.commands = []
        if self.prerequisites is None:
            self.prerequisites = []
        if self.os_compatibility is None:
            self.os_compatibility = ["windows"]
        if self.step_id is None:
            import uuid
            self.step_id = str(uuid.uuid4())[:8]

@dataclass 
class AttackPlaybook:
    playbook_id: str
    name: str
    description: str
    category: AttackCategory
    target_environment: Optional[Dict[str, Any]] = None
    steps: Optional[List[AttackStep]] = None
    estimated_duration: int = 60  # minutes
    risk_assessment: str = "medium"
    prerequisites: Optional[List[str]] = None
    cleanup_steps: Optional[List[str]] = None
    status: PlaybookStatus = PlaybookStatus.DRAFT
    created_at: Optional[str] = None
    created_by: str = "attack_agent"
    approved_by: Optional[str] = None
    execution_log: Optional[List[Dict]] = None
    
    def __post_init__(self):
        if self.target_environment is None:
            self.target_environment = {}
        if self.steps is None:
            self.steps = []
        if self.prerequisites is None:
            self.prerequisites = []
        if self.cleanup_steps is None:
            self.cleanup_steps = []
        if self.execution_log is None:
            self.execution_log = []
        if self.created_at is None:
            from datetime import datetime
            self.created_at = datetime.utcnow().isoformat()
    
    # Compatibility property for old code
    @property
    def id(self):
        return self.playbook_id

    created_at: Optional[str] = None
    created_by: str = "attack_agent"
    approved_by: Optional[str] = None
    execution_log: Optional[List[Dict]] = None
    
    def __post_init__(self):
        if self.target_environment is None:
            self.target_environment = {}
        if self.steps is None:
            self.steps = []
        if self.prerequisites is None:
            self.prerequisites = []
        if self.cleanup_steps is None:
            self.cleanup_steps = []
        if self.execution_log is None:
            self.execution_log = []
        if self.created_at is None:
            from datetime import datetime
            self.created_at = datetime.utcnow().isoformat()
    
    # Compatibility property for old code
    @property
    def id(self):
        return self.playbook_id
