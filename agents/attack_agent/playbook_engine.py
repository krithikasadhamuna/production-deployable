import json
import os
import time
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from langchain_openai import ChatOpenAI
from langchain_community.chat_models import ChatOllama
import yaml
import os

class PlaybookStatus(Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class AttackCategory(Enum):
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
    step_id: str
    name: str
    description: str
    mitre_technique: str
    target_systems: List[str]
    commands: List[str]
    expected_results: str
    prerequisites: List[str]
    estimated_duration: int  # minutes
    risk_level: str  # low, medium, high, critical
    os_compatibility: List[str]  # windows, linux, macos

@dataclass
class AttackPlaybook:
    playbook_id: str
    name: str
    description: str
    category: AttackCategory
    target_environment: Dict[str, Any]
    steps: List[AttackStep]
    estimated_duration: int
    risk_assessment: str
    prerequisites: List[str]
    cleanup_steps: List[str]
    status: PlaybookStatus
    created_at: str
    created_by: str
    approved_by: Optional[str] = None
    execution_log: List[Dict] = None

class PlaybookEngine:
    """Engine for creating and executing attack playbooks"""
    
    def __init__(self, playbooks_dir: str = "./playbooks"):
        self.playbooks_dir = playbooks_dir
        self.playbooks_file = os.path.join(playbooks_dir, "playbooks.json")
        os.makedirs(playbooks_dir, exist_ok=True)
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize LLM with local cybersec-ai as primary
        self.llm = self._initialize_llm()
        self.playbooks = {}
        self._load_playbooks()
    
    def _load_config(self):
        """Load system configuration"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.yaml")
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
        
        # Default config
        return {
            'llm': {
                'provider': 'ollama',
                'ollama_endpoint': 'http://localhost:11434',
                'ollama_model': 'cybersec-ai',
                'fallback_order': ['ollama', 'openai'],
                'temperature': 0.7
            }
        }
    
    def _initialize_llm(self):
        """Initialize LLM with local cybersec-ai as primary"""
        llm_config = self.config.get('llm', {})
        fallback_order = llm_config.get('fallback_order', ['ollama', 'openai'])
        
        for provider in fallback_order:
            try:
                if provider == 'ollama':
                    print("🧠 Initializing local cybersec-ai LLM...")
                    return ChatOllama(
                        model=llm_config.get('ollama_model', 'cybersec-ai'),
                        base_url=llm_config.get('ollama_endpoint', 'http://localhost:11434'),
                        temperature=llm_config.get('temperature', 0.7)
                    )
                elif provider == 'openai':
                    print("🔄 Fallback to OpenAI...")
                    openai_key = llm_config.get('openai_api_key', os.getenv('OPENAI_API_KEY'))
                    if openai_key and openai_key != 'sk-...':
                        return ChatOpenAI(
                            api_key=openai_key,
                            model=llm_config.get('openai_model', 'gpt-4o'),
                            temperature=llm_config.get('temperature', 0.7)
                        )
            except Exception as e:
                print(f"⚠️ Failed to initialize {provider}: {e}")
                continue
        
        # Last resort - basic Ollama
        print("🆘 Using basic Ollama fallback...")
        return ChatOllama(model='llama3.2:3b', base_url='http://localhost:11434')

    def _load_playbooks(self):
        """Load existing playbooks from storage"""
        if os.path.exists(self.playbooks_file):
            try:
                with open(self.playbooks_file, 'r') as f:
                    data = json.load(f)
                    for pb_id, pb_data in data.items():
                        # Convert steps
                        steps = [AttackStep(**step) for step in pb_data.pop('steps', [])]
                        # Convert enums
                        pb_data['category'] = AttackCategory(pb_data['category'])
                        pb_data['status'] = PlaybookStatus(pb_data['status'])
                        
                        playbook = AttackPlaybook(**pb_data, steps=steps)
                        self.playbooks[pb_id] = playbook
            except Exception as e:
                print(f"Failed to load playbooks: {e}")
                self.playbooks = {}
    
    def _save_playbooks(self):
        """Save playbooks to storage"""
        try:
            data = {}
            for pb_id, playbook in self.playbooks.items():
                pb_dict = asdict(playbook)
                # Convert enums to strings
                pb_dict['category'] = playbook.category.value
                pb_dict['status'] = playbook.status.value
                data[pb_id] = pb_dict
            
            with open(self.playbooks_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Failed to save playbooks: {e}")
    
    def generate_playbook_from_infrastructure(self, systems: List[Dict], attack_objectives: List[str]) -> Optional[str]:
        """Generate an attack playbook based on available infrastructure"""
        print("🧠 Generating attack playbook from infrastructure analysis...")
        
        # Analyze the infrastructure
        infrastructure_summary = self._analyze_infrastructure(systems)
        
        # Generate playbook using LLM
        playbook_data = self._generate_playbook_with_llm(infrastructure_summary, attack_objectives)
        
        if playbook_data:
            playbook_id = str(uuid.uuid4())
            playbook = self._create_playbook_from_data(playbook_id, playbook_data)
            
            self.playbooks[playbook_id] = playbook
            self._save_playbooks()
            
            print(f"✅ Generated playbook: {playbook.name} ({playbook_id})")
            return playbook_id
        else:
            print("❌ Failed to generate playbook")
            return None
    
    def _analyze_infrastructure(self, systems: List[Dict]) -> Dict:
        """Analyze infrastructure to determine attack vectors"""
        analysis = {
            "total_systems": len(systems),
            "os_distribution": {},
            "domain_controllers": [],
            "high_value_targets": [],
            "attack_paths": [],
            "vulnerabilities": [],
            "network_topology": {}
        }
        
        for system in systems:
            os_type = system.get('os_type', 'unknown').lower()
            analysis['os_distribution'][os_type] = analysis['os_distribution'].get(os_type, 0) + 1
            
            if system.get('is_domain_controller'):
                analysis['domain_controllers'].append(system['hostname'])
            
            # Identify high-value targets
            if any(software in system.get('installed_software', []) for software in ['Active Directory', 'SQL Server', 'Exchange']):
                analysis['high_value_targets'].append(system['hostname'])
            
            # Check for common vulnerabilities
            if 'Windows' in system.get('os_version', ''):
                if 'Windows 7' in system['os_version'] or 'Windows Server 2008' in system['os_version']:
                    analysis['vulnerabilities'].append(f"Outdated OS on {system['hostname']}")
        
        return analysis
    
    def _generate_playbook_with_llm(self, infrastructure: Dict, objectives: List[str]) -> Optional[Dict]:
        """Use LLM to generate attack playbook"""
        prompt = f"""
You are an expert red team operator creating an attack simulation playbook.

Infrastructure Analysis:
- Total Systems: {infrastructure['total_systems']}
- OS Distribution: {infrastructure['os_distribution']}
- Domain Controllers: {infrastructure['domain_controllers']}
- High-Value Targets: {infrastructure['high_value_targets']}
- Identified Vulnerabilities: {infrastructure['vulnerabilities']}

Attack Objectives: {', '.join(objectives)}

Create a comprehensive attack playbook with the following structure:

1. Playbook Name: A descriptive name for the attack scenario
2. Description: Overall attack scenario description
3. Category: One of [initial_access, execution, persistence, privilege_escalation, defense_evasion, credential_access, discovery, lateral_movement, collection, command_and_control, exfiltration, impact]
4. Risk Assessment: Overall risk level and impact assessment
5. Prerequisites: What needs to be in place before starting
6. Attack Steps: Detailed steps with:
   - Step name and description
   - MITRE ATT&CK technique ID
   - Target systems (use hostnames from infrastructure)
   - Specific commands to execute
   - Expected results
   - Prerequisites for this step
   - Estimated duration in minutes
   - Risk level (low/medium/high/critical)
   - OS compatibility
7. Cleanup Steps: How to clean up after the attack

Make the playbook realistic and executable based on the infrastructure provided.
Focus on common attack patterns that would be effective against this environment.

Return ONLY a JSON object with this structure:
{{
    "name": "Playbook Name",
    "description": "Description",
    "category": "category_value",
    "risk_assessment": "Risk assessment text",
    "prerequisites": ["prerequisite1", "prerequisite2"],
    "estimated_duration": 120,
    "steps": [
        {{
            "name": "Step Name",
            "description": "Step description",
            "mitre_technique": "T1078",
            "target_systems": ["hostname1", "hostname2"],
            "commands": ["command1", "command2"],
            "expected_results": "What should happen",
            "prerequisites": ["prereq1"],
            "estimated_duration": 30,
            "risk_level": "medium",
            "os_compatibility": ["windows", "linux"]
        }}
    ],
    "cleanup_steps": ["cleanup1", "cleanup2"]
}}
"""
        
        try:
            response = self.llm.invoke(prompt)
            playbook_data = json.loads(response.content.strip())
            return playbook_data
        except Exception as e:
            print(f"Failed to generate playbook with LLM: {e}")
            return None
    
    def _create_playbook_from_data(self, playbook_id: str, data: Dict) -> AttackPlaybook:
        """Create AttackPlaybook object from LLM-generated data"""
        steps = []
        for i, step_data in enumerate(data.get('steps', [])):
            step = AttackStep(
                step_id=f"{playbook_id}_step_{i+1}",
                name=step_data['name'],
                description=step_data['description'],
                mitre_technique=step_data['mitre_technique'],
                target_systems=step_data['target_systems'],
                commands=step_data['commands'],
                expected_results=step_data['expected_results'],
                prerequisites=step_data.get('prerequisites', []),
                estimated_duration=step_data.get('estimated_duration', 15),
                risk_level=step_data.get('risk_level', 'medium'),
                os_compatibility=step_data.get('os_compatibility', ['windows', 'linux'])
            )
            steps.append(step)
        
        playbook = AttackPlaybook(
            playbook_id=playbook_id,
            name=data['name'],
            description=data['description'],
            category=AttackCategory(data['category']),
            target_environment={},
            steps=steps,
            estimated_duration=data.get('estimated_duration', 60),
            risk_assessment=data.get('risk_assessment', ''),
            prerequisites=data.get('prerequisites', []),
            cleanup_steps=data.get('cleanup_steps', []),
            status=PlaybookStatus.DRAFT,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            created_by="attack_agent",
            execution_log=[]
        )
        
        return playbook
    
    def create_custom_playbook(self, name: str, description: str, category: AttackCategory, steps: List[AttackStep]) -> str:
        """Create a custom playbook manually"""
        playbook_id = str(uuid.uuid4())
        
        playbook = AttackPlaybook(
            playbook_id=playbook_id,
            name=name,
            description=description,
            category=category,
            target_environment={},
            steps=steps,
            estimated_duration=sum(step.estimated_duration for step in steps),
            risk_assessment="Custom playbook - review required",
            prerequisites=[],
            cleanup_steps=[],
            status=PlaybookStatus.DRAFT,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            created_by="user",
            execution_log=[]
        )
        
        self.playbooks[playbook_id] = playbook
        self._save_playbooks()
        
        return playbook_id
    
    def approve_playbook(self, playbook_id: str, approved_by: str) -> bool:
        """Approve a playbook for execution"""
        if playbook_id not in self.playbooks:
            return False
        
        playbook = self.playbooks[playbook_id]
        playbook.status = PlaybookStatus.APPROVED
        playbook.approved_by = approved_by
        
        self._save_playbooks()
        return True
    
    def get_playbook(self, playbook_id: str) -> Optional[AttackPlaybook]:
        """Get a specific playbook"""
        return self.playbooks.get(playbook_id)
    
    def list_playbooks(self, status_filter: Optional[PlaybookStatus] = None) -> List[AttackPlaybook]:
        """List all playbooks, optionally filtered by status"""
        playbooks = list(self.playbooks.values())
        
        if status_filter:
            playbooks = [pb for pb in playbooks if pb.status == status_filter]
        
        return playbooks
    
    def display_playbook_summary(self, playbook_id: str):
        """Display a summary of the playbook"""
        playbook = self.get_playbook(playbook_id)
        if not playbook:
            print(f"❌ Playbook {playbook_id} not found")
            return
        
        print(f"\n📋 Attack Playbook: {playbook.name}")
        print(f"   ID: {playbook_id}")
        print(f"   Category: {playbook.category.value}")
        print(f"   Status: {playbook.status.value}")
        print(f"   Estimated Duration: {playbook.estimated_duration} minutes")
        print(f"   Risk Assessment: {playbook.risk_assessment}")
        print(f"   Created: {playbook.created_at}")
        
        if playbook.approved_by:
            print(f"   Approved by: {playbook.approved_by}")
        
        print(f"\n📝 Description:")
        print(f"   {playbook.description}")
        
        print(f"\n⚙️ Prerequisites:")
        for prereq in playbook.prerequisites:
            print(f"   • {prereq}")
        
        print(f"\n🎯 Attack Steps ({len(playbook.steps)}):")
        for i, step in enumerate(playbook.steps, 1):
            print(f"   {i}. {step.name} ({step.mitre_technique})")
            print(f"      Risk: {step.risk_level} | Duration: {step.estimated_duration}min")
            print(f"      Targets: {', '.join(step.target_systems)}")
        
        print(f"\n🧹 Cleanup Steps:")
        for cleanup in playbook.cleanup_steps:
            print(f"   • {cleanup}")
    
    def delete_playbook(self, playbook_id: str) -> bool:
        """Delete a playbook"""
        if playbook_id in self.playbooks:
            del self.playbooks[playbook_id]
            self._save_playbooks()
            return True
        return False
    
    def search_playbooks(self, query: str) -> List[AttackPlaybook]:
        """Search playbooks by name, description, or MITRE technique"""
        results = []
        query_lower = query.lower()
        
        for playbook in self.playbooks.values():
            if (query_lower in playbook.name.lower() or 
                query_lower in playbook.description.lower() or
                any(query_lower in step.mitre_technique.lower() for step in playbook.steps)):
                results.append(playbook)
        
        return results
    
    def get_mitre_techniques_used(self, playbook_id: str) -> List[str]:
        """Get all MITRE techniques used in a playbook"""
        playbook = self.get_playbook(playbook_id)
        if not playbook:
            return []
        
        return list(set(step.mitre_technique for step in playbook.steps))
    
    def validate_playbook(self, playbook_id: str) -> Dict[str, List[str]]:
        """Validate a playbook for common issues"""
        playbook = self.get_playbook(playbook_id)
        if not playbook:
            return {"errors": ["Playbook not found"]}
        
        issues = {
            "errors": [],
            "warnings": [],
            "info": []
        }
        
        # Check for missing information
        if not playbook.steps:
            issues["errors"].append("No attack steps defined")
        
        if not playbook.cleanup_steps:
            issues["warnings"].append("No cleanup steps defined")
        
        if not playbook.prerequisites:
            issues["warnings"].append("No prerequisites defined")
        
        # Check step validation
        for i, step in enumerate(playbook.steps, 1):
            if not step.commands:
                issues["errors"].append(f"Step {i} has no commands")
            
            if not step.target_systems:
                issues["warnings"].append(f"Step {i} has no target systems")
            
            if step.risk_level == "critical":
                issues["warnings"].append(f"Step {i} has critical risk level")
        
        return issues

# Factory function
def create_playbook_engine() -> PlaybookEngine:
    """Create playbook engine with default configuration"""
    playbooks_dir = os.getenv('PLAYBOOKS_DIR', './playbooks')
    return PlaybookEngine(playbooks_dir)