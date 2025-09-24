#!/usr/bin/env python3
"""
Dynamic Attack Generator - No Hardcoded Commands
Generates MITRE ATT&CK techniques dynamically from real threat intelligence
"""

import json
import sqlite3
import requests
import yaml
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DynamicAttackCommand:
    """Dynamic attack command structure"""
    technique_id: str
    technique_name: str
    tactic: str
    platform: List[str]
    command: str
    command_type: str  # powershell, bash, cmd, python
    risk_level: str
    source: str  # mitre_cti, threat_intel, live_analysis
    confidence: float
    validation_status: str

class DynamicAttackGenerator:
    """Generates attack commands dynamically from real sources"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent.parent.parent.parent
        self.mitre_db_path = self.base_path / "processed_data" / "comprehensive_cybersec_data.db"
        self.techniques_cache = {}
        self.threat_intel_sources = self._initialize_threat_intel_sources()
        self.config = self._load_config()
        
    def _load_config(self):
        """Load system configuration"""
        try:
            config_path = self.base_path / "config" / "config.yaml"
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
        
        return {
            'llm': {
                'ollama_endpoint': 'http://localhost:11434',
                'ollama_model': 'cybersec-ai',
                'fallback_order': ['ollama', 'openai']
            }
        }
        
    def _initialize_threat_intel_sources(self) -> Dict[str, str]:
        """Initialize real threat intelligence sources"""
        return {
            "mitre_cti": "https://raw.githubusercontent.com/mitre/cti/master/",
            "atomic_red_team": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/",
            "sigma_rules": "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/",
            "car_analytics": "https://raw.githubusercontent.com/mitre-attack/car/master/analytics/"
        }
    
    async def generate_technique_commands(self, technique_id: str, target_platform: str = "any") -> List[DynamicAttackCommand]:
        """Generate commands for a MITRE technique from multiple sources"""
        logger.info(f"Generating dynamic commands for {technique_id}")
        
        commands = []
        
        # Source 1: MITRE CTI Database
        cti_commands = await self._get_mitre_cti_commands(technique_id, target_platform)
        commands.extend(cti_commands)
        
        # Source 2: Atomic Red Team
        atomic_commands = await self._get_atomic_red_team_commands(technique_id, target_platform)
        commands.extend(atomic_commands)
        
        # Source 3: Real Attack Logs Analysis
        log_commands = await self._analyze_attack_logs_for_technique(technique_id, target_platform)
        commands.extend(log_commands)
        
        # Source 4: Threat Intelligence Feeds
        intel_commands = await self._get_threat_intel_commands(technique_id, target_platform)
        commands.extend(intel_commands)
        
        # Validate and rank commands
        validated_commands = self._validate_and_rank_commands(commands)
        
        logger.info(f"Generated {len(validated_commands)} dynamic commands for {technique_id}")
        return validated_commands
    
    async def _get_mitre_cti_commands(self, technique_id: str, platform: str) -> List[DynamicAttackCommand]:
        """Extract commands from MITRE CTI data"""
        commands = []
        
        try:
            # Load technique from local database
            if self.mitre_db_path.exists():
                with sqlite3.connect(self.mitre_db_path) as conn:
                    cursor = conn.execute("""
                        SELECT name, description, tactic, platform, data_sources 
                        FROM mitre_techniques 
                        WHERE id = ?
                    """, (technique_id,))
                    
                    result = cursor.fetchone()
                    if result:
                        technique_name, description, tactic, tech_platform, data_sources = result
                        
                        # Parse description for executable commands
                        extracted_commands = self._extract_commands_from_description(
                            description, technique_id, technique_name, tactic, platform
                        )
                        commands.extend(extracted_commands)
            
            # Fetch from MITRE CTI GitHub if available
            cti_commands = await self._fetch_mitre_cti_technique(technique_id, platform)
            commands.extend(cti_commands)
            
        except Exception as e:
            logger.warning(f"MITRE CTI extraction failed for {technique_id}: {e}")
        
        return commands
    
    async def _get_atomic_red_team_commands(self, technique_id: str, platform: str) -> List[DynamicAttackCommand]:
        """Get commands from Atomic Red Team"""
        commands = []
        
        try:
            # Atomic Red Team URL structure
            atomic_url = f"{self.threat_intel_sources['atomic_red_team']}{technique_id}/{technique_id}.yaml"
            
            response = requests.get(atomic_url, timeout=10)
            if response.status_code == 200:
                atomic_data = yaml.safe_load(response.text)
                
                if 'atomic_tests' in atomic_data:
                    for test in atomic_data['atomic_tests']:
                        if self._platform_matches(test.get('supported_platforms', []), platform):
                            # Extract command from test
                            command_data = self._extract_atomic_command(test, technique_id, atomic_data)
                            if command_data:
                                commands.append(command_data)
            
        except Exception as e:
            logger.warning(f"Atomic Red Team extraction failed for {technique_id}: {e}")
        
        return commands
    
    async def _analyze_attack_logs_for_technique(self, technique_id: str, platform: str) -> List[DynamicAttackCommand]:
        """Analyze real attack logs to extract commands"""
        commands = []
        
        try:
            if self.mitre_db_path.exists():
                with sqlite3.connect(self.mitre_db_path) as conn:
                    cursor = conn.execute("""
                        SELECT log_content, log_type 
                        FROM attack_logs 
                        WHERE technique_id = ? 
                        ORDER BY RANDOM() 
                        LIMIT 10
                    """, (technique_id,))
                    
                    logs = cursor.fetchall()
                    
                    for log_content, log_type in logs:
                        # Extract executable commands from real attack logs
                        extracted = self._extract_commands_from_logs(
                            log_content, technique_id, log_type, platform
                        )
                        commands.extend(extracted)
        
        except Exception as e:
            logger.warning(f"Attack log analysis failed for {technique_id}: {e}")
        
        return commands
    
    async def _get_threat_intel_commands(self, technique_id: str, platform: str) -> List[DynamicAttackCommand]:
        """Get commands from threat intelligence feeds"""
        commands = []
        
        try:
            # Use AI to generate contextual commands based on threat intel
            intel_commands = await self._ai_generate_contextual_commands(technique_id, platform)
            commands.extend(intel_commands)
            
        except Exception as e:
            logger.warning(f"Threat intel command generation failed for {technique_id}: {e}")
        
        return commands
    
    def _extract_commands_from_description(self, description: str, technique_id: str, 
                                         technique_name: str, tactic: str, platform: str) -> List[DynamicAttackCommand]:
        """Extract executable commands from MITRE technique descriptions"""
        commands = []
        
        # Common command patterns in MITRE descriptions
        command_patterns = {
            'powershell': [
                r'powershell.*?(?=\s|$|\.)',
                r'Get-\w+.*?(?=\s|$|\.)',
                r'Invoke-\w+.*?(?=\s|$|\.)',
                r'Start-Process.*?(?=\s|$|\.)',
            ],
            'cmd': [
                r'cmd.*?(?=\s|$|\.)',
                r'net\s+\w+.*?(?=\s|$|\.)',
                r'reg\s+\w+.*?(?=\s|$|\.)',
                r'wmic.*?(?=\s|$|\.)',
            ],
            'bash': [
                r'bash.*?(?=\s|$|\.)',
                r'curl.*?(?=\s|$|\.)',
                r'wget.*?(?=\s|$|\.)',
                r'ssh.*?(?=\s|$|\.)',
            ]
        }
        
        import re
        
        for cmd_type, patterns in command_patterns.items():
            if self._command_type_matches_platform(cmd_type, platform):
                for pattern in patterns:
                    matches = re.findall(pattern, description, re.IGNORECASE)
                    for match in matches:
                        command = DynamicAttackCommand(
                            technique_id=technique_id,
                            technique_name=technique_name,
                            tactic=tactic,
                            platform=[platform] if platform != "any" else ["windows", "linux", "macos"],
                            command=match.strip(),
                            command_type=cmd_type,
                            risk_level="medium",
                            source="mitre_description",
                            confidence=0.7,
                            validation_status="extracted"
                        )
                        commands.append(command)
        
        return commands
    
    def _extract_atomic_command(self, test: Dict, technique_id: str, atomic_data: Dict) -> Optional[DynamicAttackCommand]:
        """Extract command from Atomic Red Team test"""
        try:
            # Get the main command
            executor = test.get('executor', {})
            command = executor.get('command', '')
            
            if not command:
                return None
            
            # Determine command type
            command_type = executor.get('name', 'unknown')
            if command_type == 'powershell':
                command_type = 'powershell'
            elif command_type in ['bash', 'sh']:
                command_type = 'bash'
            elif command_type == 'command_prompt':
                command_type = 'cmd'
            
            # Get technique info
            technique_name = atomic_data.get('display_name', technique_id)
            
            return DynamicAttackCommand(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=atomic_data.get('attack_technique', 'unknown'),
                platform=test.get('supported_platforms', []),
                command=command,
                command_type=command_type,
                risk_level=self._assess_command_risk(command),
                source="atomic_red_team",
                confidence=0.9,
                validation_status="atomic_verified"
            )
            
        except Exception as e:
            logger.warning(f"Failed to extract atomic command: {e}")
            return None
    
    def _extract_commands_from_logs(self, log_content: str, technique_id: str, 
                                  log_type: str, platform: str) -> List[DynamicAttackCommand]:
        """Extract commands from real attack logs"""
        commands = []
        
        try:
            # Parse different log formats
            if log_type == 'powershell':
                ps_commands = self._extract_powershell_from_logs(log_content)
                for cmd in ps_commands:
                    command = DynamicAttackCommand(
                        technique_id=technique_id,
                        technique_name=f"Technique {technique_id}",
                        tactic="unknown",
                        platform=["windows"],
                        command=cmd,
                        command_type="powershell",
                        risk_level=self._assess_command_risk(cmd),
                        source="real_attack_logs",
                        confidence=0.8,
                        validation_status="log_extracted"
                    )
                    commands.append(command)
            
            elif log_type == 'bash':
                bash_commands = self._extract_bash_from_logs(log_content)
                for cmd in bash_commands:
                    command = DynamicAttackCommand(
                        technique_id=technique_id,
                        technique_name=f"Technique {technique_id}",
                        tactic="unknown",
                        platform=["linux", "macos"],
                        command=cmd,
                        command_type="bash",
                        risk_level=self._assess_command_risk(cmd),
                        source="real_attack_logs",
                        confidence=0.8,
                        validation_status="log_extracted"
                    )
                    commands.append(command)
        
        except Exception as e:
            logger.warning(f"Log command extraction failed: {e}")
        
        return commands
    
    def _extract_powershell_from_logs(self, log_content: str) -> List[str]:
        """Extract PowerShell commands from log content"""
        import re
        
        # PowerShell command patterns
        ps_patterns = [
            r'powershell.*?(?:\n|$)',
            r'Get-\w+[^\n]*',
            r'Invoke-\w+[^\n]*',
            r'Start-Process[^\n]*',
            r'New-Object[^\n]*',
            r'\$\w+\s*=[^\n]*'
        ]
        
        commands = []
        for pattern in ps_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE | re.MULTILINE)
            commands.extend([match.strip() for match in matches if len(match.strip()) > 10])
        
        return list(set(commands))  # Remove duplicates
    
    def _extract_bash_from_logs(self, log_content: str) -> List[str]:
        """Extract Bash commands from log content"""
        import re
        
        # Bash command patterns
        bash_patterns = [
            r'curl[^\n]*',
            r'wget[^\n]*',
            r'ssh[^\n]*',
            r'nc[^\n]*',
            r'netcat[^\n]*',
            r'echo[^\n]*',
            r'cat[^\n]*',
            r'/bin/bash[^\n]*'
        ]
        
        commands = []
        for pattern in bash_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE | re.MULTILINE)
            commands.extend([match.strip() for match in matches if len(match.strip()) > 5])
        
        return list(set(commands))  # Remove duplicates
    
    async def _ai_generate_contextual_commands(self, technique_id: str, platform: str) -> List[DynamicAttackCommand]:
        """Use AI to generate contextual commands based on threat intelligence"""
        commands = []
        
        try:
            from langchain_openai import ChatOpenAI
            from langraph.config import OPENAI_API_KEY
            
            llm = ChatOpenAI(api_key=OPENAI_API_KEY, model="gpt-4o")
            
            prompt = f"""
You are a cybersecurity expert specializing in MITRE ATT&CK techniques.

Generate 3-5 realistic, executable commands for MITRE technique {technique_id} on {platform} platform.

Requirements:
1. Commands must be practical and realistic (used by real attackers)
2. Include various complexity levels (basic to advanced)
3. Use only legitimate tools and techniques
4. Provide commands that would actually execute the technique
5. Consider different variations and approaches

For each command, provide:
- The exact command to execute
- Brief description of what it does
- Risk level (low/medium/high)
- Platform compatibility

Format as JSON array with objects containing: command, description, risk_level, platforms
"""
            
            response = llm.invoke(prompt)
            
            try:
                ai_commands = json.loads(response.content)
                
                for cmd_data in ai_commands:
                    command = DynamicAttackCommand(
                        technique_id=technique_id,
                        technique_name=f"Technique {technique_id}",
                        tactic="unknown",
                        platform=cmd_data.get('platforms', [platform]),
                        command=cmd_data.get('command', ''),
                        command_type=self._detect_command_type(cmd_data.get('command', '')),
                        risk_level=cmd_data.get('risk_level', 'medium'),
                        source="ai_generated",
                        confidence=0.75,
                        validation_status="ai_generated"
                    )
                    commands.append(command)
                    
            except json.JSONDecodeError:
                logger.warning("AI response was not valid JSON")
                
        except Exception as e:
            logger.warning(f"AI command generation failed: {e}")
        
        return commands
    
    def _validate_and_rank_commands(self, commands: List[DynamicAttackCommand]) -> List[DynamicAttackCommand]:
        """Validate and rank commands by quality and safety"""
        validated = []
        
        for command in commands:
            # Safety validation
            if self._is_command_safe(command.command):
                # Quality scoring
                quality_score = self._calculate_quality_score(command)
                command.confidence = quality_score
                
                # Only include high-quality commands
                if quality_score >= 0.6:
                    validated.append(command)
        
        # Sort by confidence (highest first)
        validated.sort(key=lambda x: x.confidence, reverse=True)
        
        # Limit to top 10 commands
        return validated[:10]
    
    def _is_command_safe(self, command: str) -> bool:
        """Check if command is safe for execution"""
        # Dangerous commands to avoid
        dangerous_patterns = [
            r'rm\s+-rf\s+/',
            r'del\s+/f\s+/q\s+C:\\',
            r'format\s+c:',
            r'shutdown\s+/s',
            r'reboot',
            r'halt',
            r'init\s+0',
            r'dd\s+if=.*of=/dev/',
            r'mkfs\.',
            r'fdisk'
        ]
        
        import re
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False
        
        return True
    
    def _calculate_quality_score(self, command: DynamicAttackCommand) -> float:
        """Calculate quality score for command"""
        score = 0.0
        
        # Source reliability
        source_scores = {
            "atomic_red_team": 0.9,
            "mitre_cti": 0.85,
            "real_attack_logs": 0.8,
            "mitre_description": 0.7,
            "ai_generated": 0.6
        }
        score += source_scores.get(command.source, 0.5)
        
        # Command complexity (realistic commands are usually not too simple or complex)
        cmd_length = len(command.command)
        if 20 <= cmd_length <= 200:
            score += 0.1
        
        # Platform specificity
        if len(command.platform) <= 2:  # More specific is better
            score += 0.05
        
        # Normalize to 0-1 range
        return min(score, 1.0)
    
    def _assess_command_risk(self, command: str) -> str:
        """Assess risk level of command"""
        high_risk_patterns = [
            'delete', 'remove', 'kill', 'terminate', 'destroy',
            'format', 'wipe', 'erase', 'shutdown', 'reboot'
        ]
        
        medium_risk_patterns = [
            'download', 'upload', 'connect', 'execute', 'run',
            'invoke', 'start', 'create', 'modify'
        ]
        
        command_lower = command.lower()
        
        if any(pattern in command_lower for pattern in high_risk_patterns):
            return "high"
        elif any(pattern in command_lower for pattern in medium_risk_patterns):
            return "medium"
        else:
            return "low"
    
    def _detect_command_type(self, command: str) -> str:
        """Detect command type from command string"""
        command_lower = command.lower().strip()
        
        if any(indicator in command_lower for indicator in ['get-', 'invoke-', 'new-object', '$']):
            return "powershell"
        elif any(indicator in command_lower for indicator in ['curl', 'wget', 'ssh', 'bash', '#!/bin']):
            return "bash"
        elif any(indicator in command_lower for indicator in ['cmd', 'net ', 'reg ', 'wmic']):
            return "cmd"
        else:
            return "unknown"
    
    def _platform_matches(self, supported_platforms: List[str], target_platform: str) -> bool:
        """Check if platform matches"""
        if target_platform == "any":
            return True
        
        platform_map = {
            "windows": ["windows", "win"],
            "linux": ["linux", "ubuntu", "centos", "debian"],
            "macos": ["macos", "darwin", "osx"]
        }
        
        target_aliases = platform_map.get(target_platform.lower(), [target_platform.lower()])
        
        for platform in supported_platforms:
            if any(alias in platform.lower() for alias in target_aliases):
                return True
        
        return False
    
    def _command_type_matches_platform(self, command_type: str, platform: str) -> bool:
        """Check if command type is compatible with platform"""
        compatibility = {
            "powershell": ["windows", "any"],
            "cmd": ["windows", "any"],
            "bash": ["linux", "macos", "any"],
            "python": ["windows", "linux", "macos", "any"]
        }
        
        return platform in compatibility.get(command_type, [])
    
    async def _fetch_mitre_cti_technique(self, technique_id: str, platform: str) -> List[DynamicAttackCommand]:
        """Fetch technique details from MITRE CTI GitHub"""
        commands = []
        
        try:
            # MITRE CTI technique URL
            cti_url = f"{self.threat_intel_sources['mitre_cti']}enterprise-attack/attack-pattern/{technique_id}.json"
            
            response = requests.get(cti_url, timeout=10)
            if response.status_code == 200:
                cti_data = response.json()
                
                # Extract commands from CTI data
                # This would parse the STIX format and extract executable commands
                # Implementation depends on MITRE CTI structure
                pass
                
        except Exception as e:
            logger.warning(f"MITRE CTI fetch failed for {technique_id}: {e}")
        
        return commands

# Factory function
def create_dynamic_attack_generator() -> DynamicAttackGenerator:
    """Create dynamic attack generator"""
    return DynamicAttackGenerator()
