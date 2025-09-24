import json
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from .comprehensive_mitre_data import COMPREHENSIVE_MITRE_TECHNIQUES

class TacticType(Enum):
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"

@dataclass
class MITRETechnique:
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    data_sources: List[str]
    detection_methods: List[str]
    mitigation_id: Optional[str] = None
    sub_techniques: List[str] = None

@dataclass
class MITREDetection:
    technique_id: str
    confidence_score: float
    evidence: List[str]
    log_sources: List[str]
    timestamp: str
    severity: str  # low, medium, high, critical
    related_indicators: List[str] = None

class MITREAttackEngine:
    """Engine for MITRE ATT&CK technique detection and analysis"""
    
    def __init__(self, mitre_db_path: str = None):
        self.mitre_db_path = mitre_db_path or "Starting works/Prod/mitre_attack.json"
        self.techniques = {}
        self.tactics_map = {}
        self._load_mitre_database()
    
    def _load_mitre_database(self):
        """Load MITRE ATT&CK database"""
        try:
            # Try to load the large JSON file
            if os.path.exists(self.mitre_db_path):
                print(f" Loading MITRE ATT&CK database from {self.mitre_db_path}...")
                # For large files, we'll load incrementally
                self._load_mitre_data_incremental()
            else:
                print(" MITRE database not found, using fallback data")
                self._load_fallback_mitre_data()
        except Exception as e:
            print(f" Failed to load MITRE database: {e}")
            self._load_fallback_mitre_data()
    
    def _load_mitre_data_incremental(self):
        """Load comprehensive MITRE ATT&CK database with 200+ techniques"""
        try:
            # Load comprehensive MITRE ATT&CK techniques from external module
            comprehensive_techniques = COMPREHENSIVE_MITRE_TECHNIQUES
            
            for tech_id, tech_data in comprehensive_techniques.items():
                technique = MITRETechnique(
                    technique_id=tech_id,
                    name=tech_data["name"],
                    description=tech_data["description"],
                    tactics=tech_data["tactics"],
                    platforms=tech_data["platforms"],
                    data_sources=tech_data["data_sources"],
                    detection_methods=tech_data["detection_methods"]
                )
                self.techniques[tech_id] = technique
                
                # Build tactics mapping
                for tactic in tech_data["tactics"]:
                    if tactic not in self.tactics_map:
                        self.tactics_map[tactic] = []
                    self.tactics_map[tactic].append(tech_id)
            
            print(f" Loaded {len(self.techniques)} MITRE techniques")
            
        except Exception as e:
            print(f" Failed to load MITRE data: {e}")
            self._load_fallback_mitre_data()
    
    def _load_fallback_mitre_data(self):
        """Load minimal fallback MITRE data"""
        fallback_techniques = {
            "T1059.001": "PowerShell",
            "T1059.003": "Windows Command Shell", 
            "T1071.004": "DNS",
            "T1018": "Remote System Discovery"
        }
        
        for tech_id, name in fallback_techniques.items():
            technique = MITRETechnique(
                technique_id=tech_id,
                name=name,
                description=f"Detection for {name}",
                tactics=["execution"],
                platforms=["Windows"],
                data_sources=["Process", "Network"],
                detection_methods=["Behavioral analysis"]
            )
            self.techniques[tech_id] = technique
    
    def detect_technique_in_logs(self, log_data: Dict, log_type: str) -> List[MITREDetection]:
        """Detect MITRE techniques in log data"""
        detections = []
        
        try:
            if log_type.lower() == "powershell":
                detections.extend(self._detect_powershell_techniques(log_data))
            elif log_type.lower() == "dns":
                detections.extend(self._detect_dns_techniques(log_data))
            elif log_type.lower() == "network":
                detections.extend(self._detect_network_techniques(log_data))
            elif log_type.lower() == "process":
                detections.extend(self._detect_process_techniques(log_data))
                
        except Exception as e:
            print(f" Error detecting techniques: {e}")
        
        return detections
    
    def _detect_powershell_techniques(self, log_data: Dict) -> List[MITREDetection]:
        """Detect PowerShell-based MITRE techniques"""
        detections = []
        
        command = log_data.get('ExecutedCommand', '').lower()
        if not command:
            return detections
        
        # T1059.001 - PowerShell
        if any(indicator in command for indicator in ['invoke-', 'downloadstring', 'iex', 'bypass', 'hidden']):
            detection = MITREDetection(
                technique_id="T1059.001",
                confidence_score=0.8,
                evidence=[f"Suspicious PowerShell command: {command[:100]}"],
                log_sources=["PowerShell"],
                timestamp=log_data.get('TimeGenerated', ''),
                severity="high",
                related_indicators=[command]
            )
            detections.append(detection)
        
        # T1105 - Ingress Tool Transfer
        if any(indicator in command for indicator in ['downloadfile', 'wget', 'curl', 'bitsadmin']):
            detection = MITREDetection(
                technique_id="T1105",
                confidence_score=0.9,
                evidence=[f"File download detected: {command[:100]}"],
                log_sources=["PowerShell"],
                timestamp=log_data.get('TimeGenerated', ''),
                severity="critical",
                related_indicators=[command]
            )
            detections.append(detection)
        
        # T1082 - System Information Discovery
        if any(indicator in command for indicator in ['get-computerinfo', 'systeminfo', 'get-wmiobject', 'whoami']):
            detection = MITREDetection(
                technique_id="T1082",
                confidence_score=0.7,
                evidence=[f"System discovery command: {command[:100]}"],
                log_sources=["PowerShell"],
                timestamp=log_data.get('TimeGenerated', ''),
                severity="medium",
                related_indicators=[command]
            )
            detections.append(detection)
        
        return detections
    
    def _detect_dns_techniques(self, log_data: Dict) -> List[MITREDetection]:
        """Detect DNS-based MITRE techniques"""
        detections = []
        
        query_name = log_data.get('QueryName', '').lower()
        if not query_name:
            return detections
        
        # T1071.004 - DNS Application Layer Protocol
        suspicious_indicators = [
            len(query_name) > 50,  # Long domain names
            query_name.count('.') > 5,  # Many subdomains
            any(char in query_name for char in '0123456789abcdef' * 3),  # Hex-like patterns
            any(keyword in query_name for keyword in ['dga', 'malware', 'c2', 'backdoor'])
        ]
        
        if any(suspicious_indicators):
            confidence = 0.6 + (sum(suspicious_indicators) * 0.1)
            detection = MITREDetection(
                technique_id="T1071.004",
                confidence_score=min(confidence, 1.0),
                evidence=[f"Suspicious DNS query: {query_name}"],
                log_sources=["DNS"],
                timestamp=log_data.get('TimeGenerated', ''),
                severity="high" if confidence > 0.8 else "medium",
                related_indicators=[query_name]
            )
            detections.append(detection)
        
        # T1568 - Dynamic Resolution
        if any(dga_indicator in query_name for dga_indicator in ['random', 'generated', 'algo']):
            detection = MITREDetection(
                technique_id="T1568",
                confidence_score=0.85,
                evidence=[f"Possible DGA domain: {query_name}"],
                log_sources=["DNS"],
                timestamp=log_data.get('TimeGenerated', ''),
                severity="high",
                related_indicators=[query_name]
            )
            detections.append(detection)
        
        return detections
    
    def _detect_network_techniques(self, log_data: Dict) -> List[MITREDetection]:
        """Detect network-based MITRE techniques"""
        detections = []
        # Implementation for network log analysis
        return detections
    
    def _detect_process_techniques(self, log_data: Dict) -> List[MITREDetection]:
        """Detect process-based MITRE techniques"""
        detections = []
        # Implementation for process log analysis
        return detections
    
    def get_technique_info(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get detailed information about a MITRE technique"""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[str]:
        """Get all techniques for a specific tactic"""
        return self.tactics_map.get(tactic, [])
    
    def analyze_attack_pattern(self, detections: List[MITREDetection]) -> Dict:
        """Analyze patterns in detected techniques"""
        if not detections:
            return {"pattern": "none", "severity": "low", "techniques_count": 0}
        
        # Group by tactics
        tactics_detected = {}
        for detection in detections:
            technique = self.get_technique_info(detection.technique_id)
            if technique:
                for tactic in technique.tactics:
                    if tactic not in tactics_detected:
                        tactics_detected[tactic] = []
                    tactics_detected[tactic].append(detection.technique_id)
        
        # Determine attack pattern
        pattern = "isolated"
        if len(tactics_detected) > 3:
            pattern = "multi_stage_attack"
        elif len(tactics_detected) > 1:
            pattern = "coordinated_attack"
        
        # Calculate overall severity
        severities = [d.severity for d in detections]
        if "critical" in severities:
            overall_severity = "critical"
        elif "high" in severities:
            overall_severity = "high"
        elif "medium" in severities:
            overall_severity = "medium"
        else:
            overall_severity = "low"
        
        return {
            "pattern": pattern,
            "severity": overall_severity,
            "techniques_count": len(set(d.technique_id for d in detections)),
            "tactics_involved": list(tactics_detected.keys()),
            "confidence_avg": sum(d.confidence_score for d in detections) / len(detections)
        }
    
    def get_attack_chain_recommendations(self, detections: List[MITREDetection]) -> List[str]:
        """Get recommendations based on detected attack chain"""
        recommendations = []
        
        technique_ids = [d.technique_id for d in detections]
        
        # Common attack chain patterns
        if "T1566" in technique_ids:  # Phishing
            recommendations.append("Implement email security controls and user training")
        
        if "T1059.001" in technique_ids:  # PowerShell
            recommendations.append("Enable PowerShell logging and restrict execution policies")
        
        if "T1105" in technique_ids:  # File transfer
            recommendations.append("Monitor and restrict file download activities")
        
        if "T1071.004" in technique_ids:  # DNS C2
            recommendations.append("Implement DNS monitoring and filtering")
        
        # Multi-stage attack recommendations
        if len(set(technique_ids)) > 3:
            recommendations.append("Coordinate incident response across multiple attack vectors")
            recommendations.append("Implement network segmentation to limit lateral movement")
        
        return recommendations

# Factory function
def create_mitre_attack_engine() -> MITREAttackEngine:
    """Create MITRE ATT&CK engine"""
    return MITREAttackEngine()
 