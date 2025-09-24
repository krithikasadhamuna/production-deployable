import json
import os
import yaml
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    status: str
    author: str
    references: List[str]
    tags: List[str]
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    falsepositives: List[str]
    level: str  # low, medium, high, critical
    mitre_attack: List[str] = None

@dataclass
class DetectionResult:
    rule_id: str
    rule_title: str
    matched_log: Dict[str, Any]
    confidence_score: float
    severity: str
    mitre_techniques: List[str]
    evidence: List[str]
    timestamp: str
    log_source: str

class SigmaDetectionEngine:
    """Advanced detection engine using Sigma rules for comprehensive threat detection"""
    
    def __init__(self, sigma_rules_path: str = "db/sigma"):
        self.sigma_rules_path = sigma_rules_path
        self.rules = {}
        self.rules_by_platform = {"windows": {}, "linux": {}, "macos": {}, "network": {}, "cloud": {}}
        self.rules_by_mitre = {}
        self._load_sigma_rules()
    
    def _load_sigma_rules(self):
        """Load Sigma rules from database"""
        try:
            print(" Loading Sigma detection rules...")
            
            # Load pre-converted JSON rules for faster processing
            self._load_json_rules()
            
            # If JSON not available, load from YAML
            if not self.rules:
                self._load_yaml_rules()
            
            print(f" Loaded {len(self.rules)} Sigma rules")
            self._organize_rules()
            
        except Exception as e:
            print(f" Failed to load Sigma rules: {e}")
            self._load_fallback_rules()
    
    def _load_json_rules(self):
        """Load pre-converted JSON rules"""
        json_files = [
            "db/sigma/powershell_rules.json",
            "db/sigma/dns_rules.json"
        ]
        
        for json_file in json_files:
            if os.path.exists(json_file):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        rules_data = json.load(f)
                        
                    for rule_data in rules_data:
                        rule = self._parse_rule_data(rule_data)
                        if rule:
                            self.rules[rule.rule_id] = rule
                            
                    print(f" Loaded {len(rules_data)} rules from {json_file}")
                    
                except Exception as e:
                    print(f" Error loading {json_file}: {e}")
    
    def _load_yaml_rules(self):
        """Load rules from YAML files"""
        rules_dir = os.path.join(self.sigma_rules_path, "rules")
        if not os.path.exists(rules_dir):
            print(f" Sigma rules directory not found: {rules_dir}")
            return
        
        yaml_files = list(Path(rules_dir).rglob("*.yml"))
        
        for yaml_file in yaml_files[:100]:  # Limit for performance
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    rule_data = yaml.safe_load(f)
                
                rule = self._parse_yaml_rule(rule_data, str(yaml_file))
                if rule:
                    self.rules[rule.rule_id] = rule
                    
            except Exception as e:
                print(f" Error loading {yaml_file}: {e}")
    
    def _parse_rule_data(self, rule_data: Dict) -> Optional[SigmaRule]:
        """Parse rule data from JSON format"""
        try:
            rule_id = rule_data.get('id', f"rule_{len(self.rules)}")
            
            # Extract MITRE ATT&CK tags
            mitre_techniques = []
            tags = rule_data.get('tags', [])
            for tag in tags:
                if tag.startswith('attack.t') or tag.startswith('attack.T'):
                    # Extract technique ID (e.g., 'attack.t1059.001' -> 'T1059.001')
                    technique = tag.replace('attack.', '').upper()
                    mitre_techniques.append(technique)
            
            rule = SigmaRule(
                rule_id=rule_id,
                title=rule_data.get('title', 'Unknown Rule'),
                description=rule_data.get('description', ''),
                status=rule_data.get('status', 'experimental'),
                author=rule_data.get('author', 'Unknown'),
                references=rule_data.get('references', []),
                tags=tags,
                logsource=rule_data.get('logsource', {}),
                detection=rule_data.get('detection', {}),
                falsepositives=rule_data.get('falsepositives', []),
                level=rule_data.get('level', 'medium'),
                mitre_attack=mitre_techniques
            )
            
            return rule
            
        except Exception as e:
            print(f" Error parsing rule data: {e}")
            return None
    
    def _parse_yaml_rule(self, rule_data: Dict, file_path: str) -> Optional[SigmaRule]:
        """Parse rule data from YAML format"""
        try:
            rule_id = rule_data.get('id', os.path.basename(file_path).replace('.yml', ''))
            
            # Extract MITRE ATT&CK tags
            mitre_techniques = []
            tags = rule_data.get('tags', [])
            for tag in tags:
                if tag.startswith('attack.t') or tag.startswith('attack.T'):
                    technique = tag.replace('attack.', '').upper()
                    mitre_techniques.append(technique)
            
            rule = SigmaRule(
                rule_id=rule_id,
                title=rule_data.get('title', 'Unknown Rule'),
                description=rule_data.get('description', ''),
                status=rule_data.get('status', 'experimental'),
                author=rule_data.get('author', 'Unknown'),
                references=rule_data.get('references', []),
                tags=tags,
                logsource=rule_data.get('logsource', {}),
                detection=rule_data.get('detection', {}),
                falsepositives=rule_data.get('falsepositives', []),
                level=rule_data.get('level', 'medium'),
                mitre_attack=mitre_techniques
            )
            
            return rule
            
        except Exception as e:
            print(f" Error parsing YAML rule: {e}")
            return None
    
    def _organize_rules(self):
        """Organize rules by platform and MITRE techniques"""
        for rule in self.rules.values():
            # Organize by platform
            logsource = rule.logsource
            if 'product' in logsource:
                product = logsource['product'].lower()
                if 'windows' in product:
                    self.rules_by_platform['windows'][rule.rule_id] = rule
                elif 'linux' in product:
                    self.rules_by_platform['linux'][rule.rule_id] = rule
                elif 'macos' in product:
                    self.rules_by_platform['macos'][rule.rule_id] = rule
            
            if 'category' in logsource:
                category = logsource['category'].lower()
                if 'network' in category or 'dns' in category:
                    self.rules_by_platform['network'][rule.rule_id] = rule
                elif 'cloud' in category:
                    self.rules_by_platform['cloud'][rule.rule_id] = rule
            
            # Organize by MITRE techniques
            for technique in rule.mitre_attack or []:
                if technique not in self.rules_by_mitre:
                    self.rules_by_mitre[technique] = []
                self.rules_by_mitre[technique].append(rule)
    
    def _load_fallback_rules(self):
        """Load minimal fallback rules for testing"""
        fallback_rules = [
            {
                "id": "powershell_suspicious_001",
                "title": "Suspicious PowerShell Command",
                "description": "Detects suspicious PowerShell commands",
                "level": "high",
                "tags": ["attack.t1059.001"],
                "logsource": {"product": "windows", "service": "powershell"},
                "detection": {
                    "keywords": ["invoke-", "downloadstring", "iex", "bypass", "-encoded"]
                }
            },
            {
                "id": "dns_tunneling_001", 
                "title": "DNS Tunneling Detection",
                "description": "Detects potential DNS tunneling",
                "level": "high",
                "tags": ["attack.t1071.004"],
                "logsource": {"product": "windows", "service": "dns"},
                "detection": {
                    "keywords": ["long_query", "base64", "suspicious_tld"]
                }
            }
        ]
        
        for rule_data in fallback_rules:
            rule = self._parse_rule_data(rule_data)
            if rule:
                self.rules[rule.rule_id] = rule
        
        print(f" Loaded {len(fallback_rules)} fallback rules")
    
    def detect_threats(self, log_data: Dict, log_type: str) -> List[DetectionResult]:
        """Main threat detection function"""
        detections = []
        
        try:
            # Get relevant rules for this log type
            relevant_rules = self._get_relevant_rules(log_type)
            
            for rule in relevant_rules:
                match_result = self._match_rule_against_log(rule, log_data)
                if match_result:
                    detection = DetectionResult(
                        rule_id=rule.rule_id,
                        rule_title=rule.title,
                        matched_log=log_data,
                        confidence_score=match_result['confidence'],
                        severity=rule.level,
                        mitre_techniques=rule.mitre_attack or [],
                        evidence=match_result['evidence'],
                        timestamp=datetime.now().isoformat(),
                        log_source=log_type
                    )
                    detections.append(detection)
            
        except Exception as e:
            print(f" Error in threat detection: {e}")
        
        return detections
    
    def _get_relevant_rules(self, log_type: str) -> List[SigmaRule]:
        """Get rules relevant to the log type"""
        relevant_rules = []
        
        # Map log types to platforms
        platform_mapping = {
            "powershell": "windows",
            "dns": "network", 
            "sysmon": "windows",
            "linux_audit": "linux",
            "macos_unified": "macos",
            "network": "network",
            "cloud": "cloud"
        }
        
        platform = platform_mapping.get(log_type.lower(), "windows")
        relevant_rules = list(self.rules_by_platform.get(platform, {}).values())
        
        # Also include general rules
        for rule in self.rules.values():
            if not rule.logsource.get('product') and not rule.logsource.get('service'):
                relevant_rules.append(rule)
        
        return relevant_rules
    
    def _match_rule_against_log(self, rule: SigmaRule, log_data: Dict) -> Optional[Dict]:
        """Match a Sigma rule against log data"""
        try:
            detection_config = rule.detection
            if not detection_config:
                return None
            
            evidence = []
            confidence = 0.0
            
            # Simple keyword matching (enhanced version would parse full Sigma syntax)
            if 'keywords' in detection_config:
                keywords = detection_config['keywords']
                log_content = str(log_data).lower()
                
                matched_keywords = []
                for keyword in keywords:
                    if keyword.lower() in log_content:
                        matched_keywords.append(keyword)
                        evidence.append(f"Keyword match: {keyword}")
                
                if matched_keywords:
                    confidence = len(matched_keywords) / len(keywords)
                    
                    # Boost confidence for exact field matches
                    if self._check_field_matches(detection_config, log_data):
                        confidence = min(confidence + 0.3, 1.0)
                        evidence.append("Field pattern match")
                    
                    return {
                        'confidence': confidence,
                        'evidence': evidence,
                        'matched_keywords': matched_keywords
                    }
            
            # Field-based detection
            elif self._check_field_matches(detection_config, log_data):
                return {
                    'confidence': 0.8,
                    'evidence': ["Field pattern match"],
                    'matched_keywords': []
                }
            
            return None
            
        except Exception as e:
            print(f" Error matching rule {rule.rule_id}: {e}")
            return None
    
    def _check_field_matches(self, detection_config: Dict, log_data: Dict) -> bool:
        """Check for field-specific matches"""
        try:
            # PowerShell specific checks
            if 'ExecutedCommand' in log_data:
                command = log_data['ExecutedCommand'].lower()
                
                # Check for suspicious PowerShell patterns
                suspicious_patterns = [
                    r'invoke-\w+',
                    r'downloadstring',
                    r'iex\s*\(',
                    r'-enc.*command',
                    r'bypass.*executionpolicy',
                    r'hidden.*windowstyle'
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, command, re.IGNORECASE):
                        return True
            
            # DNS specific checks
            if 'QueryName' in log_data:
                query_name = log_data['QueryName'].lower()
                
                # Check for suspicious DNS patterns
                suspicious_dns = [
                    len(query_name) > 50,  # Long domain
                    query_name.count('.') > 6,  # Many subdomains
                    re.search(r'[0-9a-f]{20,}', query_name),  # Hex patterns
                    any(tld in query_name for tld in ['.tk', '.ml', '.ga', '.cf'])  # Suspicious TLDs
                ]
                
                if any(suspicious_dns):
                    return True
            
            return False
            
        except Exception as e:
            print(f" Error in field matching: {e}")
            return False
    
    def get_rules_by_mitre_technique(self, technique_id: str) -> List[SigmaRule]:
        """Get all rules that detect a specific MITRE technique"""
        return self.rules_by_mitre.get(technique_id.upper(), [])
    
    def analyze_detection_coverage(self) -> Dict[str, Any]:
        """Analyze MITRE ATT&CK coverage of loaded rules"""
        coverage = {
            "total_rules": len(self.rules),
            "mitre_techniques_covered": len(self.rules_by_mitre),
            "techniques_coverage": {},
            "platform_coverage": {},
            "severity_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0}
        }
        
        # Analyze techniques coverage
        for technique, rules in self.rules_by_mitre.items():
            coverage["techniques_coverage"][technique] = len(rules)
        
        # Analyze platform coverage
        for platform, rules in self.rules_by_platform.items():
            coverage["platform_coverage"][platform] = len(rules)
        
        # Analyze severity distribution
        for rule in self.rules.values():
            level = rule.level.lower()
            if level in coverage["severity_distribution"]:
                coverage["severity_distribution"][level] += 1
        
        return coverage
    
    def generate_detection_report(self, detections: List[DetectionResult]) -> Dict[str, Any]:
        """Generate comprehensive detection report"""
        if not detections:
            return {"message": "No threats detected", "detections_count": 0}
        
        # Group by severity
        severity_groups = {"low": [], "medium": [], "high": [], "critical": []}
        for detection in detections:
            severity = detection.severity.lower()
            if severity in severity_groups:
                severity_groups[severity].append(detection)
        
        # Group by MITRE techniques
        technique_groups = {}
        for detection in detections:
            for technique in detection.mitre_techniques:
                if technique not in technique_groups:
                    technique_groups[technique] = []
                technique_groups[technique].append(detection)
        
        # Calculate statistics
        avg_confidence = sum(d.confidence_score for d in detections) / len(detections)
        
        report = {
            "summary": {
                "total_detections": len(detections),
                "average_confidence": round(avg_confidence, 2),
                "highest_severity": self._get_highest_severity(detections),
                "unique_techniques": len(technique_groups),
                "detection_timespan": self._calculate_timespan(detections)
            },
            "severity_breakdown": {
                severity: len(group) for severity, group in severity_groups.items()
            },
            "mitre_techniques": list(technique_groups.keys()),
            "technique_frequency": {
                technique: len(group) for technique, group in technique_groups.items()
            },
            "recommendations": self._generate_recommendations(detections)
        }
        
        return report
    
    def _get_highest_severity(self, detections: List[DetectionResult]) -> str:
        """Get the highest severity from detections"""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max(detections, key=lambda d: severity_order.get(d.severity.lower(), 0))
        return max_severity.severity
    
    def _calculate_timespan(self, detections: List[DetectionResult]) -> str:
        """Calculate timespan of detections"""
        try:
            timestamps = [d.timestamp for d in detections if d.timestamp]
            if len(timestamps) > 1:
                earliest = min(timestamps)
                latest = max(timestamps)
                return f"{earliest} to {latest}"
            elif timestamps:
                return timestamps[0]
            else:
                return "Unknown"
        except:
            return "Unknown"
    
    def _generate_recommendations(self, detections: List[DetectionResult]) -> List[str]:
        """Generate security recommendations based on detections"""
        recommendations = []
        
        techniques = []
        for detection in detections:
            techniques.extend(detection.mitre_techniques)
        
        unique_techniques = set(techniques)
        
        # Technique-specific recommendations
        if "T1059.001" in unique_techniques:
            recommendations.append("Implement PowerShell logging and constrained language mode")
        
        if "T1071.004" in unique_techniques:
            recommendations.append("Deploy DNS monitoring and filtering solutions")
        
        if "T1105" in unique_techniques:
            recommendations.append("Monitor and restrict file download activities")
        
        if len(unique_techniques) > 3:
            recommendations.append("Coordinate incident response across multiple attack vectors")
            recommendations.append("Review and strengthen detection coverage")
        
        # Severity-based recommendations
        critical_detections = [d for d in detections if d.severity.lower() == "critical"]
        if critical_detections:
            recommendations.append("Immediate incident response required for critical threats")
        
        return recommendations

# Factory function  
def create_sigma_detection_engine() -> SigmaDetectionEngine:
    """Create Sigma detection engine"""
    return SigmaDetectionEngine()
 