import json
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from langchain_openai import ChatOpenAI
from langraph.config import OPENAI_API_KEY

from .mitre_attack_engine import MITREDetection, create_mitre_attack_engine
from .sigma_detection_engine import DetectionResult, create_sigma_detection_engine

@dataclass
class ThreatIntelligence:
    threat_actor: Optional[str]
    campaign: Optional[str]
    malware_family: Optional[str]
    confidence_score: float
    attribution_evidence: List[str]
    geographical_indicators: List[str]
    temporal_patterns: List[str]

@dataclass
class AttackNarrative:
    attack_id: str
    timeline: List[Dict[str, Any]]
    attack_chain: List[str]
    entry_point: str
    objectives: List[str]
    impact_assessment: str
    confidence_score: float
    narrative_text: str

@dataclass
class AIReasoningResult:
    analysis_id: str
    timestamp: str
    threat_level: str  # low, medium, high, critical
    confidence_score: float
    
    # Combined detections
    mitre_detections: List[MITREDetection]
    sigma_detections: List[DetectionResult]
    
    # AI Analysis
    threat_intelligence: Optional[ThreatIntelligence]
    attack_narrative: Optional[AttackNarrative]
    behavioral_analysis: Dict[str, Any]
    
    # Response recommendations
    immediate_actions: List[str]
    investigation_steps: List[str]
    remediation_steps: List[str]
    prevention_measures: List[str]
    
    # Evidence and context
    evidence_summary: List[str]
    false_positive_likelihood: float
    related_incidents: List[str]

class AIReasoningEngine:
    """Advanced AI reasoning engine for comprehensive threat analysis"""
    
    def __init__(self):
        self.llm = ChatOpenAI(api_key=OPENAI_API_KEY, model="gpt-4o")
        self.mitre_engine = create_mitre_attack_engine()
        self.sigma_engine = create_sigma_detection_engine()
        
        # Load threat intelligence data
        self.threat_intel_db = self._load_threat_intelligence()
        
        # Analysis cache
        self.analysis_cache = {}
    
    def _load_threat_intelligence(self) -> Dict[str, Any]:
        """Load threat intelligence database"""
        try:
            # In a real implementation, this would load from threat intel feeds
            return {
                "apt_groups": {
                    "APT1": {"techniques": ["T1059.001", "T1071.004"], "geography": ["China"]},
                    "APT28": {"techniques": ["T1566", "T1055"], "geography": ["Russia"]},
                    "APT29": {"techniques": ["T1078", "T1105"], "geography": ["Russia"]},
                    "Lazarus": {"techniques": ["T1566", "T1059.001"], "geography": ["North Korea"]}
                },
                "malware_families": {
                    "PowerShell Empire": {"techniques": ["T1059.001", "T1105"], "indicators": ["invoke-", "empire"]},
                    "Cobalt Strike": {"techniques": ["T1055", "T1071"], "indicators": ["beacon", "cobalt"]},
                    "Mimikatz": {"techniques": ["T1003", "T1078"], "indicators": ["sekurlsa", "kerberos"]}
                },
                "iocs": {
                    "domains": ["evil.com", "malware.tk", "c2server.org"],
                    "ips": ["192.168.1.100", "10.0.0.50"],
                    "hashes": ["abc123", "def456"]
                }
            }
        except Exception as e:
            print(f" Failed to load threat intelligence: {e}")
            return {}
    
    def analyze_comprehensive_threat(self, log_data: List[Dict], log_types: List[str], 
                                   context: Dict = None) -> AIReasoningResult:
        """Perform comprehensive threat analysis combining multiple detection engines"""
        
        print(" Starting comprehensive AI threat analysis...")
        
        # Generate analysis ID
        analysis_id = f"analysis_{int(datetime.now().timestamp())}"
        
        # Initialize result containers
        all_mitre_detections = []
        all_sigma_detections = []
        
        # Process each log entry with both engines
        for i, (log_entry, log_type) in enumerate(zip(log_data, log_types)):
            print(f" Analyzing log {i+1}/{len(log_data)} ({log_type})")
            
            # MITRE ATT&CK detection
            mitre_detections = self.mitre_engine.detect_technique_in_logs(log_entry, log_type)
            all_mitre_detections.extend(mitre_detections)
            
            # Sigma rule detection
            sigma_detections = self.sigma_engine.detect_threats(log_entry, log_type)
            all_sigma_detections.extend(sigma_detections)
        
        print(f" Found {len(all_mitre_detections)} MITRE detections, {len(all_sigma_detections)} Sigma detections")
        
        # Perform AI-powered analysis
        threat_intelligence = self._analyze_threat_intelligence(all_mitre_detections, all_sigma_detections)
        attack_narrative = self._construct_attack_narrative(all_mitre_detections, all_sigma_detections, log_data)
        behavioral_analysis = self._perform_behavioral_analysis(log_data, all_mitre_detections)
        
        # Determine overall threat level
        threat_level, confidence_score = self._calculate_threat_level(
            all_mitre_detections, all_sigma_detections, threat_intelligence, behavioral_analysis
        )
        
        # Generate recommendations
        recommendations = self._generate_ai_recommendations(
            all_mitre_detections, all_sigma_detections, threat_intelligence, attack_narrative
        )
        
        # Create comprehensive result
        result = AIReasoningResult(
            analysis_id=analysis_id,
            timestamp=datetime.now().isoformat(),
            threat_level=threat_level,
            confidence_score=confidence_score,
            mitre_detections=all_mitre_detections,
            sigma_detections=all_sigma_detections,
            threat_intelligence=threat_intelligence,
            attack_narrative=attack_narrative,
            behavioral_analysis=behavioral_analysis,
            immediate_actions=recommendations["immediate"],
            investigation_steps=recommendations["investigation"],
            remediation_steps=recommendations["remediation"],
            prevention_measures=recommendations["prevention"],
            evidence_summary=self._summarize_evidence(all_mitre_detections, all_sigma_detections),
            false_positive_likelihood=self._calculate_false_positive_likelihood(all_sigma_detections),
            related_incidents=[]
        )
        
        # Cache the analysis
        self.analysis_cache[analysis_id] = result
        
        print(f" Comprehensive analysis complete - Threat Level: {threat_level}")
        return result
    
    def _analyze_threat_intelligence(self, mitre_detections: List[MITREDetection], 
                                   sigma_detections: List[DetectionResult]) -> Optional[ThreatIntelligence]:
        """Analyze threat intelligence based on detections"""
        try:
            # Collect all detected techniques
            techniques = []
            for detection in mitre_detections:
                techniques.append(detection.technique_id)
            for detection in sigma_detections:
                techniques.extend(detection.mitre_techniques)
            
            unique_techniques = list(set(techniques))
            
            if not unique_techniques:
                return None
            
            # Check against known APT groups
            apt_matches = []
            for apt_group, apt_data in self.threat_intel_db.get("apt_groups", {}).items():
                apt_techniques = apt_data.get("techniques", [])
                overlap = len(set(unique_techniques) & set(apt_techniques))
                if overlap > 0:
                    confidence = overlap / len(apt_techniques)
                    apt_matches.append((apt_group, confidence, apt_data))
            
            # Check against malware families
            malware_matches = []
            for malware, malware_data in self.threat_intel_db.get("malware_families", {}).items():
                malware_techniques = malware_data.get("techniques", [])
                overlap = len(set(unique_techniques) & set(malware_techniques))
                if overlap > 0:
                    confidence = overlap / len(malware_techniques)
                    malware_matches.append((malware, confidence, malware_data))
            
            # Determine best matches
            best_apt = max(apt_matches, key=lambda x: x[1]) if apt_matches else None
            best_malware = max(malware_matches, key=lambda x: x[1]) if malware_matches else None
            
            if best_apt or best_malware:
                return ThreatIntelligence(
                    threat_actor=best_apt[0] if best_apt else None,
                    campaign=None,  # Would be enriched with campaign data
                    malware_family=best_malware[0] if best_malware else None,
                    confidence_score=max(best_apt[1] if best_apt else 0, best_malware[1] if best_malware else 0),
                    attribution_evidence=[
                        f"Technique overlap with {best_apt[0]}" if best_apt else "",
                        f"Malware signature match: {best_malware[0]}" if best_malware else ""
                    ],
                    geographical_indicators=best_apt[2].get("geography", []) if best_apt else [],
                    temporal_patterns=[]
                )
            
            return None
            
        except Exception as e:
            print(f" Error in threat intelligence analysis: {e}")
            return None
    
    def _construct_attack_narrative(self, mitre_detections: List[MITREDetection], 
                                  sigma_detections: List[DetectionResult], 
                                  log_data: List[Dict]) -> Optional[AttackNarrative]:
        """Construct a narrative of the attack using AI analysis"""
        try:
            if not mitre_detections and not sigma_detections:
                return None
            
            # Create timeline
            timeline = []
            for detection in mitre_detections:
                timeline.append({
                    "timestamp": detection.timestamp,
                    "technique": detection.technique_id,
                    "type": "mitre",
                    "evidence": detection.evidence
                })
            
            for detection in sigma_detections:
                timeline.append({
                    "timestamp": detection.timestamp,
                    "rule": detection.rule_title,
                    "type": "sigma",
                    "evidence": detection.evidence
                })
            
            # Sort by timestamp
            timeline.sort(key=lambda x: x.get("timestamp", ""))
            
            # Build attack chain
            attack_chain = []
            techniques = [d.technique_id for d in mitre_detections]
            
            # Common attack patterns
            if "T1566" in techniques:  # Phishing
                attack_chain.append("Initial Access via Phishing")
            if "T1059.001" in techniques:  # PowerShell
                attack_chain.append("PowerShell Execution")
            if "T1105" in techniques:  # File Transfer
                attack_chain.append("Tool/Payload Download")
            if "T1055" in techniques:  # Process Injection
                attack_chain.append("Process Injection")
            if "T1071" in techniques:  # C2 Communication
                attack_chain.append("Command & Control")
            
            # Generate narrative using AI
            narrative_text = self._generate_narrative_with_ai(timeline, attack_chain, techniques)
            
            return AttackNarrative(
                attack_id=f"attack_{int(datetime.now().timestamp())}",
                timeline=timeline,
                attack_chain=attack_chain,
                entry_point=attack_chain[0] if attack_chain else "Unknown",
                objectives=["Data Access", "System Compromise"],  # Would be inferred
                impact_assessment="Medium - System compromise detected",
                confidence_score=0.75,  # Based on detection confidence
                narrative_text=narrative_text
            )
            
        except Exception as e:
            print(f" Error constructing attack narrative: {e}")
            return None
    
    def _generate_narrative_with_ai(self, timeline: List[Dict], attack_chain: List[str], 
                                  techniques: List[str]) -> str:
        """Generate human-readable attack narrative using AI"""
        try:
            prompt = f"""
Analyze this cybersecurity incident and provide a clear narrative explanation.

Timeline of Events:
{json.dumps(timeline, indent=2)}

Attack Chain:
{' -> '.join(attack_chain)}

MITRE Techniques Detected:
{', '.join(techniques)}

Please provide a clear, professional narrative that explains:
1. What happened in this incident
2. The attack progression
3. The threat actor's likely objectives
4. The potential impact

Keep the response concise but comprehensive, suitable for a security report.
"""
            
            response = self.llm.invoke(prompt)
            return response.content.strip()
            
        except Exception as e:
            print(f" Error generating AI narrative: {e}")
            return "Attack narrative generation failed - manual analysis required."
    
    def _perform_behavioral_analysis(self, log_data: List[Dict], 
                                   mitre_detections: List[MITREDetection]) -> Dict[str, Any]:
        """Perform behavioral analysis of the activity"""
        analysis = {
            "activity_pattern": "unknown",
            "frequency_analysis": {},
            "anomaly_score": 0.0,
            "behavioral_indicators": [],
            "user_activity": {},
            "system_impact": {}
        }
        
        try:
            # Analyze command patterns
            commands = []
            for log_entry in log_data:
                if 'ExecutedCommand' in log_entry:
                    commands.append(log_entry['ExecutedCommand'])
            
            if commands:
                # Frequency analysis
                command_words = []
                for cmd in commands:
                    command_words.extend(cmd.lower().split())
                
                word_freq = {}
                for word in command_words:
                    word_freq[word] = word_freq.get(word, 0) + 1
                
                analysis["frequency_analysis"] = dict(sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:10])
                
                # Behavioral indicators
                if any("invoke-" in cmd.lower() for cmd in commands):
                    analysis["behavioral_indicators"].append("PowerShell invoke commands detected")
                
                if any("download" in cmd.lower() for cmd in commands):
                    analysis["behavioral_indicators"].append("File download activity detected")
                
                if len(commands) > 10:
                    analysis["behavioral_indicators"].append("High volume command execution")
                
                # Calculate anomaly score
                suspicious_patterns = len([cmd for cmd in commands if any(pattern in cmd.lower() for pattern in ['invoke-', 'download', 'bypass', 'hidden'])])
                analysis["anomaly_score"] = min(suspicious_patterns / len(commands), 1.0)
            
            # Analyze MITRE detection patterns
            if mitre_detections:
                technique_freq = {}
                for detection in mitre_detections:
                    technique_freq[detection.technique_id] = technique_freq.get(detection.technique_id, 0) + 1
                
                if len(technique_freq) > 3:
                    analysis["activity_pattern"] = "multi_technique_attack"
                elif len(technique_freq) > 1:
                    analysis["activity_pattern"] = "coordinated_attack"
                else:
                    analysis["activity_pattern"] = "focused_attack"
            
        except Exception as e:
            print(f" Error in behavioral analysis: {e}")
        
        return analysis
    
    def _calculate_threat_level(self, mitre_detections: List[MITREDetection], 
                              sigma_detections: List[DetectionResult],
                              threat_intel: Optional[ThreatIntelligence],
                              behavioral_analysis: Dict[str, Any]) -> Tuple[str, float]:
        """Calculate overall threat level and confidence"""
        
        # Base score from detections
        score = 0.0
        
        # MITRE detection scoring
        for detection in mitre_detections:
            severity_scores = {"low": 0.2, "medium": 0.4, "high": 0.6, "critical": 0.8}
            score += detection.confidence_score * severity_scores.get(detection.severity, 0.4)
        
        # Sigma detection scoring
        for detection in sigma_detections:
            severity_scores = {"low": 0.1, "medium": 0.3, "high": 0.5, "critical": 0.7}
            score += detection.confidence_score * severity_scores.get(detection.severity, 0.3)
        
        # Threat intelligence boost
        if threat_intel and threat_intel.confidence_score > 0.5:
            score += 0.3
        
        # Behavioral analysis boost
        anomaly_score = behavioral_analysis.get("anomaly_score", 0.0)
        score += anomaly_score * 0.2
        
        # Multi-technique attack boost
        if len(set(d.technique_id for d in mitre_detections)) > 3:
            score += 0.2
        
        # Normalize score
        final_score = min(score, 1.0)
        
        # Determine threat level
        if final_score >= 0.8:
            threat_level = "critical"
        elif final_score >= 0.6:
            threat_level = "high"
        elif final_score >= 0.3:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        return threat_level, final_score
    
    def _generate_ai_recommendations(self, mitre_detections: List[MITREDetection],
                                   sigma_detections: List[DetectionResult],
                                   threat_intel: Optional[ThreatIntelligence],
                                   attack_narrative: Optional[AttackNarrative]) -> Dict[str, List[str]]:
        """Generate AI-powered recommendations"""
        
        recommendations = {
            "immediate": [],
            "investigation": [],
            "remediation": [],
            "prevention": []
        }
        
        # Immediate actions based on detections
        techniques = [d.technique_id for d in mitre_detections]
        
        if "T1059.001" in techniques:  # PowerShell
            recommendations["immediate"].append("Review and restrict PowerShell execution policies")
            recommendations["immediate"].append("Monitor all PowerShell activity in real-time")
        
        if "T1105" in techniques:  # File Transfer
            recommendations["immediate"].append("Block suspicious file download activities")
            recommendations["immediate"].append("Quarantine downloaded files for analysis")
        
        if "T1071.004" in techniques:  # DNS C2
            recommendations["immediate"].append("Block suspicious DNS queries")
            recommendations["immediate"].append("Implement DNS filtering and monitoring")
        
        # Investigation steps
        recommendations["investigation"].extend([
            "Collect forensic images of affected systems",
            "Analyze network traffic for additional indicators",
            "Review authentication logs for compromised accounts",
            "Check for lateral movement indicators"
        ])
        
        # Remediation based on threat intelligence
        if threat_intel and threat_intel.threat_actor:
            recommendations["remediation"].append(f"Apply known countermeasures for {threat_intel.threat_actor}")
            recommendations["remediation"].append("Reset credentials for potentially compromised accounts")
        
        # Prevention measures
        recommendations["prevention"].extend([
            "Implement behavioral detection rules",
            "Enhance endpoint monitoring capabilities",
            "Conduct security awareness training",
            "Update detection rules based on this incident"
        ])
        
        return recommendations
    
    def _summarize_evidence(self, mitre_detections: List[MITREDetection], 
                          sigma_detections: List[DetectionResult]) -> List[str]:
        """Summarize all evidence from detections"""
        evidence = []
        
        for detection in mitre_detections:
            evidence.extend(detection.evidence)
        
        for detection in sigma_detections:
            evidence.extend(detection.evidence)
        
        # Remove duplicates and return top evidence
        unique_evidence = list(set(evidence))
        return unique_evidence[:10]  # Top 10 pieces of evidence
    
    def _calculate_false_positive_likelihood(self, sigma_detections: List[DetectionResult]) -> float:
        """Calculate likelihood of false positives"""
        if not sigma_detections:
            return 0.0
        
        # Consider rule quality and confidence scores
        total_confidence = sum(d.confidence_score for d in sigma_detections)
        avg_confidence = total_confidence / len(sigma_detections)
        
        # High confidence = low false positive likelihood
        false_positive_likelihood = max(0.0, 1.0 - avg_confidence)
        
        return round(false_positive_likelihood, 2)
    
    def generate_comprehensive_report(self, analysis_result: AIReasoningResult) -> Dict[str, Any]:
        """Generate comprehensive threat analysis report"""
        
        report = {
            "executive_summary": {
                "threat_level": analysis_result.threat_level,
                "confidence_score": analysis_result.confidence_score,
                "detection_count": len(analysis_result.mitre_detections) + len(analysis_result.sigma_detections),
                "false_positive_likelihood": analysis_result.false_positive_likelihood,
                "recommended_action": "immediate" if analysis_result.threat_level in ["high", "critical"] else "monitor"
            },
            
            "threat_intelligence": asdict(analysis_result.threat_intelligence) if analysis_result.threat_intelligence else None,
            
            "attack_narrative": asdict(analysis_result.attack_narrative) if analysis_result.attack_narrative else None,
            
            "technical_analysis": {
                "mitre_techniques": [d.technique_id for d in analysis_result.mitre_detections],
                "sigma_rules_triggered": [d.rule_title for d in analysis_result.sigma_detections],
                "behavioral_analysis": analysis_result.behavioral_analysis,
                "evidence_summary": analysis_result.evidence_summary
            },
            
            "recommendations": {
                "immediate_actions": analysis_result.immediate_actions,
                "investigation_steps": analysis_result.investigation_steps,
                "remediation_steps": analysis_result.remediation_steps,
                "prevention_measures": analysis_result.prevention_measures
            },
            
            "metadata": {
                "analysis_id": analysis_result.analysis_id,
                "timestamp": analysis_result.timestamp,
                "engine_version": "1.0.0"
            }
        }
        
        return report

# Factory function
def create_ai_reasoning_engine() -> AIReasoningEngine:
    """Create AI reasoning engine"""
    return AIReasoningEngine()
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from langchain_openai import ChatOpenAI
from langraph.config import OPENAI_API_KEY

from .mitre_attack_engine import MITREDetection, create_mitre_attack_engine
from .sigma_detection_engine import DetectionResult, create_sigma_detection_engine

@dataclass
class ThreatIntelligence:
    threat_actor: Optional[str]
    campaign: Optional[str]
    malware_family: Optional[str]
    confidence_score: float
    attribution_evidence: List[str]
    geographical_indicators: List[str]
    temporal_patterns: List[str]

@dataclass
class AttackNarrative:
    attack_id: str
    timeline: List[Dict[str, Any]]
    attack_chain: List[str]
    entry_point: str
    objectives: List[str]
    impact_assessment: str
    confidence_score: float
    narrative_text: str

@dataclass
class AIReasoningResult:
    analysis_id: str
    timestamp: str
    threat_level: str  # low, medium, high, critical
    confidence_score: float
    
    # Combined detections
    mitre_detections: List[MITREDetection]
    sigma_detections: List[DetectionResult]
    
    # AI Analysis
    threat_intelligence: Optional[ThreatIntelligence]
    attack_narrative: Optional[AttackNarrative]
    behavioral_analysis: Dict[str, Any]
    
    # Response recommendations
    immediate_actions: List[str]
    investigation_steps: List[str]
    remediation_steps: List[str]
    prevention_measures: List[str]
    
    # Evidence and context
    evidence_summary: List[str]
    false_positive_likelihood: float
    related_incidents: List[str]

class AIReasoningEngine:
    """Advanced AI reasoning engine for comprehensive threat analysis"""
    
    def __init__(self):
        self.llm = ChatOpenAI(api_key=OPENAI_API_KEY, model="gpt-4o")
        self.mitre_engine = create_mitre_attack_engine()
        self.sigma_engine = create_sigma_detection_engine()
        
        # Load threat intelligence data
        self.threat_intel_db = self._load_threat_intelligence()
        
        # Analysis cache
        self.analysis_cache = {}
    
    def _load_threat_intelligence(self) -> Dict[str, Any]:
        """Load threat intelligence database"""
        try:
            # In a real implementation, this would load from threat intel feeds
            return {
                "apt_groups": {
                    "APT1": {"techniques": ["T1059.001", "T1071.004"], "geography": ["China"]},
                    "APT28": {"techniques": ["T1566", "T1055"], "geography": ["Russia"]},
                    "APT29": {"techniques": ["T1078", "T1105"], "geography": ["Russia"]},
                    "Lazarus": {"techniques": ["T1566", "T1059.001"], "geography": ["North Korea"]}
                },
                "malware_families": {
                    "PowerShell Empire": {"techniques": ["T1059.001", "T1105"], "indicators": ["invoke-", "empire"]},
                    "Cobalt Strike": {"techniques": ["T1055", "T1071"], "indicators": ["beacon", "cobalt"]},
                    "Mimikatz": {"techniques": ["T1003", "T1078"], "indicators": ["sekurlsa", "kerberos"]}
                },
                "iocs": {
                    "domains": ["evil.com", "malware.tk", "c2server.org"],
                    "ips": ["192.168.1.100", "10.0.0.50"],
                    "hashes": ["abc123", "def456"]
                }
            }
        except Exception as e:
            print(f" Failed to load threat intelligence: {e}")
            return {}
    
    def analyze_comprehensive_threat(self, log_data: List[Dict], log_types: List[str], 
                                   context: Dict = None) -> AIReasoningResult:
        """Perform comprehensive threat analysis combining multiple detection engines"""
        
        print(" Starting comprehensive AI threat analysis...")
        
        # Generate analysis ID
        analysis_id = f"analysis_{int(datetime.now().timestamp())}"
        
        # Initialize result containers
        all_mitre_detections = []
        all_sigma_detections = []
        
        # Process each log entry with both engines
        for i, (log_entry, log_type) in enumerate(zip(log_data, log_types)):
            print(f" Analyzing log {i+1}/{len(log_data)} ({log_type})")
            
            # MITRE ATT&CK detection
            mitre_detections = self.mitre_engine.detect_technique_in_logs(log_entry, log_type)
            all_mitre_detections.extend(mitre_detections)
            
            # Sigma rule detection
            sigma_detections = self.sigma_engine.detect_threats(log_entry, log_type)
            all_sigma_detections.extend(sigma_detections)
        
        print(f" Found {len(all_mitre_detections)} MITRE detections, {len(all_sigma_detections)} Sigma detections")
        
        # Perform AI-powered analysis
        threat_intelligence = self._analyze_threat_intelligence(all_mitre_detections, all_sigma_detections)
        attack_narrative = self._construct_attack_narrative(all_mitre_detections, all_sigma_detections, log_data)
        behavioral_analysis = self._perform_behavioral_analysis(log_data, all_mitre_detections)
        
        # Determine overall threat level
        threat_level, confidence_score = self._calculate_threat_level(
            all_mitre_detections, all_sigma_detections, threat_intelligence, behavioral_analysis
        )
        
        # Generate recommendations
        recommendations = self._generate_ai_recommendations(
            all_mitre_detections, all_sigma_detections, threat_intelligence, attack_narrative
        )
        
        # Create comprehensive result
        result = AIReasoningResult(
            analysis_id=analysis_id,
            timestamp=datetime.now().isoformat(),
            threat_level=threat_level,
            confidence_score=confidence_score,
            mitre_detections=all_mitre_detections,
            sigma_detections=all_sigma_detections,
            threat_intelligence=threat_intelligence,
            attack_narrative=attack_narrative,
            behavioral_analysis=behavioral_analysis,
            immediate_actions=recommendations["immediate"],
            investigation_steps=recommendations["investigation"],
            remediation_steps=recommendations["remediation"],
            prevention_measures=recommendations["prevention"],
            evidence_summary=self._summarize_evidence(all_mitre_detections, all_sigma_detections),
            false_positive_likelihood=self._calculate_false_positive_likelihood(all_sigma_detections),
            related_incidents=[]
        )
        
        # Cache the analysis
        self.analysis_cache[analysis_id] = result
        
        print(f" Comprehensive analysis complete - Threat Level: {threat_level}")
        return result
    
    def _analyze_threat_intelligence(self, mitre_detections: List[MITREDetection], 
                                   sigma_detections: List[DetectionResult]) -> Optional[ThreatIntelligence]:
        """Analyze threat intelligence based on detections"""
        try:
            # Collect all detected techniques
            techniques = []
            for detection in mitre_detections:
                techniques.append(detection.technique_id)
            for detection in sigma_detections:
                techniques.extend(detection.mitre_techniques)
            
            unique_techniques = list(set(techniques))
            
            if not unique_techniques:
                return None
            
            # Check against known APT groups
            apt_matches = []
            for apt_group, apt_data in self.threat_intel_db.get("apt_groups", {}).items():
                apt_techniques = apt_data.get("techniques", [])
                overlap = len(set(unique_techniques) & set(apt_techniques))
                if overlap > 0:
                    confidence = overlap / len(apt_techniques)
                    apt_matches.append((apt_group, confidence, apt_data))
            
            # Check against malware families
            malware_matches = []
            for malware, malware_data in self.threat_intel_db.get("malware_families", {}).items():
                malware_techniques = malware_data.get("techniques", [])
                overlap = len(set(unique_techniques) & set(malware_techniques))
                if overlap > 0:
                    confidence = overlap / len(malware_techniques)
                    malware_matches.append((malware, confidence, malware_data))
            
            # Determine best matches
            best_apt = max(apt_matches, key=lambda x: x[1]) if apt_matches else None
            best_malware = max(malware_matches, key=lambda x: x[1]) if malware_matches else None
            
            if best_apt or best_malware:
                return ThreatIntelligence(
                    threat_actor=best_apt[0] if best_apt else None,
                    campaign=None,  # Would be enriched with campaign data
                    malware_family=best_malware[0] if best_malware else None,
                    confidence_score=max(best_apt[1] if best_apt else 0, best_malware[1] if best_malware else 0),
                    attribution_evidence=[
                        f"Technique overlap with {best_apt[0]}" if best_apt else "",
                        f"Malware signature match: {best_malware[0]}" if best_malware else ""
                    ],
                    geographical_indicators=best_apt[2].get("geography", []) if best_apt else [],
                    temporal_patterns=[]
                )
            
            return None
            
        except Exception as e:
            print(f" Error in threat intelligence analysis: {e}")
            return None
    
    def _construct_attack_narrative(self, mitre_detections: List[MITREDetection], 
                                  sigma_detections: List[DetectionResult], 
                                  log_data: List[Dict]) -> Optional[AttackNarrative]:
        """Construct a narrative of the attack using AI analysis"""
        try:
            if not mitre_detections and not sigma_detections:
                return None
            
            # Create timeline
            timeline = []
            for detection in mitre_detections:
                timeline.append({
                    "timestamp": detection.timestamp,
                    "technique": detection.technique_id,
                    "type": "mitre",
                    "evidence": detection.evidence
                })
            
            for detection in sigma_detections:
                timeline.append({
                    "timestamp": detection.timestamp,
                    "rule": detection.rule_title,
                    "type": "sigma",
                    "evidence": detection.evidence
                })
            
            # Sort by timestamp
            timeline.sort(key=lambda x: x.get("timestamp", ""))
            
            # Build attack chain
            attack_chain = []
            techniques = [d.technique_id for d in mitre_detections]
            
            # Common attack patterns
            if "T1566" in techniques:  # Phishing
                attack_chain.append("Initial Access via Phishing")
            if "T1059.001" in techniques:  # PowerShell
                attack_chain.append("PowerShell Execution")
            if "T1105" in techniques:  # File Transfer
                attack_chain.append("Tool/Payload Download")
            if "T1055" in techniques:  # Process Injection
                attack_chain.append("Process Injection")
            if "T1071" in techniques:  # C2 Communication
                attack_chain.append("Command & Control")
            
            # Generate narrative using AI
            narrative_text = self._generate_narrative_with_ai(timeline, attack_chain, techniques)
            
            return AttackNarrative(
                attack_id=f"attack_{int(datetime.now().timestamp())}",
                timeline=timeline,
                attack_chain=attack_chain,
                entry_point=attack_chain[0] if attack_chain else "Unknown",
                objectives=["Data Access", "System Compromise"],  # Would be inferred
                impact_assessment="Medium - System compromise detected",
                confidence_score=0.75,  # Based on detection confidence
                narrative_text=narrative_text
            )
            
        except Exception as e:
            print(f" Error constructing attack narrative: {e}")
            return None
    
    def _generate_narrative_with_ai(self, timeline: List[Dict], attack_chain: List[str], 
                                  techniques: List[str]) -> str:
        """Generate human-readable attack narrative using AI"""
        try:
            prompt = f"""
Analyze this cybersecurity incident and provide a clear narrative explanation.

Timeline of Events:
{json.dumps(timeline, indent=2)}

Attack Chain:
{' -> '.join(attack_chain)}

MITRE Techniques Detected:
{', '.join(techniques)}

Please provide a clear, professional narrative that explains:
1. What happened in this incident
2. The attack progression
3. The threat actor's likely objectives
4. The potential impact

Keep the response concise but comprehensive, suitable for a security report.
"""
            
            response = self.llm.invoke(prompt)
            return response.content.strip()
            
        except Exception as e:
            print(f" Error generating AI narrative: {e}")
            return "Attack narrative generation failed - manual analysis required."
    
    def _perform_behavioral_analysis(self, log_data: List[Dict], 
                                   mitre_detections: List[MITREDetection]) -> Dict[str, Any]:
        """Perform behavioral analysis of the activity"""
        analysis = {
            "activity_pattern": "unknown",
            "frequency_analysis": {},
            "anomaly_score": 0.0,
            "behavioral_indicators": [],
            "user_activity": {},
            "system_impact": {}
        }
        
        try:
            # Analyze command patterns
            commands = []
            for log_entry in log_data:
                if 'ExecutedCommand' in log_entry:
                    commands.append(log_entry['ExecutedCommand'])
            
            if commands:
                # Frequency analysis
                command_words = []
                for cmd in commands:
                    command_words.extend(cmd.lower().split())
                
                word_freq = {}
                for word in command_words:
                    word_freq[word] = word_freq.get(word, 0) + 1
                
                analysis["frequency_analysis"] = dict(sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:10])
                
                # Behavioral indicators
                if any("invoke-" in cmd.lower() for cmd in commands):
                    analysis["behavioral_indicators"].append("PowerShell invoke commands detected")
                
                if any("download" in cmd.lower() for cmd in commands):
                    analysis["behavioral_indicators"].append("File download activity detected")
                
                if len(commands) > 10:
                    analysis["behavioral_indicators"].append("High volume command execution")
                
                # Calculate anomaly score
                suspicious_patterns = len([cmd for cmd in commands if any(pattern in cmd.lower() for pattern in ['invoke-', 'download', 'bypass', 'hidden'])])
                analysis["anomaly_score"] = min(suspicious_patterns / len(commands), 1.0)
            
            # Analyze MITRE detection patterns
            if mitre_detections:
                technique_freq = {}
                for detection in mitre_detections:
                    technique_freq[detection.technique_id] = technique_freq.get(detection.technique_id, 0) + 1
                
                if len(technique_freq) > 3:
                    analysis["activity_pattern"] = "multi_technique_attack"
                elif len(technique_freq) > 1:
                    analysis["activity_pattern"] = "coordinated_attack"
                else:
                    analysis["activity_pattern"] = "focused_attack"
            
        except Exception as e:
            print(f" Error in behavioral analysis: {e}")
        
        return analysis
    
    def _calculate_threat_level(self, mitre_detections: List[MITREDetection], 
                              sigma_detections: List[DetectionResult],
                              threat_intel: Optional[ThreatIntelligence],
                              behavioral_analysis: Dict[str, Any]) -> Tuple[str, float]:
        """Calculate overall threat level and confidence"""
        
        # Base score from detections
        score = 0.0
        
        # MITRE detection scoring
        for detection in mitre_detections:
            severity_scores = {"low": 0.2, "medium": 0.4, "high": 0.6, "critical": 0.8}
            score += detection.confidence_score * severity_scores.get(detection.severity, 0.4)
        
        # Sigma detection scoring
        for detection in sigma_detections:
            severity_scores = {"low": 0.1, "medium": 0.3, "high": 0.5, "critical": 0.7}
            score += detection.confidence_score * severity_scores.get(detection.severity, 0.3)
        
        # Threat intelligence boost
        if threat_intel and threat_intel.confidence_score > 0.5:
            score += 0.3
        
        # Behavioral analysis boost
        anomaly_score = behavioral_analysis.get("anomaly_score", 0.0)
        score += anomaly_score * 0.2
        
        # Multi-technique attack boost
        if len(set(d.technique_id for d in mitre_detections)) > 3:
            score += 0.2
        
        # Normalize score
        final_score = min(score, 1.0)
        
        # Determine threat level
        if final_score >= 0.8:
            threat_level = "critical"
        elif final_score >= 0.6:
            threat_level = "high"
        elif final_score >= 0.3:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        return threat_level, final_score
    
    def _generate_ai_recommendations(self, mitre_detections: List[MITREDetection],
                                   sigma_detections: List[DetectionResult],
                                   threat_intel: Optional[ThreatIntelligence],
                                   attack_narrative: Optional[AttackNarrative]) -> Dict[str, List[str]]:
        """Generate AI-powered recommendations"""
        
        recommendations = {
            "immediate": [],
            "investigation": [],
            "remediation": [],
            "prevention": []
        }
        
        # Immediate actions based on detections
        techniques = [d.technique_id for d in mitre_detections]
        
        if "T1059.001" in techniques:  # PowerShell
            recommendations["immediate"].append("Review and restrict PowerShell execution policies")
            recommendations["immediate"].append("Monitor all PowerShell activity in real-time")
        
        if "T1105" in techniques:  # File Transfer
            recommendations["immediate"].append("Block suspicious file download activities")
            recommendations["immediate"].append("Quarantine downloaded files for analysis")
        
        if "T1071.004" in techniques:  # DNS C2
            recommendations["immediate"].append("Block suspicious DNS queries")
            recommendations["immediate"].append("Implement DNS filtering and monitoring")
        
        # Investigation steps
        recommendations["investigation"].extend([
            "Collect forensic images of affected systems",
            "Analyze network traffic for additional indicators",
            "Review authentication logs for compromised accounts",
            "Check for lateral movement indicators"
        ])
        
        # Remediation based on threat intelligence
        if threat_intel and threat_intel.threat_actor:
            recommendations["remediation"].append(f"Apply known countermeasures for {threat_intel.threat_actor}")
            recommendations["remediation"].append("Reset credentials for potentially compromised accounts")
        
        # Prevention measures
        recommendations["prevention"].extend([
            "Implement behavioral detection rules",
            "Enhance endpoint monitoring capabilities",
            "Conduct security awareness training",
            "Update detection rules based on this incident"
        ])
        
        return recommendations
    
    def _summarize_evidence(self, mitre_detections: List[MITREDetection], 
                          sigma_detections: List[DetectionResult]) -> List[str]:
        """Summarize all evidence from detections"""
        evidence = []
        
        for detection in mitre_detections:
            evidence.extend(detection.evidence)
        
        for detection in sigma_detections:
            evidence.extend(detection.evidence)
        
        # Remove duplicates and return top evidence
        unique_evidence = list(set(evidence))
        return unique_evidence[:10]  # Top 10 pieces of evidence
    
    def _calculate_false_positive_likelihood(self, sigma_detections: List[DetectionResult]) -> float:
        """Calculate likelihood of false positives"""
        if not sigma_detections:
            return 0.0
        
        # Consider rule quality and confidence scores
        total_confidence = sum(d.confidence_score for d in sigma_detections)
        avg_confidence = total_confidence / len(sigma_detections)
        
        # High confidence = low false positive likelihood
        false_positive_likelihood = max(0.0, 1.0 - avg_confidence)
        
        return round(false_positive_likelihood, 2)
    
    def generate_comprehensive_report(self, analysis_result: AIReasoningResult) -> Dict[str, Any]:
        """Generate comprehensive threat analysis report"""
        
        report = {
            "executive_summary": {
                "threat_level": analysis_result.threat_level,
                "confidence_score": analysis_result.confidence_score,
                "detection_count": len(analysis_result.mitre_detections) + len(analysis_result.sigma_detections),
                "false_positive_likelihood": analysis_result.false_positive_likelihood,
                "recommended_action": "immediate" if analysis_result.threat_level in ["high", "critical"] else "monitor"
            },
            
            "threat_intelligence": asdict(analysis_result.threat_intelligence) if analysis_result.threat_intelligence else None,
            
            "attack_narrative": asdict(analysis_result.attack_narrative) if analysis_result.attack_narrative else None,
            
            "technical_analysis": {
                "mitre_techniques": [d.technique_id for d in analysis_result.mitre_detections],
                "sigma_rules_triggered": [d.rule_title for d in analysis_result.sigma_detections],
                "behavioral_analysis": analysis_result.behavioral_analysis,
                "evidence_summary": analysis_result.evidence_summary
            },
            
            "recommendations": {
                "immediate_actions": analysis_result.immediate_actions,
                "investigation_steps": analysis_result.investigation_steps,
                "remediation_steps": analysis_result.remediation_steps,
                "prevention_measures": analysis_result.prevention_measures
            },
            
            "metadata": {
                "analysis_id": analysis_result.analysis_id,
                "timestamp": analysis_result.timestamp,
                "engine_version": "1.0.0"
            }
        }
        
        return report

# Factory function
def create_ai_reasoning_engine() -> AIReasoningEngine:
    """Create AI reasoning engine"""
    return AIReasoningEngine()
 
 
 
 
 
 
 
 
 