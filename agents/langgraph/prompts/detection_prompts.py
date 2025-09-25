"""
Customizable Detection Prompts for AI Detection System
All prompts can be modified at runtime for different detection scenarios
"""

class DetectionPrompts:
    """Customizable prompts for threat detection and analysis"""
    
    def __init__(self):
        # Default detection prompts
        self.prompts = {
            'log_analysis': self.default_log_analysis_prompt,
            'threat_detection': self.default_threat_detection_prompt,
            'anomaly_investigation': self.default_anomaly_investigation_prompt,
            'malware_analysis': self.default_malware_analysis_prompt,
            'behavioral_analysis': self.default_behavioral_analysis_prompt,
            'correlation_analysis': self.default_correlation_analysis_prompt,
            'risk_assessment': self.default_risk_assessment_prompt,
            'incident_classification': self.default_incident_classification_prompt,
            'false_positive_analysis': self.default_false_positive_analysis_prompt,
            'threat_hunting': self.default_threat_hunting_prompt,
            'reasoning_verdict': self.default_reasoning_verdict_prompt,
            'alert_generation': self.default_alert_generation_prompt
        }
        
        # Custom prompt overrides
        self.custom_prompts = {}
    
    def get_prompt(self, prompt_type: str, **kwargs) -> str:
        """Get prompt by type with variable substitution"""
        if prompt_type in self.custom_prompts:
            prompt_template = self.custom_prompts[prompt_type]
        elif prompt_type in self.prompts:
            prompt_template = self.prompts[prompt_type]()
        else:
            prompt_template = self.default_generic_detection_prompt()
        
        try:
            return prompt_template.format(**kwargs)
        except KeyError as e:
            return f"{prompt_template}\n[ERROR: Missing variable {e}]"
    
    def set_custom_prompt(self, prompt_type: str, prompt_template: str):
        """Set a custom prompt override"""
        self.custom_prompts[prompt_type] = prompt_template
    
    def reset_prompt(self, prompt_type: str):
        """Reset prompt to default"""
        if prompt_type in self.custom_prompts:
            del self.custom_prompts[prompt_type]
    
    # ============= DEFAULT DETECTION PROMPTS =============
    
    def default_log_analysis_prompt(self) -> str:
        return """You are an expert security analyst examining system logs for potential threats.

LOGS TO ANALYZE:
{log_entries}

CONTEXT:
- Agent: {agent_info}
- Time Period: {time_period}
- Log Count: {log_count}
- Agent Importance: {agent_importance}

Analyze these logs and identify:

1. SUSPICIOUS ACTIVITIES:
   - Unusual commands or processes
   - Unauthorized access attempts
   - Privilege escalation indicators
   - Data exfiltration signs
   - Persistence mechanisms

2. ATTACK INDICATORS:
   - Known attack patterns
   - MITRE ATT&CK techniques observed
   - Tools or scripts associated with attacks
   - Command and control communication
   - Lateral movement attempts

3. ANOMALIES:
   - Deviations from normal behavior
   - Unusual timing or frequency
   - Unexpected network connections
   - Abnormal resource usage
   - Strange file operations

4. SEVERITY ASSESSMENT:
   For each finding, rate severity:
   - Critical: Immediate action required
   - High: Significant threat detected
   - Medium: Suspicious but needs investigation
   - Low: Minor anomaly or informational

5. CONFIDENCE LEVEL:
   Rate your confidence (0-100%) for each detection

Provide structured analysis with specific evidence from logs."""

    def default_threat_detection_prompt(self) -> str:
        return """You are a threat detection specialist analyzing potential security threats.

INPUT DATA:
{detection_data}

ML MODEL RESULTS:
- Anomaly Score: {anomaly_score}
- Malware Confidence: {malware_confidence}
- Network Threat Score: {network_score}

ENRICHED CONTEXT:
{enriched_context}

Perform comprehensive threat detection:

1. THREAT IDENTIFICATION:
   - Type of threat (malware, intrusion, data theft, etc.)
   - Attack vector used
   - Threat actor profile (if identifiable)
   - Campaign or toolkit indicators

2. ATTACK STAGE:
   Identify current stage in kill chain:
   - Reconnaissance
   - Initial Access
   - Execution
   - Persistence
   - Privilege Escalation
   - Defense Evasion
   - Credential Access
   - Discovery
   - Lateral Movement
   - Collection
   - Exfiltration
   - Impact

3. INDICATORS OF COMPROMISE (IOCs):
   Extract specific IOCs:
   - IP addresses
   - Domain names
   - File hashes
   - Registry keys
   - Process names
   - Network signatures

4. IMPACT ASSESSMENT:
   - Affected systems
   - Data at risk
   - Business impact
   - Spread potential

5. DETECTION CONFIDENCE:
   Provide confidence score (0-100%) with reasoning

Format as structured JSON-like output for parsing."""

    def default_anomaly_investigation_prompt(self) -> str:
        return """You are an anomaly investigation expert examining unusual patterns.

ANOMALY DETAILS:
{anomaly_data}

BASELINE BEHAVIOR:
{baseline_metrics}

HISTORICAL CONTEXT:
{historical_data}

Investigate this anomaly:

1. ANOMALY CLASSIFICATION:
   - Type: Statistical, Behavioral, Temporal, Contextual
   - Category: User, System, Network, Application
   - Deviation Level: How far from normal (%)

2. ROOT CAUSE ANALYSIS:
   - Potential legitimate causes
   - Potential malicious causes
   - Environmental factors
   - System changes or updates

3. CORRELATION:
   - Related events in same timeframe
   - Similar anomalies on other systems
   - Previous occurrences
   - Pattern matches

4. THREAT LIKELIHOOD:
   Rate the likelihood this is malicious (0-100%):
   - Supporting evidence
   - Contradicting evidence
   - Alternative explanations

5. INVESTIGATION PRIORITY:
   - Critical: Investigate immediately
   - High: Investigate within hour
   - Medium: Investigate within day
   - Low: Monitor for patterns

Provide detailed reasoning for conclusions."""

    def default_malware_analysis_prompt(self) -> str:
        return """You are a malware analyst examining potential malicious activity.

SUSPICIOUS ACTIVITY:
{suspicious_data}

FILE/PROCESS INFORMATION:
{file_process_info}

NETWORK ACTIVITY:
{network_activity}

Analyze for malware indicators:

1. MALWARE TYPE IDENTIFICATION:
   - Ransomware indicators
   - Trojan behavior
   - Worm propagation
   - Rootkit hiding techniques
   - Spyware/Keylogger activity
   - Cryptominer resource usage

2. BEHAVIORAL PATTERNS:
   - File system modifications
   - Registry changes
   - Process injection
   - Code obfuscation
   - Anti-analysis techniques
   - Persistence mechanisms

3. COMMUNICATION PATTERNS:
   - C2 server communication
   - Data encoding methods
   - Beaconing intervals
   - DNS tunneling
   - Covert channels

4. PAYLOAD ANALYSIS:
   - Dropped files
   - Downloaded components
   - Execution chains
   - Privilege escalation
   - Defense evasion

5. ATTRIBUTION INDICATORS:
   - Known malware families
   - Threat actor TTPs
   - Code similarities
   - Infrastructure overlap

Rate malware confidence (0-100%) with evidence."""

    def default_behavioral_analysis_prompt(self) -> str:
        return """You are a behavioral analyst detecting threats through behavior patterns.

USER/SYSTEM BEHAVIOR:
{behavior_data}

NORMAL BASELINE:
{baseline_behavior}

TIME CONTEXT:
{temporal_context}

Analyze behavioral patterns:

1. USER BEHAVIOR ANALYSIS:
   - Login patterns (time, location, frequency)
   - Access patterns (resources, permissions)
   - Command usage (normal vs suspicious)
   - Data access (volume, sensitivity)
   - Communication patterns

2. SYSTEM BEHAVIOR ANALYSIS:
   - Process creation patterns
   - Network connection patterns
   - File access patterns
   - Resource utilization
   - Service interactions

3. DEVIATION DETECTION:
   - Significant deviations from baseline
   - First-time behaviors
   - Unusual sequences of actions
   - Timing anomalies
   - Volume anomalies

4. INSIDER THREAT INDICATORS:
   - Data staging behavior
   - Unusual access to sensitive data
   - Permission abuse
   - Policy violations
   - Reconnaissance activities

5. AUTOMATED VS HUMAN:
   Determine if behavior is:
   - Human-driven (legitimate or malicious)
   - Automated (script, malware, bot)
   - Mixed (human-initiated automation)

Provide risk score (0-100) with behavioral evidence."""

    def default_correlation_analysis_prompt(self) -> str:
        return """You are a correlation analyst connecting related security events.

PRIMARY EVENT:
{primary_event}

RELATED EVENTS:
{related_events}

NETWORK TOPOLOGY:
{network_context}

TIME WINDOW: {time_window}

Perform correlation analysis:

1. EVENT CORRELATION:
   - Temporal correlation (events in sequence)
   - Spatial correlation (across systems)
   - Causal relationships
   - Attack chain reconstruction

2. PATTERN IDENTIFICATION:
   - Attack patterns across multiple systems
   - Lateral movement indicators
   - Coordinated activities
   - Campaign signatures

3. SCOPE ASSESSMENT:
   - Number of affected systems
   - Attack progression timeline
   - Current attack stage
   - Predicted next targets

4. THREAT ACTOR BEHAVIOR:
   - TTPs observed
   - Tool signatures
   - Operational patterns
   - Mistakes or anomalies

5. HIDDEN CONNECTIONS:
   - Subtle relationships between events
   - Low-and-slow attack indicators
   - Covert channel usage
   - Data exfiltration patterns

Confidence in correlation (0-100%) with evidence chain."""

    def default_risk_assessment_prompt(self) -> str:
        return """You are a risk assessment specialist evaluating security threats.

THREAT INFORMATION:
{threat_data}

ASSET INFORMATION:
{asset_data}

VULNERABILITY CONTEXT:
{vulnerability_info}

BUSINESS CONTEXT:
{business_impact}

Perform comprehensive risk assessment:

1. THREAT SEVERITY:
   Rate severity (1-10) based on:
   - Attack sophistication
   - Threat actor capability
   - Attack success likelihood
   - Detection evasion ability

2. ASSET CRITICALITY:
   Rate importance (1-10) based on:
   - Business value
   - Data sensitivity
   - System dependencies
   - Recovery difficulty

3. VULNERABILITY EXPOSURE:
   Rate exposure (1-10) based on:
   - Exploitability
   - Public exploit availability
   - Mitigation status
   - Compensating controls

4. IMPACT ANALYSIS:
   Potential impacts:
   - Confidentiality breach
   - Integrity compromise
   - Availability loss
   - Financial damage
   - Reputation damage
   - Regulatory violations

5. RISK CALCULATION:
   Overall Risk Score = (Threat × Asset × Vulnerability) / 30
   - Critical Risk: 8-10
   - High Risk: 6-7.9
   - Medium Risk: 4-5.9
   - Low Risk: 1-3.9

Provide final risk score with mitigation priorities."""

    def default_incident_classification_prompt(self) -> str:
        return """You are an incident classifier categorizing security events.

INCIDENT DATA:
{incident_details}

DETECTION RESULTS:
{detection_results}

CONTEXT:
{incident_context}

Classify this incident:

1. INCIDENT TYPE:
   - Malware Infection
   - Unauthorized Access
   - Data Breach
   - Denial of Service
   - Insider Threat
   - APT Activity
   - Phishing/Social Engineering
   - Cryptomining
   - Ransomware
   - Other (specify)

2. ATTACK VECTOR:
   - Email/Phishing
   - Web Application
   - Network Service
   - Removable Media
   - Supply Chain
   - Physical Access
   - Insider Action
   - Unknown

3. INCIDENT SEVERITY:
   - Critical: Business critical impact
   - High: Significant impact
   - Medium: Moderate impact
   - Low: Minor impact
   - Informational: No immediate impact

4. RESPONSE PRIORITY:
   - P1: Immediate response (< 15 min)
   - P2: Urgent response (< 1 hour)
   - P3: High priority (< 4 hours)
   - P4: Normal priority (< 24 hours)
   - P5: Low priority (best effort)

5. REQUIRED ACTIONS:
   - Containment needed
   - Evidence collection required
   - User notification needed
   - Management escalation
   - Law enforcement involvement
   - Regulatory reporting

Provide classification with confidence score."""

    def default_false_positive_analysis_prompt(self) -> str:
        return """You are a false positive analyst reducing alert fatigue.

ALERT DETAILS:
{alert_data}

HISTORICAL ALERTS:
{historical_alerts}

SYSTEM CONTEXT:
{system_context}

Analyze for false positives:

1. FALSE POSITIVE INDICATORS:
   - Known benign patterns
   - Legitimate admin activity
   - Scheduled tasks/jobs
   - System maintenance
   - Application updates
   - User authorized actions

2. CONTEXT VALIDATION:
   - Business hours activity
   - Known user behavior
   - Approved changes
   - Expected system behavior
   - Environmental factors

3. PATTERN MATCHING:
   - Previous false positives
   - Whitelisted activities
   - Baseline deviations explained
   - Temporary conditions

4. TRUE POSITIVE INDICATORS:
   Despite appearances, check for:
   - Subtle attack indicators
   - Living-off-the-land techniques
   - Legitimate tool abuse
   - Insider threat masking

5. CONFIDENCE ASSESSMENT:
   Rate as:
   - Confirmed False Positive (90-100% confidence)
   - Likely False Positive (70-89% confidence)
   - Uncertain (30-69% confidence)
   - Likely True Positive (10-29% confidence)
   - Confirmed True Positive (0-9% confidence)

Provide reasoning and tuning recommendations."""

    def default_threat_hunting_prompt(self) -> str:
        return """You are a threat hunter proactively searching for hidden threats.

HUNT HYPOTHESIS:
{hunt_hypothesis}

AVAILABLE DATA:
{hunt_data}

INDICATORS:
{threat_indicators}

BASELINE:
{normal_baseline}

Conduct threat hunting:

1. HYPOTHESIS TESTING:
   - Evidence supporting hypothesis
   - Evidence against hypothesis
   - Data gaps identified
   - Additional data needed

2. HIDDEN THREAT DETECTION:
   - Living-off-the-land techniques
   - Fileless malware indicators
   - Legitimate tool abuse
   - Covert channels
   - Data staging areas

3. ADVANCED PERSISTENCE:
   - Hidden persistence mechanisms
   - Dormant backdoors
   - Scheduled triggers
   - Backup C2 channels
   - Hidden user accounts

4. EVASION TECHNIQUES:
   - Anti-forensics indicators
   - Log tampering
   - Timestamp manipulation
   - Encryption/obfuscation
   - Process hiding

5. HUNT FINDINGS:
   - Confirmed threats found
   - Suspicious requiring investigation
   - New IOCs discovered
   - TTPs identified
   - Recommendations for detection rules

Threat presence likelihood (0-100%) with evidence."""

    def default_reasoning_verdict_prompt(self) -> str:
        return """You are the AI Reasoning Agent making final verdict on threats.

ML DETECTION RESULTS:
{ml_results}

LLM ANALYSIS RESULTS:
{llm_results}

CORRELATION FINDINGS:
{correlation_data}

THREAT INTELLIGENCE:
{threat_intel}

CONTEXT:
- Asset Criticality: {asset_criticality}
- Time of Detection: {detection_time}
- Network Zone: {network_zone}
- Previous Incidents: {previous_incidents}

Make final determination:

1. VERDICT:
   Choose one:
   - CONFIRMED THREAT: Clear malicious activity
   - LIKELY THREAT: High probability malicious
   - SUSPICIOUS: Requires investigation
   - LIKELY BENIGN: Probably false positive
   - CONFIRMED BENIGN: Verified safe activity

2. CONFIDENCE SCORE:
   Overall confidence in verdict (0-100%)
   - ML confidence weight: 40%
   - LLM analysis weight: 40%
   - Context weight: 20%

3. EVIDENCE SUMMARY:
   - Strongest indicators
   - Supporting evidence
   - Contradicting evidence
   - Unknowns/gaps

4. THREAT DETAILS (if malicious):
   - Threat type
   - Attack stage
   - Affected systems
   - Data at risk
   - Spread potential

5. RECOMMENDED RESPONSE:
   - Immediate actions required
   - Investigation priorities
   - Containment measures
   - Evidence to collect
   - Stakeholders to notify

6. DETECTION QUALITY:
   Rate detection quality:
   - Excellent: Clear, actionable
   - Good: Useful with minor gaps
   - Fair: Requires more investigation
   - Poor: Too many unknowns

Provide final verdict with complete justification."""

    def default_alert_generation_prompt(self) -> str:
        return """You are generating security alerts for SOC analysts.

THREAT VERDICT:
{verdict_data}

INCIDENT DETAILS:
{incident_info}

AFFECTED ASSETS:
{affected_systems}

Generate comprehensive alert:

1. ALERT HEADER:
   - Title: [Concise, descriptive title]
   - Severity: Critical/High/Medium/Low
   - Category: [Threat category]
   - Confidence: [0-100%]
   - Time: [Detection time]

2. EXECUTIVE SUMMARY:
   Brief 2-3 sentence summary for management:
   - What happened
   - Impact
   - Current status

3. TECHNICAL DETAILS:
   For SOC analysts:
   - Attack description
   - Techniques used (MITRE ATT&CK)
   - Systems affected
   - Timeline of events
   - IOCs observed

4. IMPACT ASSESSMENT:
   - Business impact
   - Data exposure risk
   - System availability impact
   - Lateral movement risk

5. RECOMMENDED ACTIONS:
   Prioritized response steps:
   - Immediate containment
   - Investigation steps
   - Evidence collection
   - Remediation actions
   - Prevention measures

6. CONTEXTUAL INFORMATION:
   - Related incidents
   - Historical context
   - Threat intelligence
   - Similar attacks

Format alert for maximum clarity and actionability."""

    def default_generic_detection_prompt(self) -> str:
        return """Analyze the following security data for threats:

INPUT DATA:
{input_data}

Perform comprehensive security analysis:
1. Identify any threats or anomalies
2. Assess severity and risk
3. Determine if malicious or benign
4. Provide confidence score
5. Recommend response actions

Be specific with evidence and reasoning."""


# Singleton instance
detection_prompts = DetectionPrompts()
