"""
Customizable Attack Planning Prompts for LangGraph
All prompts can be modified at runtime
"""

class AttackPrompts:
    """Customizable prompts for attack planning"""
    
    def __init__(self):
        # Default prompts - can be customized
        self.prompts = {
            'network_analysis': self.default_network_analysis_prompt,
            'threat_assessment': self.default_threat_assessment_prompt,
            'vulnerability_analysis': self.default_vulnerability_analysis_prompt,
            'attack_planning': self.default_attack_planning_prompt,
            'scenario_generation': self.default_scenario_generation_prompt,
            'technique_selection': self.default_technique_selection_prompt,
            'target_prioritization': self.default_target_prioritization_prompt,
            'execution_planning': self.default_execution_planning_prompt
        }
        
        # Custom prompt overrides
        self.custom_prompts = {}
    
    def get_prompt(self, prompt_type: str, **kwargs) -> str:
        """
        Get prompt by type with variable substitution
        kwargs are used to fill in template variables
        """
        # Check for custom override first
        if prompt_type in self.custom_prompts:
            prompt_template = self.custom_prompts[prompt_type]
        elif prompt_type in self.prompts:
            prompt_template = self.prompts[prompt_type]()
        else:
            prompt_template = self.default_generic_prompt()
        
        # Substitute variables
        try:
            return prompt_template.format(**kwargs)
        except KeyError as e:
            # Return template with error note if variable missing
            return f"{prompt_template}\n[ERROR: Missing variable {e}]"
    
    def set_custom_prompt(self, prompt_type: str, prompt_template: str):
        """Set a custom prompt override"""
        self.custom_prompts[prompt_type] = prompt_template
    
    def reset_prompt(self, prompt_type: str):
        """Reset prompt to default"""
        if prompt_type in self.custom_prompts:
            del self.custom_prompts[prompt_type]
    
    # ============= DEFAULT PROMPT TEMPLATES =============
    
    def default_network_analysis_prompt(self) -> str:
        return """You are an expert penetration tester analyzing a network topology.

Network Information:
- Total Endpoints: {total_endpoints}
- Online Agents: {online_agents}
- Offline Agents: {offline_agents}
- Critical Assets: {critical_assets}
- Security Zones: {security_zones}

Endpoint Details:
{endpoint_details}

Analyze this network and provide:
1. Key observations about the network structure
2. Identified critical systems (domain controllers, databases, etc.)
3. Network segments and their purposes
4. Potential pivot points for lateral movement
5. High-value targets for data exfiltration
6. Security weaknesses in the topology
7. Recommended attack paths

Format your response as a structured analysis with clear sections."""

    def default_threat_assessment_prompt(self) -> str:
        return """You are a threat intelligence analyst assessing potential threats to an organization.

User Request: {user_request}
Network Profile:
- Industry: {industry}
- Size: {organization_size}
- Critical Assets: {critical_assets}
- Current Threats: {current_threats}

Based on this information, determine:

1. THREAT ACTORS:
   - Most likely APT groups targeting this profile
   - Their typical motivations
   - Historical campaigns against similar targets

2. OBJECTIVES:
   - Primary goals (ransomware, data theft, espionage, disruption)
   - Secondary objectives
   - Financial vs. strategic motivations

3. SOPHISTICATION LEVEL:
   - Required skill level for successful attack
   - Resource requirements
   - Time investment needed

4. RECOMMENDED MITRE TECHNIQUES:
   - Top 10 techniques to test
   - Rationale for each technique
   - Expected effectiveness

5. PRIORITY TARGETS:
   - Which systems to focus on
   - Why they are valuable
   - Impact of compromise

Provide a comprehensive threat assessment."""

    def default_vulnerability_analysis_prompt(self) -> str:
        return """You are a vulnerability assessment expert analyzing endpoints for security weaknesses.

Endpoints to Analyze:
{endpoints_json}

For each endpoint, identify:

1. PLATFORM VULNERABILITIES:
   - OS-specific vulnerabilities
   - Known CVEs applicable
   - Patch level concerns
   - Default configurations issues

2. SERVICE VULNERABILITIES:
   - Exposed services and ports
   - Service-specific vulnerabilities
   - Authentication weaknesses
   - Encryption issues

3. APPLICATION VULNERABILITIES:
   - Installed software vulnerabilities
   - Web application issues
   - Database vulnerabilities
   - Third-party component risks

4. CONFIGURATION ISSUES:
   - Misconfigurations
   - Weak access controls
   - Logging deficiencies
   - Monitoring gaps

5. ATTACK VECTORS:
   - Initial access possibilities
   - Privilege escalation paths
   - Lateral movement options
   - Data exfiltration channels

6. EXPLOITABILITY:
   - Ease of exploitation (1-10)
   - Required tools
   - Detection likelihood
   - Success probability

Provide detailed vulnerability assessment with risk ratings."""

    def default_attack_planning_prompt(self) -> str:
        return """You are an expert red team operator creating a comprehensive attack plan.

CONTEXT:
Network Topology: {network_topology}
Vulnerabilities Found: {vulnerabilities}
User Objective: {attack_objective}
Time Constraint: {time_limit}
Sophistication Level: {sophistication}

Design a multi-phase attack plan following the MITRE ATT&CK framework:

PHASE 1 - INITIAL ACCESS:
- Techniques to use (with MITRE IDs)
- Target endpoints
- Expected success rate
- Time required
- Detection risk

PHASE 2 - EXECUTION:
- Payload delivery methods
- Execution techniques
- Persistence mechanisms
- Anti-forensics measures

PHASE 3 - PRIVILEGE ESCALATION:
- Escalation techniques
- Target privileges
- Bypass methods
- Validation steps

PHASE 4 - DEFENSE EVASION:
- Evasion techniques
- Obfuscation methods
- Log manipulation
- Monitoring avoidance

PHASE 5 - CREDENTIAL ACCESS:
- Credential harvesting techniques
- Target accounts
- Storage locations
- Usage strategy

PHASE 6 - DISCOVERY:
- Reconnaissance techniques
- Information to gather
- Tools to use
- Stealth measures

PHASE 7 - LATERAL MOVEMENT:
- Movement techniques
- Target systems progression
- Pivot points
- Cover activities

PHASE 8 - COLLECTION:
- Data identification
- Collection methods
- Staging locations
- Compression/encryption

PHASE 9 - COMMAND AND CONTROL:
- C2 infrastructure
- Communication protocols
- Beacon intervals
- Fallback mechanisms

PHASE 10 - EXFILTRATION:
- Exfiltration techniques
- Data prioritization
- Transfer methods
- Cleanup procedures

PHASE 11 - IMPACT (if applicable):
- Impact techniques
- Timing considerations
- Reversibility
- Attribution avoidance

For each phase, specify:
- Specific commands/tools to use
- Success criteria
- Rollback procedures
- Alternative approaches

Total estimated time: _____ minutes
Overall risk level: _____
Probability of success: _____%"""

    def default_scenario_generation_prompt(self) -> str:
        return """You are a security scenario designer creating realistic attack scenarios.

User Request: {user_request}
Available Targets: {targets}
Time Available: {time_limit}
Constraints: {constraints}

Generate 3 different attack scenarios:

SCENARIO 1 - STEALTHY APT:
- Name: [Creative name]
- Threat Actor Profile: [APT group style]
- Primary Objective: [What they want]
- Approach: Low and slow, avoid detection
- Phases:
  * Phase 1: [Name] - Techniques: [MITRE IDs] - Duration: [time]
  * Phase 2: [Name] - Techniques: [MITRE IDs] - Duration: [time]
  * Phase 3: [Name] - Techniques: [MITRE IDs] - Duration: [time]
  * [Additional phases as needed]
- Total Duration: [time]
- Detection Likelihood: Low
- Impact: [Description]
- Success Metrics: [How to measure success]

SCENARIO 2 - RANSOMWARE ATTACK:
- Name: [Creative name]
- Threat Actor Profile: [Ransomware group style]
- Primary Objective: Financial gain through encryption
- Approach: Fast and aggressive
- Phases:
  * [Similar structure as above]
- Total Duration: [time]
- Detection Likelihood: High (but fast)
- Impact: [Description]
- Success Metrics: [How to measure success]

SCENARIO 3 - {scenario_type}:
- Name: [Creative name]
- Threat Actor Profile: [Appropriate profile]
- Primary Objective: [Based on scenario type]
- Approach: [Appropriate approach]
- Phases:
  * [Similar structure as above]
- Total Duration: [time]
- Detection Likelihood: [Level]
- Impact: [Description]
- Success Metrics: [How to measure success]

For each scenario, ensure:
1. Realistic timeline
2. Logical progression
3. Appropriate techniques for objectives
4. Clear success criteria
5. Measurable outcomes"""

    def default_technique_selection_prompt(self) -> str:
        return """You are a MITRE ATT&CK expert selecting appropriate techniques for an operation.

Attack Objective: {objective}
Target Environment: {environment}
Available Tools: {tools}
Time Constraint: {time_limit}
Detection Tolerance: {detection_tolerance}

Current Techniques Under Consideration:
{techniques_list}

Analyze and recommend:

1. TECHNIQUE PRIORITIZATION:
   - Rank techniques by effectiveness for objective
   - Consider detection risk vs. reward
   - Account for dependencies between techniques

2. TECHNIQUE COMBINATIONS:
   - Which techniques work well together
   - Sequence for maximum effectiveness
   - Backup techniques if primary fails

3. CUSTOM IMPLEMENTATIONS:
   - How to customize each technique for this environment
   - Specific parameters to use
   - Timing considerations

4. DETECTION ANALYSIS:
   - Detection likelihood for each technique
   - Mitigation strategies
   - Alternative techniques if detected

5. SUCCESS METRICS:
   - How to measure technique success
   - Validation methods
   - Rollback triggers

Provide specific, actionable recommendations."""

    def default_target_prioritization_prompt(self) -> str:
        return """You are a target prioritization specialist for red team operations.

Available Targets:
{targets_list}

Attack Objectives:
{objectives}

Constraints:
- Time: {time_limit}
- Resources: {resources}
- Detection Risk: {risk_tolerance}

Prioritize targets based on:

1. VALUE ASSESSMENT:
   - Data value (1-10)
   - System criticality (1-10)
   - Business impact (1-10)
   - Intelligence value (1-10)

2. ACCESSIBILITY:
   - Ease of initial access (1-10)
   - Required privileges
   - Network position
   - Security controls

3. ATTACK PATH ANALYSIS:
   - Role in kill chain
   - Pivot potential
   - Lateral movement value
   - Persistence options

4. RISK ANALYSIS:
   - Detection likelihood
   - Forensic footprint
   - Recovery difficulty
   - Collateral damage

5. RECOMMENDED ORDER:
   Priority 1: [Targets] - Reason: [Why]
   Priority 2: [Targets] - Reason: [Why]
   Priority 3: [Targets] - Reason: [Why]
   
6. ALTERNATIVE PATHS:
   If Priority 1 fails: [Alternative]
   If Priority 2 fails: [Alternative]

Provide clear prioritization with justification."""

    def default_execution_planning_prompt(self) -> str:
        return """You are an operation execution planner finalizing attack details.

Attack Plan Summary:
{plan_summary}

Target Systems:
{targets}

Available Resources:
{resources}

Create detailed execution plan:

1. PRE-EXECUTION CHECKLIST:
   □ All tools tested and ready
   □ C2 infrastructure operational
   □ Backup plans prepared
   □ Golden images created
   □ Team roles assigned
   □ Communication channels established

2. EXECUTION TIMELINE:
   T+0: [Action] - [Who] - [Expected outcome]
   T+15: [Action] - [Who] - [Expected outcome]
   T+30: [Action] - [Who] - [Expected outcome]
   [Continue with detailed timeline]

3. DECISION POINTS:
   - Point 1: [Condition] → [Action if true] / [Action if false]
   - Point 2: [Condition] → [Action if true] / [Action if false]
   
4. ABORT CRITERIA:
   - Condition 1: [When to abort]
   - Condition 2: [When to abort]
   
5. SUCCESS CRITERIA:
   - Minimum success: [Definition]
   - Target success: [Definition]
   - Stretch goals: [Definition]

6. POST-EXECUTION:
   - Data collection procedures
   - Cleanup requirements
   - Restoration from golden images
   - Reporting requirements

Provide executable, detailed plan."""

    def default_generic_prompt(self) -> str:
        return """Analyze the following information and provide expert security assessment:

Input Data:
{input_data}

Provide comprehensive analysis including:
1. Key findings
2. Risk assessment
3. Recommendations
4. Technical details
5. Next steps

Be specific and actionable in your response."""


# Singleton instance
attack_prompts = AttackPrompts()
