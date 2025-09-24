#!/usr/bin/env python3
"""
AI Reasoning Engine - Pure AI-Driven Incident Analysis
Uses local cybersec-ai LLM for intelligent security reasoning
"""

import yaml
import os
import json
import logging
import requests
import urllib.parse
from typing import Dict, List, Optional, Any
from datetime import datetime
from langchain_community.chat_models import ChatOllama
from langchain_openai import ChatOpenAI
from duckduckgo_search import DDGS
from langchain.agents import Tool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReasoningEngine:
    """AI-powered reasoning engine for security incident analysis"""
    
    def __init__(self, config=None):
        self.config = config or self._load_config()
        self.llm_config = self.config.get('llm', {})
        
        # Initialize LLM with local cybersec-ai as primary
        self.llm = self._initialize_llm()
        
        # Initialize web search capabilities
        self._initialize_web_tools()
        
        logger.info("🧠 AI Reasoning Engine initialized with local cybersec-ai + Web Search")
    
    def _load_config(self):
        """Load system configuration"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.yaml")
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
        
        # Default config
        return {
            'llm': {
                'provider': 'ollama',
                'ollama_endpoint': 'http://localhost:11434',
                'ollama_model': 'cybersec-ai',
                'fallback_order': ['ollama', 'openai'],
                'temperature': 0.3
            }
        }
    
    def _initialize_llm(self):
        """Initialize LLM with local cybersec-ai as primary"""
        llm_config = self.llm_config
        fallback_order = llm_config.get('fallback_order', ['ollama', 'openai'])
        
        for provider in fallback_order:
            try:
                if provider == 'ollama':
                    logger.info("🧠 Initializing local cybersec-ai for reasoning...")
                    return ChatOllama(
                        model=llm_config.get('ollama_model', 'cybersec-ai'),
                        base_url=llm_config.get('ollama_endpoint', 'http://localhost:11434'),
                        temperature=llm_config.get('temperature', 0.3)
                    )
                elif provider == 'openai':
                    logger.info("🔄 Fallback to OpenAI for reasoning...")
                    openai_key = llm_config.get('openai_api_key', os.getenv('OPENAI_API_KEY'))
                    if openai_key and openai_key != 'sk-...':
                        return ChatOpenAI(
                            api_key=openai_key,
                            model=llm_config.get('openai_model', 'gpt-4o'),
                            temperature=llm_config.get('temperature', 0.3)
                        )
                except Exception as e:
                logger.warning(f"⚠️ Failed to initialize {provider}: {e}")
                    continue
        
        # Last resort - basic Ollama
        logger.warning("🆘 Using basic Ollama fallback for reasoning...")
        return ChatOllama(model='llama3.2:3b', base_url='http://localhost:11434')
    
    def _initialize_web_tools(self):
        """Initialize web search and threat intelligence tools"""
        try:
            # Initialize DuckDuckGo search (privacy-focused)
            self.web_search = DDGS()
            
            # Initialize threat intelligence APIs
            self.threat_intel_apis = {
                'virustotal': 'https://www.virustotal.com/vtapi/v2/',
                'alienvault': 'https://otx.alienvault.com/api/v1/',
                'abuse_ch': 'https://urlhaus-api.abuse.ch/v1/',
                'cve_api': 'https://cve.circl.lu/api/'
            }
            
            logger.info("🌐 Web search and threat intel APIs initialized")
            
        except Exception as e:
            logger.warning(f"Web tools initialization failed: {e}")
            self.web_search = None
    
    def search_web_for_threat_intel(self, query: str, max_results: int = 5) -> str:
        """Search the web for cybersecurity threat intelligence"""
        try:
            if not self.web_search:
                return "Web search not available"
            # Enhanced query for cybersecurity context
            enhanced_query = f"cybersecurity {query} MITRE ATT&CK threat intelligence IOC"
            logger.info(f"🌐 Searching web for: {enhanced_query}")
            # Use the new DDGS API
            results = list(self.web_search.text(enhanced_query, max_results=max_results))
            # Format results
            formatted_results = []
            for result in results:
                formatted_results.append(f"Title: {result.get('title', 'N/A')}")
                formatted_results.append(f"Body: {result.get('body', 'N/A')}")
                formatted_results.append(f"URL: {result.get('href', 'N/A')}")
                formatted_results.append("---")
            return "\n".join(formatted_results)[:2000]  # Limit response size
                except Exception as e:
            logger.error(f"Web search failed: {e}")
            return f"Web search error: {e}"
    
    def lookup_cve_details(self, cve_id: str) -> Dict:
        """Look up CVE vulnerability details"""
        try:
            cve_api = self.threat_intel_apis.get('cve_api', 'https://cve.circl.lu/api/')
            response = requests.get(f"{cve_api}cve/{cve_id}", timeout=10)
            
        if response.status_code == 200:
                cve_data = response.json()
                return {
                    "cve_id": cve_id,
                    "summary": cve_data.get('summary', 'No summary available'),
                    "cvss": cve_data.get('cvss', 'Unknown'),
                    "published": cve_data.get('Published', 'Unknown'),
                    "references": cve_data.get('references', [])
                }
            else:
                return {"error": f"CVE lookup failed: {response.status_code}"}
                
        except Exception as e:
            return {"error": f"CVE lookup error: {e}"}
    
    def check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP address reputation using threat intelligence"""
        reputation_data = {
            "ip": ip_address,
            "threat_score": 0,
            "is_malicious": False,
            "categories": [],
            "last_seen": None
        }
        
        try:
            # Basic reputation checks (in production, use real APIs)
            # Check for known malicious patterns
            private_ranges = [
                '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
                '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
                '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.'
            ]
            
            if any(ip_address.startswith(prefix) for prefix in private_ranges):
                reputation_data["categories"].append("private_ip")
                reputation_data["threat_score"] = 0.1
            else:
                reputation_data["categories"].append("public_ip")
                reputation_data["threat_score"] = 0.3
                
            # Search web for IP reputation
            web_results = self.search_web_for_threat_intel(f"IP address {ip_address} malicious threat")
            if "malicious" in web_results.lower() or "threat" in web_results.lower():
                reputation_data["threat_score"] = 0.8
                reputation_data["is_malicious"] = True
                reputation_data["categories"].append("potentially_malicious")
            
        except Exception as e:
            reputation_data["error"] = str(e)
        
        return reputation_data
    
    def analyze_domain_reputation(self, domain: str) -> Dict:
        """Analyze domain reputation and threat indicators"""
        try:
            domain_data = {
                "domain": domain,
                "is_suspicious": False,
                "threat_categories": [],
                "reputation_score": 0,
                "indicators": []
            }
            
            # Check for suspicious patterns
            suspicious_patterns = [
                (len(domain) > 50, "very_long_domain"),
                (domain.count('-') > 4, "many_hyphens"),
                (any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']), "suspicious_tld"),
                (any(keyword in domain.lower() for keyword in ['phish', 'scam', 'fake', 'secure-', 'bank-']), "suspicious_keywords")
            ]
            
            for is_suspicious, indicator in suspicious_patterns:
                if is_suspicious:
                    domain_data["indicators"].append(indicator)
                    domain_data["reputation_score"] += 0.2
            
            if domain_data["reputation_score"] > 0.5:
                domain_data["is_suspicious"] = True
                domain_data["threat_categories"].append("potentially_malicious")
            
            # Search web for domain reputation
            web_results = self.search_web_for_threat_intel(f"domain {domain} malicious phishing")
            if "phishing" in web_results.lower() or "malicious" in web_results.lower():
                domain_data["reputation_score"] = min(domain_data["reputation_score"] + 0.4, 1.0)
                domain_data["is_suspicious"] = True
                domain_data["threat_categories"].append("web_reported_threat")
            
            return domain_data
            
        except Exception as e:
            return {"error": f"Domain analysis error: {e}"}
    
    def analyze_incident(self, incident_data: Dict) -> Dict[str, Any]:
        """Analyze security incident using AI reasoning"""
        logger.info(f"🔍 Analyzing incident: {incident_data.get('incident_id', 'Unknown')}")
        
        # Prepare comprehensive analysis prompt
        analysis_prompt = self._create_incident_analysis_prompt(incident_data)
        
        try:
            # Get AI analysis
            response = self.llm.invoke(analysis_prompt)
            analysis_result = self._parse_analysis_response(response.content)
            
            # Enhance with MITRE mapping
            analysis_result['mitre_analysis'] = self._map_to_mitre_techniques(incident_data)
            
            # Add confidence scoring
            analysis_result['confidence_score'] = self._calculate_confidence_score(analysis_result)
            
            # Generate recommendations
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
            
            logger.info("✅ Incident analysis completed")
            return analysis_result
            
        except Exception as e:
            logger.error(f"❌ Analysis failed: {e}")
            return {
                'error': str(e),
                'status': 'analysis_failed',
                'timestamp': datetime.now().isoformat()
            }
    
    def _create_incident_analysis_prompt(self, incident_data: Dict) -> str:
        """Create comprehensive analysis prompt for cybersec-ai"""
        prompt = f"""
You are a cybersecurity expert AI analyzing a security incident. Use your knowledge of MITRE ATT&CK, threat patterns, and security best practices.

INCIDENT DATA:
{json.dumps(incident_data, indent=2)}

Provide a comprehensive analysis including:

1. THREAT ASSESSMENT:
   - Threat type and severity level
   - Attack vector analysis
   - Potential impact assessment

2. TECHNICAL ANALYSIS:
   - Attack techniques identified
   - IOCs (Indicators of Compromise)
   - Timeline reconstruction

3. MITRE ATT&CK MAPPING:
   - Primary techniques used
   - Tactics employed
   - Attack progression

4. ROOT CAUSE ANALYSIS:
   - Initial compromise vector
   - Security control failures
   - Contributing factors

5. CONTAINMENT STRATEGY:
   - Immediate actions needed
   - Isolation requirements
   - Evidence preservation

6. REMEDIATION RECOMMENDATIONS:
   - Short-term fixes
   - Long-term improvements
   - Prevention measures

Format your response as a structured analysis with clear sections and actionable insights.
"""
        return prompt
    
    def _parse_analysis_response(self, response: str) -> Dict[str, Any]:
        """Parse AI analysis response into structured format"""
        return {
            'analysis_text': response,
            'timestamp': datetime.now().isoformat(),
            'analyzer': 'cybersec-ai',
            'status': 'completed'
        }
    
    def _map_to_mitre_techniques(self, incident_data: Dict) -> List[str]:
        """Map incident to MITRE ATT&CK techniques"""
        # Simple mapping based on incident characteristics
        techniques = []
        
        incident_type = incident_data.get('type', '').lower()
        if 'malware' in incident_type:
            techniques.extend(['T1059', 'T1055', 'T1027'])
        if 'phishing' in incident_type:
            techniques.extend(['T1566', 'T1204'])
        if 'lateral' in incident_type:
            techniques.extend(['T1021', 'T1078'])
            
        return techniques
    
    def _calculate_confidence_score(self, analysis: Dict) -> float:
        """Calculate confidence score for analysis"""
        # Simple confidence scoring based on available data
        base_score = 0.7
        
        if 'analysis_text' in analysis and len(analysis['analysis_text']) > 500:
            base_score += 0.1
        if 'mitre_analysis' in analysis and analysis['mitre_analysis']:
            base_score += 0.1
            
        return min(base_score, 1.0)
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = [
            "Review and validate the incident classification",
            "Implement recommended containment measures",
            "Update security controls based on findings",
            "Conduct post-incident review and lessons learned"
        ]
        
        return recommendations
    
    def explain_threat_intelligence(self, threat_data: Dict) -> str:
        """Explain threat intelligence in human-readable format"""
        explanation_prompt = f"""
As a cybersecurity expert, explain this threat intelligence data in clear, actionable terms:

THREAT DATA:
{json.dumps(threat_data, indent=2)}

Provide:
1. What this threat means for our organization
2. How attackers typically use this technique
3. Detection strategies we should implement
4. Mitigation recommendations

Make it understandable for both technical and non-technical stakeholders.
"""
        
        try:
            response = self.llm.invoke(explanation_prompt)
            return response.content
        except Exception as e:
            logger.error(f"Threat intelligence explanation failed: {e}")
            return f"Error generating explanation: {e}"
