"""
LLM Manager with Multiple Provider Support and Switching Capabilities
"""

import os
import json
import logging
import requests
from typing import Dict, Any, Optional, List
from enum import Enum

logger = logging.getLogger(__name__)

class LLMProvider(Enum):
    """Supported LLM providers"""
    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    LOCAL = "local"

class LLMManager:
    """
    Manages multiple LLM providers with automatic fallback and switching
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or self._default_config()
        self.current_provider = LLMProvider.OLLAMA
        self.providers = self._initialize_providers()
        self.fallback_order = [
            LLMProvider.OLLAMA,
            LLMProvider.LOCAL,
            LLMProvider.OPENAI,
            LLMProvider.ANTHROPIC,
            LLMProvider.GOOGLE
        ]
    
    def _default_config(self) -> Dict:
        """Default LLM configuration"""
        return {
            'ollama': {
                'enabled': True,
                'endpoint': 'http://localhost:11434/api/generate',
                'model': 'cybersec-ai',  # Your custom cybersecurity model
                'temperature': 0.7,
                'max_tokens': 2000
            },
            'openai': {
                'enabled': False,
                'api_key': os.getenv('OPENAI_API_KEY', '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'),
                'model': 'gpt-4',
                'temperature': 0.7,
                'max_tokens': 2000
            },
            'anthropic': {
                'enabled': False,
                'api_key': os.getenv('ANTHROPIC_API_KEY', ''),
                'model': 'claude-3-opus',
                'temperature': 0.7,
                'max_tokens': 2000
            },
            'google': {
                'enabled': False,
                'api_key': os.getenv('GOOGLE_API_KEY', ''),
                'model': 'gemini-pro',
                'temperature': 0.7,
                'max_tokens': 2000
            },
            'local': {
                'enabled': True,
                'type': 'mock',  # or 'huggingface'
                'model': 'mock-llm'
            }
        }
    
    def _initialize_providers(self) -> Dict:
        """Initialize available providers"""
        providers = {}
        
        # Ollama
        if self.config['ollama']['enabled']:
            providers[LLMProvider.OLLAMA] = OllamaProvider(self.config['ollama'])
        
        # OpenAI
        if self.config['openai']['enabled'] and self.config['openai']['api_key']:
            providers[LLMProvider.OPENAI] = OpenAIProvider(self.config['openai'])
        
        # Anthropic
        if self.config['anthropic']['enabled'] and self.config['anthropic']['api_key']:
            providers[LLMProvider.ANTHROPIC] = AnthropicProvider(self.config['anthropic'])
        
        # Google
        if self.config['google']['enabled'] and self.config['google']['api_key']:
            providers[LLMProvider.GOOGLE] = GoogleProvider(self.config['google'])
        
        # Local/Mock
        if self.config['local']['enabled']:
            providers[LLMProvider.LOCAL] = LocalProvider(self.config['local'])
        
        return providers
    
    async def generate(self, prompt: str, provider: LLMProvider = None, **kwargs) -> str:
        """
        Generate response from LLM with automatic fallback
        """
        provider = provider or self.current_provider
        
        # Try specified provider first
        if provider in self.providers:
            try:
                response = await self.providers[provider].generate(prompt, **kwargs)
                if response:
                    return response
            except Exception as e:
                logger.warning(f"Provider {provider.value} failed: {e}")
        
        # Fallback to other providers
        for fallback_provider in self.fallback_order:
            if fallback_provider != provider and fallback_provider in self.providers:
                try:
                    logger.info(f"Falling back to {fallback_provider.value}")
                    response = await self.providers[fallback_provider].generate(prompt, **kwargs)
                    if response:
                        self.current_provider = fallback_provider  # Switch to working provider
                        return response
                except Exception as e:
                    logger.warning(f"Fallback provider {fallback_provider.value} failed: {e}")
        
        # If all fail, return a basic response
        return self._emergency_response(prompt)
    
    def switch_provider(self, provider: LLMProvider) -> bool:
        """Manually switch to a specific provider"""
        if provider in self.providers:
            self.current_provider = provider
            logger.info(f"Switched to {provider.value}")
            return True
        return False
    
    def get_available_providers(self) -> List[str]:
        """Get list of available providers"""
        return [p.value for p in self.providers.keys()]
    
    def _emergency_response(self, prompt: str) -> str:
        """Emergency response when all LLMs fail"""
        if "network" in prompt.lower():
            return "Network analysis: Multiple endpoints detected. Recommend phased approach."
        elif "attack" in prompt.lower():
            return "Attack plan: Use T1566 for initial access, T1055 for privilege escalation, T1021 for lateral movement."
        elif "vulnerability" in prompt.lower():
            return "Vulnerabilities detected: SMB exposure, weak authentication, unpatched systems."
        else:
            return "Analysis complete. Proceed with standard security assessment."


class OllamaProvider:
    """Ollama LLM provider"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.endpoint = config['endpoint']
        self.model = config['model']
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate response from Ollama"""
        try:
            response = requests.post(
                self.endpoint,
                json={
                    'model': self.model,
                    'prompt': prompt,
                    'temperature': kwargs.get('temperature', self.config['temperature']),
                    'max_tokens': kwargs.get('max_tokens', self.config['max_tokens']),
                    'stream': False
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json().get('response', '')
            else:
                raise Exception(f"Ollama error: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            raise Exception("Ollama not running. Start with: ollama serve")
        except Exception as e:
            raise Exception(f"Ollama error: {e}")


class OpenAIProvider:
    """OpenAI LLM provider"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.api_key = config['api_key']
        self.model = config['model']
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate response from OpenAI"""
        try:
            # Import openai if available
            import openai
            openai.api_key = self.api_key
            
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=kwargs.get('temperature', self.config['temperature']),
                max_tokens=kwargs.get('max_tokens', self.config['max_tokens'])
            )
            
            return response.choices[0].message.content
            
        except ImportError:
            raise Exception("OpenAI library not installed. Run: pip install openai")
        except Exception as e:
            raise Exception(f"OpenAI error: {e}")


class AnthropicProvider:
    """Anthropic Claude provider"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.api_key = config['api_key']
        self.model = config['model']
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate response from Anthropic"""
        try:
            # Import anthropic if available
            import anthropic
            client = anthropic.Client(api_key=self.api_key)
            
            response = client.completions.create(
                model=self.model,
                prompt=f"\n\nHuman: {prompt}\n\nAssistant:",
                max_tokens_to_sample=kwargs.get('max_tokens', self.config['max_tokens']),
                temperature=kwargs.get('temperature', self.config['temperature'])
            )
            
            return response.completion
            
        except ImportError:
            raise Exception("Anthropic library not installed. Run: pip install anthropic")
        except Exception as e:
            raise Exception(f"Anthropic error: {e}")


class GoogleProvider:
    """Google Gemini provider"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.api_key = config['api_key']
        self.model = config['model']
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate response from Google Gemini"""
        try:
            # Import google.generativeai if available
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            
            model = genai.GenerativeModel(self.model)
            response = model.generate_content(prompt)
            
            return response.text
            
        except ImportError:
            raise Exception("Google AI library not installed. Run: pip install google-generativeai")
        except Exception as e:
            raise Exception(f"Google AI error: {e}")


class LocalProvider:
    """Local/Mock LLM provider for testing"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.responses = {
            'network': self._network_analysis,
            'attack': self._attack_planning,
            'vulnerability': self._vulnerability_analysis,
            'scenario': self._scenario_generation
        }
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate mock response based on prompt content"""
        prompt_lower = prompt.lower()
        
        for key, response_func in self.responses.items():
            if key in prompt_lower:
                return response_func(prompt)
        
        return self._default_response(prompt)
    
    def _network_analysis(self, prompt: str) -> str:
        """Mock network analysis response"""
        return json.dumps({
            'analysis': 'Network topology analyzed',
            'findings': {
                'total_endpoints': 25,
                'critical_systems': ['DC01', 'SQL01', 'WEB01'],
                'network_segments': ['DMZ', 'Internal', 'Management'],
                'pivot_points': ['PROXY01', 'VPN01'],
                'high_value_targets': ['CEO-PC', 'CFO-PC', 'HR-DB']
            },
            'recommendations': [
                'Target low-privilege endpoints first',
                'Use DC01 for lateral movement',
                'Exfiltrate from SQL01 and HR-DB'
            ]
        }, indent=2)
    
    def _attack_planning(self, prompt: str) -> str:
        """Mock attack planning response"""
        return json.dumps({
            'attack_plan': {
                'phase_1': {
                    'name': 'Initial Access',
                    'techniques': ['T1566 - Phishing', 'T1078 - Valid Accounts'],
                    'targets': ['user workstations'],
                    'duration': '30 minutes'
                },
                'phase_2': {
                    'name': 'Privilege Escalation',
                    'techniques': ['T1055 - Process Injection', 'T1053 - Scheduled Task'],
                    'targets': ['compromised endpoints'],
                    'duration': '45 minutes'
                },
                'phase_3': {
                    'name': 'Lateral Movement',
                    'techniques': ['T1021 - Remote Services', 'T1570 - Lateral Tool Transfer'],
                    'targets': ['domain controller', 'file servers'],
                    'duration': '60 minutes'
                },
                'phase_4': {
                    'name': 'Data Exfiltration',
                    'techniques': ['T1048 - Exfiltration Over Alternative Protocol'],
                    'targets': ['database servers', 'file shares'],
                    'duration': '90 minutes'
                }
            },
            'total_duration': '225 minutes',
            'risk_level': 'high'
        }, indent=2)
    
    def _vulnerability_analysis(self, prompt: str) -> str:
        """Mock vulnerability analysis response"""
        return json.dumps({
            'vulnerabilities': [
                {
                    'endpoint': 'WEB01',
                    'vulnerabilities': ['SQL Injection', 'XSS', 'Outdated framework'],
                    'severity': 'critical',
                    'exploit_available': True
                },
                {
                    'endpoint': 'DC01',
                    'vulnerabilities': ['Kerberoasting possible', 'SMB signing disabled'],
                    'severity': 'high',
                    'exploit_available': True
                },
                {
                    'endpoint': 'WORKSTATION-05',
                    'vulnerabilities': ['Unpatched OS', 'Local privilege escalation'],
                    'severity': 'medium',
                    'exploit_available': True
                }
            ],
            'summary': {
                'critical': 1,
                'high': 2,
                'medium': 5,
                'low': 3
            }
        }, indent=2)
    
    def _scenario_generation(self, prompt: str) -> str:
        """Mock scenario generation response"""
        return json.dumps({
            'scenarios': [
                {
                    'name': 'APT Simulation',
                    'description': 'Advanced persistent threat with data exfiltration',
                    'techniques': ['T1566', 'T1055', 'T1003', 'T1021', 'T1048'],
                    'duration': '4 hours',
                    'objectives': ['persistence', 'data_theft']
                },
                {
                    'name': 'Ransomware Attack',
                    'description': 'Fast-moving ransomware with encryption',
                    'techniques': ['T1566', 'T1055', 'T1021', 'T1486', 'T1490'],
                    'duration': '1 hour',
                    'objectives': ['disruption', 'financial_gain']
                },
                {
                    'name': 'Insider Threat',
                    'description': 'Malicious insider stealing sensitive data',
                    'techniques': ['T1078', 'T1005', 'T1074', 'T1048'],
                    'duration': '2 hours',
                    'objectives': ['data_theft', 'espionage']
                }
            ]
        }, indent=2)
    
    def _default_response(self, prompt: str) -> str:
        """Default mock response"""
        return f"Processed request: {prompt[:100]}... Analysis complete."


# Singleton instance
llm_manager = LLMManager()
