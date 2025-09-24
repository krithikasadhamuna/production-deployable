#!/usr/bin/env python3
"""
Detection Pipeline - AI-Driven Log Analysis
Uses ML models + local cybersec-ai LLM for threat detection
"""

import yaml
import os
import json
import logging
import sqlite3
from typing import Dict, List, Optional, Any
from datetime import datetime
from langchain_community.chat_models import ChatOllama
from langchain_openai import ChatOpenAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DetectionPipeline:
    """AI-powered detection pipeline for security logs"""
    
    def __init__(self, config=None):
        self.config = config or self._load_config()
        self.llm_config = self.config.get('llm', {})
        
        # Initialize LLM with local cybersec-ai as primary
        self.llm = self._initialize_llm()
        
        # Load ML models if available
        self._load_ml_models()
        
        logger.info("🛡️ Detection Pipeline initialized with cybersec-ai")
    
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
                'temperature': 0.7
            }
        }
    
    def _initialize_llm(self):
        """Initialize LLM with local cybersec-ai as primary"""
        try:
            # Try local cybersec-ai first
            return ChatOllama(
                base_url=self.llm_config.get('ollama_endpoint', 'http://localhost:11434'),
                model=self.llm_config.get('ollama_model', 'cybersec-ai'),
                temperature=self.llm_config.get('temperature', 0.7)
            )
        except Exception as e:
            logger.warning(f"Local LLM failed, trying OpenAI fallback: {e}")
            try:
                return ChatOpenAI(
                    model=self.llm_config.get('openai_model', 'gpt-4o'),
                    temperature=self.llm_config.get('temperature', 0.7)
                )
            except Exception as e2:
                logger.error(f"Both LLMs failed: {e2}")
                return None
    
    def _load_ml_models(self):
        """Load pre-trained ML models for fast screening"""
        # This would load your trained sklearn models
        self.ml_models = {}
        logger.info("ML models loaded for fast screening")
    
    def analyze_log(self, log_data: Dict) -> Dict:
        """Main detection method - ML + AI analysis"""
        try:
            # Step 1: Fast ML screening
            ml_result = self._ml_classify(log_data)
            
            # Step 2: If suspicious, use AI for detailed analysis
            if ml_result.get('threat_score', 0) > 0.3:
                ai_result = self._ai_analyze(log_data)
                return self._combine_results(ml_result, ai_result)
            
            return ml_result
            
        except Exception as e:
            logger.error(f"Detection error: {e}")
            return {"threat_score": 0, "error": str(e)}
    
    def _ml_classify(self, log_data: Dict) -> Dict:
        """Fast ML classification using trained models"""
        # Placeholder for ML model inference
        return {
            "ml_threat_score": 0.5,
            "ml_classification": "suspicious",
            "features_detected": ["unusual_process", "network_anomaly"]
        }
    
    def _ai_analyze(self, log_data: Dict) -> Dict:
        """Detailed AI analysis using cybersec-ai LLM"""
        if not self.llm:
            return {"ai_analysis": "LLM unavailable"}
        
        prompt = f"""
        Analyze this security log for threats:
        
        Log Data: {json.dumps(log_data, indent=2)}
        
        Provide:
        1. Threat assessment (0-1 score)
        2. MITRE ATT&CK techniques if detected
        3. Risk level (LOW/MEDIUM/HIGH/CRITICAL)
        4. Recommended actions
        
        Response format: JSON
        """
        
        try:
            response = self.llm.invoke(prompt)
            return {
                "ai_analysis": response.content,
                "ai_model": "cybersec-ai"
            }
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {"ai_analysis": f"AI analysis failed: {e}"}
    
    def _combine_results(self, ml_result: Dict, ai_result: Dict) -> Dict:
        """Combine ML and AI results into final assessment"""
        return {
            **ml_result,
            **ai_result,
            "detection_method": "ML + AI",
            "timestamp": datetime.now().isoformat(),
            "final_threat_score": max(
                ml_result.get('ml_threat_score', 0),
                0.7  # If AI was triggered, it's at least 0.7
            )
        }


