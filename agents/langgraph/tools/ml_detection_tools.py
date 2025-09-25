"""
ML Model Integration Tools for Detection System
Loads and uses pre-trained ML models for threat detection
"""

import os
import json
import pickle
import logging
import numpy as np
import sqlite3
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

logger = logging.getLogger(__name__)

class MLModelManager:
    """Manages multiple ML models for threat detection"""
    
    def __init__(self, models_path: str = "ml_models/trained_models"):
        self.models_path = models_path
        self.loaded_models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.model_metadata = {}
        
        # Load all available models
        self._load_models()
    
    def _load_models(self):
        """Load all trained models from directory"""
        if not os.path.exists(self.models_path):
            logger.warning(f"Models directory not found: {self.models_path}")
            # Create default models if directory doesn't exist
            self._create_default_models()
            return
        
        try:
            # Load anomaly detection model
            anomaly_path = os.path.join(self.models_path, "anomaly_detector.pkl")
            if os.path.exists(anomaly_path):
                self.loaded_models['anomaly'] = joblib.load(anomaly_path)
                logger.info("Loaded anomaly detection model")
            
            # Load malware detection model
            malware_path = os.path.join(self.models_path, "malware_classifier.pkl")
            if os.path.exists(malware_path):
                self.loaded_models['malware'] = joblib.load(malware_path)
                logger.info("Loaded malware detection model")
            
            # Load network intrusion model
            network_path = os.path.join(self.models_path, "network_intrusion.pkl")
            if os.path.exists(network_path):
                self.loaded_models['network'] = joblib.load(network_path)
                logger.info("Loaded network intrusion model")
            
            # Load text vectorizer for log analysis
            vectorizer_path = os.path.join(self.models_path, "log_vectorizer.pkl")
            if os.path.exists(vectorizer_path):
                self.vectorizers['logs'] = joblib.load(vectorizer_path)
                logger.info("Loaded log vectorizer")
            
            # Load feature scaler
            scaler_path = os.path.join(self.models_path, "feature_scaler.pkl")
            if os.path.exists(scaler_path):
                self.scalers['default'] = joblib.load(scaler_path)
                logger.info("Loaded feature scaler")
            
            # Load model metadata
            metadata_path = os.path.join(self.models_path, "models_metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    self.model_metadata = json.load(f)
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            self._create_default_models()
    
    def _create_default_models(self):
        """Create default models if pre-trained ones don't exist"""
        logger.info("Creating default ML models")
        
        # Create directory if it doesn't exist
        os.makedirs(self.models_path, exist_ok=True)
        
        # Default Isolation Forest for anomaly detection
        self.loaded_models['anomaly'] = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Default Random Forest for classification
        self.loaded_models['malware'] = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )
        
        # Default network intrusion detector
        self.loaded_models['network'] = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        
        # Default TF-IDF vectorizer for logs
        self.vectorizers['logs'] = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3)
        )
        
        # Default scaler
        self.scalers['default'] = StandardScaler()
        
        # Metadata
        self.model_metadata = {
            'created_at': datetime.now(timezone.utc).isoformat(),
            'models': {
                'anomaly': {'type': 'IsolationForest', 'trained': False},
                'malware': {'type': 'RandomForestClassifier', 'trained': False},
                'network': {'type': 'IsolationForest', 'trained': False}
            }
        }
    
    def predict_anomaly(self, features: np.ndarray) -> Tuple[List[int], List[float]]:
        """
        Predict anomalies using Isolation Forest
        Returns: (predictions, anomaly_scores)
        """
        try:
            if 'anomaly' not in self.loaded_models:
                return [], []
            
            model = self.loaded_models['anomaly']
            
            # Ensure features are 2D
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            
            # Scale features if scaler available
            if 'default' in self.scalers:
                try:
                    features = self.scalers['default'].transform(features)
                except:
                    # If scaler not fitted, fit it first
                    features = self.scalers['default'].fit_transform(features)
            
            # Predict (-1 for anomaly, 1 for normal)
            predictions = model.predict(features)
            scores = model.score_samples(features)
            
            # Convert to binary (1 for anomaly, 0 for normal)
            binary_predictions = [1 if p == -1 else 0 for p in predictions]
            
            return binary_predictions, scores.tolist()
            
        except Exception as e:
            logger.error(f"Anomaly prediction error: {e}")
            return [], []
    
    def predict_malware(self, features: np.ndarray) -> Tuple[List[int], List[float]]:
        """
        Predict malware using classifier
        Returns: (predictions, confidence_scores)
        """
        try:
            if 'malware' not in self.loaded_models:
                return [], []
            
            model = self.loaded_models['malware']
            
            # Ensure features are 2D
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            
            # Check if model is fitted
            if not hasattr(model, 'classes_'):
                # Return default for unfitted model
                return [0] * features.shape[0], [0.5] * features.shape[0]
            
            predictions = model.predict(features)
            probabilities = model.predict_proba(features)
            
            # Get confidence scores (probability of positive class)
            confidence_scores = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]
            
            return predictions.tolist(), confidence_scores.tolist()
            
        except Exception as e:
            logger.error(f"Malware prediction error: {e}")
            return [], []
    
    def analyze_logs(self, log_texts: List[str]) -> Dict[str, Any]:
        """
        Analyze log texts using TF-IDF and ML models
        """
        try:
            if not log_texts:
                return {'success': False, 'error': 'No logs provided'}
            
            # Vectorize logs
            if 'logs' in self.vectorizers:
                try:
                    features = self.vectorizers['logs'].transform(log_texts)
                except:
                    # If vectorizer not fitted, fit it first
                    features = self.vectorizers['logs'].fit_transform(log_texts)
                
                features_array = features.toarray()
            else:
                # Simple feature extraction if no vectorizer
                features_array = self._extract_simple_features(log_texts)
            
            # Run through anomaly detection
            anomaly_predictions, anomaly_scores = self.predict_anomaly(features_array)
            
            # Run through malware detection (if we have enough features)
            if features_array.shape[1] >= 10:
                malware_predictions, malware_confidence = self.predict_malware(features_array)
            else:
                malware_predictions = [0] * len(log_texts)
                malware_confidence = [0.0] * len(log_texts)
            
            # Combine results
            results = []
            for i, log in enumerate(log_texts):
                results.append({
                    'log': log[:200],  # First 200 chars
                    'anomaly_detected': anomaly_predictions[i] if i < len(anomaly_predictions) else 0,
                    'anomaly_score': anomaly_scores[i] if i < len(anomaly_scores) else 0.0,
                    'malware_detected': malware_predictions[i] if i < len(malware_predictions) else 0,
                    'malware_confidence': malware_confidence[i] if i < len(malware_confidence) else 0.0,
                    'threat_level': self._calculate_threat_level(
                        anomaly_predictions[i] if i < len(anomaly_predictions) else 0,
                        malware_predictions[i] if i < len(malware_predictions) else 0,
                        anomaly_scores[i] if i < len(anomaly_scores) else 0.0
                    )
                })
            
            return {
                'success': True,
                'total_logs': len(log_texts),
                'anomalies_found': sum(anomaly_predictions),
                'malware_found': sum(malware_predictions),
                'results': results
            }
            
        except Exception as e:
            logger.error(f"Log analysis error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _extract_simple_features(self, logs: List[str]) -> np.ndarray:
        """Extract simple features from logs when vectorizer not available"""
        features = []
        
        for log in logs:
            log_features = [
                len(log),  # Length
                log.count(' '),  # Word count
                log.count('error'),  # Error keywords
                log.count('failed'),  # Failed keywords
                log.count('denied'),  # Denied keywords
                log.count('unauthorized'),  # Unauthorized keywords
                log.count('.exe'),  # Executable references
                log.count('powershell'),  # PowerShell references
                log.count('cmd'),  # CMD references
                log.count('127.0.0.1'),  # Localhost references
                log.count('0.0.0.0'),  # Any interface references
                1 if 'admin' in log.lower() else 0,  # Admin activity
                1 if 'root' in log.lower() else 0,  # Root activity
                1 if 'sudo' in log.lower() else 0,  # Sudo activity
                1 if any(port in log for port in ['445', '3389', '22', '23']) else 0  # Suspicious ports
            ]
            features.append(log_features)
        
        return np.array(features)
    
    def _calculate_threat_level(self, anomaly: int, malware: int, anomaly_score: float) -> str:
        """Calculate overall threat level"""
        if malware == 1 and anomaly == 1:
            return 'critical'
        elif malware == 1 or (anomaly == 1 and anomaly_score < -0.5):
            return 'high'
        elif anomaly == 1:
            return 'medium'
        else:
            return 'low'
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            'loaded_models': list(self.loaded_models.keys()),
            'vectorizers': list(self.vectorizers.keys()),
            'scalers': list(self.scalers.keys()),
            'metadata': self.model_metadata
        }


class LogEnrichmentTool:
    """Tool for enriching logs with contextual information"""
    
    def __init__(self, db_path: str = "soc_database.db"):
        self.db_path = db_path
        self.name = "log_enrichment"
        self.description = "Enrich logs with agent and network context"
    
    def run(self, logs: List[Dict]) -> List[Dict]:
        """
        Enrich logs with additional context
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            enriched_logs = []
            
            for log in logs:
                agent_id = log.get('agent_id')
                
                # Get agent information
                cursor.execute("""
                    SELECT hostname, ip_address, platform, endpoint_importance, 
                           user_role, security_zone
                    FROM agents 
                    WHERE id = ?
                """, (agent_id,))
                
                agent_info = cursor.fetchone()
                
                enriched_log = log.copy()
                
                if agent_info:
                    enriched_log['agent_hostname'] = agent_info[0]
                    enriched_log['agent_ip'] = agent_info[1]
                    enriched_log['agent_platform'] = agent_info[2]
                    enriched_log['agent_importance'] = agent_info[3] or 'medium'
                    enriched_log['agent_role'] = agent_info[4] or 'unknown'
                    enriched_log['security_zone'] = agent_info[5] or 'internal'
                    
                    # Add risk multiplier based on agent importance
                    if agent_info[3] == 'critical':
                        enriched_log['risk_multiplier'] = 2.0
                    elif agent_info[3] == 'high':
                        enriched_log['risk_multiplier'] = 1.5
                    else:
                        enriched_log['risk_multiplier'] = 1.0
                
                # Add temporal context
                enriched_log['hour_of_day'] = datetime.fromisoformat(
                    log.get('timestamp', datetime.now(timezone.utc).isoformat())
                ).hour
                
                enriched_log['is_business_hours'] = 8 <= enriched_log['hour_of_day'] <= 18
                
                enriched_logs.append(enriched_log)
            
            conn.close()
            
            return enriched_logs
            
        except Exception as e:
            logger.error(f"Log enrichment error: {e}")
            return logs  # Return original if enrichment fails


class ThreatIntelligenceTool:
    """Tool for checking logs against threat intelligence"""
    
    def __init__(self):
        self.name = "threat_intelligence"
        self.description = "Check logs against known threat indicators"
        
        # Simulated threat intelligence database
        self.iocs = {
            'malicious_ips': [
                '192.168.1.100',  # Example malicious IPs
                '10.0.0.50',
                '172.16.0.25'
            ],
            'malicious_domains': [
                'evil.com',
                'malware-c2.net',
                'phishing-site.org'
            ],
            'malicious_hashes': [
                'd41d8cd98f00b204e9800998ecf8427e',
                '098f6bcd4621d373cade4e832627b4f6'
            ],
            'suspicious_processes': [
                'mimikatz.exe',
                'lazagne.exe',
                'procdump.exe',
                'psexec.exe'
            ],
            'attack_patterns': [
                'powershell -enc',
                'cmd /c echo',
                'wmic process call create',
                'net user /add',
                'reg add HKLM'
            ]
        }
    
    def run(self, logs: List[Dict]) -> Dict[str, Any]:
        """
        Check logs against threat intelligence
        """
        threats_found = []
        
        for log in logs:
            log_text = str(log.get('message', '')) + str(log.get('data', ''))
            log_lower = log_text.lower()
            
            # Check for malicious IPs
            for ip in self.iocs['malicious_ips']:
                if ip in log_text:
                    threats_found.append({
                        'log_id': log.get('id'),
                        'type': 'malicious_ip',
                        'indicator': ip,
                        'severity': 'high'
                    })
            
            # Check for malicious domains
            for domain in self.iocs['malicious_domains']:
                if domain in log_lower:
                    threats_found.append({
                        'log_id': log.get('id'),
                        'type': 'malicious_domain',
                        'indicator': domain,
                        'severity': 'critical'
                    })
            
            # Check for suspicious processes
            for process in self.iocs['suspicious_processes']:
                if process in log_lower:
                    threats_found.append({
                        'log_id': log.get('id'),
                        'type': 'suspicious_process',
                        'indicator': process,
                        'severity': 'high'
                    })
            
            # Check for attack patterns
            for pattern in self.iocs['attack_patterns']:
                if pattern in log_lower:
                    threats_found.append({
                        'log_id': log.get('id'),
                        'type': 'attack_pattern',
                        'indicator': pattern,
                        'severity': 'critical'
                    })
        
        return {
            'success': True,
            'threats_found': len(threats_found),
            'threat_details': threats_found,
            'checked_logs': len(logs)
        }
