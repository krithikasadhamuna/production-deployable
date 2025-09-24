#!/usr/bin/env python3
"""
CodeGrey SOC - ML/AI Threat Detection Models
Core machine learning models for threat detection and classification
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Tuple
import boto3
import yaml

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONFIG_PATH = os.getenv('SOC_CONFIG_PATH', '../config/config.yaml')

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

class ThreatDetectionModels:
    """Core ML models for SOC threat detection"""
    
    def __init__(self, s3_bucket=None, config=None):
        self.config = config or load_config()
        self.s3_bucket = s3_bucket or self.config.get('s3', {}).get('bucket')
        # Use trained_models as default
        self.models_dir = self.config.get('ml_models', {}).get('model_dir', 'ml_models/trained_models')
        os.makedirs(self.models_dir, exist_ok=True)
        
        # Initialize models
        self.anomaly_detector = None
        self.threat_classifier = None
        self.log_vectorizer = None
        self.feature_scaler = None
        
        # Model metadata
        self.model_versions = {}
        self.model_performance = {}
        
        # Load existing models (do NOT train new ones)
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models from local storage or S3. Do NOT train new ones if missing."""
        try:
            local_models = {
                'anomaly_detector': 'network_random_forest.pkl',
                'threat_classifier': 'attack_log_classifier.pkl',
                'log_vectorizer': 'attack_log_vectorizer.pkl',
                'feature_scaler': 'platform_encoder.pkl'
            }
            models_loaded = 0
            missing_models = []
            for model_name, filename in local_models.items():
                local_path = os.path.join(self.models_dir, filename)
                if os.path.exists(local_path):
                    with open(local_path, 'rb') as f:
                        setattr(self, model_name, pickle.load(f))
                    models_loaded += 1
                    logger.info(f"Loaded {model_name} from {local_path}")
                else:
                    missing_models.append(filename)
            if models_loaded < len(local_models):
                raise FileNotFoundError(f"Missing model files: {missing_models}. Please upload all required models to {self.models_dir} before starting the server.")
            logger.info(f"Loaded {models_loaded}/{len(local_models)} ML models successfully")
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise
    
    def _download_model_from_s3(self, model_name: str, filename: str) -> bool:
        """Download model from S3 if available"""
        try:
            if not self.s3_bucket:
                return False
                
            s3_client = boto3.client('s3')
            local_path = os.path.join(self.models_dir, filename)
            s3_key = f"ml_models/{filename}"
            
            s3_client.download_file(self.s3_bucket, s3_key, local_path)
            
            with open(local_path, 'rb') as f:
                setattr(self, model_name, pickle.load(f))
            
            logger.info(f"Downloaded and loaded {model_name} from S3")
            return True
            
        except Exception as e:
            logger.warning(f"Could not download {model_name} from S3: {e}")
            return False
    
    def _upload_model_to_s3(self, model_name: str, filename: str) -> bool:
        """Upload trained model to S3"""
        try:
            if not self.s3_bucket:
                return False
                
            s3_client = boto3.client('s3')
            local_path = os.path.join(self.models_dir, filename)
            s3_key = f"ml_models/{filename}"
            
            s3_client.upload_file(local_path, self.s3_bucket, s3_key)
            logger.info(f"Uploaded {model_name} to S3")
            return True
            
        except Exception as e:
            logger.error(f"Could not upload {model_name} to S3: {e}")
            return False
    
    def _train_default_models(self):
        """Train default models with synthetic data"""
        logger.info("Training default ML models with synthetic data...")
        
        # Generate synthetic training data
        synthetic_data = self._generate_synthetic_training_data()
        
        # Train anomaly detector
        self._train_anomaly_detector(synthetic_data['normal_logs'])
        
        # Train threat classifier
        self._train_threat_classifier(
            synthetic_data['all_logs'],
            synthetic_data['labels']
        )
        
        # Save models
        self._save_models()
        
        logger.info("Default models trained and saved successfully")
    
    def _generate_synthetic_training_data(self) -> Dict[str, Any]:
        """Generate synthetic training data for initial model training"""
        
        # Normal system logs
        normal_logs = [
            "User login successful for admin",
            "System service started successfully", 
            "File access: /var/log/system.log",
            "Network connection established to 192.168.1.100",
            "Process started: chrome.exe PID:1234",
            "Memory usage: 45% CPU usage: 12%",
            "Disk I/O: Read 1024KB Write 512KB",
            "User logout successful",
            "System backup completed",
            "Database query executed in 0.05s"
        ] * 100  # Repeat to create larger dataset
        
        # Malicious/suspicious logs
        malicious_logs = [
            "Multiple failed login attempts for admin",
            "Suspicious process: cmd.exe /c whoami",
            "Outbound connection to unknown IP: 185.220.101.42",
            "File encryption detected: ransomware.exe",
            "Privilege escalation attempt detected",
            "Suspicious PowerShell execution: Invoke-Expression",
            "Large data transfer to external IP",
            "Suspicious registry modification detected",
            "Process hollowing technique detected",
            "Command and control communication detected"
        ] * 50  # Fewer malicious examples (realistic ratio)
        
        # Combine all logs
        all_logs = normal_logs + malicious_logs
        
        # Create labels (0 = normal, 1 = malicious)
        labels = [0] * len(normal_logs) + [1] * len(malicious_logs)
        
        return {
            'normal_logs': normal_logs,
            'all_logs': all_logs,
            'labels': labels
        }
    
    def _train_anomaly_detector(self, normal_logs: List[str]):
        """Train anomaly detection model"""
        try:
            # Vectorize text logs
            self.log_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
            log_features = self.log_vectorizer.fit_transform(normal_logs)
            
            # Scale features
            self.feature_scaler = StandardScaler(with_mean=False)  # Sparse matrix compatibility
            scaled_features = self.feature_scaler.fit_transform(log_features)
            
            # Train isolation forest for anomaly detection
            self.anomaly_detector = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=100
            )
            
            self.anomaly_detector.fit(scaled_features)
            
            # Test on training data
            anomaly_scores = self.anomaly_detector.decision_function(scaled_features)
            anomaly_predictions = self.anomaly_detector.predict(scaled_features)
            
            normal_count = np.sum(anomaly_predictions == 1)
            anomaly_count = np.sum(anomaly_predictions == -1)
            
            logger.info(f"Anomaly detector trained: {normal_count} normal, {anomaly_count} anomalies detected")
            
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}")
    
    def _train_threat_classifier(self, logs: List[str], labels: List[int]):
        """Train threat classification model"""
        try:
            # Use the already fitted vectorizer
            if not self.log_vectorizer:
                self.log_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
                log_features = self.log_vectorizer.fit_transform(logs)
            else:
                log_features = self.log_vectorizer.transform(logs)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                log_features, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            # Train random forest classifier
            self.threat_classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10,
                min_samples_split=5
            )
            
            self.threat_classifier.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = self.threat_classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Store performance metrics
            self.model_performance['threat_classifier'] = {
                'accuracy': accuracy,
                'training_samples': len(logs),
                'trained_at': datetime.now().isoformat()
            }
            
            logger.info(f"Threat classifier trained with accuracy: {accuracy:.3f}")
            
        except Exception as e:
            logger.error(f"Error training threat classifier: {e}")
    
    def _save_models(self):
        """Save trained models to disk and S3"""
        try:
            models_to_save = {
                'anomaly_detector': self.anomaly_detector,
                'threat_classifier': self.threat_classifier,
                'log_vectorizer': self.log_vectorizer,
                'feature_scaler': self.feature_scaler
            }
            
            for model_name, model_obj in models_to_save.items():
                if model_obj is not None:
                    filename = f"{model_name}.pkl"
                    local_path = os.path.join(self.models_dir, filename)
                    
                    # Save locally
                    with open(local_path, 'wb') as f:
                        pickle.dump(model_obj, f)
                    
                    # Upload to S3
                    self._upload_model_to_s3(model_name, filename)
            
            # Save metadata
            metadata = {
                'model_versions': self.model_versions,
                'model_performance': self.model_performance,
                'last_updated': datetime.now().isoformat()
            }
            
            metadata_path = os.path.join(self.models_dir, 'model_metadata.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("All models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def detect_anomaly(self, log_text: str) -> Tuple[bool, float]:
        """Detect if a log entry is anomalous"""
        try:
            if not self.anomaly_detector or not self.log_vectorizer:
                logger.warning("Anomaly detector not available")
                return False, 0.0
            
            # Vectorize the log
            log_vector = self.log_vectorizer.transform([log_text])
            
            # Scale features
            if self.feature_scaler:
                log_vector = self.feature_scaler.transform(log_vector)
            
            # Predict anomaly
            anomaly_score = self.anomaly_detector.decision_function(log_vector)[0]
            is_anomaly = self.anomaly_detector.predict(log_vector)[0] == -1
            
            # Convert score to probability-like value (0-1)
            anomaly_probability = max(0, min(1, (0.5 - anomaly_score) * 2))
            
            return is_anomaly, anomaly_probability
            
        except Exception as e:
            logger.error(f"Error detecting anomaly: {e}")
            return False, 0.0
    
    def classify_threat(self, log_text: str) -> Tuple[str, float]:
        """Classify threat type and confidence"""
        try:
            if not self.threat_classifier or not self.log_vectorizer:
                logger.warning("Threat classifier not available")
                return "unknown", 0.0
            
            # Vectorize the log
            log_vector = self.log_vectorizer.transform([log_text])
            
            # Predict threat
            threat_prediction = self.threat_classifier.predict(log_vector)[0]
            threat_probability = self.threat_classifier.predict_proba(log_vector)[0]
            
            # Map prediction to threat type
            threat_types = {0: "normal", 1: "malicious"}
            threat_type = threat_types.get(threat_prediction, "unknown")
            
            # Get confidence (probability of predicted class)
            confidence = max(threat_probability)
            
            return threat_type, confidence
            
        except Exception as e:
            logger.error(f"Error classifying threat: {e}")
            return "unknown", 0.0
    
    def analyze_log_entry(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Complete analysis of a log entry"""
        try:
            log_text = log_data.get('raw_text', '') or str(log_data.get('data', ''))
            
            # Anomaly detection
            is_anomaly, anomaly_score = self.detect_anomaly(log_text)
            
            # Threat classification
            threat_type, threat_confidence = self.classify_threat(log_text)
            
            # Calculate overall risk score
            risk_score = (anomaly_score * 0.4 + threat_confidence * 0.6) * 10
            if threat_type == "malicious":
                risk_score = max(risk_score, 7.0)  # Minimum score for malicious
            
            # Determine severity
            if risk_score >= 8.0:
                severity = "critical"
            elif risk_score >= 6.0:
                severity = "high"
            elif risk_score >= 4.0:
                severity = "medium"
            else:
                severity = "low"
            
            analysis_result = {
                'is_anomaly': is_anomaly,
                'anomaly_score': round(anomaly_score, 3),
                'threat_type': threat_type,
                'threat_confidence': round(threat_confidence, 3),
                'risk_score': round(risk_score, 2),
                'severity': severity,
                'analyzed_at': datetime.now().isoformat(),
                'model_version': self.model_versions.get('threat_classifier', '1.0.0')
            }
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing log entry: {e}")
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'threat_type': 'unknown',
                'threat_confidence': 0.0,
                'risk_score': 0.0,
                'severity': 'low',
                'error': str(e)
            }
    
    def retrain_models(self, training_data: List[Dict[str, Any]]) -> bool:
        """Retrain models with new data"""
        try:
            logger.info(f"Retraining models with {len(training_data)} samples...")
            
            # Extract logs and labels from training data
            logs = []
            labels = []
            
            for sample in training_data:
                log_text = sample.get('log_text', '')
                is_malicious = sample.get('is_malicious', False)
                
                logs.append(log_text)
                labels.append(1 if is_malicious else 0)
            
            # Retrain models
            normal_logs = [logs[i] for i, label in enumerate(labels) if label == 0]
            self._train_anomaly_detector(normal_logs)
            self._train_threat_classifier(logs, labels)
            
            # Save retrained models
            self._save_models()
            
            logger.info("Models retrained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error retraining models: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            'models_loaded': {
                'anomaly_detector': self.anomaly_detector is not None,
                'threat_classifier': self.threat_classifier is not None,
                'log_vectorizer': self.log_vectorizer is not None,
                'feature_scaler': self.feature_scaler is not None
            },
            'model_performance': self.model_performance,
            'model_versions': self.model_versions,
            's3_bucket': self.s3_bucket,
            'models_directory': self.models_dir
        }

# Global instance
threat_detection_models = ThreatDetectionModels()
