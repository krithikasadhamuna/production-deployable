#!/usr/bin/env python3
"""
Adaptive Detection Engine - No Hardcoded Rules
Dynamically generates detection rules and adapts to new threats
"""

import sqlite3
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import logging
import hashlib
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AdaptiveDetectionRule:
    """Dynamic detection rule structure"""
    rule_id: str
    name: str
    description: str
    pattern: str
    pattern_type: str  # regex, keyword, ml_feature, behavioral
    severity: str
    confidence_score: float
    false_positive_rate: float
    creation_method: str  # learned, evolved, user_defined, ai_generated
    mitre_techniques: List[str]
    target_platforms: List[str]
    data_sources: List[str]
    last_updated: datetime
    performance_metrics: Dict[str, float]
    adaptation_history: List[Dict[str, Any]]

@dataclass
class ThreatPattern:
    """Learned threat pattern"""
    pattern_id: str
    pattern_signature: str
    attack_type: str
    frequency: int
    first_seen: datetime
    last_seen: datetime
    associated_techniques: List[str]
    evolution_stages: List[str]
    threat_actor_indicators: List[str]

class AdaptiveDetectionEngine:
    """Detection engine that adapts without hardcoded rules"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent.parent.parent.parent
        self.db_path = self.base_path / "processed_data" / "comprehensive_cybersec_data.db"
        self.rules_db_path = self.base_path / "adaptive_rules.db"
        self.ml_models_path = self.base_path / "trained_models"
        
        self.adaptive_rules: Dict[str, AdaptiveDetectionRule] = {}
        self.learned_patterns: Dict[str, ThreatPattern] = {}
        self.performance_tracker = {}
        
        self._initialize_adaptive_system()
    
    def _initialize_adaptive_system(self):
        """Initialize the adaptive detection system"""
        self._create_adaptive_database()
        self._load_existing_rules()
        self._initialize_learning_algorithms()
    
    def _create_adaptive_database(self):
        """Create database for adaptive rules and patterns"""
        with sqlite3.connect(self.rules_db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS adaptive_rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    pattern TEXT,
                    pattern_type TEXT,
                    severity TEXT,
                    confidence_score REAL,
                    false_positive_rate REAL,
                    creation_method TEXT,
                    mitre_techniques TEXT,
                    target_platforms TEXT,
                    data_sources TEXT,
                    last_updated TEXT,
                    performance_metrics TEXT,
                    adaptation_history TEXT
                );
                
                CREATE TABLE IF NOT EXISTS threat_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    pattern_signature TEXT,
                    attack_type TEXT,
                    frequency INTEGER,
                    first_seen TEXT,
                    last_seen TEXT,
                    associated_techniques TEXT,
                    evolution_stages TEXT,
                    threat_actor_indicators TEXT
                );
                
                CREATE TABLE IF NOT EXISTS detection_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    rule_id TEXT,
                    log_entry TEXT,
                    prediction TEXT,
                    actual_result TEXT,
                    analyst_feedback TEXT,
                    timestamp TEXT,
                    confidence_adjustment REAL
                );
                
                CREATE TABLE IF NOT EXISTS pattern_evolution (
                    evolution_id TEXT PRIMARY KEY,
                    pattern_id TEXT,
                    old_signature TEXT,
                    new_signature TEXT,
                    evolution_reason TEXT,
                    timestamp TEXT,
                    success_rate_before REAL,
                    success_rate_after REAL
                );
            """)
    
    def _load_existing_rules(self):
        """Load existing adaptive rules"""
        try:
            with sqlite3.connect(self.rules_db_path) as conn:
                cursor = conn.execute("SELECT * FROM adaptive_rules")
                for row in cursor.fetchall():
                    rule = self._row_to_adaptive_rule(row)
                    self.adaptive_rules[rule.rule_id] = rule
            
            logger.info(f"✅ Loaded {len(self.adaptive_rules)} adaptive rules")
        except Exception as e:
            logger.warning(f"Could not load existing rules: {e}")
    
    def _initialize_learning_algorithms(self):
        """Initialize machine learning algorithms for pattern detection"""
        self.learning_algorithms = {
            "sequence_learning": self._initialize_sequence_learner(),
            "anomaly_detection": self._initialize_anomaly_detector(),
            "pattern_evolution": self._initialize_pattern_evolver(),
            "behavioral_analysis": self._initialize_behavioral_analyzer()
        }
    
    async def learn_from_new_data(self, log_data: List[Dict], labels: List[str] = None) -> List[AdaptiveDetectionRule]:
        """Learn new detection patterns from incoming data"""
        logger.info(f"🧠 Learning from {len(log_data)} new log entries...")
        
        new_rules = []
        
        # Step 1: Extract new patterns
        new_patterns = await self._extract_new_patterns(log_data, labels)
        
        # Step 2: Analyze pattern evolution
        evolved_patterns = await self._analyze_pattern_evolution(new_patterns)
        
        # Step 3: Generate adaptive rules
        for pattern in new_patterns + evolved_patterns:
            rule = await self._generate_rule_from_pattern(pattern)
            if rule:
                new_rules.append(rule)
        
        # Step 4: Validate rules against historical data
        validated_rules = await self._validate_new_rules(new_rules)
        
        # Step 5: Store and activate rules
        for rule in validated_rules:
            await self._store_adaptive_rule(rule)
            self.adaptive_rules[rule.rule_id] = rule
        
        logger.info(f"✅ Learned {len(validated_rules)} new adaptive rules")
        return validated_rules
    
    async def _extract_new_patterns(self, log_data: List[Dict], labels: List[str] = None) -> List[ThreatPattern]:
        """Extract new threat patterns from log data"""
        patterns = []
        
        # Method 1: Sequence pattern extraction
        sequence_patterns = self._extract_sequence_patterns(log_data)
        patterns.extend(sequence_patterns)
        
        # Method 2: Statistical anomaly patterns
        anomaly_patterns = self._extract_anomaly_patterns(log_data)
        patterns.extend(anomaly_patterns)
        
        # Method 3: Behavioral patterns
        behavioral_patterns = self._extract_behavioral_patterns(log_data)
        patterns.extend(behavioral_patterns)
        
        # Method 4: N-gram analysis
        ngram_patterns = self._extract_ngram_patterns(log_data)
        patterns.extend(ngram_patterns)
        
        # Method 5: Time-series patterns
        temporal_patterns = self._extract_temporal_patterns(log_data)
        patterns.extend(temporal_patterns)
        
        return patterns
    
    def _extract_sequence_patterns(self, log_data: List[Dict]) -> List[ThreatPattern]:
        """Extract command/event sequence patterns"""
        patterns = []
        
        try:
            # Group logs by source/session to find sequences
            sessions = self._group_logs_by_session(log_data)
            
            for session_id, session_logs in sessions.items():
                if len(session_logs) >= 3:  # Minimum sequence length
                    # Extract command sequences
                    command_sequence = self._extract_command_sequence(session_logs)
                    
                    if command_sequence and len(command_sequence) >= 3:
                        # Generate pattern signature
                        pattern_signature = self._generate_sequence_signature(command_sequence)
                        
                        # Check if this is a new pattern
                        if not self._pattern_exists(pattern_signature):
                            pattern = ThreatPattern(
                                pattern_id=self._generate_pattern_id(pattern_signature),
                                pattern_signature=pattern_signature,
                                attack_type="command_sequence",
                                frequency=1,
                                first_seen=datetime.now(),
                                last_seen=datetime.now(),
                                associated_techniques=self._infer_mitre_techniques(command_sequence),
                                evolution_stages=[],
                                threat_actor_indicators=self._extract_actor_indicators(session_logs)
                            )
                            patterns.append(pattern)
        
        except Exception as e:
            logger.warning(f"Sequence pattern extraction failed: {e}")
        
        return patterns
    
    def _extract_anomaly_patterns(self, log_data: List[Dict]) -> List[ThreatPattern]:
        """Extract statistical anomaly patterns"""
        patterns = []
        
        try:
            # Convert logs to feature vectors
            features = self._logs_to_feature_vectors(log_data)
            
            if len(features) > 10:  # Minimum data for anomaly detection
                # Use isolation forest or similar for anomaly detection
                from sklearn.ensemble import IsolationForest
                
                detector = IsolationForest(contamination=0.1, random_state=42)
                anomaly_scores = detector.fit_predict(features)
                
                # Extract anomalous patterns
                for i, score in enumerate(anomaly_scores):
                    if score == -1:  # Anomaly detected
                        log_entry = log_data[i]
                        pattern_signature = self._generate_anomaly_signature(log_entry, features[i])
                        
                        if not self._pattern_exists(pattern_signature):
                            pattern = ThreatPattern(
                                pattern_id=self._generate_pattern_id(pattern_signature),
                                pattern_signature=pattern_signature,
                                attack_type="statistical_anomaly",
                                frequency=1,
                                first_seen=datetime.now(),
                                last_seen=datetime.now(),
                                associated_techniques=[],
                                evolution_stages=[],
                                threat_actor_indicators=[]
                            )
                            patterns.append(pattern)
        
        except Exception as e:
            logger.warning(f"Anomaly pattern extraction failed: {e}")
        
        return patterns
    
    def _extract_behavioral_patterns(self, log_data: List[Dict]) -> List[ThreatPattern]:
        """Extract behavioral patterns"""
        patterns = []
        
        try:
            # Group by user/system to analyze behavior
            behavioral_groups = self._group_logs_by_behavior(log_data)
            
            for group_key, group_logs in behavioral_groups.items():
                # Analyze behavior patterns
                behavior_signature = self._analyze_behavior_pattern(group_logs)
                
                if behavior_signature and self._is_suspicious_behavior(behavior_signature):
                    pattern = ThreatPattern(
                        pattern_id=self._generate_pattern_id(behavior_signature),
                        pattern_signature=behavior_signature,
                        attack_type="behavioral_anomaly",
                        frequency=len(group_logs),
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        associated_techniques=self._infer_techniques_from_behavior(behavior_signature),
                        evolution_stages=[],
                        threat_actor_indicators=[]
                    )
                    patterns.append(pattern)
        
        except Exception as e:
            logger.warning(f"Behavioral pattern extraction failed: {e}")
        
        return patterns
    
    def _extract_ngram_patterns(self, log_data: List[Dict]) -> List[ThreatPattern]:
        """Extract n-gram patterns from log content"""
        patterns = []
        
        try:
            # Extract text content from logs
            text_content = []
            for log in log_data:
                content = log.get('log_content', '') or log.get('command', '') or str(log)
                if content:
                    text_content.append(content.lower())
            
            if text_content:
                # Generate n-grams (2-grams, 3-grams, 4-grams)
                from sklearn.feature_extraction.text import CountVectorizer
                
                for n in [2, 3, 4]:
                    vectorizer = CountVectorizer(ngram_range=(n, n), min_df=2)
                    try:
                        ngram_matrix = vectorizer.fit_transform(text_content)
                        feature_names = vectorizer.get_feature_names_out()
                        
                        # Find frequent n-grams that might indicate attacks
                        ngram_counts = np.array(ngram_matrix.sum(axis=0)).flatten()
                        
                        for i, count in enumerate(ngram_counts):
                            if count >= 3:  # Minimum frequency
                                ngram = feature_names[i]
                                if self._is_suspicious_ngram(ngram):
                                    pattern_signature = f"ngram_{n}:{ngram}"
                                    
                                    if not self._pattern_exists(pattern_signature):
                                        pattern = ThreatPattern(
                                            pattern_id=self._generate_pattern_id(pattern_signature),
                                            pattern_signature=pattern_signature,
                                            attack_type="ngram_pattern",
                                            frequency=int(count),
                                            first_seen=datetime.now(),
                                            last_seen=datetime.now(),
                                            associated_techniques=[],
                                            evolution_stages=[],
                                            threat_actor_indicators=[]
                                        )
                                        patterns.append(pattern)
                    except:
                        continue
        
        except Exception as e:
            logger.warning(f"N-gram pattern extraction failed: {e}")
        
        return patterns
    
    def _extract_temporal_patterns(self, log_data: List[Dict]) -> List[ThreatPattern]:
        """Extract time-based patterns"""
        patterns = []
        
        try:
            # Sort logs by timestamp
            timestamped_logs = []
            for log in log_data:
                timestamp = log.get('timestamp') or log.get('time') or datetime.now()
                if isinstance(timestamp, str):
                    # Parse timestamp string
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    except:
                        timestamp = datetime.now()
                timestamped_logs.append((timestamp, log))
            
            timestamped_logs.sort(key=lambda x: x[0])
            
            # Analyze temporal patterns (bursts, intervals, etc.)
            temporal_clusters = self._find_temporal_clusters(timestamped_logs)
            
            for cluster in temporal_clusters:
                if len(cluster) >= 5:  # Minimum cluster size
                    pattern_signature = self._generate_temporal_signature(cluster)
                    
                    if pattern_signature and not self._pattern_exists(pattern_signature):
                        pattern = ThreatPattern(
                            pattern_id=self._generate_pattern_id(pattern_signature),
                            pattern_signature=pattern_signature,
                            attack_type="temporal_pattern",
                            frequency=len(cluster),
                            first_seen=cluster[0][0],
                            last_seen=cluster[-1][0],
                            associated_techniques=[],
                            evolution_stages=[],
                            threat_actor_indicators=[]
                        )
                        patterns.append(pattern)
        
        except Exception as e:
            logger.warning(f"Temporal pattern extraction failed: {e}")
        
        return patterns
    
    async def _analyze_pattern_evolution(self, new_patterns: List[ThreatPattern]) -> List[ThreatPattern]:
        """Analyze how existing patterns are evolving"""
        evolved_patterns = []
        
        for new_pattern in new_patterns:
            # Check for similar existing patterns
            similar_patterns = self._find_similar_patterns(new_pattern)
            
            for similar_pattern in similar_patterns:
                # Analyze evolution
                evolution_analysis = self._analyze_evolution(similar_pattern, new_pattern)
                
                if evolution_analysis['is_evolution']:
                    # Create evolved pattern
                    evolved_pattern = self._create_evolved_pattern(
                        similar_pattern, 
                        new_pattern, 
                        evolution_analysis
                    )
                    evolved_patterns.append(evolved_pattern)
                    
                    # Log evolution
                    self._log_pattern_evolution(similar_pattern, evolved_pattern, evolution_analysis)
        
        return evolved_patterns
    
    async def _generate_rule_from_pattern(self, pattern: ThreatPattern) -> Optional[AdaptiveDetectionRule]:
        """Generate detection rule from learned pattern"""
        try:
            # Determine rule type based on pattern type
            if pattern.attack_type == "command_sequence":
                rule = self._create_sequence_rule(pattern)
            elif pattern.attack_type == "statistical_anomaly":
                rule = self._create_anomaly_rule(pattern)
            elif pattern.attack_type == "behavioral_anomaly":
                rule = self._create_behavioral_rule(pattern)
            elif pattern.attack_type == "ngram_pattern":
                rule = self._create_ngram_rule(pattern)
            elif pattern.attack_type == "temporal_pattern":
                rule = self._create_temporal_rule(pattern)
            else:
                rule = self._create_generic_rule(pattern)
            
            return rule
            
        except Exception as e:
            logger.warning(f"Rule generation failed for pattern {pattern.pattern_id}: {e}")
            return None
    
    def _create_sequence_rule(self, pattern: ThreatPattern) -> AdaptiveDetectionRule:
        """Create rule for command sequence patterns"""
        # Parse sequence from signature
        sequence_parts = pattern.pattern_signature.split(' -> ')
        
        # Create regex pattern
        regex_parts = []
        for part in sequence_parts:
            # Escape special regex characters but preserve pattern essence
            escaped = re.escape(part).replace(r'\*', '.*').replace(r'\?', '.')
            regex_parts.append(escaped)
        
        regex_pattern = r'.*?'.join(regex_parts)
        
        rule = AdaptiveDetectionRule(
            rule_id=f"seq_{pattern.pattern_id}",
            name=f"Sequence Pattern: {' -> '.join(sequence_parts[:2])}...",
            description=f"Detected command sequence pattern with {len(sequence_parts)} steps",
            pattern=regex_pattern,
            pattern_type="regex",
            severity=self._assess_sequence_severity(sequence_parts),
            confidence_score=0.8,
            false_positive_rate=0.1,
            creation_method="sequence_learning",
            mitre_techniques=pattern.associated_techniques,
            target_platforms=["windows", "linux", "macos"],
            data_sources=["process_logs", "command_logs"],
            last_updated=datetime.now(),
            performance_metrics={},
            adaptation_history=[]
        )
        
        return rule
    
    def _create_anomaly_rule(self, pattern: ThreatPattern) -> AdaptiveDetectionRule:
        """Create rule for statistical anomaly patterns"""
        # Extract features from pattern signature
        features = self._parse_anomaly_signature(pattern.pattern_signature)
        
        rule = AdaptiveDetectionRule(
            rule_id=f"anom_{pattern.pattern_id}",
            name=f"Anomaly Pattern: {features.get('primary_feature', 'Unknown')}",
            description=f"Statistical anomaly detection rule",
            pattern=pattern.pattern_signature,
            pattern_type="ml_feature",
            severity="medium",
            confidence_score=0.7,
            false_positive_rate=0.15,
            creation_method="anomaly_detection",
            mitre_techniques=[],
            target_platforms=["windows", "linux", "macos"],
            data_sources=["system_logs", "security_logs"],
            last_updated=datetime.now(),
            performance_metrics={},
            adaptation_history=[]
        )
        
        return rule
    
    async def detect_with_adaptive_rules(self, log_entry: Dict) -> List[Dict[str, Any]]:
        """Run detection using adaptive rules"""
        detections = []
        
        for rule_id, rule in self.adaptive_rules.items():
            detection_result = await self._apply_adaptive_rule(rule, log_entry)
            
            if detection_result['matched']:
                detection = {
                    'rule_id': rule_id,
                    'rule_name': rule.name,
                    'severity': rule.severity,
                    'confidence': detection_result['confidence'],
                    'match_details': detection_result['details'],
                    'mitre_techniques': rule.mitre_techniques,
                    'creation_method': rule.creation_method,
                    'timestamp': datetime.now().isoformat()
                }
                detections.append(detection)
                
                # Update rule performance
                await self._update_rule_performance(rule_id, detection_result)
        
        return detections
    
    async def provide_feedback(self, rule_id: str, log_entry: Dict, 
                             actual_result: str, analyst_feedback: str):
        """Provide feedback to improve adaptive rules"""
        # Store feedback
        feedback_id = f"fb_{int(datetime.now().timestamp())}_{rule_id}"
        
        with sqlite3.connect(self.rules_db_path) as conn:
            conn.execute("""
                INSERT INTO detection_feedback 
                (feedback_id, rule_id, log_entry, actual_result, analyst_feedback, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                feedback_id, rule_id, json.dumps(log_entry), 
                actual_result, analyst_feedback, datetime.now().isoformat()
            ))
        
        # Adjust rule based on feedback
        await self._adjust_rule_based_feedback(rule_id, actual_result, analyst_feedback)
        
        logger.info(f"📝 Feedback received for rule {rule_id}: {actual_result}")
    
    # Helper methods (implementation would continue with all the helper methods)
    
    def _group_logs_by_session(self, log_data: List[Dict]) -> Dict[str, List[Dict]]:
        """Group logs by session/source"""
        sessions = {}
        
        for log in log_data:
            # Try to identify session/source
            session_id = (
                log.get('session_id') or 
                log.get('source_ip') or 
                log.get('user') or 
                log.get('hostname') or 
                'default_session'
            )
            
            if session_id not in sessions:
                sessions[session_id] = []
            sessions[session_id].append(log)
        
        return sessions
    
    def _generate_pattern_id(self, signature: str) -> str:
        """Generate unique pattern ID"""
        return hashlib.md5(signature.encode()).hexdigest()[:12]
    
    def _pattern_exists(self, signature: str) -> bool:
        """Check if pattern already exists"""
        pattern_id = self._generate_pattern_id(signature)
        return pattern_id in self.learned_patterns
    
    # Additional helper methods would be implemented here...
    
    def _initialize_sequence_learner(self):
        """Initialize sequence learning algorithm"""
        pass
    
    def _initialize_anomaly_detector(self):
        """Initialize anomaly detection algorithm"""
        pass
    
    def _initialize_pattern_evolver(self):
        """Initialize pattern evolution algorithm"""
        pass
    
    def _initialize_behavioral_analyzer(self):
        """Initialize behavioral analysis algorithm"""
        pass

# Factory function
def create_adaptive_detection_engine() -> AdaptiveDetectionEngine:
    """Create adaptive detection engine"""
    return AdaptiveDetectionEngine()
