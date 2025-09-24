# Detection Agent - Self-contained implementation
from .detection_pipeline import DetectionPipeline
from .mitre_attack_engine import MITREAttackEngine
from .sigma_detection_engine import SigmaDetectionEngine
from .adaptive_detection_engine import AdaptiveDetectionEngine

# Alias for compatibility
MitreAttackEngine = MITREAttackEngine

__all__ = ['DetectionPipeline', 'MITREAttackEngine', 'SigmaDetectionEngine', 'AdaptiveDetectionEngine', 'MitreAttackEngine']


