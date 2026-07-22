# AI Threat Engine Package
"""
AI Threat Engine - Anomaly Detection and Threat Hunting for Wazuh

This package provides:
- Anomaly detection using Isolation Forest
- Pattern analysis for known attack patterns
- Optional LLM integration for advanced analysis
- Orchestration of RAG Core for threat intelligence

NOTE: Threat Intelligence is now in RAG Core, not in AI Engine!
"""

from .main import AIThreatEngine
from .anomaly_detector import AnomalyDetector
from .pattern_analyzer import PatternAnalyzer

# ThreatIntelligence was removed - use RAG Core instead
__all__ = [
    'AIThreatEngine',
    'AnomalyDetector',
    'PatternAnalyzer',
]

__version__ = '2.0.0'
