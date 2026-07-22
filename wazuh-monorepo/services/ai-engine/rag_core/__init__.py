"""
Final RAG System for Wazuh AI Copilot Threat Detection
Production-grade RAG with Isolation Forest integration
"""
import sys
from pathlib import Path

# Ensure parent dir is on sys.path so 'rag_core.xxx' imports resolve
_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

__version__ = '1.0.0'
__author__ = 'Wazuh AI Threat Engine'
