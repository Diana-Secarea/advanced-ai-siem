"""
Wazuh Integration for RAG Core System
Provides interface for Wazuh module to call
"""

import json
import sys
from pathlib import Path

# Add parent paths
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ai_engine"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from rag_core_system import RAGCoreSystem


class WazuhRAGIntegration:
    """
    Wazuh integration wrapper for RAG Core System
    Provides simple interface for C module to call
    """
    
    def __init__(self, config_path: str = "/var/ossec/etc/wm_ai_threat_engine.json"):
        self.config_path = config_path
        self.system = None
        self._load_config()
        self._initialize_system()
    
    def _load_config(self):
        """Load configuration"""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = {
                    'base_path': '/var/ossec/ai_models',
                    'use_isolation_forest': True,
                    'anomaly_threshold': 70
                }
        except:
            self.config = {
                'base_path': '/var/ossec/ai_models',
                'use_isolation_forest': True,
                'anomaly_threshold': 70
            }
    
    def _initialize_system(self):
        """Initialize RAG system"""
        try:
            self.system = RAGCoreSystem(
                base_path=self.config.get('base_path', '/var/ossec/ai_models')
            )
        except Exception as e:
            print(f"Error initializing RAG system: {e}")
            self.system = None
    
    def analyze_alert(self, alert_json: str) -> str:
        """
        Analyze Wazuh alert - main entry point
        
        Args:
            alert_json: Wazuh alert JSON string
        
        Returns:
            Analysis result as JSON string
        """
        if not self.system:
            return json.dumps({
                "error": "RAG system not initialized",
                "decision": "unlikely"
            })
        
        try:
            result = self.system.analyze_wazuh_alert(alert_json)
            return json.dumps(result)
        except Exception as e:
            return json.dumps({
                "error": str(e),
                "decision": "unlikely"
            })
    
    def process_events(self, events_json: str) -> str:
        """
        Process batch of events and build episodes
        
        Args:
            events_json: JSON array of events
        
        Returns:
            Result with episode count
        """
        if not self.system:
            return json.dumps({"error": "RAG system not initialized"})
        
        try:
            events = json.loads(events_json)
            episodes = self.system.build_episodes_from_events(events)
            
            # Re-index if new episodes
            if episodes:
                self.system.index_episodes()
            
            return json.dumps({
                "episodes_created": len(episodes),
                "total_episodes": len(self.system.episodes)
            })
        except Exception as e:
            return json.dumps({"error": str(e)})


# CLI interface for Wazuh module
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Wazuh RAG Integration")
    parser.add_argument('--analyze', action='store_true', help='Analyze alert')
    parser.add_argument('--event', type=str, help='Event JSON')
    parser.add_argument('--init', action='store_true', help='Initialize system')
    
    args = parser.parse_args()
    
    integration = WazuhRAGIntegration()
    
    if args.init:
        print("Initializing RAG system...")
        integration.system.ingest_threat_intelligence()
        integration.system.index_episodes()
        print("✅ Initialization complete")
    
    elif args.analyze and args.event:
        result = integration.analyze_alert(args.event)
        print(result)
    
    else:
        print("Usage:")
        print("  --init                    Initialize system")
        print("  --analyze --event <json>  Analyze alert")
