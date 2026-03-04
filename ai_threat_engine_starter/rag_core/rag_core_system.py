"""
RAG Core System - RAG Operations Only
Handles: ingestion, embedding, indexing, retrieval
Does NOT handle: Isolation Forest, Pattern Analysis (handled by AI Engine)
"""

import json
import os
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import sys
from datetime import datetime, timedelta

from rag_core.ingestion.threat_intel_ingestion import ThreatIntelIngestion
from rag_core.episodes.episode_builder import (
    ProcessEpisodeBuilder,
    AuthenticationEpisodeBuilder,
    NetworkEpisodeBuilder,
    AlertEpisodeBuilder,
    SecurityEpisode
)
from rag_core.indexing.hybrid_retrieval import HybridRetrieval
from rag_core.agent.agent_workflow import SOCAgent, AgentOutput


class RAGCoreSystem:
    """
    RAG Core System for Threat Intelligence
    
    Responsibilities:
    - Threat intelligence ingestion (ATT&CK, vendor, IOCs, YARA, Sigma)
    - Episode building (process, auth, network, alert)
    - Embedding generation
    - Hybrid indexing (BM25 + Vector + Freshness)
    - Threat retrieval/search
    
    Does NOT handle:
    - Isolation Forest (handled by AI Engine)
    - Pattern Analysis (handled by AI Engine)
    - Scoring/Prioritization (handled by AI Engine)
    """
    
    def __init__(
        self,
        base_path: str = None
    ):
        if base_path is None:
            # Default to ai_threat_engine_starter
            import os
            base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        print("Initializing RAG Core System...")
        
        # Threat intelligence ingestion
        import os
        threat_intel_path = os.path.join(os.path.dirname(self.base_path), "threat_intel")
        self.ingestion = ThreatIntelIngestion(
            storage_path=threat_intel_path
        )
        
        # Episode builders
        self.process_builder = ProcessEpisodeBuilder()
        self.auth_builder = AuthenticationEpisodeBuilder()
        self.network_builder = NetworkEpisodeBuilder()
        self.alert_builder = AlertEpisodeBuilder()
        
        # Hybrid retrieval
        self.retrieval = HybridRetrieval(
            embedding_model="all-MiniLM-L6-v2",
            use_reranker=True,
            semantic_weight=0.6,
            keyword_weight=0.3,
            freshness_weight=0.1
        )
        
        # SOC Agent (for advanced workflows, but not required for basic RAG)
        self.agent = None  # Can be initialized later if needed
        
        # Episodes storage
        self.episodes: List[SecurityEpisode] = []
        self.episodes_path = self.base_path / "episodes"
        self.episodes_path.mkdir(parents=True, exist_ok=True)
        
        # Load existing episodes
        self._load_episodes()
        
        # Load existing indexes (embeddings, FAISS) if available
        self._load_indexes()
        
        print("✅ RAG Core System initialized (RAG operations only)")
    
    def _load_indexes(self):
        """Load existing indexes (embeddings, FAISS) if available"""
        index_path = self.base_path / "indexes"
        
        if index_path.exists():
            try:
                # Check if we have episodes to index
                if self.episodes:
                    # Convert episodes to dict format
                    episode_dicts = [self._episode_to_dict(ep) for ep in self.episodes]
                    
                    # Try to load existing index
                    if (index_path / "episodes.json").exists():
                        self.retrieval.load_index(str(index_path))
                        print(f"✅ Loaded existing indexes from {index_path}")
                    else:
                        # Index episodes if not already indexed
                        print("Indexing episodes...")
                        self.retrieval.index_episodes(episode_dicts)
                        self.retrieval.save_index(str(index_path))
                else:
                    # Try to load index even without episodes (for search only)
                    if (index_path / "episodes.json").exists():
                        self.retrieval.load_index(str(index_path))
                        print(f"✅ Loaded existing indexes from {index_path}")
            except Exception as e:
                print(f"⚠️ Error loading indexes: {e}")
                print("   Will rebuild indexes when episodes are indexed")
    
    # ==================== RAG Operations ====================
    
    def ingest_threat_intelligence(self, **kwargs) -> Dict[str, List]:
        """Ingest threat intelligence from all sources"""
        print("\n" + "="*60)
        print("Threat Intelligence Ingestion")
        print("="*60)
        return self.ingestion.ingest_all(**kwargs)
    
    def build_episodes_from_events(self, events: List[Dict]) -> List[SecurityEpisode]:
        """Build security episodes from Wazuh events"""
        print(f"\nBuilding episodes from {len(events)} events...")
        
        episodes = []
        
        # Group events by type
        process_events = []
        auth_events = []
        network_events = []
        alert_events = []
        
        for event in events:
            event_type = self._classify_event(event)
            if event_type == 'process':
                process_events.append(event)
            elif event_type == 'authentication':
                auth_events.append(event)
            elif event_type == 'network':
                network_events.append(event)
            elif event_type == 'alert':
                alert_events.append(event)
        
        # Build episodes
        if process_events:
            episode = self.process_builder.build_episode(process_events)
            if episode:
                episodes.append(episode)
        
        if auth_events:
            episode = self.auth_builder.build_episode(auth_events)
            if episode:
                episodes.append(episode)
        
        if network_events:
            episode = self.network_builder.build_episode(network_events)
            if episode:
                episodes.append(episode)
        
        for alert in alert_events:
            # Find correlated events
            correlated = self._find_correlated_events(alert, events)
            episode = self.alert_builder.build_episode(alert, correlated)
            episodes.append(episode)
        
        # Add to storage
        self.episodes.extend(episodes)
        self._save_episodes()
        
        print(f"✅ Built {len(episodes)} episodes")
        return episodes
    
    def index_episodes(self, rebuild: bool = False):
        """Index episodes for retrieval"""
        if not self.episodes:
            print("⚠️ No episodes to index")
            return
        
        # Convert to dict format for indexing
        episode_dicts = [self._episode_to_dict(ep) for ep in self.episodes]
        
        print(f"\nIndexing {len(episode_dicts)} episodes...")
        self.retrieval.index_episodes(episode_dicts)
        
        # Save index
        index_path = self.base_path / "indexes"
        self.retrieval.save_index(str(index_path))
        
        print("✅ Episodes indexed")
    
    def search_threats(
        self,
        query: str,
        top_k: int = 5,
        filter_entities: Optional[Dict[str, List[str]]] = None,
        filter_tags: Optional[List[str]] = None,
        time_window: Optional[Tuple[datetime, datetime]] = None
    ) -> List[Dict]:
        """
        Search for threats using hybrid retrieval (BM25 + Vector + Freshness)
        
        Args:
            query: Search query string
            top_k: Number of results to return
            filter_entities: Filter by entities {type: [values]}
            filter_tags: Filter by tags
            time_window: Filter by time range (start, end)
        
        Returns:
            List of threat intelligence results with:
            - summary: str - threat description
            - episode_type: str - type of episode
            - entities: dict - extracted entities
            - tags: list - tags
            - score: float - relevance score (0-1)
            - similarity: float - similarity score (0-1)
        """
        if not self.retrieval or not self.retrieval.episodes:
            return []
        
        try:
            results = self.retrieval.search(
                query=query,
                top_k=top_k,
                filter_entities=filter_entities,
                filter_tags=filter_tags,
                time_window=time_window,
                boost_freshness=True,
                use_reranking=True
            )
            
            # Format results for AI Engine
            formatted_results = []
            for result in results:
                formatted_results.append({
                    'episode_id': result.get('episode_id', ''),
                    'summary': result.get('summary', ''),
                    'episode_type': result.get('episode_type', ''),
                    'entities': result.get('entities', {}),
                    'tags': result.get('tags', []),
                    'score': result.get('score', 0.0),
                    'similarity': min(1.0, max(0.0, result.get('score', 0.0))),  # Normalize to 0-1
                    'time_range': result.get('time_range', {}),
                    'metadata': result.get('metadata', {}),
                    'raw_refs': result.get('raw_refs', [])
                })
            
            return formatted_results
        except Exception as e:
            print(f"Error searching threats: {e}")
            return []
    
    def get_threat_text(self, threat_results: List[Dict]) -> str:
        """
        Extract text from threat results for Pattern Analyzer
        
        Args:
            threat_results: List of threat results from search_threats()
        
        Returns:
            Combined text string for pattern analysis
        """
        texts = []
        
        for threat in threat_results[:3]:  # Top 3
            # Add summary
            summary = threat.get('summary', '')
            if summary:
                texts.append(summary)
            
            # Add tags
            tags = threat.get('tags', [])
            if tags:
                texts.append(' '.join(tags))
            
            # Add entities
            entities = threat.get('entities', {})
            for entity_type, values in entities.items():
                if values:
                    texts.append(f"{entity_type}: {', '.join(str(v) for v in values)}")
        
        return ' '.join(texts)
    
    def get_threat_intel_for_pattern_analyzer(self, threat_results: List[Dict]) -> List[Dict]:
        """
        Convert threat results to format expected by Pattern Analyzer
        
        Args:
            threat_results: List of threat results from search_threats()
        
        Returns:
            List in format:
            [
                {
                    'description': str,
                    'severity': str,
                    'similarity': float (0-1),
                    'ioc': list,
                    'mitigation': str
                }
            ]
        """
        formatted = []
        
        for threat in threat_results:
            # Build description
            summary = threat.get('summary', '')
            episode_type = threat.get('episode_type', '')
            tags = threat.get('tags', [])
            
            description_parts = []
            if summary:
                description_parts.append(summary)
            if episode_type:
                description_parts.append(f"Type: {episode_type}")
            if tags:
                description_parts.append(f"Tags: {', '.join(tags)}")
            
            description = ' '.join(description_parts) if description_parts else "Threat intelligence match"
            
            # Extract IOCs from entities
            iocs = []
            entities = threat.get('entities', {})
            for entity_type, values in entities.items():
                if entity_type in ['ip', 'domain', 'hash', 'url', 'file']:
                    iocs.extend([str(v) for v in values])
            
            # Determine severity from similarity score
            similarity = threat.get('similarity', 0.0)
            if similarity >= 0.8:
                severity = "CRITICAL"
            elif similarity >= 0.6:
                severity = "HIGH"
            elif similarity >= 0.4:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            # Get mitigation from metadata
            metadata = threat.get('metadata', {})
            mitigation = metadata.get('mitigation', '')
            
            formatted.append({
                'threat_id': threat.get('episode_id', f"THREAT-{len(formatted)}"),
                'description': description,
                'severity': severity,
                'similarity': similarity,
                'ioc': iocs,
                'mitigation': mitigation,
                'episode_type': episode_type,
                'tags': tags
            })
        
        return formatted
    
    # ==================== Agent Workflow (Optional) ====================
    
    def initialize_agent(self):
        """Initialize SOC Agent for advanced workflows (optional)"""
        if self.agent is None:
            self.agent = SOCAgent(
                retrieval=self.retrieval,
                anomaly_detector=None,  # AI Engine handles this
                threat_intel_path=str(self.base_path / "threat_intel")
            )
            print("✅ SOC Agent initialized")
    
    def analyze(self, input_data: Dict) -> AgentOutput:
        """
        Advanced analysis using SOC Agent workflow (optional)
        For basic RAG operations, use search_threats() instead
        
        Args:
            input_data: Can be alert, episode, or query
        
        Returns:
            AgentOutput with structured analysis
        """
        if self.agent is None:
            self.initialize_agent()
        
        # Run through agent workflow
        output = self.agent.process(input_data)
        
        return output
    
    def analyze_wazuh_alert(self, alert_json: str) -> Dict:
        """
        Analyze Wazuh alert - main entry point for Wazuh integration
        
        Args:
            alert_json: Wazuh alert in JSON format
        
        Returns:
            Analysis result with recommendations
        """
        try:
            alert = json.loads(alert_json) if isinstance(alert_json, str) else alert_json
        except:
            return {"error": "Invalid JSON", "decision": "unlikely"}
        
        # Run agent workflow
        output = self.agent.process(alert)
        
        # Format for Wazuh
        result = {
            "decision": output.decision,
            "confidence": output.confidence,
            "technique": output.hypothesis.technique,
            "recommendations": output.recommendations,
            "next_queries": output.next_queries,
            "indicators": output.hypothesis.indicators,
            "citations": output.citations,
            "validation": output.validation_checks
        }
        
        return result
    
    def _classify_event(self, event: Dict) -> str:
        """Classify event type"""
        message = str(event.get('message', '')).lower()
        data = event.get('data', event)
        
        if 'alert' in message or 'rule' in event:
            return 'alert'
        elif any(word in message for word in ['process', 'exec', 'command']):
            return 'process'
        elif any(word in message for word in ['login', 'auth', 'ssh', 'rdp']):
            return 'authentication'
        elif 'srcip' in data or 'dstip' in data or 'network' in message:
            return 'network'
        else:
            return 'process'  # Default
    
    def _find_correlated_events(self, alert: Dict, all_events: List[Dict]) -> List[Dict]:
        """Find events correlated with alert"""
        correlated = []
        
        # Extract entities from alert
        alert_entities = self._extract_entities(alert)
        
        # Find events with matching entities
        for event in all_events:
            event_entities = self._extract_entities(event)
            
            # Check for overlap
            if self._entities_overlap(alert_entities, event_entities):
                correlated.append(event)
        
        return correlated[:10]  # Limit to 10
    
    def _extract_entities(self, event: Dict) -> Dict[str, List[str]]:
        """Extract entities from event"""
        entities = {}
        data = event.get('data', event)
        
        if 'srcip' in data:
            entities.setdefault('ips', []).append(str(data['srcip']))
        if 'user' in data:
            entities.setdefault('users', []).append(str(data['user']))
        if 'hostname' in data:
            entities.setdefault('hosts', []).append(str(data['hostname']))
        
        return entities
    
    def _entities_overlap(self, entities1: Dict, entities2: Dict) -> bool:
        """Check if entities overlap"""
        for entity_type, values1 in entities1.items():
            if entity_type in entities2:
                values2 = entities2[entity_type]
                if set(values1) & set(values2):
                    return True
        return False
    
    def _episode_to_dict(self, episode: SecurityEpisode) -> Dict:
        """Convert SecurityEpisode to dict"""
        return {
            'episode_id': episode.episode_id,
            'episode_type': episode.episode_type,
            'time_range': episode.time_range,
            'entities': episode.entities,
            'source': episode.source,
            'tags': episode.tags,
            'summary': episode.summary,
            'raw_refs': episode.raw_refs,
            'metadata': episode.metadata
        }
    
    def _save_episodes(self):
        """Save episodes to disk"""
        episodes_file = self.episodes_path / "episodes.json"
        episode_dicts = [self._episode_to_dict(ep) for ep in self.episodes]
        
        with open(episodes_file, 'w') as f:
            json.dump(episode_dicts, f, indent=2, default=str)
    
    def _load_episodes(self):
        """Load episodes from disk"""
        episodes_file = self.episodes_path / "episodes.json"
        
        if episodes_file.exists():
            try:
                with open(episodes_file, 'r') as f:
                    episode_dicts = json.load(f)
                    # Convert back to SecurityEpisode objects
                    from rag_core.episodes.episode_builder import SecurityEpisode
                    self.episodes = [
                        SecurityEpisode(**d) for d in episode_dicts
                    ]
                print(f"✅ Loaded {len(self.episodes)} episodes")
            except Exception as e:
                print(f"⚠️ Error loading episodes: {e}")
                self.episodes = []


if __name__ == "__main__":
    # Example usage
    system = RAGCoreSystem()
    
    # Ingest threat intelligence
    system.ingest_threat_intelligence()
    
    # Index episodes
    system.index_episodes()
    
    print("\n✅ Final RAG System ready!")
