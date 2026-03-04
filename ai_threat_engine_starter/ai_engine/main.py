"""
AI Threat Engine - Main Orchestrator
Motorul principal care orchestrează:
- RAG Core pentru RAG operations (ingestion, embedding, retrieval)
- Isolation Forest pentru scoring și prioritizare
- Pattern Analyzer pentru identificarea atacurilor

NOTA: Threat Intelligence este acum în RAG Core, nu în AI Engine!
"""

import json
import os
import sys
from typing import List, Optional, Dict
from pathlib import Path
from .anomaly_detector import AnomalyDetector
from .pattern_analyzer import PatternAnalyzer

# Import RAGCoreSystem for RAG operations
RAG_CORE_AVAILABLE = False
RAGCoreSystem = None

try:
    # Add rag_core to path
    rag_core_path = Path(__file__).parent.parent / "rag_core"
    if rag_core_path.exists():
        sys.path.insert(0, str(rag_core_path.parent))
        from rag_core.rag_core_system import RAGCoreSystem
        RAG_CORE_AVAILABLE = True
        print("✅ RAG Core System available")
    else:
        print("⚠️ RAG Core path not found")
except ImportError as e:
    print(f"⚠️ RAG Core System not available: {e}")

# Fallback to simple RAG (DEPRECATED - use RAG Core instead)
ThreatIntelligence = None
if not RAG_CORE_AVAILABLE:
    try:
        from .threat_intelligence import ThreatIntelligence
        print("⚠️ Using DEPRECATED Simple RAG System - please use RAG Core instead")
    except ImportError:
        print("❌ No RAG system available")



class AIThreatEngine:
    """
    AI Threat Engine - Main Orchestrator

    Responsibilities:
    - Orchestrates all AI components
    - Uses RAG Core for RAG operations (ingestion, embedding, retrieval)
    - Performs Isolation Forest scoring and prioritization
    - Combines all results for final threat assessment
    """

    def __init__(self, model_path, vector_db_path, api_port=8000, use_rag_core=True):
        self.model_path = model_path
        self.vector_db_path = vector_db_path

        print("="*60)
        print("Initializing AI Threat Engine (Main Orchestrator)")
        print("="*60)

        # Initialize Isolation Forest
        print("\n1. Loading Isolation Forest...")
        self.anomaly_detector = AnomalyDetector(model_path)
        print("   ✅ Isolation Forest ready")

        # Initialize RAG System
        print("\n2. Loading RAG System...")
        self.use_rag_core = use_rag_core and RAG_CORE_AVAILABLE
        if self.use_rag_core:
            try:
                self.rag_system = RAGCoreSystem(base_path=vector_db_path)
                self.threat_intel = None
                print("   ✅ RAG Core System initialized")
            except Exception as e:
                print(f"   ⚠️ Failed to initialize RAG Core System: {e}")
                import traceback
                traceback.print_exc()
                self.use_rag_core = False

        if not self.use_rag_core:
            try:
                if ThreatIntelligence:
                    self.threat_intel = ThreatIntelligence(vector_db_path)
                    self.rag_system = None
                    print("   ⚠️ Using DEPRECATED Simple RAG System")
                else:
                    self.threat_intel = None
                    self.rag_system = None
                    print("   ❌ No RAG system available")
            except Exception as e:
                self.threat_intel = None
                self.rag_system = None
                print(f"   ⚠️ RAG System initialization failed: {e}")

        print("\n" + "="*60)
        print("✅ AI Threat Engine ready!")
        print("="*60 + "\n")
    
    def analyze_event(self, event_json: str, threshold: int = 70) -> dict:
        """
        Main analysis pipeline orchestrated by AI Engine:
        
        1. RAG (RAG Core) → Retrieves threat intelligence text
        2. Pattern Analyzer (AI Engine) → Analyzes RAG text to identify attack
        3. Isolation Forest (AI Engine) → Scoring and prioritization
        4. Combine results → Final threat assessment
        """
        try:
            event = json.loads(event_json)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "is_anomaly": False}
        
        # ========== STEP 1: RAG - Get Threat Intelligence Text ==========
        event_description = self._build_event_description(event)
        
        if self.use_rag_core and self.rag_system:
            # Use RAG Core for retrieval (with embeddings)
            threat_results = self.rag_system.search_threats(
                query=event_description,
                top_k=3,
                filter_entities=self._extract_entities_from_event(event),
                filter_tags=self._extract_tags_from_event(event)
            )
            
            # Convert to format for Pattern Analyzer
            threat_intel = self.rag_system.get_threat_intel_for_pattern_analyzer(threat_results)
        else:
            # Fallback to deprecated simple RAG
            if self.threat_intel:
                threat_intel = self.threat_intel.search_similar_threats(event_description, top_k=3)
            else:
                threat_intel = []
        
        # ========== STEP 2: Pattern Analyzer - Analyze RAG Text ==========
        # Pattern Analyzer analyzes TEXT from RAG (not event directly)
        pattern_result = self.pattern_analyzer.analyze_rag_text(threat_intel)
        
        # ========== STEP 3: Isolation Forest - Multi-dimensional Scoring ==========
        # AI Engine performs scoring and prioritization
        scoring_result = self.anomaly_detector.multi_dimensional_scoring(event)
        
        # ========== STEP 4: Rank Threats ==========
        threat_ranking = self.anomaly_detector.rank_threats([
            {
                'anomaly_score': scoring_result['combined_score'],
                'pattern_score': pattern_result.get('risk_score', 0),
                'similarity': pattern_result.get('confidence', 0.0)
            }
        ])
        
        # ========== STEP 5: LLM Analysis (Optional) ==========
        llm_result = None
        if self.llm_enabled:
            try:
                llm_result = self.llm_copilot.analyze_threat(event, threat_intel)
            except Exception as e:
                print(f"LLM analysis error: {e}")
        
        # ========== STEP 6: Combine Results ==========
        final_score = scoring_result['combined_score']
        
        # Also consider pattern and LLM scores
        if pattern_result.get('risk_score', 0) > final_score:
            final_score = pattern_result['risk_score']
        
        if llm_result and int(llm_result.get('confidence', 0)) > final_score:
            final_score = int(llm_result.get('confidence', 0))
        
        # Determine if anomaly
        is_anomaly = (
            scoring_result['anomaly_score'] > threshold or
            pattern_result.get('suspicious', False) or
            final_score >= threshold
        )
        
        # Determine threat level
        if final_score >= 90:
            threat_level = "CRITICAL"
        elif final_score >= 75:
            threat_level = "HIGH"
        elif final_score >= 50:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        # Build comprehensive result
        result = {
            # Isolation Forest Scoring (AI Engine)
            "anomaly_score": scoring_result['anomaly_score'],
            "time_score": scoring_result['time_score'],
            "frequency_score": scoring_result['frequency_score'],
            "network_score": scoring_result['network_score'],
            "combined_score": scoring_result['combined_score'],
            "priority_score": scoring_result['priority_score'],
            
            # Pattern Analysis (AI Engine - from RAG text)
            "pattern": pattern_result.get('pattern', 'No known pattern'),
            "pattern_confidence": pattern_result.get('confidence', 0.0),
            "pattern_risk_score": pattern_result.get('risk_score', 0),
            "pattern_severity": pattern_result.get('severity', 'LOW'),
            
            # Threat Ranking (AI Engine)
            "threat_rank": threat_ranking[0]['rank'] if threat_ranking else 999,
            "rank_score": threat_ranking[0]['combined_rank_score'] if threat_ranking else 0,
            
            # Overall results
            "is_anomaly": is_anomaly,
            "threat_level": threat_level,
            "confidence": final_score,
            
            # RAG Results (RAG Core)
            "rag_threats": threat_intel,
            "similar_threats": threat_intel,  # Backward compatibility
            
            # Pattern details
            "pattern_analysis": {
                "pattern": pattern_result.get('pattern'),
                "description": pattern_result.get('description'),
                "matched_threats": pattern_result.get('matched_threats', []),
                "all_patterns": pattern_result.get('all_patterns', [])
            }
        }
        
        # Add LLM analysis if available
        if llm_result:
            result["llm_analysis"] = {
                "threat_level": llm_result.get('threat_level', threat_level),
                "recommendations": llm_result.get('recommendations', []),
                "risk_assessment": llm_result.get('risk_assessment', '')
            }
            result["recommendations"] = llm_result.get('recommendations', [])
        else:
            result["recommendations"] = self._generate_basic_recommendations(
                scoring_result, pattern_result, threat_intel
            )
        
        return result
    
    # ==================== RAG Operations (Delegated to RAG Core) ====================
    
    def ingest_threat_intelligence(self, **kwargs) -> Dict:
        """
        Ingest threat intelligence (delegated to RAG Core)
        
        Returns:
            Dict with ingestion results
        """
        if self.use_rag_core and self.rag_system:
            return self.rag_system.ingest_threat_intelligence(**kwargs)
        else:
            return {"error": "RAG Core not available"}
    
    def build_episodes_from_events(self, events: List[dict]) -> List:
        """
        Build episodes from events (delegated to RAG Core)
        
        Args:
            events: List of Wazuh events
        
        Returns:
            List of security episodes
        """
        if self.use_rag_core and self.rag_system:
            return self.rag_system.build_episodes_from_events(events)
        else:
            return []
    
    def index_episodes(self, rebuild: bool = False):
        """
        Index episodes for retrieval (delegated to RAG Core)
        This triggers embedding generation and indexing.
        
        Args:
            rebuild: Whether to rebuild index
        """
        if self.use_rag_core and self.rag_system:
            self.rag_system.index_episodes(rebuild=rebuild)
        else:
            print("⚠️ RAG Core not available for indexing")
    
    # ==================== Isolation Forest Operations (AI Engine) ====================
    
    def prioritize_events(self, events: List[dict]) -> List[dict]:
        """
        Prioritize multiple events using Isolation Forest scoring
        
        Args:
            events: List of event dictionaries
        
        Returns:
            List of events with priority scores and ranks, sorted by priority
        """
        return self.anomaly_detector.prioritize_events(events)
    
    def score_event(self, event: dict) -> dict:
        """
        Score event using Isolation Forest
        
        Args:
            event: Event dictionary
        
        Returns:
            Dict with multi-dimensional scores
        """
        return self.anomaly_detector.multi_dimensional_scoring(event)
    
    # ==================== Helper Methods ====================
    
    def _build_event_description(self, event: dict) -> str:
        """Build human-readable event description"""
        agent_name = event.get('agent', {}).get('name', 'unknown') if isinstance(event.get('agent'), dict) else 'unknown'
        message = event.get('message', event.get('data', {}).get('srcip', ''))
        if isinstance(message, dict):
            message = str(message)
        return f"Event from {agent_name}: {str(message)[:200]}"
    
    def _generate_basic_recommendations(self, scoring_result, pattern_result, threat_intel):
        """Generate basic recommendations without LLM"""
        recommendations = []
        
        # Scoring-based recommendations
        if scoring_result.get('combined_score', 0) > 80:
            recommendations.append("High priority score detected - immediate investigation recommended")
        
        if scoring_result.get('time_score', 0) > 20:
            recommendations.append("Event occurred during off-hours - suspicious timing")
        
        if scoring_result.get('frequency_score', 0) > 30:
            recommendations.append("High frequency of failed attempts detected - possible brute force")
        
        # Pattern-based recommendations
        if pattern_result.get('suspicious'):
            pattern_name = pattern_result.get('pattern', 'unknown')
            recommendations.append(f"Suspicious pattern detected: {pattern_name}")
            
            # Pattern-specific recommendations
            if 'SSH' in pattern_name or 'Brute Force' in pattern_name:
                recommendations.append("Consider blocking source IP and enabling rate limiting")
            elif 'SQL Injection' in pattern_name:
                recommendations.append("Review database access logs and validate input sanitization")
            elif 'PowerShell' in pattern_name:
                recommendations.append("Investigate PowerShell execution and check for script obfuscation")
        
        # RAG-based recommendations
        if threat_intel:
            top_threat = threat_intel[0]
            recommendations.append(f"Similar to known threat: {top_threat.get('description', '')[:100]}")
            if top_threat.get('mitigation'):
                recommendations.append(f"Recommended mitigation: {top_threat['mitigation']}")
        
        if not recommendations:
            recommendations.append("Review event manually for potential security concerns")
        
        return recommendations
    
    def _extract_entities_from_event(self, event: dict) -> Optional[Dict[str, List[str]]]:
        """Extract entities from event for RAG filtering"""
        entities = {}
        
        # Extract IPs
        agent = event.get('agent', {})
        if isinstance(agent, dict):
            ip_list = agent.get('ip', [])
            if ip_list:
                entities['ip'] = ip_list if isinstance(ip_list, list) else [ip_list]
        
        # Extract from message/data
        message = str(event.get('message', ''))
        
        # Try to extract IPs from message
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, message)
        if ips:
            if 'ip' not in entities:
                entities['ip'] = []
            entities['ip'].extend(ips)
        
        return entities if entities else None
    
    def _extract_tags_from_event(self, event: dict) -> Optional[List[str]]:
        """Extract tags from event for RAG filtering"""
        tags = []
        
        # Extract from message
        message = str(event.get('message', '')).lower()
        
        # Common security tags
        if any(word in message for word in ['ssh', 'login', 'auth']):
            tags.append('authentication')
        if any(word in message for word in ['process', 'exec', 'command']):
            tags.append('process')
        if any(word in message for word in ['network', 'connection', 'port']):
            tags.append('network')
        if any(word in message for word in ['file', 'integrity', 'modification']):
            tags.append('file_integrity')
        
        return tags if tags else None
