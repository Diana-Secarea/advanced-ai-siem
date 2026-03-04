"""
AI Agent Workflow for SOC Operations
Multi-step pipeline: Understand → Retrieve → Reason → Validate → Output
"""

import json
from typing import Dict, List, Any, Optional, TYPE_CHECKING
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import sys
from pathlib import Path

# Add parent path for rag_core submodules only (do not import ai_engine at load time - breaks RAG Core init)
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from rag_core.indexing.hybrid_retrieval import HybridRetrieval
from rag_core.episodes.episode_builder import SecurityEpisode

# Lazy import to avoid circular import: rag_core_system -> agent_workflow -> ai_engine -> main -> rag_core_system
if TYPE_CHECKING:
    from ai_engine.anomaly_detector import AnomalyDetector
ISOLATION_FOREST_AVAILABLE = None  # Set on first use


@dataclass
class AgentTask:
    """Task classification"""
    task_type: str  # triage, hunt, write_detection, explain_technique
    confidence: float
    reasoning: str


@dataclass
class AgentHypothesis:
    """Security hypothesis"""
    technique: str  # ATT&CK technique ID
    confidence: float
    evidence: List[str]
    indicators: List[str]
    queries: List[str]  # KQL/Splunk/SQL queries


@dataclass
class AgentOutput:
    """Structured agent output"""
    hypothesis: AgentHypothesis
    decision: str  # confirmed, likely, possible, unlikely
    confidence: float
    citations: List[str]  # Links to retrieved docs
    recommendations: List[str]
    next_queries: List[str]
    validation_checks: Dict[str, bool]


def _get_anomaly_detector_class():
    """Lazy import to avoid circular import with ai_engine."""
    global ISOLATION_FOREST_AVAILABLE
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from ai_engine.anomaly_detector import AnomalyDetector
        ISOLATION_FOREST_AVAILABLE = True
        return AnomalyDetector
    except ImportError:
        ISOLATION_FOREST_AVAILABLE = False
        return None


class SOCAgent:
    """
    SOC Agent with multi-step reasoning workflow
    """
    
    def __init__(
        self,
        retrieval: HybridRetrieval,
        anomaly_detector: Optional[Any] = None,
        threat_intel_path: str = None
    ):
        self.retrieval = retrieval
        self.anomaly_detector = anomaly_detector
        
        # Default to ai_threat_engine_starter/threat_intel
        if threat_intel_path is None:
            import os
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            threat_intel_path = os.path.join(base_path, "threat_intel")
        
        self.threat_intel_path = Path(threat_intel_path)
        
        # Load threat intelligence
        self.attack_techniques = self._load_attack_techniques()
        self.playbooks = self._load_playbooks()
    
    def process(self, input_data: Dict) -> AgentOutput:
        """
        Main agent workflow
        
        Args:
            input_data: Can be alert, episode, or query
        
        Returns:
            AgentOutput with structured analysis
        """
        # Step 1: Understand task
        task = self._understand_task(input_data)
        print(f"📋 Task: {task.task_type} (confidence: {task.confidence:.2f})")
        
        # Step 2: Retrieve relevant information
        retrieved_docs = self._retrieve(input_data, task)
        print(f"🔍 Retrieved {len(retrieved_docs)} relevant documents")
        
        # Step 3: Reason
        hypothesis = self._reason(input_data, retrieved_docs, task)
        print(f"💡 Hypothesis: {hypothesis.technique} (confidence: {hypothesis.confidence:.2f})")
        
        # Step 4: Validate
        validation = self._validate(hypothesis, input_data, retrieved_docs)
        print(f"✅ Validation: {sum(validation.values())}/{len(validation)} checks passed")
        
        # Step 5: Output
        output = self._generate_output(hypothesis, validation, retrieved_docs, task)
        
        return output
    
    def _understand_task(self, input_data: Dict) -> AgentTask:
        """Step 1: Classify the task"""
        # Analyze input to determine task type
        text = json.dumps(input_data).lower()
        
        task_type = "triage"  # Default
        confidence = 0.5
        
        # Check for keywords
        if any(word in text for word in ['hunt', 'investigate', 'search']):
            task_type = "hunt"
            confidence = 0.7
        elif any(word in text for word in ['detection', 'rule', 'alert']):
            task_type = "write_detection"
            confidence = 0.7
        elif any(word in text for word in ['explain', 'what is', 'technique']):
            task_type = "explain_technique"
            confidence = 0.8
        elif any(word in text for word in ['alert', 'incident', 'anomaly']):
            task_type = "triage"
            confidence = 0.8
        
        reasoning = f"Detected {task_type} task based on input content"
        
        return AgentTask(
            task_type=task_type,
            confidence=confidence,
            reasoning=reasoning
        )
    
    def _retrieve(self, input_data: Dict, task: AgentTask) -> List[Dict]:
        """Step 2: Retrieve relevant information"""
        # Build query from input
        query = self._build_query(input_data, task)
        
        # Extract entities for filtering
        entities = self._extract_entities(input_data)
        tags = self._extract_tags(input_data)
        
        # Time window (last 30 days for telemetry)
        if task.task_type == "triage":
            time_window = (
                datetime.utcnow() - timedelta(days=30),
                datetime.utcnow()
            )
        else:
            time_window = None
        
        # Retrieve episodes
        episodes = self.retrieval.search(
            query=query,
            top_k=20,
            filter_entities=entities,
            filter_tags=tags,
            time_window=time_window,
            boost_freshness=True,
            use_reranking=True
        )
        
        # Retrieve playbooks
        playbooks = self._retrieve_playbooks(task)
        
        # Retrieve ATT&CK techniques
        attack_refs = self._retrieve_attack_techniques(query)
        
        # Combine
        retrieved = {
            'episodes': episodes,
            'playbooks': playbooks,
            'attack_techniques': attack_refs
        }
        
        return retrieved
    
    def _reason(self, input_data: Dict, retrieved: Dict, task: AgentTask) -> AgentHypothesis:
        """Step 3: Reason about the threat"""
        # Analyze with Isolation Forest if available
        anomaly_score = 0.0
        if self.anomaly_detector:
            try:
                anomaly_result = self.anomaly_detector.detect_anomaly(input_data)
                anomaly_score = anomaly_result.get('anomaly_score', 0) / 100.0
            except:
                pass
        
        # Extract likely technique from retrieved ATT&CK
        techniques = retrieved.get('attack_techniques', [])
        likely_technique = "T0000"  # Unknown
        technique_confidence = 0.0
        
        if techniques:
            # Use top technique
            top_tech = techniques[0]
            likely_technique = top_tech.get('id', 'T0000')
            technique_confidence = top_tech.get('similarity', 0.0)
        
        # Build evidence list
        evidence = []
        
        # From episodes
        for episode in retrieved.get('episodes', [])[:5]:
            evidence.append(f"Similar episode: {episode.get('summary', '')[:100]}")
        
        # From anomaly detection
        if anomaly_score > 0.7:
            evidence.append(f"High anomaly score: {anomaly_score:.2%}")
        
        # From playbooks
        for playbook in retrieved.get('playbooks', [])[:3]:
            evidence.append(f"Playbook match: {playbook.get('title', '')}")
        
        # Extract indicators
        indicators = self._extract_indicators(input_data, retrieved)
        
        # Generate queries
        queries = self._generate_queries(input_data, likely_technique, indicators)
        
        # Combine confidence
        confidence = (
            0.4 * technique_confidence +
            0.3 * anomaly_score +
            0.3 * min(len(evidence) / 5.0, 1.0)
        )
        
        return AgentHypothesis(
            technique=likely_technique,
            confidence=confidence,
            evidence=evidence[:5],
            indicators=indicators,
            queries=queries
        )
    
    def _validate(self, hypothesis: AgentHypothesis, input_data: Dict, retrieved: Dict) -> Dict[str, bool]:
        """Step 4: Validate hypothesis"""
        checks = {}
        
        # Check 1: Does detection rely on fields we have?
        checks['fields_available'] = self._check_fields_available(input_data, hypothesis)
        
        # Check 2: Does it explode (high FP risk)?
        checks['low_fp_risk'] = self._check_fp_risk(hypothesis, retrieved)
        
        # Check 3: Is it already covered?
        checks['not_duplicate'] = self._check_not_duplicate(hypothesis, retrieved)
        
        # Check 4: Does it contradict evidence?
        checks['consistent'] = self._check_consistency(hypothesis, retrieved)
        
        # Check 5: Are queries valid?
        checks['queries_valid'] = self._check_queries_valid(hypothesis.queries)
        
        return checks
    
    def _generate_output(
        self,
        hypothesis: AgentHypothesis,
        validation: Dict[str, bool],
        retrieved: Dict,
        task: AgentTask
    ) -> AgentOutput:
        """Step 5: Generate structured output"""
        # Determine decision
        passed_checks = sum(validation.values())
        total_checks = len(validation)
        
        if passed_checks == total_checks and hypothesis.confidence > 0.8:
            decision = "confirmed"
        elif passed_checks >= total_checks * 0.6 and hypothesis.confidence > 0.6:
            decision = "likely"
        elif hypothesis.confidence > 0.4:
            decision = "possible"
        else:
            decision = "unlikely"
        
        # Build citations
        citations = []
        for episode in retrieved.get('episodes', [])[:5]:
            citations.append(f"episode:{episode.get('episode_id')}")
        for tech in retrieved.get('attack_techniques', [])[:3]:
            citations.append(f"attack:{tech.get('id')}")
        
        # Generate recommendations
        recommendations = self._generate_recommendations(hypothesis, validation, task)
        
        # Next queries
        next_queries = hypothesis.queries[:5]
        
        return AgentOutput(
            hypothesis=hypothesis,
            decision=decision,
            confidence=hypothesis.confidence,
            citations=citations,
            recommendations=recommendations,
            next_queries=next_queries,
            validation_checks=validation
        )
    
    # Helper methods
    
    def _build_query(self, input_data: Dict, task: AgentTask) -> str:
        """Build search query from input"""
        parts = []
        
        if 'message' in input_data:
            parts.append(str(input_data['message'])[:200])
        if 'summary' in input_data:
            parts.append(str(input_data['summary'])[:200])
        if 'description' in input_data:
            parts.append(str(input_data['description'])[:200])
        
        # Add task context
        if task.task_type == "hunt":
            parts.append("hunt investigation")
        elif task.task_type == "write_detection":
            parts.append("detection rule")
        
        return " ".join(parts) if parts else "security event"
    
    def _extract_entities(self, input_data: Dict) -> Dict[str, List[str]]:
        """Extract entities for filtering"""
        entities = {}
        
        data = input_data.get('data', input_data)
        
        if 'srcip' in data:
            entities.setdefault('ips', []).append(str(data['srcip']))
        if 'dstip' in data:
            entities.setdefault('ips', []).append(str(data['dstip']))
        if 'user' in data:
            entities.setdefault('users', []).append(str(data['user']))
        if 'hostname' in data:
            entities.setdefault('hosts', []).append(str(data['hostname']))
        
        return entities
    
    def _extract_tags(self, input_data: Dict) -> List[str]:
        """Extract tags"""
        tags = input_data.get('tags', [])
        return tags if isinstance(tags, list) else []
    
    def _retrieve_playbooks(self, task: AgentTask) -> List[Dict]:
        """Retrieve relevant playbooks"""
        playbooks = []
        
        playbook_file = self.threat_intel_path / "playbooks.json"
        if playbook_file.exists():
            try:
                with open(playbook_file, 'r') as f:
                    data = json.load(f)
                    all_playbooks = data.get('playbooks', [])
                    
                    # Filter by task type
                    for playbook in all_playbooks:
                        if task.task_type in playbook.get('tags', []):
                            playbooks.append(playbook)
            except:
                pass
        
        return playbooks[:5]
    
    def _retrieve_attack_techniques(self, query: str) -> List[Dict]:
        """Retrieve relevant ATT&CK techniques"""
        if not self.attack_techniques:
            return []
        
        # Simple keyword matching (would use embeddings in production)
        results = []
        query_lower = query.lower()
        
        for tech in self.attack_techniques:
            score = 0.0
            name = tech.get('name', '').lower()
            desc = tech.get('description', '').lower()
            
            if any(word in name for word in query_lower.split()):
                score += 0.5
            if any(word in desc for word in query_lower.split()):
                score += 0.3
            
            if score > 0:
                results.append({
                    'id': tech.get('id'),
                    'name': tech.get('name'),
                    'description': tech.get('description', '')[:200],
                    'similarity': score
                })
        
        # Sort by similarity
        results.sort(key=lambda x: x['similarity'], reverse=True)
        return results[:5]
    
    def _extract_indicators(self, input_data: Dict, retrieved: Dict) -> List[str]:
        """Extract suspicious indicators"""
        indicators = []
        
        text = json.dumps(input_data).lower()
        
        # Common indicators
        indicator_patterns = {
            'powershell_encoded': ['powershell', 'encoded', 'base64'],
            'privilege_escalation': ['sudo', 'su', 'privilege', 'escalation'],
            'process_injection': ['injection', 'dll', 'process'],
            'lateral_movement': ['psexec', 'wmic', 'lateral'],
            'credential_access': ['password', 'credential', 'hash']
        }
        
        for indicator, keywords in indicator_patterns.items():
            if all(kw in text for kw in keywords[:2]):
                indicators.append(indicator)
        
        return indicators
    
    def _generate_queries(self, input_data: Dict, technique: str, indicators: List[str]) -> List[str]:
        """Generate investigation queries"""
        queries = []
        
        # KQL queries
        entities = self._extract_entities(input_data)
        
        if entities.get('ips'):
            ip = entities['ips'][0]
            queries.append(f"Wazuh | where srcip == '{ip}' | summarize count() by rule.description")
        
        if entities.get('users'):
            user = entities['users'][0]
            queries.append(f"Wazuh | where srcuser == '{user}' | where timestamp > ago(7d)")
        
        # Technique-specific queries
        if technique.startswith('T'):
            queries.append(f"Wazuh | where rule.mitre.id == '{technique}' | summarize count() by agent.name")
        
        return queries
    
    def _check_fields_available(self, input_data: Dict, hypothesis: AgentHypothesis) -> bool:
        """Check if required fields are available"""
        # Simplified - would check against schema
        return True
    
    def _check_fp_risk(self, hypothesis: AgentHypothesis, retrieved: Dict) -> bool:
        """Check false positive risk"""
        # If many similar episodes exist, lower FP risk
        episodes = retrieved.get('episodes', [])
        return len(episodes) > 2
    
    def _check_not_duplicate(self, hypothesis: AgentHypothesis, retrieved: Dict) -> bool:
        """Check if detection already exists"""
        # Simplified - would check against existing rules
        return True
    
    def _check_consistency(self, hypothesis: AgentHypothesis, retrieved: Dict) -> bool:
        """Check if hypothesis is consistent with evidence"""
        # If most evidence supports hypothesis, consistent
        episodes = retrieved.get('episodes', [])
        if episodes:
            avg_score = sum(e.get('score', 0) for e in episodes[:5]) / len(episodes[:5])
            return avg_score > 0.5
        return True
    
    def _check_queries_valid(self, queries: List[str]) -> bool:
        """Check if queries are valid"""
        # Simplified - would validate syntax
        return len(queries) > 0
    
    def _generate_recommendations(
        self,
        hypothesis: AgentHypothesis,
        validation: Dict[str, bool],
        task: AgentTask
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if hypothesis.confidence > 0.7:
            recommendations.append(f"Investigate technique {hypothesis.technique}")
        
        if not validation.get('low_fp_risk'):
            recommendations.append("High FP risk - review before deploying")
        
        if hypothesis.indicators:
            recommendations.append(f"Key indicators: {', '.join(hypothesis.indicators[:3])}")
        
        if hypothesis.queries:
            recommendations.append("Run investigation queries to gather more evidence")
        
        return recommendations
    
    def _load_attack_techniques(self) -> List[Dict]:
        """Load ATT&CK techniques"""
        attack_file = self.threat_intel_path / "attack" / "attack_techniques.json"
        if attack_file.exists():
            try:
                with open(attack_file, 'r') as f:
                    data = json.load(f)
                    return data.get('techniques', [])
            except:
                pass
        return []
    
    def _load_playbooks(self) -> List[Dict]:
        """Load incident response playbooks"""
        playbook_file = self.threat_intel_path / "playbooks.json"
        if playbook_file.exists():
            try:
                with open(playbook_file, 'r') as f:
                    data = json.load(f)
                    return data.get('playbooks', [])
            except:
                pass
        return []


# Import defaultdict
from collections import defaultdict
