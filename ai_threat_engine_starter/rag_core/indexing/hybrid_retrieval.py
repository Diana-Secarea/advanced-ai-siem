"""
Hybrid Retrieval System with Freshness Boosting
Combines BM25, vector search, and time-based freshness
"""

import json
from collections import defaultdict
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False

try:
    from rank_bm25 import BM25Okapi
    BM25_AVAILABLE = True
except ImportError:
    BM25_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer, CrossEncoder
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False


class HybridRetrieval:
    """
    Hybrid retrieval system with:
    - BM25 for exact keyword matches
    - Vector embeddings for semantic similarity
    - Freshness boosting for time-sensitive data
    - Metadata filtering
    - Re-ranking with cross-encoder
    """
    
    def __init__(
        self,
        embedding_model: str = "all-MiniLM-L6-v2",
        use_reranker: bool = True,
        semantic_weight: float = 0.6,
        keyword_weight: float = 0.3,
        freshness_weight: float = 0.1
    ):
        self.semantic_weight = semantic_weight
        self.keyword_weight = keyword_weight
        self.freshness_weight = freshness_weight
        
        # Initialize embedding model
        if TRANSFORMERS_AVAILABLE:
            self.embedder = SentenceTransformer(embedding_model)
            self.dimension = self.embedder.get_sentence_embedding_dimension()
            
            if use_reranker:
                try:
                    self.reranker = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
                    self.reranker_enabled = True
                except:
                    self.reranker_enabled = False
            else:
                self.reranker_enabled = False
        else:
            self.embedder = None
            self.reranker_enabled = False
        
        # Data structures
        self.episodes: List[Dict] = []
        self.embeddings: Optional[np.ndarray] = None
        self.bm25_index = None
        self.vector_index = None
        
        # Metadata indexes
        self.entity_index: Dict[str, List[int]] = defaultdict(list)  # entity -> episode indices
        self.time_index: List[datetime] = []
        self.tag_index: Dict[str, List[int]] = defaultdict(list)  # tag -> episode indices
    
    def index_episodes(self, episodes: List[Dict]):
        """Index security episodes"""
        self.episodes = episodes
        
        if not episodes:
            return
        
        print(f"Indexing {len(episodes)} episodes...")
        
        # Build text corpus for BM25 and embeddings
        texts = []
        for episode in episodes:
            # Combine all text fields
            text_parts = [
                episode.get('summary', ''),
                ' '.join(episode.get('tags', [])),
                ' '.join([f"{k}:{','.join(v)}" for k, v in episode.get('entities', {}).items()])
            ]
            texts.append(' '.join(text_parts))
        
        # Build BM25 index
        if BM25_AVAILABLE:
            tokenized = [text.lower().split() for text in texts]
            self.bm25_index = BM25Okapi(tokenized)
            print("✅ BM25 index built")
        else:
            print("⚠️ BM25 not available")
        
        # Build vector embeddings
        if self.embedder:
            print("Generating embeddings...")
            self.embeddings = self.embedder.encode(texts, batch_size=32, show_progress_bar=True)
            
            # Build FAISS index
            if FAISS_AVAILABLE:
                dimension = self.embeddings.shape[1]
                self.vector_index = faiss.IndexHNSWFlat(dimension, 32)
                self.vector_index.hnsw.efConstruction = 200
                self.vector_index.hnsw.efSearch = 50
                
                # Normalize embeddings
                faiss.normalize_L2(self.embeddings)
                self.vector_index.add(self.embeddings.astype('float32'))
                print("✅ Vector index built")
            else:
                print("⚠️ FAISS not available, using numpy")
        
        # Build metadata indexes
        self._build_metadata_indexes()
        
        print("✅ Indexing complete")
    
    def _build_metadata_indexes(self):
        """Build metadata indexes for fast filtering"""
        self.entity_index.clear()
        self.time_index.clear()
        self.tag_index.clear()
        
        for idx, episode in enumerate(self.episodes):
            # Entity index
            entities = episode.get('entities', {})
            for entity_type, values in entities.items():
                for value in values:
                    self.entity_index[f"{entity_type}:{value}"].append(idx)
            
            # Time index
            time_range = episode.get('time_range', {})
            start_str = time_range.get('start', '')
            try:
                start_time = datetime.fromisoformat(start_str.replace('Z', '+00:00'))
                self.time_index.append(start_time)
            except:
                self.time_index.append(datetime.utcnow())
            
            # Tag index
            for tag in episode.get('tags', []):
                self.tag_index[tag].append(idx)
    
    def search(
        self,
        query: str,
        top_k: int = 10,
        filter_entities: Optional[Dict[str, List[str]]] = None,
        filter_tags: Optional[List[str]] = None,
        time_window: Optional[Tuple[datetime, datetime]] = None,
        boost_freshness: bool = True,
        use_reranking: bool = True
    ) -> List[Dict]:
        """
        Hybrid search with filtering and freshness boosting
        
        Args:
            query: Search query
            top_k: Number of results
            filter_entities: Filter by entities {type: [values]}
            filter_tags: Filter by tags
            time_window: Filter by time range (start, end)
            boost_freshness: Apply freshness boosting
            use_reranking: Use cross-encoder reranking
        """
        if not self.episodes:
            return []
        
        # Pre-filter by metadata
        candidate_indices = self._prefilter(
            filter_entities=filter_entities,
            filter_tags=filter_tags,
            time_window=time_window
        )
        
        if not candidate_indices:
            candidate_indices = list(range(len(self.episodes)))
        
        # Get more candidates for reranking
        search_k = min(top_k * 3, len(candidate_indices))
        
        # Semantic search
        semantic_scores = self._semantic_search(query, candidate_indices)
        
        # Keyword search
        keyword_scores = self._keyword_search(query, candidate_indices)
        
        # Freshness scores
        freshness_scores = self._freshness_scores(candidate_indices) if boost_freshness else np.ones(len(candidate_indices))
        
        # Combine scores
        combined_scores = (
            self.semantic_weight * semantic_scores +
            self.keyword_weight * keyword_scores +
            self.freshness_weight * freshness_scores
        )
        
        # Get top candidates
        top_indices = np.argsort(combined_scores)[::-1][:search_k]
        top_indices = [candidate_indices[i] for i in top_indices]
        
        # Re-ranking
        if use_reranking and self.reranker_enabled:
            top_indices = self._rerank(query, top_indices)
        
        # Format results
        results = []
        for idx in top_indices[:top_k]:
            episode = self.episodes[idx]
            result = {
                'episode_id': episode.get('episode_id'),
                'episode_type': episode.get('episode_type'),
                'summary': episode.get('summary'),
                'entities': episode.get('entities'),
                'tags': episode.get('tags'),
                'time_range': episode.get('time_range'),
                'score': float(combined_scores[candidate_indices.index(idx)]),
                'metadata': episode.get('metadata', {}),
                'raw_refs': episode.get('raw_refs', [])
            }
            results.append(result)
        
        return results
    
    def _prefilter(
        self,
        filter_entities: Optional[Dict] = None,
        filter_tags: Optional[List] = None,
        time_window: Optional[Tuple] = None
    ) -> List[int]:
        """Pre-filter episodes by metadata"""
        candidate_sets = []
        
        # Entity filtering
        if filter_entities:
            entity_indices = set()
            for entity_type, values in filter_entities.items():
                for value in values:
                    key = f"{entity_type}:{value}"
                    entity_indices.update(self.entity_index.get(key, []))
            if entity_indices:
                candidate_sets.append(entity_indices)
        
        # Tag filtering
        if filter_tags:
            tag_indices = set()
            for tag in filter_tags:
                tag_indices.update(self.tag_index.get(tag, []))
            if tag_indices:
                candidate_sets.append(tag_indices)
        
        # Time filtering
        if time_window:
            start, end = time_window
            time_indices = set()
            for idx, episode_time in enumerate(self.time_index):
                if start <= episode_time <= end:
                    time_indices.add(idx)
            if time_indices:
                candidate_sets.append(time_indices)
        
        # Intersect all filters
        if candidate_sets:
            candidates = set.intersection(*candidate_sets)
            return list(candidates)
        
        return []
    
    def _semantic_search(self, query: str, candidate_indices: List[int]) -> np.ndarray:
        """Semantic search using vector embeddings"""
        if not self.embedder or self.embeddings is None:
            return np.zeros(len(candidate_indices))
        
        # Encode query
        query_embedding = self.embedder.encode([query])[0]
        faiss.normalize_L2(query_embedding.reshape(1, -1))
        
        # Search in FAISS
        if FAISS_AVAILABLE and self.vector_index:
            query_embedding = query_embedding.reshape(1, -1).astype('float32')
            k = min(len(candidate_indices), 100)
            distances, indices = self.vector_index.search(query_embedding, k)
            
            # Map to candidate indices and compute similarities
            similarities = np.zeros(len(candidate_indices))
            for i, idx in enumerate(indices[0]):
                if idx in candidate_indices:
                    pos = candidate_indices.index(idx)
                    # Convert distance to similarity (cosine similarity)
                    similarities[pos] = 1 - distances[0][i]
            
            return similarities
        else:
            # Fallback: cosine similarity with numpy
            candidate_embeddings = self.embeddings[candidate_indices]
            similarities = np.dot(candidate_embeddings, query_embedding)
            return (similarities + 1) / 2  # Normalize to [0, 1]
    
    def _keyword_search(self, query: str, candidate_indices: List[int]) -> np.ndarray:
        """Keyword search using BM25"""
        if not self.bm25_index:
            return np.zeros(len(candidate_indices))
        
        tokenized_query = query.lower().split()
        all_scores = self.bm25_index.get_scores(tokenized_query)
        
        # Extract scores for candidates
        candidate_scores = all_scores[candidate_indices]
        
        # Normalize to [0, 1]
        if candidate_scores.max() > 0:
            candidate_scores = candidate_scores / candidate_scores.max()
        
        return candidate_scores
    
    def _freshness_scores(self, candidate_indices: List[int]) -> np.ndarray:
        """Calculate freshness scores based on time"""
        scores = np.zeros(len(candidate_indices))
        now = datetime.utcnow()
        
        for i, idx in enumerate(candidate_indices):
            episode_time = self.time_index[idx]
            
            # Calculate age in hours
            age_hours = (now - episode_time).total_seconds() / 3600
            
            # Freshness decay: newer = higher score
            # Exponential decay: score = exp(-age / decay_constant)
            decay_constant = 24 * 7  # 1 week half-life
            freshness = np.exp(-age_hours / decay_constant)
            
            scores[i] = freshness
        
        return scores
    
    def _rerank(self, query: str, candidate_indices: List[int]) -> List[int]:
        """Re-rank using cross-encoder"""
        if not self.reranker_enabled or not candidate_indices:
            return candidate_indices
        
        # Get episode texts
        episode_texts = [self.episodes[idx].get('summary', '') for idx in candidate_indices]
        
        # Create query-document pairs
        pairs = [[query, text] for text in episode_texts]
        
        # Get rerank scores
        rerank_scores = self.reranker.predict(pairs)
        
        # Sort by rerank score
        ranked = sorted(zip(candidate_indices, rerank_scores), key=lambda x: x[1], reverse=True)
        
        return [idx for idx, _ in ranked]
    
    def save_index(self, path: str):
        """Save indexes to disk"""
        index_path = Path(path)
        index_path.mkdir(parents=True, exist_ok=True)
        
        # Save episodes
        with open(index_path / "episodes.json", 'w') as f:
            json.dump(self.episodes, f, indent=2, default=str)
        
        # Save embeddings
        if self.embeddings is not None:
            np.save(index_path / "embeddings.npy", self.embeddings)
        
        # Save FAISS index
        if self.vector_index is not None:
            faiss.write_index(self.vector_index, str(index_path / "vector_index.faiss"))
        
        # Save metadata indexes
        metadata = {
            'entity_index': {k: v for k, v in self.entity_index.items()},
            'tag_index': {k: v for k, v in self.tag_index.items()},
            'time_index': [t.isoformat() for t in self.time_index]
        }
        with open(index_path / "metadata_index.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"✅ Indexes saved to {path}")
    
    def load_index(self, path: str):
        """Load indexes from disk"""
        index_path = Path(path)
        
        # Load episodes
        with open(index_path / "episodes.json", 'r') as f:
            self.episodes = json.load(f)
        
        # Load embeddings
        embeddings_file = index_path / "embeddings.npy"
        if embeddings_file.exists():
            self.embeddings = np.load(embeddings_file)
        
        # Load FAISS index
        vector_index_file = index_path / "vector_index.faiss"
        if vector_index_file.exists() and FAISS_AVAILABLE:
            self.vector_index = faiss.read_index(str(vector_index_file))
        
        # Rebuild other indexes
        self._build_metadata_indexes()
        
        print(f"✅ Indexes loaded from {path}")
