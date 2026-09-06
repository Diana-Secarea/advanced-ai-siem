"""
Qdrant vector store for Wazuh AI Threat Engine.

Uses hybrid search: dense (semantic) + sparse (BM25 keyword) vectors,
fused with Reciprocal Rank Fusion (RRF).

Collections:
  wazuh_threat_intel     — threat intelligence episodes
  wazuh_alert_episodes   — alert episodes for similarity search

Search returns episode dicts compatible with the rest of the system.
"""

import uuid
from typing import Optional

import numpy as np
from sentence_transformers import SentenceTransformer
from fastembed import SparseTextEmbedding

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    SparseVectorParams,
    SparseIndexParams,
    SparseVector,
    PointStruct,
    Prefetch,
    FusionQuery,
    Fusion,
    Filter,
    FieldCondition,
    MatchValue,
    MatchAny,
    PayloadSchemaType,
)

from rag_core.database.config import (
    QDRANT_HOST,
    QDRANT_PORT,
    QDRANT_TIMEOUT,
    COLLECTION_THREAT_INTEL,
    COLLECTION_ALERT_EPISODES,
    EMBEDDING_MODEL,
    EMBEDDING_DIM,
    SPARSE_MODEL,
)

# Named vector keys
DENSE_VEC  = "dense"
SPARSE_VEC = "sparse"

# Candidates fetched from each retriever before fusion.
# Must be > top_k so RRF has enough candidates to rerank.
PREFETCH_LIMIT = 40


# ---------------------------------------------------------------------------
# Standalone RRF fusion (importable without QdrantStore)
# ---------------------------------------------------------------------------

def rrf_fusion(
    ranked_lists: list[list[tuple]],
    k: int = 60,
) -> list[tuple]:
    """
    Reciprocal Rank Fusion over multiple ranked lists.

    Each list contains tuples of (doc_id, original_score, payload) sorted
    best-first. RRF assigns every document a fused score:

        RRF(d) = Σ_i  1 / (k + rank_i(d))

    where rank_i is 1-based position in list i and k=60 is the standard
    smoothing constant (dampens the impact of very high ranks).

    Documents that appear in only one list still receive a partial score;
    documents that appear in multiple lists accumulate contributions.

    Args:
        ranked_lists  List of ranked lists, each [(id, score, payload), ...]
        k             RRF smoothing constant (default 60)

    Returns:
        List of (doc_id, rrf_score, payload) sorted by rrf_score descending.
    """
    rrf_scores: dict[str, float] = {}
    payloads:   dict[str, dict]  = {}

    for ranked_list in ranked_lists:
        for rank, (doc_id, _orig_score, payload) in enumerate(ranked_list):
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + 1.0 / (k + rank + 1)
            payloads[doc_id]   = payload  # last writer wins (same doc, same payload)

    fused = [
        (doc_id, rrf_score, payloads[doc_id])
        for doc_id, rrf_score in rrf_scores.items()
    ]
    fused.sort(key=lambda x: x[1], reverse=True)
    return fused


class QdrantStore:
    """
    Manages two Qdrant collections with hybrid dense+sparse search.

    Dense  — sentence-transformers semantic embeddings (cosine similarity)
    Sparse — BM25 keyword embeddings via fastembed (exact/rare term matching)
    Fusion — Reciprocal Rank Fusion (RRF) combines both ranked lists

    Usage:
        store = QdrantStore()
        store.index_episodes(episodes)
        results = store.search("ssh brute force")
        results = store.search("CVE-2021-44228", filter_source_type="cisa_kev")
    """

    def __init__(self):
        self.client   = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT,
                                     timeout=QDRANT_TIMEOUT)
        self.embedder = SentenceTransformer(EMBEDDING_MODEL)
        self.sparse_embedder = SparseTextEmbedding(model_name=SPARSE_MODEL)
        self._ensure_collections()

    # ------------------------------------------------------------------
    # Collection setup
    # ------------------------------------------------------------------

    def _ensure_collections(self):
        """Create collections with dense+sparse vector config if they don't exist."""
        existing = {c.name for c in self.client.get_collections().collections}

        for name in (COLLECTION_THREAT_INTEL, COLLECTION_ALERT_EPISODES):
            if name not in existing:
                self.client.create_collection(
                    collection_name=name,
                    vectors_config={
                        DENSE_VEC: VectorParams(
                            size=EMBEDDING_DIM,
                            distance=Distance.COSINE,
                        ),
                    },
                    sparse_vectors_config={
                        SPARSE_VEC: SparseVectorParams(
                            index=SparseIndexParams(on_disk=False),
                        ),
                    },
                )
                # Payload indexes for fast metadata filtering
                for field, schema in [
                    ("source_type",  PayloadSchemaType.KEYWORD),
                    ("episode_type", PayloadSchemaType.KEYWORD),
                    ("tags",         PayloadSchemaType.KEYWORD),
                ]:
                    self.client.create_payload_index(name, field, schema)

                print(f"  [qdrant] Created collection: {name}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _episode_to_text(self, ep: dict) -> str:
        """Build the text string that will be embedded for an episode."""
        parts = [
            ep.get("summary", ""),
            " ".join(ep.get("tags", [])),
            " ".join(
                f"{k}:{','.join(str(v) for v in vals)}"
                for k, vals in (ep.get("entities") or {}).items()
            ),
        ]
        return " ".join(p for p in parts if p)

    def _episode_to_payload(self, ep: dict) -> dict:
        """Extract payload fields stored alongside the vector."""
        return {
            "episode_id":   ep.get("episode_id", ""),
            "episode_type": ep.get("episode_type", ""),
            "source_type":  ep.get("source", ep.get("source_type", "")),
            "summary":      ep.get("summary", ""),
            "tags":         list(ep.get("tags") or []),
            "entities":     ep.get("entities") or {},
            "time_range":   ep.get("time_range") or {},
            "metadata":     ep.get("metadata") or {},
            "raw_refs":     ep.get("raw_refs") or [],
        }

    def _sparse_vec(self, sparse_emb) -> SparseVector:
        """Convert a fastembed SparseEmbedding to a Qdrant SparseVector."""
        return SparseVector(
            indices=sparse_emb.indices.tolist(),
            values=sparse_emb.values.tolist(),
        )

    def _build_filter(
        self,
        filter_source_type: Optional[str] = None,
        filter_tags: Optional[list] = None,
        filter_episode_type: Optional[str] = None,
    ) -> Optional[Filter]:
        """Build a Qdrant Filter from optional metadata constraints."""
        conditions = []
        if filter_source_type:
            conditions.append(
                FieldCondition(key="source_type", match=MatchValue(value=filter_source_type))
            )
        if filter_episode_type:
            conditions.append(
                FieldCondition(key="episode_type", match=MatchValue(value=filter_episode_type))
            )
        if filter_tags:
            for tag in filter_tags:
                conditions.append(
                    FieldCondition(key="tags", match=MatchValue(value=tag))
                )
        return Filter(must=conditions) if conditions else None

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def index_episodes(
        self,
        episodes: list,
        collection: str = COLLECTION_THREAT_INTEL,
        batch_size: int = 256,
    ) -> int:
        """
        Embed (dense + sparse) and upsert episodes into Qdrant.
        Returns number of points upserted.
        """
        if not episodes:
            return 0

        print(f"  [qdrant] Indexing {len(episodes)} episodes into '{collection}'...")

        texts = [self._episode_to_text(ep) for ep in episodes]

        # --- Dense embeddings (sentence-transformers) ---
        dense_vecs = self.embedder.encode(
            texts,
            batch_size=64,
            show_progress_bar=True,
            normalize_embeddings=True,
        )

        # --- Sparse embeddings (BM25 via fastembed) ---
        sparse_embs = list(self.sparse_embedder.embed(texts, batch_size=64))

        # --- Upsert in batches ---
        total = 0
        for i in range(0, len(episodes), batch_size):
            batch_eps    = episodes[i : i + batch_size]
            batch_dense  = dense_vecs[i : i + batch_size]
            batch_sparse = sparse_embs[i : i + batch_size]

            points = []
            for ep, dvec, svec in zip(batch_eps, batch_dense, batch_sparse):
                point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, ep.get("episode_id", str(i))))
                points.append(
                    PointStruct(
                        id=point_id,
                        vector={
                            DENSE_VEC:  dvec.tolist(),
                            SPARSE_VEC: self._sparse_vec(svec),
                        },
                        payload=self._episode_to_payload(ep),
                    )
                )

            self.client.upsert(collection_name=collection, points=points)
            total += len(points)

        print(f"  [qdrant] Upserted {total} points into '{collection}'")
        return total

    # ------------------------------------------------------------------
    # Search — hybrid retrieval pipeline
    # ------------------------------------------------------------------

    def _fetch_dense(
        self,
        query_vec: list,
        limit: int,
        collection: str,
        qdrant_filter,
    ) -> list[tuple]:
        """
        Fetch top-`limit` candidates by dense (cosine) similarity.

        Returns [(point_id, score, payload), ...] sorted best-first.
        """
        response = self.client.query_points(
            collection_name=collection,
            query=query_vec,
            using=DENSE_VEC,
            limit=limit,
            query_filter=qdrant_filter,
            with_payload=True,
        )
        return [
            (hit.id, hit.score, hit.payload)
            for hit in response.points
        ]

    def _fetch_sparse(
        self,
        sparse_vec: SparseVector,
        limit: int,
        collection: str,
        qdrant_filter,
    ) -> list[tuple]:
        """
        Fetch top-`limit` candidates by sparse BM25 dot-product.

        Returns [(point_id, score, payload), ...] sorted best-first.
        """
        response = self.client.query_points(
            collection_name=collection,
            query=sparse_vec,
            using=SPARSE_VEC,
            limit=limit,
            query_filter=qdrant_filter,
            with_payload=True,
        )
        return [
            (hit.id, hit.score, hit.payload)
            for hit in response.points
        ]

    def search(
        self,
        query: str,
        top_k: int = 5,
        collection: str = COLLECTION_THREAT_INTEL,
        filter_source_type: Optional[str] = None,
        filter_tags: Optional[list] = None,
        filter_episode_type: Optional[str] = None,
        score_threshold: float = 0.0,
        rrf_k: int = 60,
    ) -> list:
        """
        Hybrid retrieval: dense + BM25 sparse → RRF fusion → top-k.

        Step 1  Encode query into a dense vector (sentence-transformers)
                and a sparse BM25 vector (fastembed).
        Step 2  Fetch PREFETCH_LIMIT candidates independently from Qdrant
                using the dense vector (cosine) and the sparse vector (dot).
                Metadata filters are applied at this stage so only matching
                documents enter the fusion step.
        Step 3  Merge the two ranked lists with rrf_fusion() and return
                the top-k results sorted by RRF score.

        Args:
            query               Natural language or keyword query
            top_k               Number of results to return
            collection          Qdrant collection name
            filter_source_type  Restrict to one source ('cisa_kev', 'sigma', ...)
            filter_tags         Restrict to episodes that have ALL of these tags
            filter_episode_type Restrict to one episode type ('mitre_attack', ...)
            score_threshold     Drop results with RRF score below this value
            rrf_k               RRF smoothing constant (default 60)

        Returns:
            List of episode dicts sorted by RRF score descending.
        """
        # --- Step 1: encode query ---
        dense_vec = self.embedder.encode(
            [query], normalize_embeddings=True
        )[0].tolist()

        sparse_vec = self._sparse_vec(
            next(self.sparse_embedder.embed([query]))
        )

        f = self._build_filter(filter_source_type, filter_tags, filter_episode_type)

        # --- Steps 2+3: prefer ONE native hybrid query (server-side RRF) ---
        # Qdrant (>=1.10) fuses the dense and sparse prefetches with RRF in a
        # single round-trip, halving the network latency of the old two-query +
        # client-side fusion path and offloading the merge onto the DB. Qdrant's
        # RRF uses the same 1/(k+rank) formula, so the [0,1] normalization below
        # (max_rrf = 2/(rrf_k+1)) stays valid. Fall back to the two-query path if
        # the server rejects the fused query for any reason (fail open).
        top = None
        try:
            response = self.client.query_points(
                collection_name=collection,
                prefetch=[
                    Prefetch(query=dense_vec,  using=DENSE_VEC,
                             limit=PREFETCH_LIMIT, filter=f),
                    Prefetch(query=sparse_vec, using=SPARSE_VEC,
                             limit=PREFETCH_LIMIT, filter=f),
                ],
                query=FusionQuery(fusion=Fusion.RRF),
                limit=top_k,
                with_payload=True,
            )
            top = [(hit.id, hit.score, hit.payload) for hit in response.points]
        except Exception as e:
            print(f"[qdrant] native fusion failed, using client-side RRF: {e}")

        if top is None:
            # --- Fallback: fetch each retriever independently, fuse in Python ---
            dense_hits  = self._fetch_dense(dense_vec,  PREFETCH_LIMIT, collection, f)
            sparse_hits = self._fetch_sparse(sparse_vec, PREFETCH_LIMIT, collection, f)
            fused = rrf_fusion([dense_hits, sparse_hits], k=rrf_k)
            top   = fused[:top_k]

        # Raw RRF scores live on a tiny scale: a document ranked #1 in BOTH
        # lists gets 2/(k+1) ≈ 0.0328 (k=60). Downstream consumers (severity
        # mapping, thresholds) expect a [0,1] similarity, so normalize by the
        # theoretical maximum. `score` keeps the raw RRF value for debugging.
        max_rrf = 2.0 / (rrf_k + 1)

        # --- Format output ---
        results = []
        for doc_id, rrf_score, payload in top:
            if score_threshold > 0 and rrf_score < score_threshold:
                continue
            results.append({
                "episode_id":   payload.get("episode_id"),
                "episode_type": payload.get("episode_type"),
                "summary":      payload.get("summary"),
                "entities":     payload.get("entities", {}),
                "tags":         payload.get("tags", []),
                "time_range":   payload.get("time_range", {}),
                "score":        rrf_score,
                "similarity":   min(1.0, rrf_score / max_rrf),
                "metadata":     payload.get("metadata", {}),
                "raw_refs":     payload.get("raw_refs", []),
            })

        return results

    # ------------------------------------------------------------------
    # Alert episodes
    # ------------------------------------------------------------------

    def index_alert_episode(self, episode: dict) -> str:
        """Index a single alert episode. Returns the Qdrant point UUID."""
        text      = self._episode_to_text(episode)
        dense_vec = self.embedder.encode([text], normalize_embeddings=True)[0].tolist()
        sparse_vec = self._sparse_vec(next(self.sparse_embedder.embed([text])))
        point_id  = str(uuid.uuid5(uuid.NAMESPACE_DNS, episode.get("episode_id", str(uuid.uuid4()))))

        self.client.upsert(
            collection_name=COLLECTION_ALERT_EPISODES,
            points=[PointStruct(
                id=point_id,
                vector={
                    DENSE_VEC:  dense_vec,
                    SPARSE_VEC: sparse_vec,
                },
                payload=self._episode_to_payload(episode),
            )],
        )
        return point_id

    def find_similar_alerts(self, episode: dict, top_k: int = 5) -> list:
        """Find past alert episodes similar to the given one."""
        return self.search(
            query=episode.get("summary", ""),
            top_k=top_k,
            collection=COLLECTION_ALERT_EPISODES,
        )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def collection_info(self, collection: str = COLLECTION_THREAT_INTEL) -> dict:
        """Return basic stats about a collection."""
        info   = self.client.get_collection(collection)
        points = info.points_count or getattr(info, "vectors_count", 0) or 0
        return {
            "name":         collection,
            "points_count": points,
            "status":       str(info.status),
        }

    def ping(self) -> bool:
        """Return True if Qdrant is reachable."""
        try:
            self.client.get_collections()
            return True
        except Exception:
            return False

    def list_user_documents(self, collection: str = COLLECTION_THREAT_INTEL) -> list:
        """Return all user-uploaded documents grouped by doc_id, sorted newest first."""
        docs: dict[str, dict] = {}
        offset = None

        while True:
            response, next_offset = self.client.scroll(
                collection_name=collection,
                scroll_filter=Filter(must=[
                    FieldCondition(key="source_type", match=MatchValue(value="user_upload"))
                ]),
                limit=100,
                offset=offset,
                with_payload=True,
                with_vectors=False,
            )

            for point in response:
                meta = point.payload.get("metadata", {})
                doc_id = meta.get("doc_id")
                if not doc_id:
                    continue
                if doc_id not in docs:
                    user_tags = [t for t in (point.payload.get("tags") or []) if t != "user_upload"]
                    docs[doc_id] = {
                        "doc_id":      doc_id,
                        "title":       meta.get("title", ""),
                        "filename":    meta.get("filename", ""),
                        "uploaded_at": meta.get("uploaded_at", ""),
                        "tags":        user_tags,
                        "chunks":      0,
                    }
                docs[doc_id]["chunks"] += 1

            if next_offset is None:
                break
            offset = next_offset

        return sorted(docs.values(), key=lambda d: d["uploaded_at"], reverse=True)

    def delete_document(self, doc_id: str, collection: str = COLLECTION_THREAT_INTEL) -> None:
        """Delete all vectors belonging to a user-uploaded document."""
        from qdrant_client.models import FilterSelector
        self.client.delete(
            collection_name=collection,
            points_selector=FilterSelector(
                filter=Filter(must=[
                    FieldCondition(key="metadata.doc_id", match=MatchValue(value=doc_id))
                ])
            ),
        )

    def delete_collection(self, collection: str):
        """Delete and recreate a collection (full re-index)."""
        self.client.delete_collection(collection)
        self._ensure_collections()
        print(f"  [qdrant] Deleted and recreated '{collection}'")
