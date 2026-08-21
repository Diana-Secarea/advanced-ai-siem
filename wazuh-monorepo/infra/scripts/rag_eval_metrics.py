#!/usr/bin/env python3
"""
RAG retrieval evaluation → JSON (for Prometheus/Grafana via push_metrics.py).

Runs the same 82-query benchmark as rag_core/evaluation/run_eval2.py
(hybrid dense+BM25 RRF, k=5) but emits machine-readable metrics.

Usage:
    ./venv/bin/python3 ../../infra/scripts/rag_eval_metrics.py \
        [--out data/eval/rag_metrics.json]
"""
import argparse
import json
import math
import sys
import time
from pathlib import Path

INFRA_DIR   = Path(__file__).resolve().parent.parent
REPO_DIR    = INFRA_DIR.parent
STARTER_DIR = REPO_DIR / "services" / "ai-engine"
sys.path.insert(0, str(STARTER_DIR))

from rag_core.database.qdrant_store import QdrantStore
from rag_core.evaluation.retrieval_metrics import (
    hit_rate_at_k, reciprocal_rank, recall_at_k, precision_at_k)

K = 5
DATASET = STARTER_DIR / "rag_core/evaluation/eval_dataset_82.json"


def ndcg_at_k(retrieved, relevant, k=K):
    rel = set(relevant)
    dcg = sum((1.0 / math.log2(i + 2)) for i, r in enumerate(retrieved[:k]) if r in rel)
    ideal = sum((1.0 / math.log2(i + 2)) for i in range(min(len(rel), k)))
    return dcg / ideal if ideal else 0.0


def agg(rows):
    n = len(rows)
    return {
        "hit_rate":     round(sum(r["hr"] for r in rows) / n, 4),
        "precision_at_k": round(sum(r["prec"] for r in rows) / n, 4),
        "recall_at_k":  round(sum(r["rec"] for r in rows) / n, 4),
        "mrr":          round(sum(r["rr"] for r in rows) / n, 4),
        "ndcg_at_k":    round(sum(r["ndcg"] for r in rows) / n, 4),
        "queries":      n,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(STARTER_DIR / "data/eval/rag_metrics.json"))
    args = ap.parse_args()

    data = json.load(open(DATASET))
    store = QdrantStore()

    rows = []
    for d in data:
        rids = [r["episode_id"] for r in store.search(query=d["query"], top_k=K)]
        rel = d["relevant"]
        rows.append({
            "cat": d["category"],
            "hr": hit_rate_at_k(rids, rel, K), "rr": reciprocal_rank(rids, rel),
            "rec": recall_at_k(rids, rel, K), "prec": precision_at_k(rids, rel, K),
            "ndcg": ndcg_at_k(rids, rel),
        })

    result = {
        "timestamp": int(time.time()),
        "k": K,
        "overall": agg(rows),
        "categories": {
            cat: agg([r for r in rows if r["cat"] == cat])
            for cat in sorted({r["cat"] for r in rows})
        },
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result["overall"], indent=2))
    print(f"[rag-eval] Written to {out}")


if __name__ == "__main__":
    main()
