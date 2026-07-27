"""A/B retrieval eval: baseline one-shot search vs Phase-1 multi-query rewrite.

Baseline  = QdrantStore.search(query, k=5)            (identical to run_eval2.py)
Multi-query = agentic_rag.rewrite_queries() via local Ollama → one search per
              query → merge deduped by episode keeping the best score → top-5
              (mirrors _multi_query_kb in apps/backend/server.py).

Needs Qdrant + Ollama running. ~2-3 min: one small LLM rewrite per query.
"""
import json
import math
import os
import sys

sys.path.insert(0, "/home/sek/wazuh/wazuh-monorepo/services/ai-engine")
sys.path.insert(0, "/home/sek/wazuh/wazuh-monorepo/apps/backend")

import requests

import agentic_rag
from rag_core.database.qdrant_store import QdrantStore
from rag_core.evaluation.retrieval_metrics import (
    hit_rate_at_k, reciprocal_rank, recall_at_k, precision_at_k)

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
K = 5


def llm(messages, max_tokens=120):
    r = requests.post(f"{OLLAMA_URL}/v1/chat/completions",
                      json={"model": OLLAMA_MODEL, "messages": messages,
                            "temperature": 0.0, "max_tokens": max_tokens},
                      timeout=30)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def multi_query_search(store, queries, top_k=K):
    best = {}
    for q in queries:
        for r in store.search(query=q, top_k=top_k):
            key = r.get("episode_id") or r.get("summary", "")[:80]
            if key not in best or r.get("score", 0) > best[key].get("score", 0):
                best[key] = r
    ranked = sorted(best.values(), key=lambda r: r.get("score", 0), reverse=True)
    return [r["episode_id"] for r in ranked[:top_k]]


def ndcg_at_k(retrieved, relevant, k=K):
    rel = set(relevant)
    dcg = sum((1.0 / math.log2(i + 2)) for i, r in enumerate(retrieved[:k]) if r in rel)
    ideal = sum((1.0 / math.log2(i + 2)) for i in range(min(len(rel), k)))
    return dcg / ideal if ideal else 0.0


def score(rids, rel):
    return {"hr": hit_rate_at_k(rids, rel, K), "rr": reciprocal_rank(rids, rel),
            "rec": recall_at_k(rids, rel, K), "prec": precision_at_k(rids, rel, K),
            "ndcg": ndcg_at_k(rids, rel)}


def agg(rs):
    n = len(rs)
    return {m: sum(r[m] for r in rs) / n for m in ("hr", "prec", "rec", "rr", "ndcg")}


def main():
    data = json.load(open(os.path.join(os.path.dirname(__file__), "eval_dataset_82.json")))
    store = QdrantStore()
    base_rows, agent_rows, cats = [], [], []
    for i, d in enumerate(data, 1):
        rel = d["relevant"]
        base = [r["episode_id"] for r in store.search(query=d["query"], top_k=K)]
        queries = agentic_rag.rewrite_queries(llm, d["query"], history=[])
        multi = multi_query_search(store, queries)
        base_rows.append(score(base, rel))
        agent_rows.append(score(multi, rel))
        cats.append(d["category"])
        extra = " | +" + " / +".join(q[:40] for q in queries[1:]) if len(queries) > 1 else ""
        print(f"[{i:2}/{len(data)}] {d['query'][:55]:<55}{extra}", flush=True)

    def show(title, rows_b, rows_a):
        b, a = agg(rows_b), agg(rows_a)
        print(f"\n{title}")
        print(f"{'':>12}{'HitRate':>9}{'Prec@5':>8}{'Recall@5':>10}{'MRR':>8}{'nDCG@5':>9}")
        print(f"{'baseline':>12}{b['hr']:>8.1%}{b['prec']:>8.1%}{b['rec']:>9.1%}{b['rr']:>8.3f}{b['ndcg']:>9.3f}")
        print(f"{'multi-query':>12}{a['hr']:>8.1%}{a['prec']:>8.1%}{a['rec']:>9.1%}{a['rr']:>8.3f}{a['ndcg']:>9.3f}")
        print(f"{'delta':>12}{a['hr']-b['hr']:>+8.1%}{a['prec']-b['prec']:>+8.1%}"
              f"{a['rec']-b['rec']:>+9.1%}{a['rr']-b['rr']:>+8.3f}{a['ndcg']-b['ndcg']:>+9.3f}")

    show(f"=== OVERALL ({len(data)} queries, k={K}) ===", base_rows, agent_rows)
    for c in ("mitre-attack", "cve-vulnerability", "lateral-movement",
              "c2-exfiltration", "apt-group", "wazuh-rules"):
        rb = [r for r, cc in zip(base_rows, cats) if cc == c]
        ra = [r for r, cc in zip(agent_rows, cats) if cc == c]
        if rb:
            show(f"--- {c} ({len(rb)} queries) ---", rb, ra)


if __name__ == "__main__":
    main()
