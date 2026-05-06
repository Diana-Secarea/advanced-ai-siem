"""
RAG Retrieval Evaluation Metrics

Evaluates retrieval quality using:
- Hit Rate@k: Does at least one relevant doc appear in top-k?
- MRR (Mean Reciprocal Rank): How high is the first relevant result?
- Recall@k: What fraction of all relevant docs appear in top-k?

Usage:
    cd /home/sek/wazuh/ai_threat_engine_starter
    ./venv/bin/python3 -m rag_core.evaluation.retrieval_metrics
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rag_core.database.qdrant_store import QdrantStore


def hit_rate_at_k(retrieved_ids: List[str], relevant_ids: List[str], k: int = 5) -> float:
    """1.0 if any relevant doc is in top-k, else 0.0."""
    top_k = retrieved_ids[:k]
    return 1.0 if any(rid in relevant_ids for rid in top_k) else 0.0


def reciprocal_rank(retrieved_ids: List[str], relevant_ids: List[str]) -> float:
    """1/rank of the first relevant result. 0 if none found."""
    for i, rid in enumerate(retrieved_ids):
        if rid in relevant_ids:
            return 1.0 / (i + 1)
    return 0.0


def recall_at_k(retrieved_ids: List[str], relevant_ids: List[str], k: int = 5) -> float:
    """Fraction of relevant docs found in top-k."""
    if not relevant_ids:
        return 0.0
    top_k = set(retrieved_ids[:k])
    found = sum(1 for rid in relevant_ids if rid in top_k)
    return found / len(relevant_ids)


def precision_at_k(retrieved_ids: List[str], relevant_ids: List[str], k: int = 5) -> float:
    """Fraction of top-k results that are relevant."""
    top_k = retrieved_ids[:k]
    if not top_k:
        return 0.0
    relevant_set = set(relevant_ids)
    hits = sum(1 for rid in top_k if rid in relevant_set)
    return hits / len(top_k)


def evaluate_retrieval(
    retriever: QdrantStore,
    eval_data: List[Dict],
    k: int = 5,
    verbose: bool = True,
    **_kwargs,
) -> Dict:
    """
    Run full evaluation on the Qdrant retrieval system.

    Args:
        retriever: QdrantStore instance (connected to Qdrant)
        eval_data: List of {"query": str, "relevant": [episode_ids], "category": str}
        k: Top-k cutoff for metrics
        verbose: Print per-query results

    Returns:
        Dict with aggregate metrics and per-query breakdown
    """
    results = []
    total_hit = 0.0
    total_mrr = 0.0
    total_recall = 0.0
    total_precision = 0.0

    if verbose:
        info = retriever.collection_info()
        print(f"\n{'='*70}")
        print(f"  RAG Retrieval Evaluation (k={k}, hybrid dense+BM25 RRF)")
        print(f"  {len(eval_data)} queries, {info['points_count']} indexed episodes")
        print(f"{'='*70}\n")

    for i, item in enumerate(eval_data):
        query = item["query"]
        relevant_ids = set(item["relevant"])
        category = item.get("category", "")

        # Run retrieval
        search_results = retriever.search(query=query, top_k=k)
        retrieved_ids = [r["episode_id"] for r in search_results]

        # Compute metrics
        hr = hit_rate_at_k(retrieved_ids, relevant_ids, k)
        rr = reciprocal_rank(retrieved_ids, relevant_ids)
        rec = recall_at_k(retrieved_ids, relevant_ids, k)
        prec = precision_at_k(retrieved_ids, relevant_ids, k)

        total_hit += hr
        total_mrr += rr
        total_recall += rec
        total_precision += prec

        # Find which relevant IDs were found/missed
        found = [rid for rid in relevant_ids if rid in retrieved_ids[:k]]
        missed = [rid for rid in relevant_ids if rid not in retrieved_ids[:k]]

        result = {
            "query": query,
            "category": category,
            "hit_rate": hr,
            "mrr": rr,
            "recall": rec,
            "precision": prec,
            "retrieved": retrieved_ids,
            "found": found,
            "missed": missed
        }
        results.append(result)

        if verbose:
            status = "HIT" if hr > 0 else "MISS"
            print(f"[{i+1:2d}] [{status:4s}] {query}")
            print(f"     RR={rr:.2f}  Recall={rec:.2f}  Prec={prec:.2f}  [{category}]")
            if found:
                print(f"     Found:  {found}")
            if missed:
                print(f"     Missed: {missed}")
            # Show what was actually retrieved
            top_retrieved = [(r["episode_id"], f'{r["score"]:.3f}') for r in search_results[:3]]
            print(f"     Top-3:  {top_retrieved}")
            print()

    n = len(eval_data)
    aggregate = {
        "num_queries": n,
        "k": k,
        "hit_rate_at_k": total_hit / n,
        "mrr": total_mrr / n,
        "recall_at_k": total_recall / n,
        "precision_at_k": total_precision / n,
    }

    if verbose:
        print(f"{'='*70}")
        print(f"  AGGREGATE RESULTS (k={k})")
        print(f"{'='*70}")
        print(f"  Hit Rate@{k}:   {aggregate['hit_rate_at_k']:.1%}")
        print(f"  MRR:           {aggregate['mrr']:.3f}")
        print(f"  Recall@{k}:     {aggregate['recall_at_k']:.1%}")
        print(f"  Precision@{k}:  {aggregate['precision_at_k']:.1%}")
        print()

        # Per-category breakdown
        categories = {}
        for r in results:
            cat = r["category"]
            if cat not in categories:
                categories[cat] = {"hit": 0, "mrr": 0, "recall": 0, "count": 0}
            categories[cat]["hit"] += r["hit_rate"]
            categories[cat]["mrr"] += r["mrr"]
            categories[cat]["recall"] += r["recall"]
            categories[cat]["count"] += 1

        print(f"  Per-Category Breakdown:")
        print(f"  {'Category':<25s} {'Queries':>7s} {'Hit@k':>7s} {'MRR':>7s} {'Recall':>7s}")
        print(f"  {'-'*25} {'-'*7} {'-'*7} {'-'*7} {'-'*7}")
        for cat in sorted(categories):
            c = categories[cat]
            n_cat = c["count"]
            print(f"  {cat:<25s} {n_cat:>7d} {c['hit']/n_cat:>7.1%} {c['mrr']/n_cat:>7.3f} {c['recall']/n_cat:>7.1%}")
        print()

        # Worst performing queries
        misses = [r for r in results if r["hit_rate"] == 0]
        if misses:
            print(f"  MISSED QUERIES ({len(misses)}):")
            for r in misses:
                print(f"    - {r['query']}")
                print(f"      Expected: {r['missed']}")
                print(f"      Got: {r['retrieved'][:3]}")
            print()

    return {"aggregate": aggregate, "per_query": results}


def compare_configurations(
    retriever: QdrantStore,
    eval_data: List[Dict],
    k: int = 5
) -> None:
    """Compare retrieval at different k values."""
    print("\n" + "="*70)
    print("  COMPARISON: Metrics at k=3, k=5, k=10")
    print("="*70)

    results_by_k = {}
    for k_val in (3, 5, 10):
        res = evaluate_retrieval(retriever, eval_data, k=k_val, verbose=False)
        results_by_k[k_val] = res["aggregate"]

    print(f"\n  {'Metric':<20s} {'k=3':>10s} {'k=5':>10s} {'k=10':>10s}")
    print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*10}")
    for metric in ["hit_rate_at_k", "mrr", "recall_at_k", "precision_at_k"]:
        vals = [results_by_k[k_val][metric] for k_val in (3, 5, 10)]
        print(f"  {metric:<20s} {vals[0]:>9.1%} {vals[1]:>9.1%} {vals[2]:>9.1%}")
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate RAG retrieval quality")
    parser.add_argument("-k", type=int, default=5, help="Top-k cutoff (default: 5)")
    parser.add_argument("--compare", action="store_true", help="Compare metrics at k=3,5,10")
    parser.add_argument("--dataset", type=str, default=None, help="Path to eval dataset JSON")
    args = parser.parse_args()

    # Load eval dataset
    dataset_path = Path(args.dataset) if args.dataset else Path(__file__).parent / "eval_dataset.json"
    with open(dataset_path) as f:
        eval_data = json.load(f)
    print(f"Loaded {len(eval_data)} eval queries from {dataset_path}")

    retriever = QdrantStore()

    if args.compare:
        evaluate_retrieval(retriever, eval_data, k=args.k)
        compare_configurations(retriever, eval_data, k=args.k)
    else:
        evaluate_retrieval(retriever, eval_data, k=args.k)


if __name__ == "__main__":
    main()
