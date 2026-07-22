#!/usr/bin/env python3
"""
Push evaluation metrics (ML or RAG JSON produced by ml_eval_metrics.py /
rag_eval_metrics.py) to the Prometheus Pushgateway. Stdlib only.

Usage:
    python3 push_metrics.py --kind ml  --file data/eval/ml_metrics.json  \
        [--gateway http://localhost:9091] [--job wazuh-ml-eval]
    python3 push_metrics.py --kind rag --file data/eval/rag_metrics.json \
        [--gateway http://localhost:9091] [--job wazuh-rag-eval]
"""
import argparse
import json
import urllib.request


def ml_exposition(data):
    lines = [
        f'wazuh_ml_eval_timestamp {data["timestamp"]}',
        f'wazuh_ml_test_alerts {data["n_alerts"]}',
        f'wazuh_ml_test_attacks {data["n_attacks"]}',
        f'wazuh_ml_stacking_active {1 if data.get("stacking_active") else 0}',
    ]
    for model, m in data["models"].items():
        for metric in ("precision", "recall", "f1", "fpr",
                       "avg_attack_score", "avg_clean_score", "separation"):
            lines.append(f'wazuh_ml_{metric}{{model="{model}"}} {m[metric]}')
        for cell in ("tp", "fp", "fn", "tn"):
            lines.append(f'wazuh_ml_confusion{{model="{model}",cell="{cell}"}} {m[cell]}')
    return "\n".join(lines) + "\n"


def rag_exposition(data):
    lines = [
        f'wazuh_rag_eval_timestamp {data["timestamp"]}',
        f'wazuh_rag_k {data["k"]}',
    ]
    o = data["overall"]
    for metric in ("hit_rate", "precision_at_k", "recall_at_k", "mrr", "ndcg_at_k", "queries"):
        lines.append(f'wazuh_rag_{metric} {o[metric]}')
    for cat, m in data["categories"].items():
        for metric in ("hit_rate", "recall_at_k", "mrr", "ndcg_at_k"):
            lines.append(f'wazuh_rag_category_{metric}{{category="{cat}"}} {m[metric]}')
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=("ml", "rag"), required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--gateway", default="http://localhost:9091")
    ap.add_argument("--job", default=None)
    args = ap.parse_args()

    data = json.load(open(args.file))
    body = (ml_exposition if args.kind == "ml" else rag_exposition)(data)
    job = args.job or f"wazuh-{args.kind}-eval"
    url = f"{args.gateway.rstrip('/')}/metrics/job/{job}"

    req = urllib.request.Request(url, data=body.encode(), method="PUT")
    req.add_header("Content-Type", "text/plain")
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(f"[push] {url} → HTTP {resp.status}")


if __name__ == "__main__":
    main()
