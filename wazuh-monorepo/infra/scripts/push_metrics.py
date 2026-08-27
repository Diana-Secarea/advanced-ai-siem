#!/usr/bin/env python3
"""
Push evaluation metrics (ML or RAG JSON produced by ml_eval_metrics.py /
rag_eval_metrics.py) to the Prometheus Pushgateway. Stdlib only.

Usage:
    python3 push_metrics.py --kind ml  --file data/eval/ml_metrics.json  \
        [--gateway http://localhost:9091] [--job wazuh-ml-eval]
    python3 push_metrics.py --kind rag --file data/eval/rag_metrics.json \
        [--gateway http://localhost:9091] [--job wazuh-rag-eval]
    python3 push_metrics.py --kind health --file data/eval/model_health.json \
        [--gateway http://localhost:9091] [--job wazuh-ml-health]
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


def health_exposition(data):
    """Live model-health metrics (model_health.py). Unlike the eval metrics,
    these describe the model against the CURRENT alert stream, so Grafana can
    show calibration drifting away from the host it was trained on."""
    status = data.get("status", "unknown")
    lines = [
        f'wazuh_ml_health_timestamp {data["timestamp"]}',
        f'wazuh_ml_health_ok {1 if status == "ok" else 0}',
        # inconclusive is neither pass nor fail — surface it so a quiet host
        # is never mistaken for a healthy one on the dashboard
        f'wazuh_ml_health_inconclusive {1 if status == "inconclusive" else 0}',
        f'wazuh_ml_health_alerts_scored {data.get("n_alerts", 0)}',
    ]
    if data.get("score_stdev") is not None:
        lines.append(f'wazuh_ml_health_score_stdev {data["score_stdev"]}')
    if data.get("projected_alerts_per_day") is not None:
        lines.append(f'wazuh_ml_health_projected_alerts_per_day {data["projected_alerts_per_day"]}')
    if data.get("stacking_active") is not None:
        lines.append(f'wazuh_ml_health_stacking_active {1 if data["stacking_active"] else 0}')
    for comp, present in (data.get("components") or {}).items():
        lines.append(f'wazuh_ml_health_component{{component="{comp}"}} {1 if present else 0}')
    for model, frac in (data.get("saturation") or {}).items():
        lines.append(f'wazuh_ml_health_saturation{{model="{model}"}} {frac}')
    for label, frac in (data.get("label_share") or {}).items():
        lines.append(f'wazuh_ml_health_label_share{{label="{label}"}} {frac}')
    for model, age in (data.get("model_age_days") or {}).items():
        lines.append(f'wazuh_ml_health_model_age_days{{model="{model}"}} {age}')
    for check, c in (data.get("checks") or {}).items():
        lines.append(f'wazuh_ml_health_check{{check="{check}"}} {1 if c["ok"] else 0}')
        if isinstance(c.get("value"), (int, float)):
            lines.append(f'wazuh_ml_health_check_value{{check="{check}"}} {c["value"]}')
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=("ml", "rag", "health"), required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--gateway", default="http://localhost:9091")
    ap.add_argument("--job", default=None)
    args = ap.parse_args()

    data = json.load(open(args.file))
    body = {"ml": ml_exposition, "rag": rag_exposition,
            "health": health_exposition}[args.kind](data)
    job = args.job or ("wazuh-ml-health" if args.kind == "health"
                       else f"wazuh-{args.kind}-eval")
    url = f"{args.gateway.rstrip('/')}/metrics/job/{job}"

    req = urllib.request.Request(url, data=body.encode(), method="PUT")
    req.add_header("Content-Type", "text/plain")
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(f"[push] {url} → HTTP {resp.status}")


if __name__ == "__main__":
    main()
