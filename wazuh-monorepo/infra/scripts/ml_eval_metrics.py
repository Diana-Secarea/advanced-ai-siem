#!/usr/bin/env python3
"""
Evaluate every detector (IF, AE, UEBA) + the learned stacker on the held-out
test set and write the results as JSON — the single source of truth consumed
by push_metrics.py (→ Prometheus/Grafana) and the Flask /metrics endpoint.

Usage:
    ./venv/bin/python3 ../wazuh-ai-infra/scripts/ml_eval_metrics.py \
        [--test-file data/test/all_test_alerts.json] \
        [--out data/eval/ml_metrics.json]
"""
import argparse
import json
import sys
import time
from pathlib import Path

INFRA_DIR   = Path(__file__).resolve().parent.parent
REPO_DIR    = INFRA_DIR.parent
STARTER_DIR = REPO_DIR / "services" / "ai-engine"
sys.path.insert(0, str(STARTER_DIR))

from attack_labels import is_attack_alert as _is_attack_alert
from autoencoders_approach.ensemble_detector import load_ensemble


def _load_benign_ids():
    f = REPO_DIR / "apps" / "backend" / "benign_rules.json"
    try:
        if f.exists():
            return set(json.load(open(f)).keys())
    except Exception:
        pass
    return set()


BENIGN = _load_benign_ids()


def load_alerts(path):
    alerts = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def prf(tp, fp, fn, tn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall    = tp / (tp + fn) if tp + fn else 0.0
    f1  = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-file", default=str(STARTER_DIR / "data/test/all_test_alerts.json"))
    ap.add_argument("--out", default=str(STARTER_DIR / "data/eval/ml_metrics.json"))
    args = ap.parse_args()

    ensemble = load_ensemble()
    alerts = load_alerts(args.test_file)
    y = [1 if _is_attack_alert(a, BENIGN) else 0 for a in alerts]

    # verdict flags per model + ensemble
    preds = {"isolation_forest": [], "autoencoder": [], "ueba": [], "ensemble": []}
    scores = {"isolation_forest": [], "autoencoder": [], "ueba": [], "ensemble": []}
    for a in alerts:
        r = ensemble.score(a)
        if_r   = ensemble.if_det.detect_anomaly(a)
        ae_r   = ensemble.ae_det.detect_anomaly(a)   if ensemble.ae_det   else None
        ueba_r = ensemble.ueba_det.detect_anomaly(a) if ensemble.ueba_det else None
        preds["isolation_forest"].append(1 if if_r["is_anomaly"] else 0)
        preds["autoencoder"].append(1 if (ae_r and ae_r["is_anomaly"]) else 0)
        preds["ueba"].append(1 if (ueba_r and ueba_r["is_anomaly"]) else 0)
        preds["ensemble"].append(1 if r["is_anomaly"] else 0)
        scores["isolation_forest"].append(if_r["anomaly_score"])
        scores["autoencoder"].append(ae_r["anomaly_score"] if ae_r else 0)
        scores["ueba"].append(ueba_r["anomaly_score"] if ueba_r else 0)
        scores["ensemble"].append(r["combined_score"])

    models = {}
    for name, p in preds.items():
        tp = sum(1 for yi, pi in zip(y, p) if yi and pi)
        fp = sum(1 for yi, pi in zip(y, p) if not yi and pi)
        fn = sum(1 for yi, pi in zip(y, p) if yi and not pi)
        tn = sum(1 for yi, pi in zip(y, p) if not yi and not pi)
        m = prf(tp, fp, fn, tn)
        atk = [s for s, yi in zip(scores[name], y) if yi]
        cln = [s for s, yi in zip(scores[name], y) if not yi]
        m["avg_attack_score"] = round(sum(atk) / len(atk), 2) if atk else 0
        m["avg_clean_score"]  = round(sum(cln) / len(cln), 2) if cln else 0
        m["separation"] = round(m["avg_attack_score"] - m["avg_clean_score"], 2)
        models[name] = m

    result = {
        "timestamp": int(time.time()),
        "test_file": args.test_file,
        "n_alerts": len(alerts),
        "n_attacks": sum(y),
        "stacking_active": ensemble.meta is not None,
        "models": models,
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    print(f"\n[ml-eval] Written to {out}")


if __name__ == "__main__":
    main()
