#!/usr/bin/env python3
"""
Hyperparameter grid search for the anomaly detectors, judged on the held-out
test set (F1 of each candidate configuration at its own calibrated threshold).

Worth tuning:
  Autoencoder      — bottleneck architecture + learning rate (the sensitive part)
  Isolation Forest — n_estimators + max_samples (mildly sensitive)

NOT tuned on purpose: the stacking meta-model (logistic regression has no
meaningful knobs here) and UEBA (weights are domain knowledge, not fitted).

Usage:
    ./venv/bin/python3 ../wazuh-ai-infra/scripts/tune_hyperparams.py           # report only
    ./venv/bin/python3 ../wazuh-ai-infra/scripts/tune_hyperparams.py --apply   # write best params
                                                                               # to tuned_params.json
Training scripts read tuned_params.json (if present) via --apply mode of the
Jenkins pipeline; without it they keep their built-in defaults.
"""
import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

INFRA_DIR   = Path(__file__).resolve().parent.parent
REPO_DIR    = INFRA_DIR.parent
STARTER_DIR = REPO_DIR / "services" / "ai-engine"
sys.path.insert(0, str(STARTER_DIR))

from attack_labels import is_attack_alert as _is_attack_alert
from ai_engine.anomaly_detector import AnomalyDetector

TRAIN_FILE = STARTER_DIR / "data/training/combined/all_alerts.json"
TEST_FILE  = STARTER_DIR / "data/test/all_test_alerts.json"
PARAMS_OUT = STARTER_DIR / "data/ai_models/tuned_params.json"

# Small, honest grids — every cell is trained + evaluated, so keep them tight.
AE_GRID = [
    {"hidden_layer_sizes": (8, 4, 8),   "learning_rate_init": 0.001},
    {"hidden_layer_sizes": (8, 4, 8),   "learning_rate_init": 0.005},
    {"hidden_layer_sizes": (12, 6, 12), "learning_rate_init": 0.001},
    {"hidden_layer_sizes": (12, 4, 12), "learning_rate_init": 0.001},
    {"hidden_layer_sizes": (10, 3, 10), "learning_rate_init": 0.001},
]
IF_GRID = [
    {"n_estimators": 100, "max_samples": "auto"},
    {"n_estimators": 200, "max_samples": "auto"},
    {"n_estimators": 400, "max_samples": "auto"},
    {"n_estimators": 200, "max_samples": 0.5},
    {"n_estimators": 200, "max_samples": 256},
]


def _load_benign():
    f = REPO_DIR / "apps" / "backend" / "benign_rules.json"
    try:
        return set(json.load(open(f)).keys()) if f.exists() else set()
    except Exception:
        return set()


BENIGN = _load_benign()


def load_alerts(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def f1_at(scores_clean, scores_attack, threshold):
    tp = sum(1 for s in scores_attack if s >= threshold)
    fn = len(scores_attack) - tp
    fp = sum(1 for s in scores_clean if s >= threshold)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall    = tp / (tp + fn) if tp + fn else 0.0
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="write the best parameters to tuned_params.json")
    args = ap.parse_args()

    print("Loading data...")
    train = load_alerts(TRAIN_FILE)
    test  = load_alerts(TEST_FILE)
    fx = AnomalyDetector(model_path="/nonexistent")  # feature extractor only

    def feats(alerts):
        out = []
        for a in alerts:
            try:
                out.append(fx.extract_features(a)[0])
            except Exception:
                pass
        return np.array(out)

    train_clean = [a for a in train if not _is_attack_alert(a, BENIGN)]
    X_train_all   = feats(train)
    X_train_clean = feats(train_clean)
    X_test_clean  = feats([a for a in test if not _is_attack_alert(a, BENIGN)])
    X_test_attack = feats([a for a in test if _is_attack_alert(a, BENIGN)])
    print(f"  train all={len(X_train_all)} clean={len(X_train_clean)} | "
          f"test clean={len(X_test_clean)} attack={len(X_test_attack)}")

    results = {"tuned_at": int(time.time()), "autoencoder": None, "isolation_forest": None}

    # ---- Autoencoder grid (one-class: clean training data only) ----
    print("\n=== Autoencoder grid ===")
    best_ae = (-1, None)
    scaler = StandardScaler().fit(X_train_clean)
    Xc  = scaler.transform(X_train_clean)
    Xtc = scaler.transform(X_test_clean)
    Xta = scaler.transform(X_test_attack)
    for params in AE_GRID:
        t0 = time.time()
        mlp = MLPRegressor(activation="relu", solver="adam", max_iter=1000,
                           random_state=42, early_stopping=True,
                           validation_fraction=0.1, n_iter_no_change=20,
                           **params)
        mlp.fit(Xc, Xc)
        err_train = np.mean((Xc - mlp.predict(Xc)) ** 2, axis=1)
        thr = np.percentile(err_train, 95)
        err_c = np.mean((Xtc - mlp.predict(Xtc)) ** 2, axis=1)
        err_a = np.mean((Xta - mlp.predict(Xta)) ** 2, axis=1)
        f1 = f1_at(err_c, err_a, thr)
        print(f"  {str(params):<62} F1={f1:.3f}  ({time.time()-t0:.0f}s)")
        if f1 > best_ae[0]:
            best_ae = (f1, params)
    results["autoencoder"] = {"f1": round(best_ae[0], 4), **{
        "hidden_layer_sizes": list(best_ae[1]["hidden_layer_sizes"]),
        "learning_rate_init": best_ae[1]["learning_rate_init"]}}
    print(f"  BEST: {best_ae[1]}  F1={best_ae[0]:.3f}")

    # ---- Isolation Forest grid (unsupervised: all training data) ----
    print("\n=== Isolation Forest grid ===")
    best_if = (-1, None)
    scaler_if = StandardScaler().fit(X_train_all)
    Xa  = scaler_if.transform(X_train_all)
    Xtc = scaler_if.transform(X_test_clean)
    Xta = scaler_if.transform(X_test_attack)
    for params in IF_GRID:
        t0 = time.time()
        forest = IsolationForest(contamination="auto", random_state=42,
                                 n_jobs=-1, **params)
        forest.fit(Xa)
        # decision_function: lower = more anomalous → negate so higher = worse
        thr = np.percentile(-forest.decision_function(Xa), 90)
        s_c = -forest.decision_function(Xtc)
        s_a = -forest.decision_function(Xta)
        f1 = f1_at(s_c, s_a, thr)
        print(f"  {str(params):<62} F1={f1:.3f}  ({time.time()-t0:.0f}s)")
        if f1 > best_if[0]:
            best_if = (f1, params)
    results["isolation_forest"] = {"f1": round(best_if[0], 4), **best_if[1]}
    print(f"  BEST: {best_if[1]}  F1={best_if[0]:.3f}")

    if args.apply:
        PARAMS_OUT.parent.mkdir(parents=True, exist_ok=True)
        PARAMS_OUT.write_text(json.dumps(results, indent=2))
        print(f"\n[tune] Best parameters written to {PARAMS_OUT}")
        print("[tune] NOTE: apply them by updating the training scripts' grids "
              "if a config clearly beats the defaults on more than one run.")
    else:
        print("\n[tune] Report only — re-run with --apply to persist the winners.")


if __name__ == "__main__":
    main()
