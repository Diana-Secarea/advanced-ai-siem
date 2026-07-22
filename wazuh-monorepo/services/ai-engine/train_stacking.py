#!/usr/bin/env python3
"""
Train the stacking meta-model that combines IF + AE + UEBA scores.

The three base models are one-class detectors trained on clean data only —
they never saw an attack. The stacker is the supervised layer on top: a
logistic regression over the three base scores that LEARNS how much to trust
each model, replacing the old hardcoded 0.45*IF + 0.55*AE combination.

Run AFTER the base models are trained:
    ./venv/bin/python3 train_isolation_forest.py
    ./venv/bin/python3 autoencoders_approach/train_autoencoder.py
    ./venv/bin/python3 train_ueba.py
    ./venv/bin/python3 train_stacking.py

Labels come from the keyword heuristics in attack_labels.py, applied to the
full training set (clean + attacks). Evaluation is done on the separate test
set to keep the reported numbers honest.
"""
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

from attack_labels import is_attack_alert as _is_attack_alert
from autoencoders_approach.ensemble_detector import load_ensemble


def _load_user_benign_ids():
    rules_file = SCRIPT_DIR.parent.parent / "apps" / "backend" / "benign_rules.json"
    try:
        if rules_file.exists():
            with open(rules_file) as f:
                data = json.load(f)
            return set(data.keys())
    except Exception:
        pass
    return set()


BENIGN_RULE_IDS = _load_user_benign_ids()


def is_attack_alert(alert):
    return _is_attack_alert(alert, BENIGN_RULE_IDS)


def load_alerts(filepath):
    alerts = []
    try:
        with open(filepath) as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except Exception:
                    continue
    except FileNotFoundError:
        print(f"File not found: {filepath}")
    return alerts


def base_scores(ensemble, alerts):
    """Return (X, y, kept_alerts): base-model score vectors + attack labels."""
    X, y, kept = [], [], []
    for alert in alerts:
        try:
            if_s = ensemble.if_det.detect_anomaly(alert)['anomaly_score']
            ae_s = ensemble.ae_det.detect_anomaly(alert)['anomaly_score'] \
                if ensemble.ae_det else 0
            ub_s = ensemble.ueba_det.detect_anomaly(alert)['anomaly_score'] \
                if ensemble.ueba_det else 0
            X.append([if_s / 100.0, ae_s / 100.0, ub_s / 100.0])
            y.append(1 if is_attack_alert(alert) else 0)
            kept.append(alert)
        except Exception:
            continue
    return np.array(X), np.array(y), kept


def report(name, y_true, y_pred):
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall    = tp / (tp + fn) if tp + fn else 0.0
    f1  = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    print(f"  {name}")
    print(f"    TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"    Precision: {precision*100:.1f}%  Recall: {recall*100:.1f}%  "
          f"F1: {f1*100:.1f}%  FPR: {fpr*100:.1f}%")
    return f1


def train(alerts_file, model_path, test_file=None):
    print("Loading base models (IF + AE + UEBA)...")
    ensemble = load_ensemble(meta_model_path="/nonexistent")  # force no meta
    if ensemble.ae_det is None:
        print("Autoencoder model missing — train it first. Exiting.")
        return False
    if ensemble.ueba_det is None:
        print("[warn] UEBA baselines missing — stacker will learn ueba weight ≈ 0")

    print(f"\nLoading training alerts from: {alerts_file}")
    alerts = load_alerts(alerts_file)
    if len(alerts) < 50:
        print("Not enough alerts. Exiting.")
        return False

    print(f"Scoring {len(alerts)} training alerts with all base models...")
    X, y, _ = base_scores(ensemble, alerts)
    print(f"  Feature matrix: {X.shape} | attacks: {int(y.sum())} | clean: {int((y == 0).sum())}")

    if y.sum() < 10 or (y == 0).sum() < 10:
        print("Need at least 10 attack and 10 clean alerts to train the stacker. Exiting.")
        return False

    # The supervised layer: learns the combination weights from data.
    # class_weight balances the attack/clean imbalance in the training set.
    # C=10 + decision threshold 0.4 chosen by 5-fold out-of-fold CV on the
    # training set (2026-07-17 HPO): F1 0.959 vs 0.929 at the old C=1/0.5.
    DECISION_THRESHOLD = 0.4
    print("\nTraining logistic-regression stacker on [IF, AE, UEBA] scores...")
    meta = LogisticRegression(C=10.0, class_weight='balanced', max_iter=1000, random_state=42)
    meta.fit(X, y)

    coefs = meta.coef_[0]
    names = ['Isolation Forest', 'Autoencoder', 'UEBA']
    print(f"  Intercept: {meta.intercept_[0]:+.3f}")
    positive = np.clip(coefs, 0, None)
    rel = positive / positive.sum() if positive.sum() > 0 else positive
    for n, c, r in zip(names, coefs, rel):
        print(f"  {n:<17} coef {c:+.3f}  → learned relative weight {r*100:.1f}%"
              f"  (was hardcoded {'45%' if n.startswith('Isol') else '55%' if n.startswith('Auto') else '0%'})")

    # ---- Evaluation on the held-out test set ----
    eval_file = test_file or alerts_file
    eval_name = "TEST SET (held-out)" if test_file else "TRAINING SET (no held-out set found!)"
    eval_alerts = load_alerts(eval_file)
    Xe, ye, _ = base_scores(ensemble, eval_alerts)
    print(f"\n{'='*50}")
    print(f"EVALUATION on {eval_name}: {len(ye)} alerts "
          f"({int(ye.sum())} attacks, {int((ye == 0).sum())} clean)")
    print(f"{'='*50}")

    # Learned stacker @ tuned threshold
    prob = meta.predict_proba(Xe)[:, 1]
    f1_meta = report(f"Learned stacker (meta ≥ {DECISION_THRESHOLD}):", ye,
                     (prob >= DECISION_THRESHOLD).astype(int))

    # Legacy fixed weights @ 50 for comparison
    legacy = (0.45 * Xe[:, 0] + 0.55 * Xe[:, 1]) * 100
    f1_leg = report("Legacy fixed weights (0.45 IF + 0.55 AE ≥ 50):", ye,
                    (legacy >= 50).astype(int))
    print(f"\n  F1 change vs legacy: {(f1_meta - f1_leg)*100:+.1f} points")

    # Archive previous meta-model
    if Path(model_path).exists():
        archive = model_path.replace('.pkl', f'_{datetime.now().strftime("%Y-%m-%d")}.pkl')
        shutil.copy(model_path, archive)
        print(f"\nArchived previous meta-model to: {archive}")

    print(f"Saving stacking meta-model to: {model_path}")
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        'model': meta,
        'decision_threshold': DECISION_THRESHOLD,
        'feature_names': ['if_score', 'ae_score', 'ueba_score'],
        'trained_on': str(alerts_file),
        'trained_at': datetime.now().isoformat(),
    }, model_path)

    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train the stacking meta-model")
    parser.add_argument("--test-file", default=None,
                        help="Separate test set (default: data/test/all_test_alerts.json)")
    args = parser.parse_args()

    COMBINED_TRAINING = SCRIPT_DIR / "data" / "training" / "combined" / "all_alerts.json"
    COMBINED_TEST     = SCRIPT_DIR / "data" / "test" / "all_test_alerts.json"

    META_MODEL_LOCAL = str(SCRIPT_DIR / "data" / "ai_models" / "stacking_meta.pkl")
    META_MODEL_PROD  = "/var/ossec/ai_models/stacking_meta.pkl"

    alerts_file = str(COMBINED_TRAINING)
    test_file = args.test_file
    if test_file is None and COMBINED_TEST.exists() and COMBINED_TEST.stat().st_size > 0:
        test_file = str(COMBINED_TEST)

    try:
        model_path = META_MODEL_PROD if Path(META_MODEL_PROD).parent.exists() else META_MODEL_LOCAL
    except PermissionError:
        model_path = META_MODEL_LOCAL

    print("========================================")
    print("Stacking Meta-Model Training (IF+AE+UEBA)")
    print("========================================\n")
    print(f"Alerts file:  {alerts_file}")
    print(f"Test file:    {test_file or '(none — evaluating on training data)'}")
    print(f"Model output: {model_path}\n")

    success = train(alerts_file, model_path, test_file=test_file)
    print("\n✅ Stacking meta-model ready." if success else "\n❌ Training failed.")
