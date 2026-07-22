#!/usr/bin/env python3
"""
Train the Autoencoder anomaly detector on clean Wazuh alerts only.

Architecture: bottleneck MLP (16 → 8 → 4 → 8 → 16) trained one-class /
self-supervised: attack-labelled alerts are removed BEFORE training so the
network learns to reconstruct only normal behaviour. Anything outside that
manifold then reconstructs poorly and scores high.

Because the keyword labels are imperfect, a self-supervised trimming round
removes residual contamination:

Round 1: train on labelled-clean alerts, drop top 10% highest reconstruction
         errors (mislabelled attacks that slipped through).
Round 2: retrain on the purified clean set, calibrate threshold.

Usage:
    cd ai_threat_engine_starter
    ./venv/bin/python3 autoencoders_approach/train_autoencoder.py
"""
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
from sklearn.neural_network import MLPRegressor

# Resolve paths
SCRIPT_DIR   = Path(__file__).parent
STARTER_DIR  = SCRIPT_DIR.parent
sys.path.insert(0, str(STARTER_DIR))

from autoencoders_approach.autoencoder_detector import AutoencoderDetector
from attack_labels import is_attack_alert as _is_attack_alert


def _load_user_benign_ids():
    rules_file = STARTER_DIR.parent.parent / "apps" / "backend" / "benign_rules.json"
    try:
        if rules_file.exists():
            with open(rules_file) as f:
                data = json.load(f)
            ids = set(data.keys())
            if ids:
                print(f"[benign] Loaded {len(ids)} user-defined benign rule IDs")
            return ids
    except Exception as e:
        print(f"[benign] Could not load benign_rules.json: {e}")
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


def _build_mlp(seed=42, lr=0.001):
    # early_stopping is deliberately OFF: it monitors R² on a held-out split,
    # and several of our binary feature columns are near-constant there, so
    # R² is numerically meaningless (≈ -1e29) and stopped training after
    # ~30 iterations — shipping an underfit model with a wide clean-error
    # range that destroyed score calibration (found 2026-07-17). Convergence
    # on training loss is the right criterion for a reconstruction objective.
    return MLPRegressor(
        hidden_layer_sizes=(8, 4, 8),
        activation='relu',
        solver='adam',
        learning_rate_init=lr,
        max_iter=4000,
        random_state=seed,
        early_stopping=False,
        n_iter_no_change=30,
        tol=1e-7,
        verbose=False,
    )


def _fit_robust(X_scaled):
    """Fit over several seeds, keep the run with the lowest final training
    loss (tightest reconstruction of the clean manifold — an unsupervised
    criterion). Guards against occasional bad Adam trajectories."""
    best = None
    for seed in (42, 7, 2026):
        m = _build_mlp(seed=seed).fit(X_scaled, X_scaled)
        if not np.isfinite(m.loss_):
            print(f"  [ae] seed {seed}: non-finite loss — discarded")
            continue
        print(f"  [ae] seed {seed}: loss {m.loss_:.5f}, {m.n_iter_} iters")
        if best is None or m.loss_ < best.loss_:
            best = m
    if best is None:
        raise RuntimeError("Autoencoder training failed for every seed — inspect training data")
    return best


def train(alerts_file, model_path, test_file=None):
    """Train the autoencoder on clean alerts only (one-class + self-supervised trim)."""
    print(f"Loading alerts from: {alerts_file}")
    alerts = load_alerts(alerts_file)
    if len(alerts) < 10:
        print("Not enough alerts. Exiting.")
        return False

    # Label split: attacks are EXCLUDED from training (one-class learning),
    # and kept only for the evaluation section below.
    clean_alerts  = [a for a in alerts if not is_attack_alert(a)]
    attack_alerts = [a for a in alerts if is_attack_alert(a)]

    print(f"Total alerts: {len(alerts)}")
    print(f"  Clean: {len(clean_alerts)} | Attack (excluded from training): {len(attack_alerts)}")
    print(f"  Training on {len(clean_alerts)} clean alerts (one-class + self-supervised trimming)")

    if len(clean_alerts) < 10:
        print("Not enough clean alerts to train. Exiting.")
        return False

    # Initialise detector (skip auto-load — we are about to overwrite)
    detector = AutoencoderDetector(model_path=model_path)
    detector.model = None

    # Extract features from CLEAN alerts only
    print("\nExtracting features from clean alerts...")
    all_features = []
    for alert in clean_alerts:
        try:
            all_features.append(detector.extract_features(alert)[0])
        except Exception as e:
            print(f"Feature error: {e}")
    if len(all_features) < 10:
        print("Not enough valid features. Exiting.")
        return False
    print(f"Extracted features from {len(all_features)} clean alerts")

    X_all = np.array(all_features)

    # ── Round 1: fit on the labelled-clean set, find residual contamination ──
    print("\nRound 1/2: Training on labelled-clean alerts...")
    X_scaled = detector.scaler.fit_transform(X_all)
    detector.model = _fit_robust(X_scaled)
    errors_r1 = np.mean((X_scaled - detector.model.predict(X_scaled)) ** 2, axis=1)
    keep_mask = errors_r1 <= np.percentile(errors_r1, 90)
    X_clean   = X_all[keep_mask]
    print(f"  Iterations: {detector.model.n_iter_} | Kept {len(X_clean)}/{len(X_all)} "
          f"(dropped 10% highest errors — self-supervised purge of mislabelled attacks)")

    # ── Round 2: retrain on the purified clean set ──
    print("Round 2/2: Retraining on purified clean set...")
    X_scaled = detector.scaler.fit_transform(X_clean)
    detector.model = _fit_robust(X_scaled)
    print(f"  Iterations: {detector.model.n_iter_} | Final training set: {len(X_clean)} alerts")

    # Calibrate reconstruction-error range from the purified clean training data
    errors_final = np.mean((X_scaled - detector.model.predict(X_scaled)) ** 2, axis=1)
    detector.recon_error_min = float(np.percentile(errors_final, 2))
    detector.recon_error_max = float(np.percentile(errors_final, 98))
    print(f"Reconstruction error range (clean): "
          f"[{detector.recon_error_min:.6f}, {detector.recon_error_max:.6f}]")

    # Threshold: with clean-only training the clean score distribution IS the
    # baseline — no gap heuristic needed. Flag anything above the 95th
    # percentile of clean scores.
    clean_norm_scores = np.array([detector._normalize_score(e) for e in errors_final])
    threshold = int(np.percentile(clean_norm_scores, 95))
    threshold = max(40, threshold)
    detector.anomaly_threshold = threshold
    print(f"Anomaly threshold: {threshold}/100 (95th pct of clean training scores)")

    # Archive previous model
    if Path(model_path).exists():
        archive = model_path.replace('.pkl', f'_{datetime.now().strftime("%Y-%m-%d")}.pkl')
        shutil.copy(model_path, archive)
        print(f"Archived previous model to: {archive}")

    print(f"\nSaving model to: {model_path}")
    detector.save_model()

    # ---- Evaluate ----
    if test_file:
        test_alerts = load_alerts(test_file)
        attack_alerts = [a for a in test_alerts if is_attack_alert(a)]
        clean_for_fp  = [a for a in test_alerts if not is_attack_alert(a)] or clean_alerts
        print(f"\nLoaded test set: {len(attack_alerts)} attacks, {len(clean_for_fp)} clean")
    else:
        clean_for_fp = clean_alerts

    if attack_alerts:
        print(f"\n{'='*50}")
        print(f"EVALUATION: {len(attack_alerts)} attack alerts")
        print(f"{'='*50}")

        attack_detected = 0
        attack_scores = []
        for alert in attack_alerts:
            r = detector.detect_anomaly(alert)
            attack_scores.append(r['anomaly_score'])
            if r['is_anomaly']:
                attack_detected += 1

        det_rate = attack_detected * 100 / len(attack_alerts)
        print(f"  Detected: {attack_detected}/{len(attack_alerts)} ({det_rate:.1f}%)")
        print(f"  Avg attack score: {sum(attack_scores)/len(attack_scores):.1f}/100")

        clean_fp = 0
        clean_scores = []
        for alert in clean_for_fp:
            r = detector.detect_anomaly(alert)
            clean_scores.append(r['anomaly_score'])
            if r['is_anomaly']:
                clean_fp += 1
        fp_rate = clean_fp * 100 / len(clean_for_fp)
        print(f"  False positives: {clean_fp}/{len(clean_for_fp)} ({fp_rate:.1f}%)")
        print(f"  Avg clean score: {sum(clean_scores)/len(clean_scores):.1f}/100")

        # Quick top-10
        print("\n--- Top 10 highest-scored attack alerts ---")
        scored = sorted(zip(attack_scores, attack_alerts), key=lambda x: x[0], reverse=True)
        for score, alert in scored[:10]:
            desc = alert.get('rule', {}).get('description', 'unknown')
            print(f"  Score: {score:>3}/100 | {desc}")
    else:
        print("\nNo attack alerts found for evaluation.")

    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train Autoencoder on Wazuh alerts")
    parser.add_argument("--test-file", default=None,
                        help="Separate test set (default: use attack alerts from training data)")
    args = parser.parse_args()

    COMBINED_TRAINING = STARTER_DIR / "data" / "training" / "combined" / "all_alerts.json"
    COMBINED_TEST     = STARTER_DIR / "data" / "test" / "all_test_alerts.json"
    WAZUH_LIVE        = Path("/var/ossec/logs/alerts/alerts.json")
    LOCAL_SAMPLE      = STARTER_DIR / "data" / "alerts.json"

    AE_MODEL_LOCAL = str(STARTER_DIR / "data" / "ai_models" / "autoencoder_model.pkl")
    AE_MODEL_PROD  = "/var/ossec/ai_models/autoencoder_model.pkl"

    if COMBINED_TRAINING.exists() and COMBINED_TRAINING.stat().st_size > 0:
        alerts_file = str(COMBINED_TRAINING)
        print("[Using collected training data from data/training/combined/]")
    elif WAZUH_LIVE.exists():
        alerts_file = str(WAZUH_LIVE)
        print("[Using live Wazuh alerts]")
    else:
        alerts_file = str(LOCAL_SAMPLE)
        print("[Using local sample alerts]")

    test_file = args.test_file
    if test_file is None and COMBINED_TEST.exists() and COMBINED_TEST.stat().st_size > 0:
        test_file = str(COMBINED_TEST)
        print(f"[Using separate test set from data/test/]")

    try:
        model_path = AE_MODEL_PROD if Path(AE_MODEL_PROD).parent.exists() else AE_MODEL_LOCAL
    except PermissionError:
        model_path = AE_MODEL_LOCAL

    print("========================================")
    print("Autoencoder Anomaly Detector Training")
    print("========================================\n")
    print(f"Alerts file:  {alerts_file}")
    print(f"Test file:    {test_file or '(using attacks from training data)'}")
    print(f"Model output: {model_path}\n")

    success = train(alerts_file, model_path, test_file=test_file)

    if success:
        print("\n✅ Autoencoder model ready.")
        print("\nNext steps:")
        print("  Evaluate:  ./venv/bin/python3 autoencoders_approach/evaluate_autoencoder.py")
        print("  Compare:   ./venv/bin/python3 autoencoders_approach/compare_models.py")
    else:
        print("\n❌ Training failed.")
