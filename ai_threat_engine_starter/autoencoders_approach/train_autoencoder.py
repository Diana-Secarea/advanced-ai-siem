#!/usr/bin/env python3
"""
Train the Autoencoder anomaly detector on real Wazuh alerts.

Architecture: bottleneck MLP (16 → 8 → 4 → 8 → 16) trained via iterative
trimming — fully unsupervised, no attack labels used during training.

Round 1: train on ALL alerts, drop top 25% highest reconstruction errors.
Round 2: retrain on remaining 75%, drop top 15% of those.
Round 3: retrain on final clean estimate, calibrate threshold.

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
    rules_file = STARTER_DIR.parent / "backend" / "benign_rules.json"
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


def _build_mlp():
    return MLPRegressor(
        hidden_layer_sizes=(8, 4, 8),
        activation='relu',
        solver='adam',
        learning_rate_init=0.001,
        max_iter=1000,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=20,
        verbose=False,
    )


def train(alerts_file, model_path, test_file=None):
    """Train the autoencoder via iterative trimming — no attack labels used."""
    print(f"Loading alerts from: {alerts_file}")
    alerts = load_alerts(alerts_file)
    if len(alerts) < 10:
        print("Not enough alerts. Exiting.")
        return False

    # Label split kept ONLY for evaluation reporting — not used in training
    clean_alerts  = [a for a in alerts if not is_attack_alert(a)]
    attack_alerts = [a for a in alerts if is_attack_alert(a)]

    print(f"Total alerts:      {len(alerts)}")
    print(f"  Estimated clean: {len(clean_alerts)} | Estimated attack: {len(attack_alerts)}")
    print(f"  Training on ALL {len(alerts)} alerts (iterative trimming)")

    # Initialise detector (skip auto-load — we are about to overwrite)
    detector = AutoencoderDetector(model_path=model_path)
    detector.model = None

    # Extract features from ALL alerts — no label filter
    print("\nExtracting features from all alerts...")
    all_features = []
    valid_alerts  = []
    for alert in alerts:
        try:
            all_features.append(detector.extract_features(alert)[0])
            valid_alerts.append(alert)
        except Exception as e:
            print(f"Feature error: {e}")
    if len(all_features) < 10:
        print("Not enough valid features. Exiting.")
        return False
    print(f"Extracted features from {len(all_features)} alerts")

    X_all   = np.array(all_features)
    idx_all = np.arange(len(X_all))

    # ── Round 1: train on ALL, drop top 25% highest reconstruction errors ──
    print("\nRound 1/3: Training on all alerts...")
    X_scaled = detector.scaler.fit_transform(X_all)
    detector.model = _build_mlp()
    detector.model.fit(X_scaled, X_scaled)
    errors_r1 = np.mean((X_scaled - detector.model.predict(X_scaled)) ** 2, axis=1)
    keep_r1   = idx_all[errors_r1 <= np.percentile(errors_r1, 75)]
    print(f"  Iterations: {detector.model.n_iter_} | Kept {len(keep_r1)}/{len(X_all)} (dropped top 25%)")

    # ── Round 2: retrain on 75%, drop top 15% of remaining ──
    print("Round 2/3: Retraining on estimated clean subset...")
    X_r2        = X_all[keep_r1]
    X_scaled_r2 = detector.scaler.fit_transform(X_r2)
    detector.model = _build_mlp()
    detector.model.fit(X_scaled_r2, X_scaled_r2)
    errors_r2 = np.mean((X_scaled_r2 - detector.model.predict(X_scaled_r2)) ** 2, axis=1)
    keep_r2   = keep_r1[errors_r2 <= np.percentile(errors_r2, 85)]
    print(f"  Iterations: {detector.model.n_iter_} | Kept {len(keep_r2)}/{len(X_r2)} (dropped top 15%)")

    # ── Round 3: final training on clean estimate ──
    print("Round 3/3: Final training on clean estimate...")
    X_r3        = X_all[keep_r2]
    X_scaled_r3 = detector.scaler.fit_transform(X_r3)
    detector.model = _build_mlp()
    detector.model.fit(X_scaled_r3, X_scaled_r3)
    print(f"  Iterations: {detector.model.n_iter_} | Final training set: {len(X_r3)} alerts")

    # Calibrate reconstruction-error range from final clean estimate
    errors_r3 = np.mean((X_scaled_r3 - detector.model.predict(X_scaled_r3)) ** 2, axis=1)
    detector.recon_error_min = float(np.percentile(errors_r3, 2))
    detector.recon_error_max = float(np.percentile(errors_r3, 98))
    print(f"Reconstruction error range (estimated clean): "
          f"[{detector.recon_error_min:.6f}, {detector.recon_error_max:.6f}]")

    # Threshold: score ALL training alerts, find the natural gap in the score
    # distribution (same heuristic as IF) — adapts to any data distribution.
    all_norm_scores = []
    for alert in valid_alerts:
        try:
            all_norm_scores.append(detector.detect_anomaly(alert)['anomaly_score'])
        except Exception:
            pass
    scores_arr = np.array(all_norm_scores)

    hist, bin_edges = np.histogram(scores_arr, bins=20)
    gap_idx = int(np.argmin(hist[5:15]) + 5)
    gap_score = float(bin_edges[gap_idx + 1])
    estimated_clean_scores = scores_arr[scores_arr <= gap_score]
    if len(estimated_clean_scores) < len(scores_arr) * 0.4:
        gap_score = float(np.percentile(scores_arr, 70))
        estimated_clean_scores = scores_arr[scores_arr <= gap_score]
    print(f"Score gap at: {gap_score:.1f} "
          f"({len(estimated_clean_scores)}/{len(scores_arr)} estimated clean)")

    threshold = int(np.percentile(estimated_clean_scores, 90))
    threshold = max(40, threshold)
    detector.anomaly_threshold = threshold
    print(f"Anomaly threshold: {threshold}/100 (90th pct of estimated clean via gap)")

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
