#!/usr/bin/env python3
"""
Train Isolation Forest on real Wazuh alerts from alerts.json
Run after collecting real alerts for a few days/weeks.
"""
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from ai_engine.anomaly_detector import AnomalyDetector


def load_real_alerts(alerts_file):
    """Load alerts from Wazuh alerts.json"""
    alerts = []
    try:
        with open(alerts_file, 'r') as f:
            for line in f:
                try:
                    alert = json.loads(line.strip())
                    alerts.append(alert)
                except:
                    continue
    except FileNotFoundError:
        print(f"File not found: {alerts_file}")
        print("Collect alerts first by running Wazuh for a few days.")
        return []
    
    return alerts


from attack_labels import is_attack_alert as _is_attack_alert

def _load_user_benign_ids():
    """Load user-defined benign rule IDs from the UI-managed benign_rules.json."""
    rules_file = Path(__file__).resolve().parent.parent.parent / "apps" / "backend" / "benign_rules.json"
    try:
        if rules_file.exists():
            with open(rules_file, "r") as f:
                data = json.load(f)
            user_ids = set(data.keys())
            if user_ids:
                print(f"[benign] Loaded {len(user_ids)} user-defined benign rule IDs from benign_rules.json")
            return user_ids
    except Exception as e:
        print(f"[benign] Could not load benign_rules.json: {e}")
    return set()


# Only user-defined exceptions are treated as benign during training.
# See suggested_benign_rule_ids.json for common candidates.
BENIGN_RULE_IDS = _load_user_benign_ids()


def is_attack_alert(alert):
    return _is_attack_alert(alert, BENIGN_RULE_IDS)


def train_on_real_data(alerts_file, output_model_path, test_file=None):
    """Train Isolation Forest on all Wazuh alerts (unsupervised, contamination=auto).

    No label filter is applied during training.  attack_labels is used only in
    the evaluation section below to measure detection rate and false-positive rate.

    NOTE: unlike the AE and UEBA detectors (one-class, clean-only), the IF is
    deliberately kept fully unsupervised on ALL alerts — clean-only training
    was tried and made the IF markedly weaker (attacks landed inside the clean
    score range), so this stronger configuration is retained.

    If test_file is provided, evaluation is done on that separate file instead of
    the attack-labelled alerts extracted from the training data.
    """
    print(f"Loading alerts from: {alerts_file}")
    alerts = load_real_alerts(alerts_file)

    if len(alerts) < 10:
        print("Not enough data to train. Exiting.")
        return False

    # Label split used ONLY for evaluation reporting — not used in training
    clean_alerts  = [a for a in alerts if not is_attack_alert(a)]
    attack_alerts = [a for a in alerts if is_attack_alert(a)]

    print(f"Total alerts: {len(alerts)}")
    print(f"  Estimated clean: {len(clean_alerts)} | Estimated attack: {len(attack_alerts)}")
    print(f"  Training on ALL {len(alerts)} alerts (unsupervised, contamination=auto)")

    # Initialize detector (skip auto-load to avoid loading old model)
    detector = AnomalyDetector(model_path=output_model_path)

    # Extract features from ALL alerts — no label filter
    print("\nExtracting features from all alerts...")
    import numpy as np
    all_features = []
    for alert in alerts:
        try:
            feat = detector.extract_features(alert)
            all_features.append(feat[0])
        except Exception as e:
            print(f"Error extracting features: {e}")
            continue

    if len(all_features) < 10:
        print("Not enough valid features extracted. Exiting.")
        return False

    print(f"Extracted features from {len(all_features)} alerts")

    # Train on ALL data — contamination='auto' makes no assumption about attack ratio
    print("Training Isolation Forest on all data (contamination=auto)...")
    X = np.array(all_features)
    X_scaled = detector.scaler.fit_transform(X)

    from sklearn.ensemble import IsolationForest
    detector.model = IsolationForest(
        contamination='auto',
        random_state=42,
        n_estimators=200,
        n_jobs=-1
    )
    detector.model.fit(X_scaled)

    # Calibrate score normalization from all training data
    raw_scores = detector.model.decision_function(X_scaled)
    detector.score_min = float(np.percentile(raw_scores, 2))
    detector.score_max = float(np.percentile(raw_scores, 98))
    print(f"Calibration range: [{detector.score_min:.4f}, {detector.score_max:.4f}]")

    # Threshold: score all alerts, find natural gap in distribution (score gap heuristic),
    # use everything below the gap as the estimated clean set
    all_norm_scores = []
    for alert in alerts:
        try:
            feats = detector.extract_features(alert)
            Xs = detector.scaler.transform(feats)
            raw = detector.model.decision_function(Xs)[0]
            all_norm_scores.append(detector._normalize_score(raw))
        except Exception:
            pass
    scores_arr = np.array(all_norm_scores)

    # Find the largest empty/sparse bucket in the middle of the score range
    hist, bin_edges = np.histogram(scores_arr, bins=20)
    gap_idx = int(np.argmin(hist[5:15]) + 5)
    gap_score = float(bin_edges[gap_idx + 1])
    estimated_clean_scores = scores_arr[scores_arr <= gap_score]
    # Fall back to 70th percentile if gap lands in a useless position
    if len(estimated_clean_scores) < len(scores_arr) * 0.4:
        gap_score = float(np.percentile(scores_arr, 70))
        estimated_clean_scores = scores_arr[scores_arr <= gap_score]
    print(f"Score gap at: {gap_score:.1f} "
          f"({len(estimated_clean_scores)}/{len(scores_arr)} estimated clean)")

    threshold = int(np.percentile(estimated_clean_scores, 90))
    threshold = max(40, threshold)
    detector.anomaly_threshold = threshold
    print(f"Anomaly threshold: {threshold}/100 (90th pct of estimated clean, contamination=auto)")

    # Archive previous model before overwriting
    if Path(output_model_path).exists():
        archive_path = output_model_path.replace('.pkl', f'_{datetime.now().strftime("%Y-%m-%d")}.pkl')
        shutil.copy(output_model_path, archive_path)
        print(f"Archived previous model to: {archive_path}")

    # Save model
    print(f"Saving model to: {output_model_path}")
    detector.save_model()

    print(f"\nModel trained on {len(all_features)} alerts (unsupervised)")

    # --- Evaluate on test data (separate file) or fall back to training attacks ---
    if test_file:
        print(f"\nLoading separate test set from: {test_file}")
        test_alerts = load_real_alerts(test_file)
        test_clean   = [a for a in test_alerts if not is_attack_alert(a)]
        attack_alerts = [a for a in test_alerts if is_attack_alert(a)]
        print(f"  Test set: {len(test_clean)} clean, {len(attack_alerts)} attack alerts")
        # Use test clean alerts for false-positive check instead of training clean
        clean_alerts_for_fp = test_clean if test_clean else clean_alerts
    else:
        clean_alerts_for_fp = clean_alerts

    if attack_alerts:
        print(f"\n{'='*50}")
        print(f"EVALUATION: Scoring {len(attack_alerts)} attack alerts")
        print(f"{'='*50}")

        attack_detected = 0
        attack_scores = []
        for alert in attack_alerts:
            result = detector.detect_anomaly(alert)
            attack_scores.append(result['anomaly_score'])
            if result['is_anomaly']:
                attack_detected += 1

        detection_rate = attack_detected * 100 / len(attack_alerts)
        avg_score = sum(attack_scores) / len(attack_scores)

        print(f"  Attacks detected as anomaly: {attack_detected}/{len(attack_alerts)} ({detection_rate:.1f}%)")
        print(f"  Average attack score:        {avg_score:.1f}/100")
        print(f"  Max attack score:            {max(attack_scores)}/100")
        print(f"  Min attack score:            {min(attack_scores)}/100")

        # Also check false positives on clean data
        clean_fp = 0
        clean_scores = []
        for alert in clean_alerts_for_fp:
            result = detector.detect_anomaly(alert)
            clean_scores.append(result['anomaly_score'])
            if result['is_anomaly']:
                clean_fp += 1

        fp_rate = clean_fp * 100 / len(clean_alerts_for_fp)
        label = "test" if test_file else "training"
        print(f"\n  Clean false positives ({label}): {clean_fp}/{len(clean_alerts_for_fp)} ({fp_rate:.1f}%)")
        print(f"  Average clean score:           {sum(clean_scores)/len(clean_scores):.1f}/100")

        # Show top-scored attacks
        print(f"\n--- Top 10 highest-scored attack alerts ---")
        scored_attacks = list(zip(attack_scores, range(len(attack_alerts)), attack_alerts))
        scored_attacks.sort(key=lambda x: x[0], reverse=True)
        for score, _, alert in scored_attacks[:10]:
            desc = alert.get('rule', {}).get('description', 'unknown')
            level = alert.get('rule', {}).get('level', 0)
            log = str(alert.get('full_log', ''))[:60]
            print(f"  Score: {score:>3}/100 | Level: {level:>2} | {desc}")
            if log:
                print(f"         {log}")
    else:
        print("\nNo attack alerts found for evaluation.")
        print("Run attacks and collect data to evaluate detection rate.")

    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train Isolation Forest on Wazuh alerts")
    parser.add_argument("--test-file", type=str, default=None,
                        help="Path to separate test set for evaluation (default: use attack alerts from training data)")
    args = parser.parse_args()

    SCRIPT_DIR = Path(__file__).parent

    COMBINED_TRAINING = SCRIPT_DIR / "data" / "training" / "combined" / "all_alerts.json"
    COMBINED_TEST     = SCRIPT_DIR / "data" / "test" / "all_test_alerts.json"
    WAZUH_LIVE        = Path("/var/ossec/logs/alerts/alerts.json")
    LOCAL_SAMPLE      = SCRIPT_DIR / "data" / "alerts.json"

    MODEL_PATH_PROD  = "/var/ossec/ai_models/anomaly_detector.pkl"
    MODEL_PATH_LOCAL = str(SCRIPT_DIR / "data" / "ai_models" / "anomaly_detector.pkl")

    if COMBINED_TRAINING.exists() and COMBINED_TRAINING.stat().st_size > 0:
        ALERTS_FILE = str(COMBINED_TRAINING)
        print("[Using collected training data from data/training/combined/]")
    elif WAZUH_LIVE.exists():
        ALERTS_FILE = str(WAZUH_LIVE)
        print("[Using live Wazuh alerts]")
    else:
        ALERTS_FILE = str(LOCAL_SAMPLE)
        print("[Using local sample alerts — collect real data for better results]")

    # Resolve test file: CLI arg > auto-detected > None (falls back to training attacks)
    test_file = args.test_file
    if test_file is None and COMBINED_TEST.exists() and COMBINED_TEST.stat().st_size > 0:
        test_file = str(COMBINED_TEST)
        print(f"[Using separate test set from data/test/]")

    try:
        MODEL_PATH = MODEL_PATH_PROD if Path(MODEL_PATH_PROD).parent.exists() else MODEL_PATH_LOCAL
    except PermissionError:
        MODEL_PATH = MODEL_PATH_LOCAL

    print("========================================")
    print("Isolation Forest Training")
    print("========================================\n")
    print(f"Alerts file:  {ALERTS_FILE}")
    print(f"Test file:    {test_file or '(using attack alerts from training data)'}")
    print(f"Model output: {MODEL_PATH}\n")

    daily_dir = SCRIPT_DIR / "data" / "training" / "daily_logs"
    if daily_dir.exists():
        daily_files = sorted(daily_dir.glob("*.json"))
        if daily_files:
            total = sum(sum(1 for _ in open(f)) for f in daily_files)
            print(f"Training data: {len(daily_files)} days, {total} total alerts")
            print(f"Date range: {daily_files[0].stem} to {daily_files[-1].stem}\n")

    success = train_on_real_data(ALERTS_FILE, MODEL_PATH, test_file=test_file)

    if success:
        print("\n✅ Model ready to use!")
        print("\nNext steps:")
        print("  1. Start AI engine: ./start_wazuh_rag.sh --wazuh")
        print("  2. Monitor with: python3 monitor_alerts.py")
    else:
        print("\n❌ Training failed.")
        print("\nTo collect training data, run daily:")
        print("  python3 collect_training_data.py")
        print("\nAfter 1-2 weeks of collection, re-run this script.")
