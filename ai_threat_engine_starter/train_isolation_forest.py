#!/usr/bin/env python3
"""
Train Isolation Forest on real Wazuh alerts from alerts.json
Run after collecting real alerts for a few days/weeks.
"""
import json
import sys
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


ATTACK_KEYWORDS = {
    'failed', 'denied', 'invalid', 'non-existent', 'brute force',
    'authentication_failed', 'invalid_login', 'authentication_failures',
    'multiple failed', 'error', 'attack', 'exploit',
}

ATTACK_RULE_IDS = {
    '5503',   # PAM: User login failed
    '5710',   # sshd: non-existent user
    '5760',   # sshd: authentication failed
    '5758',   # sshd: max auth attempts
    '5712',   # sshd: brute force (non-existent)
    '5720',   # sshd: Multiple failed logins
    '2502',   # User missed password for UID change
}


def is_attack_alert(alert):
    """Classify an alert as attack or benign based on rule metadata."""
    rule = alert.get('rule', {})
    rule_id = str(rule.get('id', ''))
    description = rule.get('description', '').lower()
    groups = set(rule.get('groups', []))
    level = rule.get('level', 0)

    # Rule ID match
    if rule_id in ATTACK_RULE_IDS:
        return True
    # High severity
    if level >= 8:
        return True
    # Keyword match in description
    if any(kw in description for kw in ATTACK_KEYWORDS):
        return True
    # Suspicious groups
    if groups & {'authentication_failed', 'invalid_login', 'attack', 'exploit'}:
        return True
    # Has MITRE ATT&CK tags (strong signal)
    mitre = rule.get('mitre', {})
    if mitre.get('technique'):
        return True

    return False


def train_on_real_data(alerts_file, output_model_path):
    """Train Isolation Forest on CLEAN (benign-only) alerts, then evaluate on attacks."""
    print(f"Loading alerts from: {alerts_file}")
    alerts = load_real_alerts(alerts_file)

    if len(alerts) < 10:
        print("Not enough data to train. Exiting.")
        return False

    # --- Fix #6: Separate clean data from attack data ---
    clean_alerts = []
    attack_alerts = []
    for alert in alerts:
        if is_attack_alert(alert):
            attack_alerts.append(alert)
        else:
            clean_alerts.append(alert)

    print(f"Total alerts: {len(alerts)}")
    print(f"  Clean (benign): {len(clean_alerts)} -> used for TRAINING")
    print(f"  Attack:         {len(attack_alerts)} -> used for EVALUATION")

    if len(clean_alerts) < 10:
        print("Not enough clean alerts to train. Need more normal operational data.")
        print("Run Wazuh normally (without attacks) for a few days first.")
        return False

    # Initialize detector (skip auto-load to avoid loading old model)
    detector = AnomalyDetector(model_path=output_model_path)

    # Extract features from CLEAN alerts only for training
    print("\nExtracting features from clean alerts...")
    import numpy as np
    clean_features = []
    for alert in clean_alerts:
        try:
            feat = detector.extract_features(alert)
            clean_features.append(feat[0])
        except Exception as e:
            print(f"Error extracting features: {e}")
            continue

    if len(clean_features) < 10:
        print("Not enough valid features extracted. Exiting.")
        return False

    print(f"Extracted features from {len(clean_features)} clean alerts")

    # Train on CLEAN data only — attacks should then appear as outliers
    print("Training Isolation Forest on clean data...")
    X = np.array(clean_features)
    X_scaled = detector.scaler.fit_transform(X)

    from sklearn.ensemble import IsolationForest
    detector.model = IsolationForest(
        contamination=0.05,     # Low contamination: clean data should have very few anomalies
        random_state=42,
        n_estimators=200,       # More trees for better accuracy
        n_jobs=-1
    )
    detector.model.fit(X_scaled)

    # Calibrate score normalization from training data
    raw_scores = detector.model.decision_function(X_scaled)
    detector.score_min = float(np.percentile(raw_scores, 2))   # Most anomalous boundary
    detector.score_max = float(np.percentile(raw_scores, 98))  # Most normal boundary
    print(f"Calibration range: [{detector.score_min:.4f}, {detector.score_max:.4f}]")

    # --- Find optimal anomaly threshold ---
    # Score all clean alerts to find where "normal" ends
    clean_norm_scores = []
    for alert in clean_alerts:
        feats = detector.extract_features(alert)
        Xs = detector.scaler.transform(feats)
        raw = detector.model.decision_function(Xs)[0]
        clean_norm_scores.append(detector._normalize_score(raw))

    # Threshold = 90th percentile of clean scores
    # This means: only 10% of clean data scores above this, so anything above is suspicious
    threshold = int(np.percentile(clean_norm_scores, 90))
    # Ensure minimum threshold of 40 to avoid too many false positives
    threshold = max(40, threshold)
    detector.anomaly_threshold = threshold
    print(f"Anomaly threshold: {threshold}/100 (90th percentile of clean scores)")

    # Save model
    print(f"Saving model to: {output_model_path}")
    detector.save_model()

    print(f"\nModel trained on {len(clean_features)} clean alerts")

    # --- Evaluate on attack data ---
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
        for alert in clean_alerts:
            result = detector.detect_anomaly(alert)
            clean_scores.append(result['anomaly_score'])
            if result['is_anomaly']:
                clean_fp += 1

        fp_rate = clean_fp * 100 / len(clean_alerts)
        print(f"\n  Clean false positives:        {clean_fp}/{len(clean_alerts)} ({fp_rate:.1f}%)")
        print(f"  Average clean score:          {sum(clean_scores)/len(clean_scores):.1f}/100")

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
    SCRIPT_DIR = Path(__file__).parent

    # Priority order for training data:
    #   1. Combined training data (collected over days/weeks)
    #   2. Live Wazuh alerts file
    #   3. Local sample alerts (dev/test)
    COMBINED_TRAINING = SCRIPT_DIR / "data" / "training" / "combined" / "all_alerts.json"
    WAZUH_LIVE = Path("/var/ossec/logs/alerts/alerts.json")
    LOCAL_SAMPLE = SCRIPT_DIR / "data" / "alerts.json"

    MODEL_PATH_PROD = "/var/ossec/ai_models/anomaly_detector.pkl"
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

    try:
        MODEL_PATH = MODEL_PATH_PROD if Path(MODEL_PATH_PROD).parent.exists() else MODEL_PATH_LOCAL
    except PermissionError:
        MODEL_PATH = MODEL_PATH_LOCAL

    print("========================================")
    print("Isolation Forest Training")
    print("========================================\n")
    print(f"Alerts file: {ALERTS_FILE}")
    print(f"Model output: {MODEL_PATH}\n")

    # Show collection status if training directory exists
    daily_dir = SCRIPT_DIR / "data" / "training" / "daily_logs"
    if daily_dir.exists():
        daily_files = sorted(daily_dir.glob("*.json"))
        if daily_files:
            total = sum(sum(1 for _ in open(f)) for f in daily_files)
            print(f"Training data: {len(daily_files)} days, {total} total alerts")
            print(f"Date range: {daily_files[0].stem} to {daily_files[-1].stem}\n")

    success = train_on_real_data(ALERTS_FILE, MODEL_PATH)

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
