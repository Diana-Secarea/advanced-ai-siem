#!/usr/bin/env python3
"""
Build the UEBA behavioral baselines from clean Wazuh alerts.

Same one-class philosophy as the IF and AE trainers: attack-labelled alerts
are excluded, so the baselines describe only normal user/host/network
behaviour. Deviations from those baselines then score high at detection time.

Usage:
    cd wazuh-monorepo/services/ai-engine
    ./venv/bin/python3 train_ueba.py
"""
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

import numpy as np

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

from ai_engine.ueba_detector import UEBADetector
from attack_labels import is_attack_alert as _is_attack_alert


def _load_user_benign_ids():
    rules_file = SCRIPT_DIR.parent.parent / "apps" / "backend" / "benign_rules.json"
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


def train(alerts_file, model_path, test_file=None):
    print(f"Loading alerts from: {alerts_file}")
    alerts = load_alerts(alerts_file)
    if len(alerts) < 10:
        print("Not enough alerts. Exiting.")
        return False

    # Attacks are EXCLUDED from baseline building (one-class learning)
    clean_alerts  = [a for a in alerts if not is_attack_alert(a)]
    attack_alerts = [a for a in alerts if is_attack_alert(a)]

    print(f"Total alerts: {len(alerts)}")
    print(f"  Clean: {len(clean_alerts)} | Attack (excluded from baselines): {len(attack_alerts)}")

    if len(clean_alerts) < 10:
        print("Not enough clean alerts. Exiting.")
        return False

    detector = UEBADetector(model_path=model_path)

    print(f"\nBuilding behavioral baselines from {len(clean_alerts)} clean alerts...")
    detector.build_baselines(clean_alerts)
    print(f"  Users profiled:   {len(detector.user_profiles)}")
    print(f"  Hosts profiled:   {len(detector.host_profiles)}")
    print(f"  Known source IPs: {len(detector.known_srcips)}")
    print(f"  User-host pairs:  {len(detector.user_host_pairs)}")

    # Threshold: 95th percentile of clean scores — clean baselines score their
    # own training data low, so anything above this is a behavioral deviation.
    clean_scores = np.array([detector.raw_score(a)[0] for a in clean_alerts])
    clean_scores = np.clip(clean_scores, 0, 100)
    threshold = int(np.percentile(clean_scores, 95))
    threshold = max(40, threshold)
    detector.anomaly_threshold = threshold
    print(f"\nAnomaly threshold: {threshold}/100 (95th pct of clean training scores)")

    # Archive previous model
    if Path(model_path).exists():
        archive = model_path.replace('.pkl', f'_{datetime.now().strftime("%Y-%m-%d")}.pkl')
        shutil.copy(model_path, archive)
        print(f"Archived previous model to: {archive}")

    print(f"Saving UEBA baselines to: {model_path}")
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
        clean_eval_scores = []
        for alert in clean_for_fp:
            r = detector.detect_anomaly(alert)
            clean_eval_scores.append(r['anomaly_score'])
            if r['is_anomaly']:
                clean_fp += 1
        fp_rate = clean_fp * 100 / len(clean_for_fp)
        print(f"  False positives: {clean_fp}/{len(clean_for_fp)} ({fp_rate:.1f}%)")
        print(f"  Avg clean score: {sum(clean_eval_scores)/len(clean_eval_scores):.1f}/100")

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

    parser = argparse.ArgumentParser(description="Build UEBA baselines from Wazuh alerts")
    parser.add_argument("--test-file", default=None,
                        help="Separate test set (default: data/test/all_test_alerts.json)")
    args = parser.parse_args()

    COMBINED_TRAINING = SCRIPT_DIR / "data" / "training" / "combined" / "all_alerts.json"
    COMBINED_TEST     = SCRIPT_DIR / "data" / "test" / "all_test_alerts.json"
    WAZUH_LIVE        = Path("/var/ossec/logs/alerts/alerts.json")
    LOCAL_SAMPLE      = SCRIPT_DIR / "data" / "alerts.json"

    UEBA_MODEL_LOCAL = str(SCRIPT_DIR / "data" / "ai_models" / "ueba_model.pkl")
    UEBA_MODEL_PROD  = "/var/ossec/ai_models/ueba_model.pkl"

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
        print("[Using separate test set from data/test/]")

    try:
        model_path = UEBA_MODEL_PROD if Path(UEBA_MODEL_PROD).parent.exists() else UEBA_MODEL_LOCAL
    except PermissionError:
        model_path = UEBA_MODEL_LOCAL

    print("========================================")
    print("UEBA Behavioral Baseline Training")
    print("========================================\n")
    print(f"Alerts file:  {alerts_file}")
    print(f"Test file:    {test_file or '(using attacks from training data)'}")
    print(f"Model output: {model_path}\n")

    success = train(alerts_file, model_path, test_file=test_file)
    print("\n✅ UEBA baselines ready." if success else "\n❌ Training failed.")
