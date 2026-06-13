#!/usr/bin/env python3
"""
Evaluate Autoencoder anomaly detector performance.

Produces the same report format as evaluate_isolation_forest.py so results
are directly comparable.

Usage:
    cd ai_threat_engine_starter
    ./venv/bin/python3 autoencoders_approach/evaluate_autoencoder.py
    ./venv/bin/python3 autoencoders_approach/evaluate_autoencoder.py --plot
    ./venv/bin/python3 autoencoders_approach/evaluate_autoencoder.py \
        --alerts data/training/combined/all_alerts.json \
        --model  data/ai_models/autoencoder_model.pkl
"""
import json
import sys
import argparse
from pathlib import Path

SCRIPT_DIR  = Path(__file__).parent
STARTER_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(STARTER_DIR))

from autoencoders_approach.autoencoder_detector import AutoencoderDetector
from attack_labels import is_attack_alert as _is_attack_alert


def _load_user_benign_ids():
    rules_file = STARTER_DIR.parent / "backend" / "benign_rules.json"
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
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return alerts


def evaluate(detector, alerts):
    clean_results  = []
    attack_results = []
    for alert in alerts:
        result = detector.detect_anomaly(alert)
        multi  = detector.multi_dimensional_scoring(alert)
        rule   = alert.get('rule', {})
        entry  = {
            'anomaly_score':     result['anomaly_score'],
            'reconstruction_error': result.get('reconstruction_error', 0.0),
            'is_anomaly':        result['is_anomaly'],
            'combined_score':    multi['combined_score'],
            'confidence':        result['confidence'],
            'rule_desc':         rule.get('description', 'unknown'),
            'rule_id':           str(rule.get('id', '')),
            'rule_level':        rule.get('level', 0),
            'full_log':          str(alert.get('full_log', ''))[:80],
        }
        if is_attack_alert(alert):
            attack_results.append(entry)
        else:
            clean_results.append(entry)
    return clean_results, attack_results


def print_report(clean_results, attack_results):
    total = len(clean_results) + len(attack_results)

    print()
    print("=" * 70)
    print("  AUTOENCODER MODEL EVALUATION REPORT")
    print("=" * 70)

    print(f"\n  Total alerts evaluated: {total}")
    print(f"  Clean (benign):         {len(clean_results)}")
    print(f"  Attack:                 {len(attack_results)}")

    if not attack_results:
        print("\n  No attack alerts found. Cannot evaluate detection rate.")
        return

    clean_scores   = [r['anomaly_score'] for r in clean_results]
    attack_scores  = [r['anomaly_score'] for r in attack_results]
    clean_combined = [r['combined_score'] for r in clean_results]
    attack_combined = [r['combined_score'] for r in attack_results]
    clean_errors   = [r['reconstruction_error'] for r in clean_results]
    attack_errors  = [r['reconstruction_error'] for r in attack_results]

    clean_detected  = sum(1 for r in clean_results  if r['is_anomaly'])
    attack_detected = sum(1 for r in attack_results if r['is_anomaly'])

    avg_clean  = sum(clean_scores)  / len(clean_scores)  if clean_scores  else 0
    avg_attack = sum(attack_scores) / len(attack_scores) if attack_scores else 0
    separation = avg_attack - avg_clean

    print(f"\n  {'Metric':<35} {'Clean':>10} {'Attack':>10}")
    print(f"  {'-'*35} {'-'*10} {'-'*10}")
    print(f"  {'Avg anomaly score':<35} {avg_clean:>8.1f}/100 {avg_attack:>8.1f}/100")
    print(f"  {'Max anomaly score':<35} {max(clean_scores):>8}/100 {max(attack_scores):>8}/100")
    print(f"  {'Min anomaly score':<35} {min(clean_scores):>8}/100 {min(attack_scores):>8}/100")
    avg_cc = sum(clean_combined)  / len(clean_combined)  if clean_combined  else 0
    avg_ac = sum(attack_combined) / len(attack_combined) if attack_combined else 0
    print(f"  {'Avg combined score':<35} {avg_cc:>8.1f}/100 {avg_ac:>8.1f}/100")
    avg_ce = sum(clean_errors)  / len(clean_errors)  if clean_errors  else 0
    avg_ae = sum(attack_errors) / len(attack_errors) if attack_errors else 0
    print(f"  {'Avg reconstruction error':<35} {avg_ce:>10.5f} {avg_ae:>10.5f}")
    print(f"  {'Detected as anomaly':<35} {clean_detected:>7}/{len(clean_results)} "
          f"{attack_detected:>7}/{len(attack_results)}")

    fp_rate  = clean_detected  * 100 / len(clean_results)  if clean_results  else 0
    det_rate = attack_detected * 100 / len(attack_results) if attack_results else 0

    print(f"\n  Score separation (attack − clean avg): {separation:.1f} points")
    print(f"  Detection rate (true positives):        {det_rate:.1f}%")
    print(f"  False positive rate:                    {fp_rate:.1f}%")

    # Confusion matrix
    tp = attack_detected
    fn = len(attack_results) - attack_detected
    fp = clean_detected
    tn = len(clean_results)  - clean_detected

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n  --- Confusion Matrix ---")
    print(f"  {'':>25} {'Predicted':>22}")
    print(f"  {'':>25} {'Anomaly':>10} {'Normal':>10}")
    print(f"  {'Actual Attack':<25} {tp:>10} {fn:>10}")
    print(f"  {'Actual Clean':<25} {fp:>10} {tn:>10}")
    print(f"\n  Precision: {precision:.1%}  (of flagged alerts, how many are real attacks)")
    print(f"  Recall:    {recall:.1%}  (of real attacks, how many were caught)")
    print(f"  F1-Score:  {f1:.1%}")

    # Score distribution buckets
    print(f"\n  {'Score Range':<20} {'Clean':>8} {'Attack':>8}")
    print(f"  {'-'*20} {'-'*8} {'-'*8}")
    buckets = [(0, 20, 'LOW'), (20, 40, 'MEDIUM'), (40, 60, 'HIGH'),
               (60, 80, 'CRITICAL'), (80, 101, 'SEVERE')]
    for lo, hi, label in buckets:
        c = sum(1 for s in clean_scores  if lo <= s < hi)
        a = sum(1 for s in attack_scores if lo <= s < hi)
        c_bar = '#' * (c * 20 // max(len(clean_scores), 1))
        a_bar = '#' * (a * 20 // max(len(attack_scores), 1))
        print(f"  {lo:>3}-{hi-1:<3} ({label:<8}) {c:>8} {a:>8}  {c_bar}|{a_bar}")

    # Per-rule breakdown (attack rules)
    print(f"\n  {'Rule Description':<55} {'Count':>5} {'Avg':>5} {'Max':>5} {'Det%':>5}")
    print(f"  {'-'*55} {'-'*5} {'-'*5} {'-'*5} {'-'*5}")
    by_rule = {}
    for r in attack_results:
        by_rule.setdefault(r['rule_desc'], []).append(r)
    for desc in sorted(by_rule, key=lambda d: -(sum(r['anomaly_score'] for r in by_rule[d]) / len(by_rule[d]))):
        entries  = by_rule[desc]
        scores   = [e['anomaly_score'] for e in entries]
        detected = sum(1 for e in entries if e['is_anomaly'])
        det_pct  = detected * 100 // len(entries)
        avg_s    = sum(scores) / len(scores)
        print(f"  {desc[:55]:<55} {len(entries):>5} {avg_s:>5.0f} {max(scores):>5} {det_pct:>4}%")

    # Top 15
    print(f"\n  --- Top 15 Highest-Scored Attack Alerts ---")
    for i, r in enumerate(sorted(attack_results, key=lambda x: x['anomaly_score'], reverse=True)[:15], 1):
        print(f"  {i:>2}. Score: {r['anomaly_score']:>3}/100 | Combined: {r['combined_score']:>3}/100 | "
              f"Lvl {r['rule_level']:>2} | {r['rule_desc']}")
        if r['full_log']:
            print(f"      {r['full_log']}")

    # 5 lowest (missed)
    sorted_atk = sorted(attack_results, key=lambda x: x['anomaly_score'])
    print(f"\n  --- 5 Lowest-Scored Attack Alerts (potential misses) ---")
    for i, r in enumerate(sorted_atk[:5], 1):
        print(f"  {i}. Score: {r['anomaly_score']:>3}/100 | Lvl {r['rule_level']:>2} | {r['rule_desc']}")

    print(f"\n{'='*70}")
    if separation >= 30 and det_rate >= 50:
        print("  VERDICT: GOOD — Autoencoder separates attacks from clean alerts well.")
    elif separation >= 15:
        print("  VERDICT: FAIR — Some separation. May need more training data.")
    else:
        print("  VERDICT: POOR — Low separation. Check features or data quality.")
    print(f"{'='*70}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate Autoencoder anomaly detector")
    parser.add_argument('--alerts', help='Path to alerts JSONL file')
    parser.add_argument('--model',  help='Path to autoencoder .pkl file')
    args = parser.parse_args()

    if args.alerts:
        alerts_file = Path(args.alerts)
    else:
        candidates = [
            STARTER_DIR / 'data' / 'training' / 'combined' / 'all_alerts.json',
            STARTER_DIR / 'data' / 'alerts.json',
        ]
        alerts_file = next((c for c in candidates if c.exists() and c.stat().st_size > 0), None)
        if not alerts_file:
            print("No alerts file found. Provide --alerts path.")
            sys.exit(1)

    if args.model:
        model_path = args.model
    else:
        prod  = Path("/var/ossec/ai_models/autoencoder_model.pkl")
        local = STARTER_DIR / 'data' / 'ai_models' / 'autoencoder_model.pkl'
        model_path = str(prod if prod.exists() else local)

    print(f"Alerts: {alerts_file}")
    print(f"Model:  {model_path}")

    alerts = load_alerts(str(alerts_file))
    if not alerts:
        print("No alerts loaded.")
        sys.exit(1)

    detector = AutoencoderDetector(model_path=model_path)
    if detector.model is None:
        print("\nModel not loaded. Train first:")
        print("  ./venv/bin/python3 autoencoders_approach/train_autoencoder.py")
        sys.exit(1)

    clean_results, attack_results = evaluate(detector, alerts)
    print_report(clean_results, attack_results)


if __name__ == '__main__':
    main()
