#!/usr/bin/env python3
"""
Evaluate Isolation Forest model performance.

Loads the trained model and scores all alerts in the combined training data,
separating them into clean (benign) vs attack categories.
Produces a full report with detection rates, score distributions, and per-rule breakdown.

Usage:
    python3 evaluate_isolation_forest.py
    python3 evaluate_isolation_forest.py --alerts /path/to/alerts.json --model /path/to/model.pkl
"""
import json
import sys
import argparse
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent))

from ai_engine.anomaly_detector import AnomalyDetector


from attack_labels import is_attack_alert as _is_attack_alert

def _load_user_benign_ids():
    """Load user-defined benign rule IDs from the UI-managed benign_rules.json."""
    rules_file = Path(__file__).resolve().parent.parent.parent / "apps" / "backend" / "benign_rules.json"
    try:
        if rules_file.exists():
            with open(rules_file, "r") as f:
                data = json.load(f)
            return set(data.keys())
    except Exception as e:
        print(f"[benign] Could not load benign_rules.json: {e}")
    return set()


# Only user-defined exceptions are treated as benign during evaluation.
# See suggested_benign_rule_ids.json for common candidates.
BENIGN_RULE_IDS = _load_user_benign_ids()

def is_attack_alert(alert):
    return _is_attack_alert(alert, BENIGN_RULE_IDS)


def load_alerts(filepath):
    """Load line-delimited JSON alerts."""
    alerts = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def evaluate(detector, alerts):
    """Score all alerts and return structured results."""
    clean_results = []
    attack_results = []

    for alert in alerts:
        result = detector.detect_anomaly(alert)
        multi = detector.multi_dimensional_scoring(alert)
        rule = alert.get('rule', {})

        entry = {
            'anomaly_score': result['anomaly_score'],
            'is_anomaly': result['is_anomaly'],
            'combined_score': multi['combined_score'],
            'confidence': result['confidence'],
            'rule_desc': rule.get('description', 'unknown'),
            'rule_id': str(rule.get('id', '')),
            'rule_level': rule.get('level', 0),
            'full_log': str(alert.get('full_log', ''))[:80],
        }

        if is_attack_alert(alert):
            attack_results.append(entry)
        else:
            clean_results.append(entry)

    return clean_results, attack_results


def print_report(clean_results, attack_results):
    """Print full evaluation report."""
    total = len(clean_results) + len(attack_results)

    print()
    print("=" * 70)
    print("  ISOLATION FOREST MODEL EVALUATION REPORT")
    print("=" * 70)

    # --- Overview ---
    print(f"\n  Total alerts evaluated: {total}")
    print(f"  Clean (benign):         {len(clean_results)}")
    print(f"  Attack:                 {len(attack_results)}")

    if not attack_results:
        print("\n  No attack alerts found. Cannot evaluate detection rate.")
        return

    # --- Core Metrics ---
    clean_scores = [r['anomaly_score'] for r in clean_results]
    attack_scores = [r['anomaly_score'] for r in attack_results]
    clean_combined = [r['combined_score'] for r in clean_results]
    attack_combined = [r['combined_score'] for r in attack_results]

    clean_detected = sum(1 for r in clean_results if r['is_anomaly'])
    attack_detected = sum(1 for r in attack_results if r['is_anomaly'])

    avg_clean = sum(clean_scores) / len(clean_scores) if clean_scores else 0
    avg_attack = sum(attack_scores) / len(attack_scores) if attack_scores else 0
    separation = avg_attack - avg_clean

    print(f"\n  {'Metric':<30} {'Clean':>10} {'Attack':>10}")
    print(f"  {'-'*30} {'-'*10} {'-'*10}")
    print(f"  {'Avg anomaly score':<30} {avg_clean:>8.1f}/100 {avg_attack:>8.1f}/100")
    print(f"  {'Max anomaly score':<30} {max(clean_scores):>8}/100 {max(attack_scores):>8}/100")
    print(f"  {'Min anomaly score':<30} {min(clean_scores):>8}/100 {min(attack_scores):>8}/100")
    avg_cc = sum(clean_combined) / len(clean_combined) if clean_combined else 0
    avg_ac = sum(attack_combined) / len(attack_combined) if attack_combined else 0
    print(f"  {'Avg combined score':<30} {avg_cc:>8.1f}/100 {avg_ac:>8.1f}/100")
    print(f"  {'Detected as anomaly':<30} {clean_detected:>7}/{len(clean_results)} {attack_detected:>7}/{len(attack_results)}")

    fp_rate = clean_detected * 100 / len(clean_results) if clean_results else 0
    det_rate = attack_detected * 100 / len(attack_results) if attack_results else 0

    print(f"\n  Score separation (attack - clean avg): {separation:.1f} points")
    print(f"  Detection rate (true positives):        {det_rate:.1f}%")
    print(f"  False positive rate:                    {fp_rate:.1f}%")

    # --- Confusion Matrix ---
    tp = attack_detected
    fn = len(attack_results) - attack_detected
    fp = clean_detected
    tn = len(clean_results) - clean_detected

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n  --- Confusion Matrix ---")
    print(f"  {'':>25} {'Predicted':>22}")
    print(f"  {'':>25} {'Anomaly':>10} {'Normal':>10}")
    print(f"  {'Actual Attack':<25} {tp:>10} {fn:>10}")
    print(f"  {'Actual Clean':<25} {fp:>10} {tn:>10}")
    print(f"\n  Precision: {precision:.1%}  (of flagged alerts, how many are real attacks)")
    print(f"  Recall:    {recall:.1%}  (of real attacks, how many were caught)")
    print(f"  F1-Score:  {f1:.1%}")

    # --- Score Distribution ---
    print(f"\n  {'Score Range':<20} {'Clean':>8} {'Attack':>8}")
    print(f"  {'-'*20} {'-'*8} {'-'*8}")
    buckets = [(0, 20, 'LOW'), (20, 40, 'MEDIUM'), (40, 60, 'HIGH'),
               (60, 80, 'CRITICAL'), (80, 101, 'SEVERE')]
    for lo, hi, label in buckets:
        c = sum(1 for s in clean_scores if lo <= s < hi)
        a = sum(1 for s in attack_scores if lo <= s < hi)
        c_bar = '#' * (c * 20 // max(len(clean_scores), 1))
        a_bar = '#' * (a * 20 // max(len(attack_scores), 1))
        print(f"  {lo:>3}-{hi-1:<3} ({label:<8}) {c:>8} {a:>8}  {c_bar}|{a_bar}")

    # --- Per-Rule Breakdown ---
    print(f"\n  {'Rule Description':<55} {'Count':>5} {'Avg':>5} {'Max':>5} {'Det%':>5}")
    print(f"  {'-'*55} {'-'*5} {'-'*5} {'-'*5} {'-'*5}")

    # Group attack results by rule description
    by_rule = {}
    for r in attack_results:
        desc = r['rule_desc']
        if desc not in by_rule:
            by_rule[desc] = []
        by_rule[desc].append(r)

    for desc in sorted(by_rule, key=lambda d: -(sum(r['anomaly_score'] for r in by_rule[d]) / len(by_rule[d]))):
        entries = by_rule[desc]
        scores = [e['anomaly_score'] for e in entries]
        detected = sum(1 for e in entries if e['is_anomaly'])
        det_pct = detected * 100 // len(entries)
        avg_s = sum(scores) / len(scores)
        short_desc = desc[:55]
        print(f"  {short_desc:<55} {len(entries):>5} {avg_s:>5.0f} {max(scores):>5} {det_pct:>4}%")

    # --- Top 15 Highest-Scored Attacks ---
    print(f"\n  --- Top 15 Highest-Scored Attack Alerts ---")
    sorted_attacks = sorted(attack_results, key=lambda r: r['anomaly_score'], reverse=True)
    for i, r in enumerate(sorted_attacks[:15], 1):
        print(f"  {i:>2}. Score: {r['anomaly_score']:>3}/100 | Combined: {r['combined_score']:>3}/100 | "
              f"Lvl {r['rule_level']:>2} | {r['rule_desc']}")
        if r['full_log']:
            print(f"      {r['full_log']}")

    # --- Lowest-Scored Attacks (missed detections) ---
    print(f"\n  --- 5 Lowest-Scored Attack Alerts (potential misses) ---")
    for i, r in enumerate(sorted_attacks[-5:], 1):
        print(f"  {i}. Score: {r['anomaly_score']:>3}/100 | Lvl {r['rule_level']:>2} | {r['rule_desc']}")

    # --- Summary ---
    print(f"\n{'='*70}")
    if separation >= 30 and det_rate >= 50:
        print("  VERDICT: GOOD - Model separates attacks from clean alerts well.")
    elif separation >= 15:
        print("  VERDICT: FAIR - Model shows some separation. Needs more training data.")
    else:
        print("  VERDICT: POOR - Model cannot distinguish attacks. Check features/data.")
    print(f"{'='*70}")


def main():
    parser = argparse.ArgumentParser(description='Evaluate Isolation Forest model')
    parser.add_argument('--alerts', type=str, help='Path to alerts JSONL file')
    parser.add_argument('--model', type=str, help='Path to model .pkl file')
    args = parser.parse_args()

    script_dir = Path(__file__).parent

    # Resolve alerts file
    if args.alerts:
        alerts_file = Path(args.alerts)
    else:
        candidates = [
            script_dir / 'data' / 'training' / 'combined' / 'all_alerts.json',
            script_dir / 'data' / 'alerts.json',
        ]
        alerts_file = next((c for c in candidates if c.exists() and c.stat().st_size > 0), None)
        if not alerts_file:
            print("No alerts file found. Provide --alerts path.")
            sys.exit(1)

    # Resolve model path (mirrors train_isolation_forest.py: prefer prod, fallback to local)
    if args.model:
        model_path = args.model
    else:
        prod_path = Path("/var/ossec/ai_models/anomaly_detector.pkl")
        model_path = str(prod_path if prod_path.exists() else script_dir / 'data' / 'ai_models' / 'anomaly_detector.pkl')

    print(f"Alerts: {alerts_file}")
    print(f"Model:  {model_path}")

    # Load
    alerts = load_alerts(str(alerts_file))
    if not alerts:
        print("No alerts loaded.")
        sys.exit(1)

    detector = AnomalyDetector(model_path=model_path)

    # Evaluate
    clean_results, attack_results = evaluate(detector, alerts)
    print_report(clean_results, attack_results)


if __name__ == '__main__':
    main()
