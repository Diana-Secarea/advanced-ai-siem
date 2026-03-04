#!/usr/bin/env python3
"""
Monitor Isolation Forest performance and show statistics.
Run this daily/weekly to check model health.
"""
import json
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))

from ai_engine.anomaly_detector import AnomalyDetector


def analyze_model_performance(alerts_file, model_path):
    """Analyze how the model is scoring alerts"""
    
    # Load model
    detector = AnomalyDetector(model_path)
    
    # Load recent alerts (last 100-500)
    alerts = []
    try:
        with open(alerts_file, 'r') as f:
            lines = f.readlines()
            # Take last 500 alerts
            for line in lines[-500:]:
                try:
                    alert = json.loads(line.strip())
                    alerts.append(alert)
                except:
                    continue
    except FileNotFoundError:
        print(f"File not found: {alerts_file}")
        return
    
    if len(alerts) == 0:
        print("No alerts found to analyze")
        return
    
    print("=" * 60)
    print(f"Isolation Forest Performance Report")
    print("=" * 60)
    print(f"\nAnalyzing {len(alerts)} recent alerts...\n")
    
    # Score all alerts
    scores = []
    score_distribution = defaultdict(int)
    anomaly_count = 0
    high_score_alerts = []
    
    for alert in alerts:
        result = detector.detect_anomaly(alert)
        score = result['anomaly_score']
        is_anomaly = result['is_anomaly']
        
        scores.append(score)
        if is_anomaly:
            anomaly_count += 1
        
        # Distribution buckets
        bucket = (score // 10) * 10
        score_distribution[bucket] += 1
        
        # Track high-score alerts
        if score >= 70:
            msg = str(alert.get('message', alert.get('full_log', '')))[:80]
            rule = alert.get('rule', {})
            high_score_alerts.append({
                'score': score,
                'rule_id': rule.get('id', 'N/A'),
                'rule_desc': rule.get('description', 'N/A'),
                'message': msg
            })
    
    # Statistics
    import numpy as np
    avg_score = np.mean(scores)
    median_score = np.median(scores)
    max_score = np.max(scores)
    min_score = np.min(scores)
    
    print("--- Score Statistics ---")
    print(f"  Average score:    {avg_score:.1f}/100")
    print(f"  Median score:     {median_score:.1f}/100")
    print(f"  Min score:        {min_score}/100")
    print(f"  Max score:        {max_score}/100")
    print(f"  Anomalies:        {anomaly_count} ({anomaly_count/len(alerts)*100:.1f}%)")
    
    print("\n--- Score Distribution ---")
    for bucket in sorted(score_distribution.keys()):
        bar = "█" * (score_distribution[bucket] // 5 or 1)
        print(f"  {bucket:3d}-{bucket+9:3d}: {score_distribution[bucket]:4d} alerts {bar}")
    
    print("\n--- High-Score Alerts (>= 70) ---")
    if high_score_alerts:
        # Sort by score descending
        high_score_alerts.sort(key=lambda x: x['score'], reverse=True)
        for i, alert in enumerate(high_score_alerts[:10], 1):
            print(f"\n  {i}. Score: {alert['score']}/100")
            print(f"     Rule: {alert['rule_id']} - {alert['rule_desc']}")
            print(f"     Message: {alert['message']}")
    else:
        print("  None (all alerts scored < 70)")
    
    print("\n--- Model Health Assessment ---")
    
    # Check for issues
    issues = []
    recommendations = []
    
    if avg_score > 60:
        issues.append("⚠️  Average score is high (60+) - model may be too sensitive")
        recommendations.append("→ Retrain with more data or increase contamination parameter")
    
    if avg_score < 20:
        issues.append("⚠️  Average score is low (<20) - model may miss threats")
        recommendations.append("→ Check if you're collecting diverse enough data")
    
    if anomaly_count / len(alerts) > 0.25:
        issues.append(f"⚠️  {anomaly_count/len(alerts)*100:.1f}% marked as anomalies (expected ~10%)")
        recommendations.append("→ Too many false positives - retrain with larger baseline")
    
    if anomaly_count / len(alerts) < 0.05:
        issues.append(f"⚠️  Only {anomaly_count/len(alerts)*100:.1f}% anomalies (expected ~10%)")
        recommendations.append("→ Model may be too conservative - check contamination parameter")
    
    if len(high_score_alerts) == 0:
        issues.append("ℹ️  No high-score alerts in recent data")
        recommendations.append("→ Good if your system is secure, or model needs tuning")
    
    if issues:
        print("\n  Issues detected:")
        for issue in issues:
            print(f"    {issue}")
        print("\n  Recommendations:")
        for rec in recommendations:
            print(f"    {rec}")
    else:
        print("  ✅ Model looks healthy!")
        print(f"  - Average score in normal range (20-50)")
        print(f"  - Anomaly rate ~10% (as expected)")
        print(f"  - {len(high_score_alerts)} high-priority alerts detected")
    
    print("\n" + "=" * 60)
    print("Next steps:")
    print("  - Review high-score alerts above")
    print("  - If too many false positives: retrain with more data")
    print("  - If missing threats: lower threshold or retrain")
    print("  - Retrain monthly: python3 train_isolation_forest.py")
    print("=" * 60)


if __name__ == "__main__":
    ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
    MODEL_PATH = "/var/ossec/ai_models/anomaly_detector.pkl"
    
    # Or use local paths
    if not Path(ALERTS_FILE).exists():
        ALERTS_FILE = "data/alerts.json"
        MODEL_PATH = "data/ai_models/anomaly_detector.pkl"
    
    analyze_model_performance(ALERTS_FILE, MODEL_PATH)
