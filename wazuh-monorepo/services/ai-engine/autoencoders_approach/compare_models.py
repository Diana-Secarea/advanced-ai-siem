#!/usr/bin/env python3
"""
Side-by-side comparison: Isolation Forest vs Autoencoder.

Both models are scored on the same alert set and evaluated against identical
ground truth labels.  The output includes:

  1. Console report — metrics table, per-rule detection breakdown, agreement analysis
  2. Score distribution histograms   → comparison_score_distributions.png
  3. ROC curves (both on one chart)  → comparison_roc_curves.png
  4. IF score vs AE score scatter    → comparison_scatter.png
  5. Per-rule detection heatmap      → comparison_rule_heatmap.png
  6. Ensemble confusion matrix       → ensemble_confusion_matrix.png

Usage:
    cd wazuh-monorepo/services/ai-engine
    ./venv/bin/python3 autoencoders_approach/compare_models.py
    ./venv/bin/python3 autoencoders_approach/compare_models.py --plot
"""
import json
import sys
import argparse
from pathlib import Path

import numpy as np

SCRIPT_DIR  = Path(__file__).parent
STARTER_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(STARTER_DIR))

from ai_engine.anomaly_detector       import AnomalyDetector
from autoencoders_approach.autoencoder_detector import AutoencoderDetector
from attack_labels import is_attack_alert as _is_attack_alert


def _load_user_benign_ids():
    rules_file = STARTER_DIR.parent.parent / "apps" / "backend" / "benign_rules.json"
    try:
        if rules_file.exists():
            with open(rules_file) as f:
                return set(json.load(f).keys())
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


def score_all(if_detector, ae_detector, alerts):
    """Score every alert with both models.  Returns list of result dicts."""
    results = []
    for alert in alerts:
        label = is_attack_alert(alert)
        rule  = alert.get('rule', {})
        if_r  = if_detector.detect_anomaly(alert)
        ae_r  = ae_detector.detect_anomaly(alert)
        results.append({
            'is_attack':   label,
            'rule_desc':   rule.get('description', 'unknown'),
            'rule_id':     str(rule.get('id', '')),
            'rule_level':  rule.get('level', 0),
            'if_score':    if_r['anomaly_score'],
            'ae_score':    ae_r['anomaly_score'],
            'if_anomaly':  if_r['is_anomaly'],
            'ae_anomaly':  ae_r['is_anomaly'],
        })
    return results


def metrics(results, score_key, anomaly_key):
    """Compute TP/FP/FN/TN and derived metrics."""
    tp = sum(1 for r in results if r['is_attack']  and r[anomaly_key])
    fn = sum(1 for r in results if r['is_attack']  and not r[anomaly_key])
    fp = sum(1 for r in results if not r['is_attack'] and r[anomaly_key])
    tn = sum(1 for r in results if not r['is_attack'] and not r[anomaly_key])

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fp_rate   = fp / (fp + tn) if (fp + tn) > 0 else 0

    attack_scores = [r[score_key] for r in results if r['is_attack']]
    clean_scores  = [r[score_key] for r in results if not r['is_attack']]
    separation = (sum(attack_scores) / len(attack_scores)) - (sum(clean_scores) / len(clean_scores)) \
        if attack_scores and clean_scores else 0

    return {
        'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn,
        'precision': precision, 'recall': recall, 'f1': f1,
        'fp_rate': fp_rate,
        'detection_rate': recall,
        'separation': separation,
        'avg_attack': sum(attack_scores) / len(attack_scores) if attack_scores else 0,
        'avg_clean':  sum(clean_scores)  / len(clean_scores)  if clean_scores  else 0,
    }


def ensemble_anomaly_key(r):
    """Derive ensemble verdict from per-alert IF + AE flags."""
    if r['if_anomaly'] and r['ae_anomaly']:
        return True, "CRITICAL"
    elif r['ae_anomaly']:
        return True, "HIGH"
    elif r['if_anomaly']:
        return True, "POSSIBLE"
    return False, "NORMAL"


def metrics_ensemble(results):
    tp = sum(1 for r in results if r['is_attack']     and ensemble_anomaly_key(r)[0])
    fn = sum(1 for r in results if r['is_attack']     and not ensemble_anomaly_key(r)[0])
    fp = sum(1 for r in results if not r['is_attack'] and ensemble_anomaly_key(r)[0])
    tn = sum(1 for r in results if not r['is_attack'] and not ensemble_anomaly_key(r)[0])

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fp_rate   = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn,
        'precision': precision, 'recall': recall, 'f1': f1,
        'fp_rate': fp_rate, 'detection_rate': recall,
    }


def print_comparison(results):
    attacks = [r for r in results if r['is_attack']]
    cleans  = [r for r in results if not r['is_attack']]

    if_m  = metrics(results, 'if_score', 'if_anomaly')
    ae_m  = metrics(results, 'ae_score', 'ae_anomaly')
    ens_m = metrics_ensemble(results)

    print()
    print("=" * 78)
    print("  MODEL COMPARISON: ISOLATION FOREST vs AUTOENCODER vs ENSEMBLE")
    print("=" * 78)
    print(f"\n  Dataset: {len(attacks)} attacks, {len(cleans)} clean "
          f"({len(results)} total)\n")

    hdr = f"  {'Metric':<32} {'Isolation Forest':>17} {'Autoencoder':>13} {'Ensemble':>10}"
    print(hdr)
    print(f"  {'-'*32} {'-'*17} {'-'*13} {'-'*10}")

    rows = [
        ("Detection Rate (Recall)",
         f"{if_m['detection_rate']:.1%}", f"{ae_m['detection_rate']:.1%}", f"{ens_m['detection_rate']:.1%}"),
        ("False Positive Rate",
         f"{if_m['fp_rate']:.1%}", f"{ae_m['fp_rate']:.1%}", f"{ens_m['fp_rate']:.1%}"),
        ("Precision",
         f"{if_m['precision']:.1%}", f"{ae_m['precision']:.1%}", f"{ens_m['precision']:.1%}"),
        ("F1-Score",
         f"{if_m['f1']:.1%}", f"{ae_m['f1']:.1%}", f"{ens_m['f1']:.1%}"),
        ("TP", str(if_m['tp']), str(ae_m['tp']), str(ens_m['tp'])),
        ("FP", str(if_m['fp']), str(ae_m['fp']), str(ens_m['fp'])),
        ("FN", str(if_m['fn']), str(ae_m['fn']), str(ens_m['fn'])),
        ("TN", str(if_m['tn']), str(ae_m['tn']), str(ens_m['tn'])),
    ]
    for label, iv, av, ev in rows:
        print(f"  {label:<32} {iv:>17} {av:>13} {ev:>10}")

    # Winner summary
    all_f1s  = {'IF': if_m['f1'], 'AE': ae_m['f1'], 'Ensemble': ens_m['f1']}
    best_f1  = max(all_f1s, key=all_f1s.get)
    all_fps  = {'IF': if_m['fp_rate'], 'AE': ae_m['fp_rate'], 'Ensemble': ens_m['fp_rate']}
    best_fp  = min(all_fps, key=all_fps.get)
    all_rec  = {'IF': if_m['detection_rate'], 'AE': ae_m['detection_rate'], 'Ensemble': ens_m['detection_rate']}
    best_rec = max(all_rec, key=all_rec.get)

    print()
    print("  --- Summary ---")
    print(f"  Best F1-Score:       {best_f1}  ({all_f1s[best_f1]:.1%})")
    print(f"  Fewest False Pos:    {best_fp}  ({all_fps[best_fp]:.1%})")
    print(f"  Highest Recall:      {best_rec}  ({all_rec[best_rec]:.1%})")

    # Ensemble tier breakdown for attacks
    tiers = {'CRITICAL': 0, 'HIGH': 0, 'POSSIBLE': 0, 'NORMAL': 0}
    for r in attacks:
        _, tier = ensemble_anomaly_key(r)
        tiers[tier] += 1
    print(f"\n  --- Ensemble Tier Breakdown ({len(attacks)} attacks) ---")
    print(f"  CRITICAL  (both agree):   {tiers['CRITICAL']:>4}  ({tiers['CRITICAL']*100//len(attacks)}%)  ← highest confidence")
    print(f"  HIGH      (only AE):      {tiers['HIGH']:>4}  ({tiers['HIGH']*100//len(attacks)}%)  ← precise catch")
    print(f"  POSSIBLE  (only IF):      {tiers['POSSIBLE']:>4}  ({tiers['POSSIBLE']*100//len(attacks)}%)  ← low-signal catch")
    print(f"  NORMAL    (missed):       {tiers['NORMAL']:>4}  ({tiers['NORMAL']*100//len(attacks)}%)")

    # Agreement analysis
    both_detect   = sum(1 for r in attacks if r['if_anomaly']  and r['ae_anomaly'])
    only_if       = sum(1 for r in attacks if r['if_anomaly']  and not r['ae_anomaly'])
    only_ae       = sum(1 for r in attacks if not r['if_anomaly'] and r['ae_anomaly'])
    neither       = sum(1 for r in attacks if not r['if_anomaly'] and not r['ae_anomaly'])
    false_both    = sum(1 for r in cleans  if r['if_anomaly']  and r['ae_anomaly'])
    false_if_only = sum(1 for r in cleans  if r['if_anomaly']  and not r['ae_anomaly'])
    false_ae_only = sum(1 for r in cleans  if not r['if_anomaly'] and r['ae_anomaly'])

    print(f"\n  --- Agreement Analysis (on {len(attacks)} attacks) ---")
    print(f"  Both detect:     {both_detect:>4} ({both_detect*100//len(attacks)}%)")
    print(f"  Only IF detects: {only_if:>4} ({only_if*100//len(attacks)}%)")
    print(f"  Only AE detects: {only_ae:>4} ({only_ae*100//len(attacks)}%)")
    print(f"  Neither detects: {neither:>4} ({neither*100//len(attacks)}%)")
    print(f"\n  --- False Positive Agreement (on {len(cleans)} clean) ---")
    print(f"  Both flag as FP:   {false_both}")
    print(f"  Only IF flags FP:  {false_if_only}")
    print(f"  Only AE flags FP:  {false_ae_only}")

    # Per-rule breakdown
    by_rule = {}
    for r in attacks:
        by_rule.setdefault(r['rule_desc'], []).append(r)

    print(f"\n  --- Per-Rule Detection: IF% vs AE% ---")
    print(f"  {'Rule Description':<52} {'Count':>5} {'IF%':>5} {'AE%':>5} {'Δ':>5}")
    print(f"  {'-'*52} {'-'*5} {'-'*5} {'-'*5} {'-'*5}")
    for desc in sorted(by_rule, key=lambda d: len(by_rule[d]), reverse=True):
        entries  = by_rule[desc]
        if_det   = sum(1 for e in entries if e['if_anomaly'])
        ae_det   = sum(1 for e in entries if e['ae_anomaly'])
        if_pct   = if_det * 100 // len(entries)
        ae_pct   = ae_det * 100 // len(entries)
        delta    = ae_pct - if_pct
        arrow    = "▲" if delta > 0 else ("▼" if delta < 0 else "=")
        print(f"  {desc[:52]:<52} {len(entries):>5} {if_pct:>4}% {ae_pct:>4}% {arrow}{abs(delta):>3}%")

    print(f"\n{'='*78}")
    names = {'IF': 'Isolation Forest', 'AE': 'Autoencoder', 'Ensemble': 'Ensemble (IF+AE)'}
    print(f"  OVERALL WINNER (by F1-Score): {names[best_f1]}  ({all_f1s[best_f1]:.1%})")
    top_two = sorted(all_f1s.values(), reverse=True)
    if top_two[0] - top_two[1] < 0.02:
        print("  (Top two differ by < 2% — performance is comparable on this dataset)")
    print(f"{'='*78}")


# ------------------------------------------------------------------ #
#  Visualisations                                                      #
# ------------------------------------------------------------------ #

def plot_all(results, output_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve, auc

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    attacks = [r for r in results if r['is_attack']]
    cleans  = [r for r in results if not r['is_attack']]

    dark_bg  = "#1a1a2e"
    card_bg  = "#16213e"
    text_col = "#e2e8f0"
    grid_col = "#334155"
    if_col   = "#3b82f6"   # blue for IF
    ae_col   = "#f97316"   # orange for AE
    atk_col  = "#ef4444"   # red for attacks
    cln_col  = "#22c55e"   # green for clean

    # ---- 1. Score distributions ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.patch.set_facecolor(dark_bg)
    titles = ["Isolation Forest", "Autoencoder"]
    score_keys = ['if_score', 'ae_score']
    cols = [if_col, ae_col]

    for ax, title, sk, col in zip(axes, titles, score_keys, cols):
        ax.set_facecolor(card_bg)
        ax.hist([r[sk] for r in cleans],  bins=30, alpha=0.6, color=cln_col, label='Clean',  density=True)
        ax.hist([r[sk] for r in attacks], bins=30, alpha=0.6, color=atk_col, label='Attack', density=True)
        ax.set_title(title, fontsize=13, fontweight='bold', color=text_col)
        ax.set_xlabel("Anomaly Score (0-100)", color=text_col)
        ax.set_ylabel("Density", color=text_col)
        ax.legend(facecolor=card_bg, edgecolor=grid_col, labelcolor=text_col)
        ax.tick_params(colors=text_col)
        for spine in ax.spines.values():
            spine.set_color(grid_col)

    fig.suptitle("Score Distributions: Clean vs Attack", fontsize=14,
                 fontweight='bold', color=text_col, y=1.02)
    plt.tight_layout()
    p = out / "comparison_score_distributions.png"
    fig.savefig(p, dpi=150, bbox_inches='tight', facecolor=dark_bg)
    plt.close()
    print(f"  Saved {p}")

    # ---- 2. ROC curves ----
    labels = np.array([1 if r['is_attack'] else 0 for r in results])
    if_scores = np.array([r['if_score'] for r in results])
    ae_scores = np.array([r['ae_score'] for r in results])

    if_fpr, if_tpr, _ = roc_curve(labels, if_scores)
    ae_fpr, ae_tpr, _ = roc_curve(labels, ae_scores)
    if_auc = auc(if_fpr, if_tpr)
    ae_auc = auc(ae_fpr, ae_tpr)

    fig, ax = plt.subplots(figsize=(7, 6))
    fig.patch.set_facecolor(dark_bg)
    ax.set_facecolor(card_bg)
    ax.plot(if_fpr, if_tpr, color=if_col, lw=2, label=f"Isolation Forest (AUC={if_auc:.3f})")
    ax.plot(ae_fpr, ae_tpr, color=ae_col, lw=2, label=f"Autoencoder     (AUC={ae_auc:.3f})")
    ax.plot([0, 1], [0, 1], color=grid_col, linestyle='--', lw=1, label="Random baseline")
    ax.set_xlabel("False Positive Rate", color=text_col)
    ax.set_ylabel("True Positive Rate",  color=text_col)
    ax.set_title("ROC Curves: IF vs Autoencoder", fontsize=13,
                 fontweight='bold', color=text_col)
    ax.legend(facecolor=card_bg, edgecolor=grid_col, labelcolor=text_col)
    ax.tick_params(colors=text_col)
    for spine in ax.spines.values():
        spine.set_color(grid_col)
    plt.tight_layout()
    p = out / "comparison_roc_curves.png"
    fig.savefig(p, dpi=150, facecolor=dark_bg)
    plt.close()
    print(f"  Saved {p}")

    # ---- 3. IF score vs AE score scatter ----
    fig, ax = plt.subplots(figsize=(7, 6))
    fig.patch.set_facecolor(dark_bg)
    ax.set_facecolor(card_bg)

    c_x = [r['if_score'] for r in cleans]
    c_y = [r['ae_score'] for r in cleans]
    a_x = [r['if_score'] for r in attacks]
    a_y = [r['ae_score'] for r in attacks]

    ax.scatter(c_x, c_y, alpha=0.3, s=12, color=cln_col, label='Clean')
    ax.scatter(a_x, a_y, alpha=0.5, s=16, color=atk_col, label='Attack')

    # Threshold lines
    if_thr = sum(r['if_score'] >= 50 for r in cleans)  # crude visual guide
    ax.axvline(x=50, color=if_col, linestyle='--', lw=1, label='IF threshold (~50)')
    ax.axhline(y=50, color=ae_col, linestyle='--', lw=1, label='AE threshold (~50)')

    ax.set_xlabel("Isolation Forest Score", color=text_col)
    ax.set_ylabel("Autoencoder Score",      color=text_col)
    ax.set_title("IF Score vs AE Score\n(colored by actual label)",
                 fontsize=12, fontweight='bold', color=text_col)
    ax.legend(facecolor=card_bg, edgecolor=grid_col, labelcolor=text_col, markerscale=2)
    ax.tick_params(colors=text_col)
    for spine in ax.spines.values():
        spine.set_color(grid_col)
    plt.tight_layout()
    p = out / "comparison_scatter.png"
    fig.savefig(p, dpi=150, facecolor=dark_bg)
    plt.close()
    print(f"  Saved {p}")

    # ---- 4. Per-rule detection heatmap ----
    by_rule = {}
    for r in [x for x in results if x['is_attack']]:
        by_rule.setdefault(r['rule_desc'], []).append(r)

    rule_names = sorted(by_rule, key=lambda d: len(by_rule[d]), reverse=True)[:20]
    if_pcts = []
    ae_pcts = []
    counts  = []
    for desc in rule_names:
        entries = by_rule[desc]
        counts.append(len(entries))
        if_pcts.append(sum(1 for e in entries if e['if_anomaly']) * 100 / len(entries))
        ae_pcts.append(sum(1 for e in entries if e['ae_anomaly']) * 100 / len(entries))

    short_names = [n[:40] for n in rule_names]
    y = np.arange(len(short_names))
    height = 0.35

    fig, ax = plt.subplots(figsize=(10, max(6, len(short_names) * 0.45)))
    fig.patch.set_facecolor(dark_bg)
    ax.set_facecolor(card_bg)

    bars_if = ax.barh(y + height/2, if_pcts, height=height, color=if_col, alpha=0.8, label='Isolation Forest')
    bars_ae = ax.barh(y - height/2, ae_pcts, height=height, color=ae_col, alpha=0.8, label='Autoencoder')

    for bar, cnt in zip(bars_if, counts):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                f'n={cnt}', va='center', fontsize=7, color=text_col)

    ax.set_yticks(y)
    ax.set_yticklabels(short_names, fontsize=8, color=text_col)
    ax.set_xlabel("Detection Rate (%)", color=text_col)
    ax.set_title("Per-Rule Detection Rate: IF vs Autoencoder\n(Top 20 attack rule types)",
                 fontsize=12, fontweight='bold', color=text_col)
    ax.set_xlim(0, 115)
    ax.legend(facecolor=card_bg, edgecolor=grid_col, labelcolor=text_col)
    ax.tick_params(colors=text_col)
    for spine in ax.spines.values():
        spine.set_color(grid_col)
    plt.tight_layout()
    p = out / "comparison_rule_heatmap.png"
    fig.savefig(p, dpi=150, bbox_inches='tight', facecolor=dark_bg)
    plt.close()
    print(f"  Saved {p}")

    # ---- 5. Ensemble confusion matrix ----
    ens_m = metrics_ensemble(results)
    tp, fn, fp, tn = ens_m['tp'], ens_m['fn'], ens_m['fp'], ens_m['tn']
    precision = ens_m['precision']
    recall    = ens_m['recall']
    f1        = ens_m['f1']

    labels_cm = np.array([[f"TP\n{tp}", f"FN\n{fn}"], [f"FP\n{fp}", f"TN\n{tn}"]])
    colors_cm = np.array([["#22c55e", "#ef4444"], ["#ef4444", "#22c55e"]])

    fig, ax = plt.subplots(figsize=(7, 6))
    fig.patch.set_facecolor(dark_bg)
    ax.set_facecolor(card_bg)

    for i in range(2):
        for j in range(2):
            ax.add_patch(plt.Rectangle((j, 1 - i), 1, 1,
                         facecolor=colors_cm[i][j], alpha=0.3,
                         edgecolor=grid_col, linewidth=2))
            ax.text(j + 0.5, 1.5 - i, labels_cm[i][j],
                    ha="center", va="center", fontsize=18,
                    fontweight="bold", color=text_col)

    ax.set_xlim(0, 2)
    ax.set_ylim(0, 2)
    ax.set_xticks([0.5, 1.5])
    ax.set_xticklabels(["Flagged\nAnomaly", "Flagged\nNormal"], fontsize=11, color=text_col)
    ax.set_yticks([0.5, 1.5])
    ax.set_yticklabels(["Clean", "Attack"], fontsize=11, color=text_col)
    ax.set_xlabel("Predicted", fontsize=12, color=text_col, labelpad=10)
    ax.set_ylabel("Actual",    fontsize=12, color=text_col, labelpad=10)
    ax.set_title(
        f"Ensemble (IF+AE) Confusion Matrix\n"
        f"Precision: {precision:.1%}   Recall: {recall:.1%}   F1: {f1:.1%}",
        fontsize=12, fontweight="bold", color=text_col, pad=15,
    )
    for spine in ax.spines.values():
        spine.set_color(grid_col)
    ax.tick_params(colors=text_col)

    plt.tight_layout()
    p = out / "ensemble_confusion_matrix.png"
    fig.savefig(p, dpi=150, facecolor=dark_bg)
    plt.close()
    print(f"  Saved {p}")


# ------------------------------------------------------------------ #
#  Main                                                               #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(description="Compare Isolation Forest vs Autoencoder")
    parser.add_argument('--alerts',   help='Path to alerts JSONL file')
    parser.add_argument('--if-model', help='Path to Isolation Forest .pkl file')
    parser.add_argument('--ae-model', help='Path to Autoencoder .pkl file')
    parser.add_argument('--plot',     action='store_true', help='Generate comparison charts')
    args = parser.parse_args()

    # Resolve alerts
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

    # Resolve IF model
    if args.if_model:
        if_model_path = args.if_model
    else:
        prod  = Path("/var/ossec/ai_models/anomaly_detector.pkl")
        local = STARTER_DIR / 'data' / 'ai_models' / 'anomaly_detector.pkl'
        if_model_path = str(prod if prod.exists() else local)

    # Resolve AE model
    if args.ae_model:
        ae_model_path = args.ae_model
    else:
        prod  = Path("/var/ossec/ai_models/autoencoder_model.pkl")
        local = STARTER_DIR / 'data' / 'ai_models' / 'autoencoder_model.pkl'
        ae_model_path = str(prod if prod.exists() else local)

    print(f"Alerts:    {alerts_file}")
    print(f"IF model:  {if_model_path}")
    print(f"AE model:  {ae_model_path}")

    alerts = load_alerts(str(alerts_file))
    if not alerts:
        print("No alerts loaded.")
        sys.exit(1)

    # Load both detectors
    if_det = AnomalyDetector(model_path=if_model_path)
    ae_det = AutoencoderDetector(model_path=ae_model_path)

    if ae_det.model is None:
        print("\nAutoencoder model not loaded. Train first:")
        print("  ./venv/bin/python3 autoencoders_approach/train_autoencoder.py")
        sys.exit(1)

    print(f"\nScoring {len(alerts)} alerts with both models...")
    results = score_all(if_det, ae_det, alerts)
    print_comparison(results)

    if args.plot:
        output_dir = STARTER_DIR / 'data' / 'eval_reports'
        print(f"\nGenerating charts → {output_dir}/")
        plot_all(results, output_dir)


if __name__ == '__main__':
    main()
