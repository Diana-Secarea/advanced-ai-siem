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
    cd wazuh-monorepo/services/ai-engine
    ./venv/bin/python3 autoencoders_approach/train_autoencoder.py
"""
import json
import os
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

from autoencoders_approach import autoencoder_detector
from autoencoders_approach.autoencoder_detector import (
    AutoencoderDetector, apply_variance_floor)
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


#: Train on EVERY alert and let reconstruction error decide what is normal,
#: instead of asking is_attack_alert() which rows to keep.
#:
#: Why this is the better default: the label function is a hand-maintained list
#: of Wazuh rule ids and description substrings. It is wrong in two directions.
#: It misses any attack nobody has written a rule for — which is precisely the
#: class of thing an anomaly detector is FOR — and it silently reclassifies
#: whenever a Wazuh ruleset upgrade renumbers a rule or rewords a description.
#: Worse, filtering on those signals is what defined the clean set as "the rows
#: where the discriminative features are zero" and saturated the model.
#:
#: Empirical purification has neither problem IN PRINCIPLE. It asks the data
#: which rows are hard to reconstruct and drops those, so it finds anomalous
#: BEHAVIOUR rather than anomalous paperwork.
#:
#: MEASURED — DEFAULT OFF, because it only holds when contamination is genuinely
#: small. On the current corpus (20.8% labelled attacks) it fails badly:
#:
#:     label-filtered        : precision 93.6%  recall 61.9%  F1 0.745
#:     unsupervised c=0.12x3 : precision 13.0%  recall  2.2%  F1 0.038
#:
#: and the trim does the exact opposite of its job — 80.3% of labelled attacks
#: SURVIVED it while only 31.7% of the rare benign events did. The reason is
#: structural: at 20% of the corpus, attacks are not contamination, they are a
#: dense MODE. An autoencoder reconstructs whatever is dense, so the rows with
#: the worst error are the genuinely rare ones — which are the benign edge
#: cases. It also re-broke the variance we had just restored (port_count
#: 0.238 -> 0.047, external_srcip 0.161 -> 0.047).
#:
#: This is worth keeping, not deleting: on a REAL production stream, where
#: attacks are a fraction of a percent, the premise holds and this is the
#: better estimator — it needs no hand-maintained rule list and can find
#: attacks nobody wrote a rule for. The guard below is what decides.
AE_UNSUPERVISED = os.environ.get("AE_UNSUPERVISED", "0") != "0"

#: Above this labelled-attack share, empirical purification is unsound — the
#: anomalies are too dense to be trimmed as contamination. Checked at train
#: time so the failure above cannot be repeated silently.
AE_MAX_CONTAMINATION = float(os.environ.get("AE_MAX_CONTAMINATION", "0.05"))

#: Fraction dropped per purification round. Total retained is
#: (1 - contamination) ** rounds, so 0.12 over 3 rounds keeps ~68%.
AE_CONTAMINATION = float(os.environ.get("AE_CONTAMINATION", "0.12"))

#: More rounds = a tighter notion of normal. Too many and the model collapses
#: onto the single most common event shape and calls everything else an attack,
#: so this stays small.
AE_TRIM_ROUNDS = int(os.environ.get("AE_TRIM_ROUNDS", "3"))


def _purify(detector, X_all, contamination, rounds):
    """Iteratively fit and drop the worst-reconstructed rows.

    Returns (kept_index_array, per_round_log). Each round refits the scaler on
    the surviving rows, so the notion of "normal" tightens as contamination is
    removed rather than staying anchored to the polluted first fit.
    """
    keep = np.arange(len(X_all))
    log = []
    for r in range(rounds):
        Xr = X_all[keep]
        detector.scaler.fit(Xr)
        apply_variance_floor(detector.scaler)
        Xs = detector.scaler.transform(Xr)
        detector.model = _fit_robust(Xs)
        errors = np.mean((Xs - detector.model.predict(Xs)) ** 2, axis=1)
        cut = float(np.percentile(errors, 100.0 * (1.0 - contamination)))
        survivors = errors <= cut
        dropped = int((~survivors).sum())
        log.append({"round": r + 1, "before": len(keep), "dropped": dropped,
                    "cut": cut})
        print(f"  Round {r + 1}/{rounds}: {len(keep)} rows -> dropped {dropped} "
              f"(error > {cut:.4f}), {int(survivors.sum())} kept")
        keep = keep[survivors]
        if len(keep) < 50:
            print("  Stopping early — too few rows left to keep trimming")
            break
    return keep, log


def train(alerts_file, model_path, test_file=None, unsupervised=None,
          contamination=None, rounds=None):
    """Train the autoencoder on what the data says is normal.

    unsupervised=True (the default) trains on EVERY alert and lets iterative
    reconstruction-error trimming decide what normal is. unsupervised=False
    keeps the historical behaviour of starting from the label-filtered set.

    The labels are still used below to REPORT detection quality — measuring
    against them is fine, training on them is what caused the saturation.
    """
    unsupervised  = AE_UNSUPERVISED if unsupervised is None else unsupervised
    contamination = AE_CONTAMINATION if contamination is None else contamination
    rounds        = AE_TRIM_ROUNDS if rounds is None else rounds

    print(f"Loading alerts from: {alerts_file}")
    alerts = load_alerts(alerts_file)
    if len(alerts) < 10:
        print("Not enough alerts. Exiting.")
        return False

    clean_alerts  = [a for a in alerts if not is_attack_alert(a)]
    attack_alerts = [a for a in alerts if is_attack_alert(a)]
    print(f"Total alerts: {len(alerts)}")
    print(f"  Labelled clean: {len(clean_alerts)} | labelled attack: {len(attack_alerts)}")

    # Initialise detector (skip auto-load — we are about to overwrite)
    detector = AutoencoderDetector(model_path=model_path)
    detector.model = None

    # Guard: empirical purification assumes the anomalies are RARE. When they
    # are not, the autoencoder learns them as normal and the trim discards
    # rare-but-benign rows instead — measured at 20.8% attacks, 80.3% of the
    # attacks survived the trim. Refuse rather than train a model that looks
    # fine and detects nothing.
    attack_share = len(attack_alerts) / len(alerts) if alerts else 0.0
    if unsupervised and attack_share > AE_MAX_CONTAMINATION:
        print(f"  !! UNSUPERVISED MODE REFUSED: {attack_share:.1%} of this corpus is "
              f"labelled attack, above the {AE_MAX_CONTAMINATION:.0%} ceiling.")
        print("     At this density the anomalies are a mode, not contamination: the")
        print("     trim would keep the attacks and drop the rare benign events.")
        print("     Falling back to label-filtered training. Set AE_MAX_CONTAMINATION")
        print("     higher only if you have measured that the premise still holds.")
        unsupervised = False

    training_alerts = alerts if unsupervised else clean_alerts
    if unsupervised:
        print(f"  Mode: UNSUPERVISED — training on all {len(alerts)} alerts, "
              f"purifying by reconstruction error "
              f"({contamination:.0%} x {rounds} rounds)")
    else:
        print(f"  Mode: label-filtered — training on {len(clean_alerts)} clean alerts")
    if len(training_alerts) < 10:
        print("Not enough alerts to train. Exiting.")
        return False

    print("\nExtracting features...")
    all_features, kept_alerts = [], []
    for alert in training_alerts:
        try:
            all_features.append(detector.extract_features(alert)[0])
            kept_alerts.append(alert)
        except Exception as e:
            print(f"Feature error: {e}")
    if len(all_features) < 10:
        print("Not enough valid features. Exiting.")
        return False
    print(f"Extracted features from {len(all_features)} alerts")

    X_all = np.array(all_features)

    # ── Purify: fit, drop the worst-reconstructed rows, refit ──
    print(f"\nPurifying ({rounds} rounds)...")
    keep_idx, trim_log = _purify(detector, X_all, contamination, rounds)
    X_clean = X_all[keep_idx]

    # What did the trim actually throw away? With labels available this is
    # measurable, and it is the number that says whether empirical purification
    # is finding attacks or just discarding rare-but-benign events.
    kept_set = set(keep_idx.tolist())
    dropped_alerts = [a for i, a in enumerate(kept_alerts) if i not in kept_set]
    if dropped_alerts:
        dropped_attacks = sum(1 for a in dropped_alerts if is_attack_alert(a))
        purity = dropped_attacks / len(dropped_alerts)
        total_attacks = sum(1 for a in kept_alerts if is_attack_alert(a))
        caught = dropped_attacks / total_attacks if total_attacks else 0.0
        print(f"  Trim purity: {dropped_attacks}/{len(dropped_alerts)} dropped rows "
              f"were labelled attacks ({purity:.1%})")
        print(f"  Trim recall: removed {dropped_attacks}/{total_attacks} "
              f"of the labelled attacks ({caught:.1%})")
        detector.trim_purity = round(purity, 4)
        detector.trim_recall = round(caught, 4)

    # ── Final fit on the purified set ──
    print("Final fit on the purified set...")
    detector.scaler.fit(X_clean)
    apply_variance_floor(detector.scaler)
    # Recorded so load_model() can re-apply it and, just as importantly, so a
    # model trained WITHOUT a floor is never rescaled behind the network's back.
    detector.variance_floor = autoencoder_detector.UNIT_SCALE_FLOOR
    X_scaled = detector.scaler.transform(X_clean)
    detector.model = _fit_robust(X_scaled)
    detector.trained_unsupervised = bool(unsupervised)
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
            r = detector.detect_anomaly(alert, learn=False)
            attack_scores.append(r['anomaly_score'])
            if r['is_anomaly']:
                attack_detected += 1

        det_rate = attack_detected * 100 / len(attack_alerts)
        print(f"  Detected: {attack_detected}/{len(attack_alerts)} ({det_rate:.1f}%)")
        print(f"  Avg attack score: {sum(attack_scores)/len(attack_scores):.1f}/100")

        clean_fp = 0
        clean_scores = []
        for alert in clean_for_fp:
            r = detector.detect_anomaly(alert, learn=False)
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
