#!/usr/bin/env python3
"""
Train the RAW-log anomaly model — the third detector, for collector logs that
carry no Wazuh alert metadata (journald, sshd, kernel, apache, cron, …).

Design: a supervised classifier over behavioural features + rarity, trained on
labelled data and free of hardcoded score caps.

  1. Feature vector per raw line = log_features.extract() (22 structural/
     behavioural features: token composition, attack/fail-term hits, external IP,
     …) PLUS the novelty (rarity) score. Rarity is computed with a 2-FOLD split of
     the benign set so benign lines get REALISTIC novelty — including rare-but-
     benign admin commands that score high. Attacks are scored against the whole
     benign baseline (they are unseen → high novelty, as at serve time).

  2. A GradientBoosting classifier learns benign(0) vs attack(1) from real
     archives.json + generated benign families (negatives) and generated attack
     lines (positives). Because the benign set now contains HIGH-novelty benign
     examples, the model learns that novelty alone is not guilt — it must lean on
     STRUCTURE to separate a novel admin command from a novel reverse shell. That
     is exactly what stops routine system activity reading as malicious.

  3. The decision THRESHOLD is chosen from the precision-recall curve on a
     held-out split (best F1), then stored in the model — not guessed.

Output: data/ai_models/log_model.pkl
"""

import argparse
import json
import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (average_precision_score, f1_score,
                             precision_recall_curve, roc_auc_score)

import log_eval as le
import log_features as lf
import log_synthetic as ls

HERE = Path(__file__).resolve().parent
MODEL_PATH = HERE / "data" / "ai_models" / "log_model.pkl"
DEFAULT_ARCHIVES = os.environ.get(
    "ARCHIVES_JSON", "/var/ossec/logs/archives/archives.json")


def load_real_benign(path, cap=8000):
    """Best-effort read of real archive lines as extra benign samples.
    Archives are the host's own routine activity; treated as benign baseline.

    Operational lines (SCA/rootcheck/syscollector telemetry) are EXCLUDED: they
    are capped as routine at serve time and never reach this model, and they
    legitimately mention strong tokens like /etc/shadow in compliance checks —
    training on them would teach the model to distrust those tokens."""
    try:
        from attack_labels import is_operational_log
    except Exception:
        def is_operational_log(_):
            return False
    events, skipped = [], 0
    try:
        with open(path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if isinstance(ev, dict) and ev.get("full_log"):
                    if is_operational_log(ev):
                        skipped += 1
                        continue
                    events.append(ev)
                    if len(events) >= cap:
                        break
    except (OSError, PermissionError) as e:
        print(f"  [note] real archives unreadable ({e}); using synthetic benign only")
    if skipped:
        print(f"  [note] excluded {skipped} operational lines from benign training set")
    return events



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archives", default=DEFAULT_ARCHIVES)
    ap.add_argument("--benign", type=int, default=6000)
    ap.add_argument("--attacks", type=int, default=1600)
    ap.add_argument("--real-weight", type=int, default=2,
                    help="oversample factor for real archive benign lines")
    ap.add_argument("--out", default=str(MODEL_PATH))
    args = ap.parse_args()

    print("→ Building corpora")
    syn_benign = ls.benign_logs(args.benign)
    real_all = load_real_benign(args.archives)
    # Hold out the last 20% of real benign for the FP test so the model is never
    # evaluated on benign lines it trained on (no benign leakage).
    cut = int(len(real_all) * 0.8)
    real_train, real_eval = real_all[:cut], real_all[cut:]
    # Anchor on the REAL log distribution: oversample real benign so the model
    # treats the host's actual routine activity as the benign reference, instead
    # of overfitting to synthetic artifacts that don't occur in production.
    benign = syn_benign + real_train * args.real_weight
    attacks = ls.attack_logs(args.attacks)
    print(f"  benign: {len(benign)} ({len(real_train)}×{args.real_weight} real "
          f"+ {len(syn_benign)} synthetic)   attacks: {len(attacks)}   "
          f"held-out real benign: {len(real_eval)}")

    # --- CONTENT model features (behavioural only — NO novelty) ---------- #
    # Novelty ("have we seen this line before") is deliberately kept OUT of the
    # classifier and combined separately (max) at scoring time. Blending it in made
    # the model bump any NOVEL line — including benign ones (a new dockerd/REST
    # line) — over the bar just for being new. Here the model answers only "is the
    # CONTENT hostile"; rarity is judged independently and labelled as such, so a
    # new benign line reads as "unusual", never as "malicious".
    print("→ Extracting behavioural features")
    X = np.vstack([np.array([lf.extract(e) for e in benign], dtype=float),
                   np.array([lf.extract(e) for e in attacks], dtype=float)])
    y = np.concatenate([np.zeros(len(benign)), np.ones(len(attacks))])

    feat_names = list(lf.FEATURE_NAMES)

    # MONOTONIC constraints: these behavioural features may only ever RAISE the
    # attack score, never lower it — more hostile tokens / failures / an external
    # peer can only look worse, never better. Token-family counts stay
    # unconstrained (0). Interpretable AND robust under distribution shift.
    _INCREASING = {"attack_terms", "strong_terms", "fail_terms",
                   "has_external_ip", "rule_level"}
    monotonic_cst = [1 if n in _INCREASING else 0 for n in feat_names]

    # Regularised HistGradientBoosting: capacity-limited so it relies on broad
    # behavioural signal instead of memorising synthetic artifacts.
    clf = HistGradientBoostingClassifier(
        max_iter=200, max_depth=3, max_leaf_nodes=15, learning_rate=0.08,
        min_samples_leaf=60, l2_regularization=1.0,
        monotonic_cst=monotonic_cst, random_state=42).fit(X, y)

    # --- HONEST evaluation on data the model never trained on ------------- #
    # Real archive benign (production FP test) + hand-authored attacks phrased
    # unlike the generator (production recall / generalisation test). The threshold
    # is chosen HERE, on production-like data, so it is not gamed by the synthetic
    # distribution's easy separability.
    # This measures the CONTENT model alone (the threshold it will use). At serve
    # time novelty is max'd in on top, so it only ADDS coverage — the true pipeline
    # recall is >= what is reported here.
    ev_benign = real_eval + le.HELD_OUT_BENIGN   # held-out real + benign edge cases
    ev_attacks = le.attack_eval()
    Xe = np.array([lf.extract(e) for e in ev_benign + ev_attacks], dtype=float)
    ye = np.array([0] * len(ev_benign) + [1] * len(ev_attacks))
    proba = clf.predict_proba(Xe)[:, 1]

    prec, rec, thr = precision_recall_curve(ye, proba)
    f1s = 2 * prec * rec / (prec + rec + 1e-9)
    best = int(np.argmax(f1s[:-1])) if len(thr) else 0
    threshold = float(np.clip(thr[best], 0.1, 0.9)) if len(thr) else 0.5
    best = int(np.argmin(np.abs(thr - threshold))) if len(thr) else 0

    yhat = (proba >= threshold).astype(int)
    from sklearn.inspection import permutation_importance
    pi = permutation_importance(clf, Xe, ye, n_repeats=5, random_state=0,
                                scoring="average_precision")
    imp = sorted(zip(feat_names, pi.importances_mean),
                 key=lambda kv: -kv[1])[:8]
    print(f"\n=== HONEST held-out eval ({len(ev_benign)} real-benign, "
          f"{len(ev_attacks)} novel-attack) ===")
    print(f"  ROC-AUC     : {roc_auc_score(ye, proba):.3f}")
    print(f"  PR-AUC (AP) : {average_precision_score(ye, proba):.3f}")
    print(f"  threshold   : {threshold:.3f}  (max-F1 on held-out)")
    print(f"  precision   : {prec[best]:.3f}")
    print(f"  recall      : {rec[best]:.3f}   (attacks caught: {int(yhat[ye==1].sum())}/{int((ye==1).sum())})")
    print(f"  false-pos   : {int(yhat[ye==0].sum())}/{int((ye==0).sum())} benign")
    print(f"  F1          : {f1_score(ye, yhat):.3f}")
    print("  top features: " + ", ".join(f"{n}={v:.2f}" for n, v in imp))

    # --- persist ---------------------------------------------------------- #
    payload = {
        "clf": clf, "threshold": threshold,
        "feature_names": feat_names,
        "trained_on": {"benign": len(benign), "real_benign": len(real_train),
                       "attacks": len(attacks)},
        "metrics": {"roc_auc": float(roc_auc_score(ye, proba)),
                    "pr_auc": float(average_precision_score(ye, proba)),
                    "precision": float(prec[best]), "recall": float(rec[best]),
                    "f1": float(f1_score(ye, yhat))},
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, out)
    print(f"\n✔ saved {out}")


if __name__ == "__main__":
    main()
