#!/usr/bin/env python3
"""
Temporal validation of the detection pipeline.

Random shuffled CV over log data is optimistic: alerts from one burst are
near-duplicates, and shuffling puts some of them in training and some in
validation. This script does the honest protocol instead — train on the
EARLY days, evaluate on the LATER days — using the exact production
configuration (IF feature mask, AE one-class + trim, UEBA baselines,
LogReg stacker C=10 @ threshold 0.4). Models are trained in memory; the
pkls on disk are not touched.

Usage:
    ./venv/bin/python3 temporal_validation.py [--train-frac 0.7]
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

from attack_labels import is_attack_alert as _is_attack_alert
from ai_engine.anomaly_detector import AnomalyDetector
from ai_engine.ueba_detector import UEBADetector
from autoencoders_approach.autoencoder_detector import AutoencoderDetector

META_C = 10.0
META_THRESHOLD = 0.4


def _load_benign_ids():
    f = SCRIPT_DIR.parent.parent / "apps" / "backend" / "benign_rules.json"
    try:
        if f.exists():
            return set(json.load(open(f)).keys())
    except Exception:
        pass
    return set()


BENIGN = _load_benign_ids()


def load_alerts(path):
    alerts = []
    for line in open(path):
        line = line.strip()
        if line:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return alerts


def day_of(alert):
    ts = str(alert.get("timestamp", alert.get("@timestamp", "")))
    return ts.split("T")[0] if "T" in ts else "unknown"


def prf(y_true, y_pred):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=p, recall=r, f1=f1, fpr=fpr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-frac", type=float, default=0.7,
                    help="Fraction of DAYS used for training (default 0.7)")
    ap.add_argument("--alerts", default=str(SCRIPT_DIR / "data/training/combined/all_alerts.json"))
    args = ap.parse_args()

    alerts = load_alerts(args.alerts)
    y_all = np.array([1 if _is_attack_alert(a, BENIGN) else 0 for a in alerts])

    # ---- split by day boundary ----
    days = sorted({day_of(a) for a in alerts})
    n_train_days = max(1, min(len(days) - 1, int(round(len(days) * args.train_frac))))
    train_days, eval_days = set(days[:n_train_days]), set(days[n_train_days:])

    tr_idx = [i for i, a in enumerate(alerts) if day_of(a) in train_days]
    ev_idx = [i for i, a in enumerate(alerts) if day_of(a) in eval_days]
    if not ev_idx:
        print("Not enough distinct days for a temporal split.")
        return

    print("=" * 60)
    print("TEMPORAL VALIDATION — train on early days, eval on later days")
    print("=" * 60)
    day_counts = Counter(day_of(a) for a in alerts)
    for d in days:
        attacks = sum(1 for i, a in enumerate(alerts) if day_of(a) == d and y_all[i])
        side = "TRAIN" if d in train_days else "EVAL"
        print(f"  {d}  {day_counts[d]:>5} alerts  ({attacks:>4} attacks)  [{side}]")

    tr_alerts = [alerts[i] for i in tr_idx]
    ev_alerts = [alerts[i] for i in ev_idx]
    y_tr, y_ev = y_all[tr_idx], y_all[ev_idx]
    print(f"\nTrain: {len(tr_alerts)} alerts ({y_tr.sum()} attacks) | "
          f"Eval: {len(ev_alerts)} alerts ({y_ev.sum()} attacks)")

    # ---- feature extraction (production code paths) ----
    if_fx = AnomalyDetector.__new__(AnomalyDetector)      # skip pkl auto-load
    if_fx._effective_benign_ids = set()
    if_fx.SUSPICIOUS_GROUPS = AutoencoderDetector(model_path="/nonexistent").SUSPICIOUS_GROUPS
    ae_fx = AutoencoderDetector(model_path="/nonexistent")

    Xif_tr = np.array([if_fx.extract_features(a)[0] for a in tr_alerts])
    Xif_ev = np.array([if_fx.extract_features(a)[0] for a in ev_alerts])
    Xae_tr = np.array([ae_fx.extract_features(a)[0] for a in tr_alerts])
    Xae_ev = np.array([ae_fx.extract_features(a)[0] for a in ev_alerts])

    # ---- IF: unsupervised on all train rows (production params) ----
    sc_if = StandardScaler().fit(Xif_tr)
    m_if = IsolationForest(n_estimators=200, max_samples="auto", max_features=1.0,
                           contamination="auto", random_state=42, n_jobs=-1)
    m_if.fit(sc_if.transform(Xif_tr))
    s_if_tr = -m_if.decision_function(sc_if.transform(Xif_tr))
    s_if_ev = -m_if.decision_function(sc_if.transform(Xif_ev))

    # ---- AE: one-class on clean train rows + 10% trim (production params) ----
    def fit_ae(Xc):
        sc = StandardScaler().fit(Xc)
        Xs = sc.transform(Xc)
        m = MLPRegressor(hidden_layer_sizes=(8, 4, 8), activation="relu", solver="adam",
                         learning_rate_init=0.001, alpha=0.0001, max_iter=1000,
                         random_state=42, early_stopping=True, validation_fraction=0.1,
                         n_iter_no_change=20).fit(Xs, Xs)
        return sc, m

    Xclean = Xae_tr[y_tr == 0]
    sc_ae, m_ae = fit_ae(Xclean)
    err = np.mean((sc_ae.transform(Xclean) - m_ae.predict(sc_ae.transform(Xclean))) ** 2, axis=1)
    sc_ae, m_ae = fit_ae(Xclean[err <= np.percentile(err, 90)])

    def ae_err(X):
        Xs = sc_ae.transform(X)
        return np.mean((Xs - m_ae.predict(Xs)) ** 2, axis=1)

    s_ae_tr, s_ae_ev = ae_err(Xae_tr), ae_err(Xae_ev)

    # ---- UEBA: baselines from clean train alerts ----
    ub = UEBADetector(model_path="/nonexistent")
    ub.build_baselines([a for a, yy in zip(tr_alerts, y_tr) if yy == 0])
    s_ub_tr = np.array([ub.detect_anomaly(a)["anomaly_score"] for a in tr_alerts]) / 100.0
    s_ub_ev = np.array([ub.detect_anomaly(a)["anomaly_score"] for a in ev_alerts]) / 100.0

    # ---- normalize IF/AE with TRAIN-derived calibration only ----
    def calib(train_s):
        lo, hi = np.percentile(train_s, 2), np.percentile(train_s, 98)
        return lambda s: np.clip((s - lo) / (hi - lo + 1e-12), 0, 1)

    n_if, n_ae = calib(s_if_tr), calib(s_ae_tr)
    Xm_tr = np.column_stack([n_if(s_if_tr), n_ae(s_ae_tr), s_ub_tr])
    Xm_ev = np.column_stack([n_if(s_if_ev), n_ae(s_ae_ev), s_ub_ev])

    # ---- stacker: production settings ----
    meta = LogisticRegression(C=META_C, class_weight="balanced", max_iter=1000, random_state=42)
    meta.fit(Xm_tr, y_tr)
    prob_ev = meta.predict_proba(Xm_ev)[:, 1]

    print("\n---- results on later-days eval split ----")
    for name, s in (("Isolation Forest", n_if(s_if_ev)), ("Autoencoder", n_ae(s_ae_ev)),
                    ("UEBA", s_ub_ev), ("Stacked ensemble", prob_ev)):
        try:
            auc = roc_auc_score(y_ev, s)
        except ValueError:
            auc = float("nan")
        print(f"  {name:<18} AUC {auc:.4f}")

    m = prf(y_ev, (prob_ev >= META_THRESHOLD).astype(int))
    print(f"\n  Stacked ensemble @ {META_THRESHOLD}: "
          f"P {m['precision']*100:.1f}%  R {m['recall']*100:.1f}%  F1 {m['f1']*100:.1f}%  "
          f"FPR {m['fpr']*100:.1f}%   (TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']})")

    # Oracle threshold (diagnostic only — uses eval labels, never deployable):
    # separates "the model ranks badly" from "the threshold drifted".
    best = max((prf(y_ev, (prob_ev >= t).astype(int)) | {"th": t}
                for t in np.arange(0.05, 1.0, 0.01)), key=lambda d: d["f1"])
    print(f"  Oracle threshold {best['th']:.2f} (diagnostic): "
          f"P {best['precision']*100:.1f}%  R {best['recall']*100:.1f}%  F1 {best['f1']*100:.1f}%  "
          f"FPR {best['fpr']*100:.1f}%")
    print("\nIf AUC is high but F1-at-fixed-threshold is low, the ranking survived the")
    print("time shift and only the calibration drifted → periodic threshold recalibration")
    print("(see monitor_model_health.py / retrain_all.sh), not a model rebuild.")


if __name__ == "__main__":
    main()
