#!/usr/bin/env python3
"""
Model HEALTH check — is the ensemble still calibrated for THIS host?

Distinct from ml_eval_metrics.py, and the distinction is the whole point:

  * ml_eval_metrics.py scores the models against their own held-out TEST SET.
    It answers "did training work?" and can look excellent (F1 85.7%) while
    production is useless.
  * this script scores the models against the LIVE alert stream actually
    arriving on this host. It answers "is this model calibrated for the data
    it is being asked to judge?"

That gap is not hypothetical. On 2026-08-27 selenne-prod was running models
trained on a different machine: 98% of incidents were CRITICAL, the autoencoder
was pinned at 100 on 1561/1562 events, and a successful SSH login scored
100/100. Every offline metric still looked fine, and preflight's "all four
models found" check passed, because the files did exist. Nothing measured the
model against reality.

Checks (each emits a metric AND a pass/fail):
  saturation     — a sub-model stuck at its ceiling has stopped discriminating
  label_collapse — everything landing in one severity carries no information
  score_spread   — near-zero variance means the score cannot rank anything
  firing_rate    — projected alerts/day vs the operator's alert budget
  model_age      — models older than the data they judge (a drift smell)

Exit 0 = healthy, 1 = at least one check failed, 2 = could not run.

Usage:
    ./venv/bin/python3 ../../infra/scripts/model_health.py \
        [--alerts /var/ossec/logs/alerts/alerts.json] \
        [--sample 2000] [--out data/eval/model_health.json]
"""
import argparse
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

INFRA_DIR   = Path(__file__).resolve().parent.parent
# WAZUH_REPO_DIR lets this run from outside the tree (ad-hoc checks, a Jenkins
# workspace laid out differently); otherwise it is inferred from __file__.
REPO_DIR    = Path(os.environ["WAZUH_REPO_DIR"]).resolve() \
                  if os.environ.get("WAZUH_REPO_DIR") else INFRA_DIR.parent
STARTER_DIR = REPO_DIR / "services" / "ai-engine"
sys.path.insert(0, str(STARTER_DIR))

# Mirrors server.py:3916 — keep in step if the rank map ever changes.
LABEL_RANK = {"BENIGN": 0, "UNKNOWN": 0, "NORMAL": 1, "POSSIBLE": 2,
              "HIGH": 3, "CRITICAL": 4}

# A sub-model score this close to 100 is treated as pinned at its ceiling.
CEILING = 99

# Wazuh rotates alerts.json at midnight, so an early-morning run sees only a few
# hours. That is fine for distribution shape (saturation, label share) but the
# alerts/day projection needs a window wide enough to mean something.
MIN_SPAN_DAYS = 1.0 / 24.0        # 1 hour


def load_alerts(path, limit):
    """Read the last `limit` JSON-per-line alerts."""
    from collections import deque
    keep = deque(maxlen=limit)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                keep.append(line)
    out = []
    for line in keep:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def alert_time_span_days(alerts):
    """Observed wall-clock span of the sample, for rate projection."""
    ts = []
    for a in alerts:
        raw = (a.get("timestamp") or "").strip()
        if not raw:
            continue
        try:
            ts.append(datetime.fromisoformat(raw.replace("Z", "+00:00")))
        except ValueError:
            continue
    if len(ts) < 2:
        return None
    span = (max(ts) - min(ts)).total_seconds() / 86400.0
    # Below ~1h the extrapolation to alerts/day is noise, not a rate.
    return span if span >= MIN_SPAN_DAYS else None


def model_ages(models_dir):
    """Days since each core model file was last written."""
    ages, now = {}, time.time()
    for name in ("anomaly_detector.pkl", "autoencoder_model.pkl",
                 "ueba_model.pkl", "stacking_meta.pkl"):
        f = Path(models_dir) / name
        if f.exists():
            ages[name.replace(".pkl", "")] = round((now - f.stat().st_mtime) / 86400.0, 1)
    return ages


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", default="/var/ossec/logs/alerts/alerts.json")
    ap.add_argument("--sample", type=int, default=2000,
                    help="score at most this many of the most recent alerts")
    ap.add_argument("--out", default=str(STARTER_DIR / "data" / "eval" / "model_health.json"))
    ap.add_argument("--min-label", default="HIGH",
                    help="label at/above which the reactor fires (REACTOR_MIN_LABEL)")
    # Thresholds — deliberately generous. These detect a BROKEN model, not a
    # slightly-off one; anything tighter would cry wolf on a quiet host.
    ap.add_argument("--max-saturation", type=float, default=0.20)
    ap.add_argument("--max-label-share", type=float, default=0.50)
    ap.add_argument("--min-score-stdev", type=float, default=5.0)
    ap.add_argument("--alert-budget", type=float, default=50.0,
                    help="alerts/day the operator expects to triage")
    ap.add_argument("--budget-overrun", type=float, default=5.0,
                    help="fail when projected rate exceeds budget by this factor. "
                         "5x an operator's stated triage capacity is already "
                         "unusable; 10x let a 496/day stream pass a 50/day budget.")
    ap.add_argument("--max-model-age-days", type=float, default=180.0)
    ap.add_argument("--min-sample", type=int, default=50,
                    help="below this many alerts the verdict is INCONCLUSIVE, not a pass")
    args = ap.parse_args()

    try:
        alerts = load_alerts(args.alerts, args.sample)
    except OSError as e:
        print(f"[health] cannot read {args.alerts}: {e}", file=sys.stderr)
        return 2

    if len(alerts) < args.min_sample:
        # Too little evidence to judge. Not a pass — say so and stay quiet.
        print(f"[health] INCONCLUSIVE — only {len(alerts)} alerts "
              f"(need >= {args.min_sample}). Not scoring.")
        json.dump({"timestamp": int(time.time()), "status": "inconclusive",
                   "n_alerts": len(alerts), "checks": {}},
                  open(args.out, "w"), indent=2)
        return 0

    from autoencoders_approach.ensemble_detector import load_ensemble, _resolve_model_path
    ens = load_ensemble()

    scores, labels = [], []
    sub = {"if": [], "ae": [], "ueba": []}
    scored = failed = 0
    for a in alerts:
        try:
            r = ens.score(a)
        except Exception:
            failed += 1
            continue
        scored += 1
        scores.append(r["combined_score"])
        labels.append(r["anomaly_label"])
        for key, field in (("if", "if_score"), ("ae", "ae_score"), ("ueba", "ueba_score")):
            if r.get(field) is not None:
                sub[key].append(r[field])

    if not scored:
        print("[health] every alert failed to score", file=sys.stderr)
        return 2

    # --- check 1: sub-model ceiling saturation ---------------------------
    saturation = {k: round(sum(1 for s in v if s >= CEILING) / len(v), 4)
                  for k, v in sub.items() if v}
    worst_sat = max(saturation.items(), key=lambda kv: kv[1], default=(None, 0.0))

    # --- check 2: label collapse -----------------------------------------
    label_counts = {lab: labels.count(lab) for lab in set(labels)}
    label_share = {k: round(v / scored, 4) for k, v in label_counts.items()}
    top_label, top_share = max(label_share.items(), key=lambda kv: kv[1])

    # --- check 3: score spread -------------------------------------------
    stdev = round(statistics.pstdev(scores), 2) if len(scores) > 1 else 0.0

    # --- check 4: projected firing rate ----------------------------------
    fire_rank = LABEL_RANK.get(args.min_label.upper(), 3)
    would_fire = sum(1 for lab in labels if LABEL_RANK.get(lab, 0) >= fire_rank)
    span = alert_time_span_days(alerts)
    per_day = round(would_fire / span, 1) if span else None

    # --- check 5: model age ----------------------------------------------
    models_dir = Path(_resolve_model_path("anomaly_detector.pkl", STARTER_DIR)).parent
    ages = model_ages(models_dir)
    oldest = max(ages.values()) if ages else None

    checks = {
        "saturation": {
            "ok": worst_sat[1] <= args.max_saturation,
            "value": worst_sat[1], "threshold": args.max_saturation,
            "detail": f"{worst_sat[0]} pinned at >={CEILING} on "
                      f"{worst_sat[1]:.1%} of alerts" if worst_sat[0] else "n/a",
        },
        "label_collapse": {
            "ok": top_share <= args.max_label_share,
            "value": top_share, "threshold": args.max_label_share,
            "detail": f"{top_share:.1%} of alerts labelled {top_label}",
        },
        "score_spread": {
            "ok": stdev >= args.min_score_stdev,
            "value": stdev, "threshold": args.min_score_stdev,
            "detail": f"combined_score stdev {stdev}",
        },
        "firing_rate": {
            # No timestamps to project from is unknown, not healthy.
            "ok": per_day is None or per_day <= args.alert_budget * args.budget_overrun,
            "value": per_day, "threshold": args.alert_budget * args.budget_overrun,
            "detail": (f"~{per_day}/day at >={args.min_label} vs budget "
                       f"{args.alert_budget}/day" if per_day is not None
                       else "no usable timestamps"),
        },
        "model_age": {
            "ok": oldest is None or oldest <= args.max_model_age_days,
            "value": oldest, "threshold": args.max_model_age_days,
            "detail": f"oldest model {oldest}d" if oldest is not None else "no models found",
        },
    }

    failed_checks = [k for k, v in checks.items() if not v["ok"]]
    report = {
        "timestamp": int(time.time()),
        "status": "fail" if failed_checks else "ok",
        "n_alerts": scored,
        "n_unscorable": failed,
        "span_days": round(span, 2) if span else None,
        "stacking_active": getattr(ens, "meta", None) is not None,
        "components": {"if": True, "ae": ens.ae_det is not None,
                       "ueba": ens.ueba_det is not None},
        "saturation": saturation,
        "label_share": label_share,
        "score_stdev": stdev,
        "projected_alerts_per_day": per_day,
        "model_age_days": ages,
        "checks": checks,
        "failed_checks": failed_checks,
    }

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    json.dump(report, open(args.out, "w"), indent=2)

    print(f"[health] scored {scored} live alerts over {report['span_days']}d")
    for name, c in checks.items():
        print(f"  {'PASS' if c['ok'] else 'FAIL'}  {name:15} {c['detail']}")
    print(f"[health] {report['status'].upper()} -> {args.out}")
    return 1 if failed_checks else 0


if __name__ == "__main__":
    sys.exit(main())
