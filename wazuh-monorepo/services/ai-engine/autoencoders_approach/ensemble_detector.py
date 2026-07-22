"""
Ensemble anomaly detector: Isolation Forest + Autoencoder + UEBA,
combined by a LEARNED stacking meta-model.

Each base model is trained one-class on clean data only, so each scores
"how far is this alert from normal" from a different angle:

  IF    — global feature-space outlierness (tree isolation depth)
  AE    — reconstruction error against the learned normal manifold
  UEBA  — behavioral deviation of the user / host / source IP involved

Instead of hardcoding combination weights (the old 0.45*IF + 0.55*AE), a
logistic-regression meta-model is trained on the three base scores
(train_stacking.py) and LEARNS how much to trust each model. The combined
score is the meta-model's attack probability × 100.

If the meta-model (or a base model) is missing, the ensemble degrades
gracefully to the legacy fixed-weight combination.

anomaly_label values:
  CRITICAL  — two or more base models flag the alert (highest confidence)
  HIGH      — only the Autoencoder or only UEBA flags it (high precision)
  POSSIBLE  — only Isolation Forest flags it, or only the meta-model
              pushes the combined score over the line
  NORMAL    — nothing flags the alert
"""

from pathlib import Path

import joblib

# Legacy fixed weights — used only when the stacking meta-model is missing
LEGACY_IF_WEIGHT = 0.45
LEGACY_AE_WEIGHT = 0.55


class EnsembleDetector:
    """Wraps IF + AE + UEBA behind a learned stacking meta-model."""

    ANOMALY_LABELS = {"CRITICAL", "HIGH", "POSSIBLE"}

    def __init__(self, if_detector, ae_detector, ueba_detector=None, meta_model=None,
                 meta_threshold=0.5):
        self.if_det   = if_detector
        self.ae_det   = ae_detector
        self.ueba_det = ueba_detector
        self.meta     = meta_model   # sklearn classifier over [if, ae, ueba]/100
        # Attack-probability cutoff for the meta-only POSSIBLE branch —
        # tuned by CV and stored alongside the stacker (0.5 if absent).
        self.meta_threshold = meta_threshold

    # ------------------------------------------------------------------ #
    #  Scoring                                                            #
    # ------------------------------------------------------------------ #

    def _meta_probability(self, if_score, ae_score, ueba_score):
        """Attack probability from the stacking meta-model, or None."""
        if self.meta is None or ae_score is None:
            return None
        try:
            X = [[if_score / 100.0, ae_score / 100.0, (ueba_score or 0) / 100.0]]
            return float(self.meta.predict_proba(X)[0][1])
        except Exception:
            return None

    def score(self, alert):
        """Score a single Wazuh alert.

        Returns dict with:
            anomaly_label    — CRITICAL / HIGH / POSSIBLE / NORMAL
            combined_score   — 0-100 (meta-model probability × 100 when available)
            if_score         — Isolation Forest score (0-100)
            ae_score         — Autoencoder score (0-100), None if AE unavailable
            ueba_score       — UEBA behavioral score (0-100), None if unavailable
            meta_probability — learned stacker's attack probability, None if
                               falling back to fixed weights
            is_anomaly       — bool (True for CRITICAL / HIGH / POSSIBLE)
        """
        if_result  = self.if_det.detect_anomaly(alert)
        if_score   = if_result['anomaly_score']
        if_anomaly = if_result['is_anomaly']

        ae_score = ae_anomaly = None
        if self.ae_det is not None:
            ae_result  = self.ae_det.detect_anomaly(alert)
            ae_score   = ae_result['anomaly_score']
            ae_anomaly = ae_result['is_anomaly']

        ueba_score = ueba_anomaly = None
        if self.ueba_det is not None:
            ueba_result  = self.ueba_det.detect_anomaly(alert)
            ueba_score   = ueba_result['anomaly_score']
            ueba_anomaly = ueba_result['is_anomaly']

        # ---- Combined score: learned stacking, else legacy fixed weights ----
        meta_prob = self._meta_probability(if_score, ae_score, ueba_score)
        if meta_prob is not None:
            combined_score = int(round(meta_prob * 100))
        elif ae_score is not None:
            combined_score = int(LEGACY_IF_WEIGHT * if_score + LEGACY_AE_WEIGHT * ae_score)
        else:
            combined_score = if_score

        # ---- Detection decision: the learned stacker is the gate ----
        # Base-model thresholds are percentile budgets (e.g. the AE flags ~5%
        # of clean by construction), so a lone base-model vote is a weak
        # signal. The meta-model was trained to arbitrate exactly these
        # score combinations — it decides WHETHER this is an anomaly; the
        # votes only grade HOW severe a detected anomaly is. Without a
        # meta-model we fall back to the legacy pure-vote behaviour.
        votes = sum(1 for flag in (if_anomaly, ae_anomaly, ueba_anomaly) if flag)
        if meta_prob is not None:
            if meta_prob >= self.meta_threshold:
                if votes >= 2:
                    anomaly_label = "CRITICAL"
                elif ae_anomaly or ueba_anomaly:
                    anomaly_label = "HIGH"
                else:
                    anomaly_label = "POSSIBLE"
            else:
                anomaly_label = "NORMAL"      # meta vetoes weak single-model flags
        else:
            if votes >= 2:
                anomaly_label = "CRITICAL"
            elif ae_anomaly or ueba_anomaly:
                anomaly_label = "HIGH"
            elif if_anomaly:
                anomaly_label = "POSSIBLE"
                combined_score = int(combined_score * 0.65)  # dampen lone IF
            else:
                anomaly_label = "NORMAL"

        combined_score = max(0, min(100, combined_score))

        return {
            'anomaly_label':    anomaly_label,
            'combined_score':   combined_score,
            'if_score':         if_score,
            'ae_score':         ae_score,
            'ueba_score':       ueba_score,
            'meta_probability': meta_prob,
            'is_anomaly':       anomaly_label in self.ANOMALY_LABELS,
        }

    def score_many(self, alerts):
        """Score a list of alerts.  Returns list of (alert, ensemble_result) tuples."""
        return [(a, self.score(a)) for a in alerts]


# ------------------------------------------------------------------ #
#  Factory — used by server.py and evaluate scripts                   #
# ------------------------------------------------------------------ #

def _resolve_model_path(filename, starter_dir):
    """Model lookup order:
    1. $AI_MODELS_DIR            — explicit environment override (dev/staging/prod
                                   instances point at their own model registry)
    2. /var/ossec/ai_models      — production default
    3. data/ai_models            — repo-local fallback
    """
    import os
    env_dir = os.environ.get("AI_MODELS_DIR", "").strip()
    if env_dir:
        return str(Path(env_dir) / filename)
    prod  = Path("/var/ossec/ai_models") / filename
    local = starter_dir / "data" / "ai_models" / filename
    return str(prod if prod.exists() else local)


def load_ensemble(if_model_path=None, ae_model_path=None,
                  ueba_model_path=None, meta_model_path=None):
    """Load all detectors + stacking meta-model and return an EnsembleDetector.

    Falls back gracefully for every optional component: AE and UEBA may be
    untrained, and without the meta-model the legacy fixed weights are used.
    """
    import sys
    starter_dir = Path(__file__).resolve().parent.parent
    if str(starter_dir) not in sys.path:
        sys.path.insert(0, str(starter_dir))

    from ai_engine.anomaly_detector import AnomalyDetector
    from ai_engine.ueba_detector import UEBADetector
    from autoencoders_approach.autoencoder_detector import AutoencoderDetector

    # --- Isolation Forest (required) ---
    if if_model_path is None:
        if_model_path = _resolve_model_path("anomaly_detector.pkl", starter_dir)
    if_det = AnomalyDetector(model_path=if_model_path)

    # --- Autoencoder (optional) ---
    if ae_model_path is None:
        ae_model_path = _resolve_model_path("autoencoder_model.pkl", starter_dir)
    ae_det = AutoencoderDetector(model_path=ae_model_path)
    if ae_det.model is None:
        print("[ensemble] Autoencoder model not found — running without AE")
        ae_det = None

    # --- UEBA (optional) ---
    if ueba_model_path is None:
        ueba_model_path = _resolve_model_path("ueba_model.pkl", starter_dir)
    ueba_det = UEBADetector(model_path=ueba_model_path)
    if not ueba_det.is_trained:
        print("[ensemble] UEBA baselines not found — running without UEBA")
        ueba_det = None

    # --- Stacking meta-model (optional) ---
    meta = None
    meta_threshold = 0.5
    if meta_model_path is None:
        meta_model_path = _resolve_model_path("stacking_meta.pkl", starter_dir)
    if Path(meta_model_path).exists():
        try:
            bundle = joblib.load(meta_model_path)
            meta = bundle['model']
            meta_threshold = float(bundle.get('decision_threshold', 0.5))
            print(f"[ensemble] Loaded stacking meta-model (learned weights, "
                  f"threshold {meta_threshold})")
        except Exception as e:
            print(f"[ensemble] Failed to load stacking meta-model: {e}")
    else:
        print("[ensemble] No stacking meta-model — using legacy fixed weights")

    return EnsembleDetector(if_det, ae_det, ueba_det, meta_model=meta,
                            meta_threshold=meta_threshold)
