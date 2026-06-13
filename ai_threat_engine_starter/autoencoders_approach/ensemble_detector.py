"""
Ensemble anomaly detector: Isolation Forest + Autoencoder.

Combines both models into a single anomaly_label so callers don't need to
reason about two scores simultaneously.

anomaly_label values:
  CRITICAL  — both models flag the alert (highest confidence)
  HIGH      — only Autoencoder flags it  (high precision, low FP rate)
  POSSIBLE  — only Isolation Forest flags it (low-signal catch)
  NORMAL    — neither model flags it

Combined score (0-100):
  Weighted average leaning slightly toward AE (higher precision):
      combined = 0.45 * if_score + 0.55 * ae_score
  For POSSIBLE the combined score is dampened (×0.65) to reflect
  lower confidence from a single-model detection.
"""

from pathlib import Path


class EnsembleDetector:
    """Wraps AnomalyDetector (IF) + AutoencoderDetector (AE) into one scorer."""

    ANOMALY_LABELS = {"CRITICAL", "HIGH", "POSSIBLE"}

    def __init__(self, if_detector, ae_detector):
        self.if_det = if_detector
        self.ae_det = ae_detector

    def score(self, alert):
        """Score a single Wazuh alert.

        Returns dict with:
            anomaly_label   — CRITICAL / HIGH / POSSIBLE / NORMAL
            combined_score  — 0-100, weighted average
            if_score        — Isolation Forest score (0-100)
            ae_score        — Autoencoder score (0-100), None if AE unavailable
            is_anomaly      — bool (True for CRITICAL / HIGH / POSSIBLE)
        """
        if_result  = self.if_det.detect_anomaly(alert)
        if_score   = if_result['anomaly_score']
        if_anomaly = if_result['is_anomaly']

        ae_score   = None
        ae_anomaly = None

        if self.ae_det is not None:
            ae_result  = self.ae_det.detect_anomaly(alert)
            ae_score   = ae_result['anomaly_score']
            ae_anomaly = ae_result['is_anomaly']

        # ---- Label decision ----
        if ae_anomaly is None:
            # AE not available — IF only
            anomaly_label  = "CRITICAL" if if_anomaly else "NORMAL"
            combined_score = if_score
        elif if_anomaly and ae_anomaly:
            anomaly_label  = "CRITICAL"
            combined_score = int(0.45 * if_score + 0.55 * ae_score)
        elif ae_anomaly:
            anomaly_label  = "HIGH"
            combined_score = ae_score
        elif if_anomaly:
            anomaly_label  = "POSSIBLE"
            combined_score = int((0.45 * if_score + 0.55 * (ae_score or 0)) * 0.65)
        else:
            anomaly_label  = "NORMAL"
            combined_score = int(0.45 * if_score + 0.55 * (ae_score or 0))

        combined_score = max(0, min(100, combined_score))

        return {
            'anomaly_label':  anomaly_label,
            'combined_score': combined_score,
            'if_score':       if_score,
            'ae_score':       ae_score,
            'is_anomaly':     anomaly_label in self.ANOMALY_LABELS,
        }

    def score_many(self, alerts):
        """Score a list of alerts.  Returns list of (alert, ensemble_result) tuples."""
        return [(a, self.score(a)) for a in alerts]


# ------------------------------------------------------------------ #
#  Factory — used by server.py and evaluate scripts                   #
# ------------------------------------------------------------------ #

def load_ensemble(if_model_path=None, ae_model_path=None):
    """Load both detectors and return an EnsembleDetector.

    Falls back gracefully if the AE model has not been trained yet.
    """
    import sys
    starter_dir = Path(__file__).resolve().parent.parent
    if str(starter_dir) not in sys.path:
        sys.path.insert(0, str(starter_dir))

    from ai_engine.anomaly_detector import AnomalyDetector
    from autoencoders_approach.autoencoder_detector import AutoencoderDetector

    # --- Isolation Forest ---
    if if_model_path is None:
        prod  = Path("/var/ossec/ai_models/anomaly_detector.pkl")
        local = starter_dir / "data" / "ai_models" / "anomaly_detector.pkl"
        if_model_path = str(prod if prod.exists() else local)

    if_det = AnomalyDetector(model_path=if_model_path)

    # --- Autoencoder (optional) ---
    if ae_model_path is None:
        prod  = Path("/var/ossec/ai_models/autoencoder_model.pkl")
        local = starter_dir / "data" / "ai_models" / "autoencoder_model.pkl"
        ae_model_path = str(prod if prod.exists() else local)

    ae_det = AutoencoderDetector(model_path=ae_model_path)
    if ae_det.model is None:
        print("[ensemble] Autoencoder model not found — running IF-only mode")
        ae_det = None

    return EnsembleDetector(if_det, ae_det)
