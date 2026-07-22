"""
Runtime scorer for the trained raw-log CONTENT model (train_log_model.py).

Loads data/ai_models/log_model.pkl once and returns, per raw event, a 0-100
"is this line's content hostile?" score from the monotonic HistGradientBoosting
model over behavioural features (log_features.extract). Novelty ("have we seen
this template before?") is deliberately NOT an input here — the caller combines it
separately by max, so an unseen-but-benign line is judged new, not malicious.

Gracefully degrades: if the model file is missing the caller falls back to pure
novelty, so the pipeline still runs before the first training.
"""

import threading
from pathlib import Path

import joblib
import numpy as np

import log_features as lf

_MODEL_PATH = Path(__file__).resolve().parent / "data" / "ai_models" / "log_model.pkl"
_lock = threading.Lock()
_cache = {"mtime": None, "model": None}


def load_model(path=_MODEL_PATH):
    """Return the cached model dict, reloading if the file changed. None if absent."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    with _lock:
        if _cache["model"] is None or _cache["mtime"] != mtime:
            try:
                _cache["model"] = joblib.load(path)
                _cache["mtime"] = mtime
            except Exception:
                return None
        return _cache["model"]


class RawLogScorer:
    """Thin wrapper the stream scorer holds for a batch."""

    def __init__(self, model):
        self.model = model

    @property
    def ok(self):
        return self.model is not None and "clf" in self.model

    def score(self, ev):
        """Return (content_score 0-100, raw_probability 0-100) for one raw event.

        The model reads BEHAVIOURAL features only — 'is the content hostile' — with
        no novelty input; rarity is combined separately by the caller. Returns
        (0, None) if the model is unavailable so the caller falls back to novelty."""
        if not self.ok:
            return 0.0, None
        feats = lf.extract(ev)
        prob = float(self.model["clf"].predict_proba([feats])[0, 1])
        # Rescale so the learned threshold maps to a readable 60/100 boundary:
        # below threshold compresses into 0-60, above expands into 60-100, keeping
        # the UI's severity bands aligned with the model's own decision point.
        thr = self.model["threshold"]
        if prob <= thr:
            score = 60.0 * (prob / thr) if thr > 0 else 0.0
        else:
            score = 60.0 + 40.0 * (prob - thr) / (1 - thr + 1e-9)
        return round(float(np.clip(score, 0, 100)), 1), round(prob * 100, 1)


def get_scorer():
    return RawLogScorer(load_model())
