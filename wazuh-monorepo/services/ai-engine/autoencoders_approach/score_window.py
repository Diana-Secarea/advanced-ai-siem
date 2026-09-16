"""Rolling window of recent reconstruction errors for one host.

Why this exists
---------------
The autoencoder's 0-100 score was calibrated once, at training time, against
the 2nd/98th percentile of reconstruction error on the *clean* training set.
Clean alerts reconstruct almost perfectly, so that range spans roughly 0.5 MSE
— and every event past it clamps to 100. On the production host 97% of events
landed past it, which is how a detector ends up calling 98% of incidents
CRITICAL.

A rank against recent traffic has no such ceiling. "Worse than 99% of what this
host emitted lately" means the same thing on a noisy host and a quiet one, on
the box the model was fitted on and on a customer's, and it keeps meaning it
after the input distribution drifts. A saturated model then degrades to
"today's weirdest events" instead of "everything is critical" — wrong ordering
is survivable, a wall of CRITICAL is not.

This is the per-host half of the split in the productization plan: the content
model is portable, the sense of "normal here" is not and must be measured where
it runs.
"""

import json
import os
import threading
import time

import numpy as np

#: Smallest window that can produce a meaningful rank. Below this the caller
#: must fall back to the fitted calibration — a rank among 5 samples would
#: swing wildly and is worse than a stale but stable scale.
MIN_SAMPLES = 50

#: Events kept. Large enough that one busy hour cannot redefine "normal",
#: small enough to follow a host that genuinely changes.
DEFAULT_MAXLEN = 2000


class ScoreWindow:
    """Thread-safe, disk-backed ring of recent reconstruction errors.

    Persisted because the alternative is a detector that forgets what normal
    looks like on every restart and spends the next MIN_SAMPLES events back on
    the saturated calibration.
    """

    def __init__(self, path, maxlen=DEFAULT_MAXLEN, save_every=25,
                 save_interval=60.0):
        self.path = path
        self.maxlen = int(maxlen)
        self.save_every = int(save_every)
        self.save_interval = float(save_interval)
        self._errors = []
        self._lock = threading.Lock()
        self._unsaved = 0
        self._last_save = 0.0
        self._load()

    # ---------------------------------------------------------------- io --
    def _load(self):
        try:
            with open(self.path) as fh:
                data = json.load(fh)
            errors = [float(e) for e in data.get("errors", [])
                      if isinstance(e, (int, float))]
            self._errors = errors[-self.maxlen:]
        except (OSError, ValueError, TypeError, AttributeError):
            # A missing or corrupt window is not an error: the detector simply
            # falls back to the fitted calibration until it refills.
            self._errors = []

    def _save_locked(self):
        tmp = f"{self.path}.tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w") as fh:
                json.dump({"errors": self._errors,
                           "updated_at": time.time()}, fh)
            os.replace(tmp, self.path)          # atomic: never a half-written window
            self._unsaved = 0
            self._last_save = time.time()
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def flush(self):
        with self._lock:
            self._save_locked()

    # ------------------------------------------------------------- scoring --
    def rank(self, error):
        """Percentile of `error` within the window, 0-100, or None if too small.

        Ties count as half, so a value equal to everything already seen scores
        50 rather than 0 or 100 — on a host emitting one repeated event that is
        the honest answer.
        """
        with self._lock:
            n = len(self._errors)
            if n < MIN_SAMPLES:
                return None
            arr = np.asarray(self._errors, dtype=float)
        below = float(np.count_nonzero(arr < error))
        equal = float(np.count_nonzero(arr == error))
        return max(0.0, min(100.0, (below + 0.5 * equal) / len(arr) * 100.0))

    def add(self, error):
        """Record an observed error. Call AFTER rank() so nothing ranks itself."""
        try:
            value = float(error)
        except (TypeError, ValueError):
            return
        if not np.isfinite(value):
            return
        with self._lock:
            self._errors.append(value)
            if len(self._errors) > self.maxlen:
                del self._errors[:len(self._errors) - self.maxlen]
            self._unsaved += 1
            due = (self._unsaved >= self.save_every
                   or time.time() - self._last_save >= self.save_interval)
            if due:
                self._save_locked()

    # -------------------------------------------------------------- status --
    @property
    def ready(self):
        with self._lock:
            return len(self._errors) >= MIN_SAMPLES

    def __len__(self):
        with self._lock:
            return len(self._errors)

    def stats(self):
        """Window summary for the model-health monitor and the ml.html panel."""
        with self._lock:
            arr = np.asarray(self._errors, dtype=float)
        if arr.size == 0:
            return {"count": 0, "ready": False}
        return {
            "count": int(arr.size),
            "ready": bool(arr.size >= MIN_SAMPLES),
            "min": float(arr.min()),
            "p50": float(np.percentile(arr, 50)),
            "p95": float(np.percentile(arr, 95)),
            "max": float(arr.max()),
        }
