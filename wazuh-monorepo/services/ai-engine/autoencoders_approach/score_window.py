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

import hashlib
import json
import os
import threading
import time
from collections import deque

import numpy as np

#: Smallest window that can produce a meaningful rank. Below this the caller
#: must fall back to the fitted calibration — a rank among 5 samples would
#: swing wildly and is worse than a stale but stable scale.
MIN_SAMPLES = 50

#: Events kept. Large enough that one busy hour cannot redefine "normal",
#: small enough to follow a host that genuinely changes.
DEFAULT_MAXLEN = 2000


def event_key(event):
    """Stable identity for one observation, or None when it cannot be derived.

    This separates "the same alert scored again" from "the same KIND of event
    happened again", and only the first is a duplicate. A host that emits five
    hundred identical failed logins really did emit five hundred events and the
    baseline should say so; the dashboard re-rendering one of them fifty times
    did not.

    Real Wazuh alerts carry a unique `id` ("1788682606.0"). Synthetic and
    test alerts have none, so fall back to a digest that INCLUDES the
    timestamp — content alone would collapse genuinely repeated events into
    one and quietly starve the window.
    """
    if not isinstance(event, dict):
        return None
    ident = event.get("id")
    if ident:
        return str(ident)
    rule = event.get("rule") or {}
    parts = (str(event.get("timestamp", "")),
             str(rule.get("id", "")),
             str(event.get("full_log", ""))[:512])
    if not any(parts):
        return None
    return hashlib.sha1("|".join(parts).encode("utf-8", "replace")).hexdigest()[:24]


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
        # Identities already recorded, so the same alert scored twice moves the
        # baseline once. Without this the API path is the problem: it rescores
        # up to 500 alerts per request against a 2000-slot window, so a handful
        # of dashboard refreshes replace the host's traffic profile with
        # whatever page was last rendered.
        self._seen = set()
        self._seen_order = deque()
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
            seen = [str(k) for k in data.get("seen", [])][-self.maxlen:]
            self._seen_order = deque(seen)
            self._seen = set(seen)
        except (OSError, ValueError, TypeError, AttributeError):
            # A missing or corrupt window is not an error: the detector simply
            # falls back to the fitted calibration until it refills.
            self._errors = []
            self._seen = set()
            self._seen_order = deque()

    def _save_locked(self):
        tmp = f"{self.path}.tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w") as fh:
                json.dump({"errors": self._errors,
                           "seen": list(self._seen_order),
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

    def add(self, error, key=None):
        """Record an observed error. Call AFTER rank() so nothing ranks itself.

        `key` is the observation's identity (see event_key). When it has
        already been recorded the call is a no-op, so rescoring an alert — on
        every dashboard poll, say — cannot reshape the baseline. Passing no key
        always records, which is what synthetic callers without an identity
        want.

        Returns True when the window actually changed.
        """
        try:
            value = float(error)
        except (TypeError, ValueError):
            return False
        if not np.isfinite(value):
            return False
        with self._lock:
            if key is not None:
                if key in self._seen:
                    return False
                # Keys are only ever appended when unseen, so each appears at
                # most once in the ring and eviction can discard directly.
                self._seen.add(key)
                self._seen_order.append(key)
                while len(self._seen_order) > self.maxlen:
                    self._seen.discard(self._seen_order.popleft())
            self._errors.append(value)
            if len(self._errors) > self.maxlen:
                del self._errors[:len(self._errors) - self.maxlen]
            self._unsaved += 1
            due = (self._unsaved >= self.save_every
                   or time.time() - self._last_save >= self.save_interval)
            if due:
                self._save_locked()
        return True

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
