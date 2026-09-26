"""Install-time observation mode: learn a host before judging it.

Why this exists
---------------
Every detection failure this project has chased traces to one mistake —
deciding what "normal" looks like somewhere other than where the model runs.

  * models fitted on a WSL laptop, deployed to a Hetzner box: 98% of
    production incidents came back CRITICAL
  * a clean training set defined by a hand-written rule list: the features
    that discriminate collapsed to zero variance and the autoencoder saturated
  * a synthetic corpus tuned to fix a real miss: held-out AUC 1.000 while the
    boundary where real traffic sits moved at random (see log_synthetic.py)

A customer's host is not the dev box and is not the last customer's host. The
only source of truth about what is ordinary there is the host itself, and the
only way to get it is to watch for a while before drawing conclusions.

The lifecycle
-------------
    COLLECTING  ──(enough days AND enough events)──>  READY  ──(operator)──>  ARMED
         │                                                                      │
         └───────────────────── reset / re-baseline ────────────────────────────┘

  COLLECTING  score everything, fire nothing. The host is being learned.
  READY       enough evidence to fit. Waiting on a human, deliberately — the
              transition from "silent" to "can page you" is not automatic.
  ARMED       normal operation.

Suppression is at the ALERT layer only. Scoring, collection and baseline
updates all continue throughout, because the point is to accumulate exactly
the data a fitted model will need.

Fails closed in the useful direction: an unknown or unreadable state means
COLLECTING, so a broken install stays quiet rather than paging someone with
verdicts from a model that has never seen their traffic.
"""

import json
import os
import threading
import time

#: Minimum days of observation before a host can be armed. Wazuh's own
#: documentation recommends a week for the same reason: a workload has a shape
#: across a week (weekday vs weekend, nightly jobs, the Monday backlog) that
#: three days cannot show.
MIN_DAYS = float(os.environ.get("OBSERVATION_MIN_DAYS", "7"))

#: …and enough events that the distribution means something. A host that
#: emitted 40 events in a week has not been observed, it has been idle.
MIN_EVENTS = int(os.environ.get("OBSERVATION_MIN_EVENTS", "500"))

COLLECTING = "collecting"
READY = "ready"
ARMED = "armed"


class ObservationMode:
    """Per-owner observation state, persisted as one small JSON file."""

    def __init__(self, path=None, min_days=None, min_events=None):
        self.path = path
        self.min_days = MIN_DAYS if min_days is None else float(min_days)
        self.min_events = MIN_EVENTS if min_events is None else int(min_events)
        self._state = {}
        self._lock = threading.Lock()
        self._dirty = 0
        self._load()

    # ------------------------------------------------------------- io --
    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path) as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._state = {str(k): v for k, v in data.get("owners", {}).items()
                               if isinstance(v, dict)}
        except (OSError, ValueError, TypeError, AttributeError):
            self._state = {}       # unreadable state == everyone is collecting

    def save(self):
        if not self.path:
            return
        tmp = f"{self.path}.tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with self._lock:
                payload = {"owners": self._state, "updated_at": time.time()}
            with open(tmp, "w") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(tmp, self.path)
            self._dirty = 0
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # ---------------------------------------------------------- record --
    def _entry(self, owner):
        return self._state.setdefault(str(owner), {
            "state": COLLECTING,
            "started_at": time.time(),
            "events": 0,
            "days": [],
        })

    def observe(self, owner, day, n=1, now=None):
        """Record `n` observed events for `owner` on `day` (YYYY-MM-DD)."""
        if not owner:
            return
        with self._lock:
            e = self._entry(owner)
            e["events"] = int(e.get("events", 0)) + int(n)
            days = e.setdefault("days", [])
            if day and day not in days:
                days.append(day)
            # Promote to READY as soon as the evidence is there, but never
            # past it — arming stays a human decision.
            if e["state"] == COLLECTING and self._sufficient(e, now):
                e["state"] = READY
        self._dirty += n
        if self._dirty >= 500:
            self.save()

    def _sufficient(self, entry, now=None):
        now = time.time() if now is None else now
        elapsed_days = (now - float(entry.get("started_at", now))) / 86400.0
        return (len(entry.get("days", [])) >= self.min_days
                and elapsed_days >= self.min_days
                and int(entry.get("events", 0)) >= self.min_events)

    # ----------------------------------------------------------- query --
    def state(self, owner):
        with self._lock:
            e = self._state.get(str(owner))
            return e.get("state", COLLECTING) if e else COLLECTING

    def should_alert(self, owner):
        """False while a host is still being learned.

        This is the whole behavioural contract. Everything else here exists to
        decide this one boolean honestly.
        """
        return self.state(owner) == ARMED

    def progress(self, owner, now=None):
        """What the UI shows: how far through observation this host is."""
        now = time.time() if now is None else now
        with self._lock:
            e = self._state.get(str(owner))
            if not e:
                return {"state": COLLECTING, "days_seen": 0, "days_needed": self.min_days,
                        "events": 0, "events_needed": self.min_events,
                        "percent": 0, "ready": False}
            days_seen = len(e.get("days", []))
            events = int(e.get("events", 0))
            elapsed = (now - float(e.get("started_at", now))) / 86400.0
            state = e.get("state", COLLECTING)
        by_days = min(1.0, min(days_seen, elapsed) / self.min_days) if self.min_days else 1.0
        by_events = min(1.0, events / self.min_events) if self.min_events else 1.0
        return {
            "state": state,
            "days_seen": days_seen,
            "days_needed": self.min_days,
            "events": events,
            "events_needed": self.min_events,
            # The slower axis governs — a busy host still waits out the week,
            # and a quiet one still waits for enough events.
            "percent": int(100 * min(by_days, by_events)),
            "ready": state in (READY, ARMED),
        }

    # --------------------------------------------------------- control --
    def arm(self, owner):
        """Operator action. Refuses while the evidence is not there yet."""
        with self._lock:
            e = self._entry(owner)
            if e["state"] == COLLECTING and not self._sufficient(e):
                return False, "still collecting — not enough observed yet"
            e["state"] = ARMED
        self.save()
        return True, None

    def reset(self, owner, now=None):
        """Start observation again. For a host that changed shape enough that
        its old baseline is a lie — a migration, a new workload, a re-image."""
        with self._lock:
            self._state[str(owner)] = {
                "state": COLLECTING,
                "started_at": time.time() if now is None else now,
                "events": 0,
                "days": [],
            }
        self.save()
        return True, None

    def all_owners(self):
        with self._lock:
            return sorted(self._state)
