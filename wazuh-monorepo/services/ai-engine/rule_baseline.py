"""What this host normally emits, measured rather than declared.

The problem this replaces
-------------------------
`FAILURE_RULE_IDS` was a hand-written list asserting that certain Wazuh rule
ids describe "an ordinary failure". That assertion is not a property of the
rule — it is a property of the HOST. Rule 5710 ("attempt to login using a
non-existent user") is a typo on a laptop behind NAT and a port-scan on a box
with a public IP. Measured on selenne-prod 2026-09-25: 142 in one day, 27% of
all traffic. A list cannot know that; only counting can.

A hand-maintained id table is also the single most drift-prone thing in the
pipeline. It is silently wrong the moment a Wazuh ruleset upgrade renumbers a
rule or rewords a description, and nothing fails loudly when it happens.

So: no list. Count what arrives, per rule, per day, and let "ambient" mean
what it actually means — this host emits a lot of these, routinely, over time.

Ambient is NOT benign
---------------------
This is the distinction the alert path never had. A scan is hostile whether or
not it is frequent; being frequent only changes how loudly to say so. Ambient
therefore suppresses *noise*, never *classification* — and ambient events are
still kept out of the clean training baseline, because "we see this daily" is
not the same as "this is what healthy looks like".
"""

import json
import os
import threading
import time
from collections import deque

#: A rule must clear this many events per day, averaged over the days it has
#: been seen, before frequency alone is allowed to quieten it.
AMBIENT_MIN_PER_DAY = float(os.environ.get("AMBIENT_MIN_PER_DAY", "20"))

#: …and must have been seen on at least this many distinct days. One noisy
#: afternoon is an incident, not a baseline; without this a single burst would
#: teach the host that the burst is normal.
AMBIENT_MIN_DAYS = int(os.environ.get("AMBIENT_MIN_DAYS", "3"))

#: A rule running this many times above its own established rate is a campaign
#: rather than the usual background, and escalates even while ambient.
SPIKE_MULTIPLIER = float(os.environ.get("AMBIENT_SPIKE_MULTIPLIER", "5"))

#: Days of per-rule history kept. Long enough to survive a quiet weekend,
#: short enough to follow a host whose workload genuinely changes.
HISTORY_DAYS = int(os.environ.get("AMBIENT_HISTORY_DAYS", "30"))

#: How long a failure from one source stays "recent" for the
#: failure-then-success escalation, in seconds.
SOURCE_MEMORY_SECONDS = float(os.environ.get("AMBIENT_SOURCE_MEMORY", "3600"))

#: Sources tracked for that escalation. Bounded so a spray across thousands of
#: addresses cannot grow this without limit.
MAX_SOURCES = 4096


class RuleBaseline:
    """Per-rule daily counts for one host, persisted between restarts."""

    def __init__(self, path=None):
        self.path = path
        self._days = {}          # rule_id -> {day: count}
        self._fails = {}         # srcip -> [ts, ...] recent failures
        self._order = deque()    # srcip insertion order, for bounded eviction
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
            days = data.get("days") or {}
            self._days = {str(r): {str(d): int(c) for d, c in v.items()}
                          for r, v in days.items() if isinstance(v, dict)}
        except (OSError, ValueError, TypeError, AttributeError):
            self._days = {}      # a missing or corrupt baseline just starts cold

    def save(self):
        if not self.path:
            return
        tmp = f"{self.path}.tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with self._lock:
                payload = {"days": self._days, "updated_at": time.time()}
            with open(tmp, "w") as fh:
                json.dump(payload, fh)
            os.replace(tmp, self.path)
            self._dirty = 0
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # -------------------------------------------------------- counting --
    def observe(self, rule_id, day, srcip=None, is_failure=False, now=None):
        """Record one event. `day` is a YYYY-MM-DD string."""
        rule_id = str(rule_id or "")
        if not rule_id:
            return
        with self._lock:
            buckets = self._days.setdefault(rule_id, {})
            buckets[day] = buckets.get(day, 0) + 1
            if len(buckets) > HISTORY_DAYS:
                for stale in sorted(buckets)[:-HISTORY_DAYS]:
                    buckets.pop(stale, None)
            if srcip and is_failure:
                ts = now if now is not None else time.time()
                seen = self._fails.get(srcip)
                if seen is None:
                    seen = self._fails[srcip] = []
                    self._order.append(srcip)
                    while len(self._order) > MAX_SOURCES:
                        self._fails.pop(self._order.popleft(), None)
                seen.append(ts)
                cutoff = ts - SOURCE_MEMORY_SECONDS
                self._fails[srcip] = [t for t in seen if t >= cutoff]
        self._dirty += 1
        if self._dirty >= 200:
            self.save()

    # --------------------------------------------------------- queries --
    def stats(self, rule_id):
        with self._lock:
            buckets = dict(self._days.get(str(rule_id), {}))
        if not buckets:
            return 0, 0, 0.0
        total = sum(buckets.values())
        days = len(buckets)
        return total, days, total / days

    def is_ambient(self, rule_id):
        """True when this host emits enough of this rule, often enough, that
        an individual one carries no information on its own."""
        _, days, per_day = self.stats(rule_id)
        return days >= AMBIENT_MIN_DAYS and per_day >= AMBIENT_MIN_PER_DAY

    def is_spiking(self, rule_id, today):
        """True when today already exceeds the established rate by
        SPIKE_MULTIPLIER — ambient volume behaving unlike itself."""
        with self._lock:
            buckets = dict(self._days.get(str(rule_id), {}))
        today_n = buckets.pop(str(today), 0)
        if not buckets:
            return False
        baseline = sum(buckets.values()) / len(buckets)
        return baseline > 0 and today_n > baseline * SPIKE_MULTIPLIER

    def recent_failures(self, srcip):
        """How many failures this source produced inside the memory window."""
        if not srcip:
            return 0
        now = time.time()
        with self._lock:
            seen = self._fails.get(srcip) or []
            fresh = [t for t in seen if t >= now - SOURCE_MEMORY_SECONDS]
            self._fails[srcip] = fresh
        return len(fresh)

    def summary(self, limit=10):
        """Per-rule view for the UI and the model-health monitor."""
        out = []
        with self._lock:
            rules = list(self._days)
        for r in rules:
            total, days, per_day = self.stats(r)
            out.append({"rule_id": r, "total": total, "days": days,
                        "per_day": round(per_day, 2),
                        "ambient": self.is_ambient(r)})
        out.sort(key=lambda d: -d["per_day"])
        return out[:limit]
