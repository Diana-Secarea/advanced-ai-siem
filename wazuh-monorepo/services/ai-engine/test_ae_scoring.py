"""Tests for the autoencoder's rank scoring, rolling window and variance floor.

Runnable without pytest:
    venv/bin/python test_ae_scoring.py

Each case pins a property that the saturation post-mortem showed was missing:
the score must have no ceiling to hit, the window must not rank an event
against itself, and a model must never be rescaled behind the network's back.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "autoencoders_approach"))

import numpy as np
from sklearn.preprocessing import StandardScaler

from autoencoders_approach.score_window import (
    ScoreWindow, MIN_SAMPLES, event_key)
from autoencoders_approach.autoencoder_detector import apply_variance_floor

_fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected {want!r}, got {got!r}")
        _fails.append(label)


def truthy(label, got):
    ok = bool(got)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        _fails.append(label)


tmp = tempfile.mkdtemp()

print("\n1. The window refuses to rank until it has enough samples")
w = ScoreWindow(os.path.join(tmp, "w1.json"))
check("cold window ranks nothing", w.rank(1.0), None)
check("cold window is not ready", w.ready, False)
for i in range(MIN_SAMPLES - 1):
    w.add(float(i))
check("one short still ranks nothing", w.rank(1.0), None)
w.add(float(MIN_SAMPLES))
truthy("ready at MIN_SAMPLES", w.ready)
truthy("and now ranks", w.rank(1.0) is not None)


print("\n2. Rank is a percentile with no ceiling to saturate")
w2 = ScoreWindow(os.path.join(tmp, "w2.json"))
for i in range(100):
    w2.add(float(i))
check("below everything -> 0", w2.rank(-1.0), 0.0)
check("above everything -> 100", w2.rank(1e9), 100.0)
check("median -> ~50", round(w2.rank(49.5)), 50)
# The saturation that started all this: a huge error cannot exceed 100, but
# neither can it drag every ordinary event up with it.
w2.add(1e9)
truthy("an extreme outlier does not make ordinary events anomalous",
       w2.rank(10.0) < 20)


print("\n3. Ties score as half, not as 0 or 100")
w3 = ScoreWindow(os.path.join(tmp, "w3.json"))
for _ in range(MIN_SAMPLES + 10):
    w3.add(5.0)
check("a host emitting one repeated event scores it mid-scale",
      round(w3.rank(5.0)), 50)


print("\n4. The window survives a restart")
path = os.path.join(tmp, "w4.json")
w4 = ScoreWindow(path)
for i in range(MIN_SAMPLES + 5):
    w4.add(float(i))
w4.flush()
reloaded = ScoreWindow(path)
check("reloaded with the same sample count", len(reloaded), len(w4))
truthy("and can rank immediately", reloaded.rank(1.0) is not None)

corrupt = os.path.join(tmp, "w5.json")
with open(corrupt, "w") as fh:
    fh.write("{not json")
w5 = ScoreWindow(corrupt)
check("a corrupt window degrades to empty, not a crash", len(w5), 0)


print("\n5. The window is bounded")
w6 = ScoreWindow(os.path.join(tmp, "w6.json"), maxlen=100)
for i in range(500):
    w6.add(float(i))
check("never grows past maxlen", len(w6), 100)
truthy("and holds the most RECENT samples", w6.rank(450.0) < 100)

w7 = ScoreWindow(os.path.join(tmp, "w7.json"))
before = len(w7)
w7.add(float("nan")); w7.add(float("inf")); w7.add("not a number")
check("non-finite and non-numeric input is ignored", len(w7), before)


print("\n6. The variance floor clamps only degenerate scales")
sc = StandardScaler().fit(np.array([
    [0.0, 100.0], [0.0, 900.0], [0.0, 500.0], [1.0, 300.0]]))
narrow_before = float(sc.scale_[0])
wide_before = float(sc.scale_[1])
apply_variance_floor(sc, floor=1.0)
truthy("a near-zero scale is raised", sc.scale_[0] >= 1.0)
truthy("it really was degenerate before", narrow_before < 1.0)
check("a wide scale is untouched", float(sc.scale_[1]), wide_before)
check("var_ stays consistent with scale_",
      [round(v, 6) for v in sc.var_],
      [round(float(x) ** 2, 6) for x in sc.scale_])

again = [float(x) for x in sc.scale_]
apply_variance_floor(sc, floor=1.0)
check("idempotent", [float(x) for x in sc.scale_], again)

sc2 = StandardScaler().fit(np.array([[0.0], [1.0], [2.0], [3.0]]))
untouched = [float(x) for x in sc2.scale_]
apply_variance_floor(sc2, floor=0)
check("floor=0 is a no-op", [float(x) for x in sc2.scale_], untouched)

print("\n7. Rescoring the same alert moves the baseline exactly once")
# The live bug this closes: the scored-alerts endpoint rescores up to 500
# alerts per request against a 2000-slot window, so a few dashboard refreshes
# replaced the host's traffic profile with whatever page was last rendered.
w8 = ScoreWindow(os.path.join(tmp, "w8.json"))
check("first add is recorded", w8.add(1.0, key="alert-1"), True)
check("the same identity is refused", w8.add(1.0, key="alert-1"), False)
for _ in range(500):
    w8.add(1.0, key="alert-1")
check("hammering it 500 more times changes nothing", len(w8), 1)
truthy("a different identity is recorded", w8.add(2.0, key="alert-2"))
check("window grew by exactly one", len(w8), 2)
check("an unkeyed add always records", w8.add(3.0), True)
check("…and again", w8.add(3.0), True)
check("so unkeyed callers are unaffected", len(w8), 4)

print("\n8. Dedupe survives a restart, and is bounded")
w8.flush()
again = ScoreWindow(os.path.join(tmp, "w8.json"))
check("a known identity is still refused after reload",
      again.add(1.0, key="alert-1"), False)
# The seen-ring is capped with the window, or it would grow without bound on a
# busy host and become the memory leak the window was designed to avoid.
w9 = ScoreWindow(os.path.join(tmp, "w9.json"), maxlen=50)
for i in range(500):
    w9.add(float(i), key=f"k{i}")
check("window stays at maxlen", len(w9), 50)
truthy("the id ring is bounded too", len(w9._seen) <= 50)
truthy("an identity evicted long ago may be recorded again",
       w9.add(1.0, key="k0"))


print("\n9. Identity separates a rescore from a genuinely repeated event")
def ev(**kw):
    base = {"timestamp": "2026-09-16T10:00:00.000+0000",
            "rule": {"id": "5503"}, "full_log": "PAM: login failed"}
    base.update(kw)
    return base

check("a real Wazuh id is used verbatim", event_key(ev(id="1788682606.0")), "1788682606.0")
check("the same alert twice yields the same key",
      event_key(ev()), event_key(ev()))
# Two identical events at DIFFERENT times are two events, not one. Hashing
# content alone would collapse them and starve the window on a host that
# repeats itself — which is most hosts.
truthy("the same event at a later time is a DIFFERENT observation",
       event_key(ev()) != event_key(ev(timestamp="2026-09-16T10:00:01.000+0000")))
truthy("different rules are different observations",
       event_key(ev()) != event_key(ev(rule={"id": "5710"})))
check("an unusable event has no identity", event_key({}), None)
check("a non-dict has no identity", event_key("nope"), None)

print()
if _fails:
    print(f"{len(_fails)} FAILED: " + ", ".join(_fails))
    sys.exit(1)
print("All autoencoder scoring tests passed.")
