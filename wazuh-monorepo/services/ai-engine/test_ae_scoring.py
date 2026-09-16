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

from autoencoders_approach.score_window import ScoreWindow, MIN_SAMPLES
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

print()
if _fails:
    print(f"{len(_fails)} FAILED: " + ", ".join(_fails))
    sys.exit(1)
print("All autoencoder scoring tests passed.")
