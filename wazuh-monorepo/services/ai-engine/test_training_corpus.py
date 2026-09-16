"""Tests for the outcome/verdict label split and the benign edge-case generator.

Runnable without pytest:
    venv/bin/python test_training_corpus.py

The bug these guard against is not a crash — it is a corpus that looks fine and
trains a model that calls everything CRITICAL. The clean training set is defined
by is_attack_alert(), so if that function treats an ordinary failed login as an
attack, the clean set has zero variance on failed_count and the autoencoder
saturates on the first real failure. Measured before the split: failed_count
sd 0.088, off_hours 0.000, unknown_user 0.000.
"""

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np

import attack_labels as L
import generate_normal_logs as G
from ai_engine.anomaly_detector import AnomalyDetector

_fails = []
BEN = frozenset()


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


def alert(rule_id, level, desc, full_log="", groups=None):
    return {"rule": {"id": str(rule_id), "level": level, "description": desc,
                     "groups": groups or ["syslog"]},
            "full_log": full_log, "message": full_log, "data": {},
            "timestamp": "2026-09-16T10:00:00.000+0000",
            "agent": {"id": "001", "name": "h", "ip": "192.168.1.10"}}


print("\n1. A single failure is an OUTCOME, not a verdict")
singles = [
    (5503, 5, "PAM: User login failed."),
    (5760, 5, "sshd: authentication failed."),
    (5710, 5, "sshd: Attempt to login using a non-existent user"),
    (5557, 5, "unix_chkpwd: Password check failed."),
    (5301, 5, "User missed the password to change UID (user id)."),
]
for rid, lvl, desc in singles:
    a = alert(rid, lvl, desc)
    check(f"{desc[:38]!r} is not an attack", L.is_attack_alert(a, BEN), False)
    check(f"   …but IS a failure outcome", L.failure_outcome(a), True)


print("\n2. A BURST is still an attack")
bursts = [
    (5503, 10, "Multiple authentication failures."),
    (5720, 10, "sshd: Multiple failed logins in a short period of time."),
    (5758, 10, "sshd: Maximum authentication attempts exceeded."),
    (5712, 10, "sshd: brute force trying to get access to the system."),
]
for rid, lvl, desc in bursts:
    truthy(f"{desc[:44]!r} is an attack", L.is_attack_alert(alert(rid, lvl, desc), BEN))

# The same rule id carries both a single miss and the burst — only the
# description separates them, so a rule-id-only split cannot work.
check("one rule id, two meanings: single 5503 is clean",
      L.is_attack_alert(alert(5503, 5, "PAM: User login failed."), BEN), False)
check("one rule id, two meanings: burst 5503 is an attack",
      L.is_attack_alert(alert(5503, 10, "Multiple authentication failures."), BEN), True)


print("\n3. Techniques stay attacks regardless of failure wording")
for rid, lvl, desc in [(31103, 7, "SQL injection attempt."),
                       (510, 7, "Host-based anomaly detection event (rootkit)."),
                       (5104, 8, "Interface entered in promiscuous(sniffing) mode."),
                       (100002, 9, "Process execution at unusual time")]:
    truthy(f"{desc[:44]!r} is an attack", L.is_attack_alert(alert(rid, lvl, desc), BEN))


print("\n4. Severity alone no longer convicts at level 8")
# Wazuh assigns level 8 to routine administration; the old `level >= 8` rule
# pushed all of it out of the clean training set.
check("routine level-8 admin event is clean",
      L.is_attack_alert(alert(5902, 8, "New user added to the system."), BEN), False)
truthy("level >= SEVERE_LEVEL still convicts",
       L.is_attack_alert(alert(99999, L.SEVERE_LEVEL, "Unrecognised severe event"), BEN))
check("SEVERE_LEVEL is above Wazuh's routine-admin level 8",
      L.SEVERE_LEVEL > 8, True)


print("\n5. Explicit overrides still win")
check("user-flagged benign id beats everything",
      L.is_attack_alert(alert(5720, 10, "sshd: Multiple failed logins."),
                        frozenset({"5720"})), False)
check("SAFE_RULE_IDS still clean",
      L.is_attack_alert(alert(31101, 8, "Web server 400 error code."), BEN), False)


print("\n6. Outcome markers are not in the attack sets")
# The regression that started all this would reappear the moment one of these
# leaks back into an ATTACK_* collection.
for kw in ("authentication_failed", "invalid_login", "non-existent"):
    check(f"{kw!r} is not an ATTACK_KEYWORD", kw in L.ATTACK_KEYWORDS, False)
    truthy(f"{kw!r} is a failure marker",
           kw in L.FAILURE_KEYWORDS or kw in L.FAILURE_GROUPS)
check("FAILURE_GROUPS and ATTACK_GROUPS are disjoint",
      bool(L.FAILURE_GROUPS & L.ATTACK_GROUPS), False)
check("FAILURE_RULE_IDS and ATTACK_RULE_IDS are disjoint",
      bool(L.FAILURE_RULE_IDS & L.ATTACK_RULE_IDS), False)


print("\n7. Generated edge cases survive into the CLEAN training set")
gen = []
for i in range(30):
    day = datetime(2026, 4, 1, tzinfo=timezone.utc).replace(day=1 + i % 28)
    gen += G.generate_edge_cases(day, 40)
truthy("generator produced alerts", len(gen) > 500)
mislabelled = [a for a in gen if L.is_attack_alert(a, BEN)]
check("none are labelled an attack", len(mislabelled), 0)


print("\n8. …and they carry the markers the old corpus never had")
det = AnomalyDetector()
X = np.vstack([det._extract_features_full(a) for a in gen])
IDX = {"failed_count": 2, "off_hours": 4, "port_count": 6,
       "external_srcip": 12, "unknown_user": 14}
for name, i in IDX.items():
    sd = float(X[:, i].std())
    ok = sd > 0.1
    print(f"  {'PASS' if ok else 'FAIL'}  {name} has real variance (sd {sd:.3f})")
    if not ok:
        _fails.append(f"{name} variance")

# The point is a MINORITY of failures, not a corpus where failure is the norm:
# a model trained on mostly-failures would stop finding them notable at all.
share = float(np.count_nonzero(X[:, IDX["failed_count"]]) / len(X))
truthy(f"failures are a minority of the edge batch ({share:.0%})", 0.05 < share < 0.6)
truthy("maintenance really lands in the 02:00-06:00 window",
       0.1 < float(np.count_nonzero(X[:, IDX["off_hours"]]) / len(X)) < 0.8)

print("\n9. Unsupervised purification is available but guarded")
import autoencoders_approach.train_autoencoder as TR

# Default OFF. Measured on this corpus (20.8% attacks): label-filtered F1
# 0.745 vs unsupervised 0.038, and 80.3% of attacks SURVIVED the trim while
# only 31.7% of rare benign events did.
check("unsupervised is not the default", TR.AE_UNSUPERVISED, False)
truthy("a contamination ceiling exists", TR.AE_MAX_CONTAMINATION > 0)
truthy("and it is low enough to mean 'rare'", TR.AE_MAX_CONTAMINATION <= 0.10)


print("\n10. _purify drops the worst-reconstructed rows, and only those")
rng = np.random.default_rng(0)
# 200 tight rows plus 20 DIFFUSE outliers — each one different, scattered over
# a wide range. Diffuseness is the part that matters, and it is easy to get
# wrong: an earlier version of this test used a tight CLUSTER of 20 outliers
# and 90% of them survived the trim, because a 4-neuron bottleneck represents
# two compact clusters as happily as one. Low contamination is necessary but
# not sufficient — the anomalies must also be varied, or the autoencoder
# simply learns them. That is the same mechanism that made unsupervised mode
# fail on the real corpus, at a different scale.
bulk = rng.normal(0, 1, size=(200, 4))
outliers = rng.uniform(-60, 60, size=(20, 4))
X = np.vstack([bulk, outliers])
is_outlier = np.array([False] * 200 + [True] * 20)


class _Stub:
    """Just the two attributes _purify touches."""
    def __init__(self):
        from sklearn.preprocessing import StandardScaler
        self.scaler = StandardScaler()
        self.model = None


keep, log = TR._purify(_Stub(), X, contamination=0.10, rounds=2)
kept = np.zeros(len(X), bool)
kept[keep] = True
check("two rounds were logged", len(log), 2)
truthy("it dropped roughly (1-c)^rounds worth", 0.7 * len(X) <= len(keep) <= 0.85 * len(X))
# The whole point: when anomalies are rare AND varied, the trim finds THEM.
# Asserted as a RATIO rather than an absolute rate — the trim drops a fixed
# fraction of rows, so what matters is that outliers are hit far harder than
# ordinary rows, not that every last one goes in two rounds.
out_rate = float((~kept & is_outlier).sum()) / is_outlier.sum()
bulk_rate = float((~kept & ~is_outlier).sum()) / (~is_outlier).sum()
ok = out_rate > 4 * bulk_rate
print(f"  {'PASS' if ok else 'FAIL'}  outliers are removed far faster than bulk "
      f"({out_rate:.0%} vs {bulk_rate:.0%}, want >4x)")
if not ok:
    _fails.append("purify targets outliers")
truthy("and the bulk is mostly kept",
       float((kept & ~is_outlier).sum()) / (~is_outlier).sum() > 0.8)

print()
if _fails:
    print(f"{len(_fails)} FAILED: " + ", ".join(_fails))
    sys.exit(1)
print("All training-corpus tests passed.")
