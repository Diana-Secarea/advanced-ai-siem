"""The third verdict: hostile, but ordinary on this host.

    venv/bin/python test_ambient_hostile.py

Stance under test:

    Ambient hostile traffic is suppressed by frequency but never reclassified
    as benign; it escalates on success, on targeting a real account, or on
    volume above this host's own baseline.

Measured on selenne-prod 2026-09-25: rule 5710 ("attempt to login using a
non-existent user") fired 142 times in one day, 27% of all traffic. It is
hostile and it is also the weather. Neither of the two labels we had could say
both, and picking either one broke something.
"""

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import attack_labels as L
from rule_baseline import RuleBaseline, AMBIENT_MIN_DAYS

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


def scan(srcip="203.0.113.9", desc="sshd: Attempt to login using a non-existent user",
         rule_id="5710", level=5, groups=None, **data):
    d = {"srcip": srcip}
    d.update(data)
    # groups matter: 'invalid_login' is in FAILURE_GROUPS, so leaving it on an
    # event meant to be table-invisible would make the tables fire and hide
    # whatever the second judge was supposed to be tested for.
    return {"timestamp": "2026-09-25T10:00:00.000+0000",
            "rule": {"id": rule_id, "level": level, "description": desc,
                     "groups": groups if groups is not None
                               else ["syslog", "sshd", "invalid_login"]},
            "agent": {"id": "001", "name": "selenne-prod"},
            "full_log": f"sshd[1]: {desc}", "data": d}


def seeded(days=AMBIENT_MIN_DAYS, per_day=40, rule_id="5710"):
    b = RuleBaseline()
    for i in range(days):
        for _ in range(per_day):
            b.observe(rule_id, f"2026-09-{10 + i:02d}")
    return b


print("\n1. Nothing is hardcoded — ambient is measured")
truthy("FAILURE_RULE_IDS no longer exists", not hasattr(L, "FAILURE_RULE_IDS"))
cold = RuleBaseline()
check("an unmeasured rule is never ambient", cold.is_ambient("5710"), False)
check("…so with no baseline it is a plain attack",
      L.classify(scan(), baseline=None)[0], L.ATTACK)
truthy("a measured, frequent rule IS ambient", seeded().is_ambient("5710"))


print("\n2. One noisy day is an incident, not a baseline")
burst = RuleBaseline()
for _ in range(5000):
    burst.observe("5710", "2026-09-25")
check("5000 events in a single day is not ambient", burst.is_ambient("5710"), False)
check("so it still reads as an attack",
      L.classify(scan(), baseline=burst, today="2026-09-25")[0], L.ATTACK)


print("\n3. Frequent hostile traffic is suppressed, never called benign")
b = seeded()
verdict, reasons = L.classify(scan(), baseline=b, today="2026-09-25")
check("verdict is ambient_hostile", verdict, L.AMBIENT_HOSTILE)
truthy("and it explains itself", reasons)
truthy("ambient is NOT benign", verdict != L.BENIGN)
truthy("ambient is NOT routine", verdict != L.ROUTINE)


print("\n4. …but it stays IN the training baseline")
# This is the crux. Filtering every failure out of training is what gave
# failed_count sd 0.088 and saturated the autoencoder at 100.
check("ambient hostile is NOT excluded from training",
      L.excluded_from_clean_training(scan(), baseline=b, today="2026-09-25"), False)
real_attack = scan(desc="sshd: brute force trying to get access to the system.",
                   rule_id="5712", level=10)
check("a real attack IS excluded",
      L.excluded_from_clean_training(real_attack, baseline=b, today="2026-09-25"), True)


print("\n5. Escalation: it worked")
b2 = seeded()
now = time.time()
for _ in range(4):
    b2.observe("5710", "2026-09-25", srcip="198.51.100.7", is_failure=True, now=now)
success = scan(srcip="198.51.100.7", desc="sshd: authentication success.",
               rule_id="5715", level=3)
# The success rule is itself ambient here, so only the escalation can lift it.
for i in range(AMBIENT_MIN_DAYS):
    for _ in range(40):
        b2.observe("5715", f"2026-09-{10 + i:02d}")
verdict, reasons = L.classify(success, baseline=b2, today="2026-09-25")
check("a success after repeated failures escalates", verdict, L.ATTACK)
truthy("and names the reason", any("success after" in r for r in reasons))
check("the same success from a clean source does not",
      L.classify(scan(srcip="203.0.113.250", desc="sshd: authentication success.",
                      rule_id="5715", level=3),
                 baseline=b2, today="2026-09-25")[0], L.AMBIENT_HOSTILE)


print("\n6. Escalation: it is aimed, not sprayed")
verdict, reasons = L.classify(scan(srcuser="alexandru"), baseline=b,
                              known_users={"admin", "alexandru"}, today="2026-09-25")
check("probing a real account escalates", verdict, L.ATTACK)
truthy("and names it", any("existing account" in r for r in reasons))
check("a username nobody has stays ambient",
      L.classify(scan(srcuser="oracle"), baseline=b,
                 known_users={"admin", "alexandru"}, today="2026-09-25")[0],
      L.AMBIENT_HOSTILE)


print("\n7. Escalation: the volume itself is abnormal")
b3 = seeded(days=5, per_day=20)
for _ in range(400):                       # today is 20x the established rate
    b3.observe("5710", "2026-09-25")
truthy("a spike is detected", b3.is_spiking("5710", "2026-09-25"))
verdict, reasons = L.classify(scan(), baseline=b3, today="2026-09-25")
check("and escalates", verdict, L.ATTACK)
truthy("naming the volume", any("volume" in r for r in reasons))
check("a normal day does not spike", seeded().is_spiking("5710", "2026-09-25"), False)


print("\n8. Explicit overrides still win")
check("a user-flagged benign rule is routine",
      L.classify(scan(), benign_rule_ids=frozenset({"5710"}), baseline=b)[0], L.ROUTINE)


print("\n9. The baseline survives a restart")
path = os.path.join(tempfile.mkdtemp(), "rb.json")
b4 = RuleBaseline(path)
for i in range(AMBIENT_MIN_DAYS):
    for _ in range(40):
        b4.observe("5710", f"2026-09-{10 + i:02d}")
b4.save()
truthy("reloaded baseline still says ambient", RuleBaseline(path).is_ambient("5710"))
truthy("a corrupt file degrades to cold, not a crash",
       not RuleBaseline("/nonexistent/dir/x.json").is_ambient("5710"))

print("\n10. The content model is a second judge, and a quiet one")


class FakeScorer:
    """Stands in for raw_log_scorer; `ok` and `score` are the whole contract."""
    def __init__(self, value, ok=True):
        self.value = value
        self.ok = ok

    def score(self, ev):
        return self.value, None


class BrokenScorer:
    ok = True

    def score(self, ev):
        raise RuntimeError("model file corrupt")


quiet = scan(desc="sshd: connection reset", rule_id="5762", level=4,
             groups=["syslog", "sshd"])
# Nothing in the tables matches "connection reset" — the tables are silent.
check("the tables alone see nothing here",
      L.is_attack_alert(quiet) or L.failure_outcome(quiet), False)
check("…so it is benign with no second judge",
      L.classify(quiet, baseline=None)[0], L.BENIGN)

# Real prod scores: 94.7 for brute force, 77.8 for Diana's own logins.
check("a confident model (94.7) makes it hostile",
      L.classify(quiet, baseline=None, scorer=FakeScorer(94.7))[0], L.ATTACK)
check("an unsure model (77.8) does NOT — that is her own SSH login",
      L.classify(quiet, baseline=None, scorer=FakeScorer(77.8))[0], L.BENIGN)
check("the threshold sits between the two classes",
      77.8 < L.CONTENT_HOSTILE_MIN <= 94.7, True)

verdict, reasons = L.classify(quiet, baseline=None, scorer=FakeScorer(94.7))
truthy("and it records WHICH judge fired", any("content model" in r for r in reasons))

print("\n11. A second judge must never create new alerts on ambient traffic")
# The safety property Diana asked for. On prod this moved 124 events from
# benign to ambient_hostile and fired zero extra alerts.
b5 = seeded(rule_id="5762")
check("frequent + model-hostile = suppressed, not alerted",
      L.classify(quiet, baseline=b5, today="2026-09-25", scorer=FakeScorer(94.7))[0],
      L.AMBIENT_HOSTILE)
check("and it is still not benign",
      L.classify(quiet, baseline=b5, today="2026-09-25",
                 scorer=FakeScorer(94.7))[0] != L.BENIGN, True)
check("…and still trains, keeping the feature variance",
      L.excluded_from_clean_training(quiet, baseline=b5, today="2026-09-25",
                                     scorer=FakeScorer(94.7)), False)

print("\n12. The second judge can only ADD, and fails silent")
# It is consulted only when the tables are silent, so it can never argue an
# existing detection down.
real = scan(desc="sshd: brute force trying to get access to the system.",
            rule_id="5712", level=10)
check("a table detection survives a model that says benign",
      L.classify(real, baseline=None, scorer=FakeScorer(0.0))[0], L.ATTACK)
check("no scorer at all is fine", L.classify(quiet, baseline=None, scorer=None)[0], L.BENIGN)
check("an unloaded model is ignored",
      L.classify(quiet, baseline=None, scorer=FakeScorer(99, ok=False))[0], L.BENIGN)
check("a model that throws is ignored, not fatal",
      L.classify(quiet, baseline=None, scorer=BrokenScorer())[0], L.BENIGN)

print()
if _fails:
    print(f"{len(_fails)} FAILED: " + ", ".join(_fails))
    sys.exit(1)
print("All ambient-hostile tests passed.")
