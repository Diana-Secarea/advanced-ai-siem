"""Observation mode: learn a host for a week before it is allowed to page anyone.

    venv/bin/python test_observation.py

The property under test is mostly a negative one — that a freshly installed
host stays SILENT — which is the kind of thing that quietly stops working and
nobody notices until a customer is paged with verdicts from a model that has
never seen their traffic.
"""

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from observation import ObservationMode, COLLECTING, READY, ARMED

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


def fed(owner="acme", days=7, per_day=100, min_days=7, min_events=500, path=None):
    """A host observed for `days` days, back-dated so the clock agrees."""
    o = ObservationMode(path=path, min_days=min_days, min_events=min_events)
    start = time.time() - days * 86400
    o._state[owner] = {"state": COLLECTING, "started_at": start,
                       "events": 0, "days": []}
    for d in range(days):
        o.observe(owner, f"2026-09-{1 + d:02d}", n=per_day)
    return o


print("\n1. A brand-new install is silent")
fresh = ObservationMode()
check("unknown owner is collecting", fresh.state("nobody"), COLLECTING)
check("and must not alert", fresh.should_alert("nobody"), False)
fresh.observe("acme", "2026-09-01", n=10)
check("one day in, still collecting", fresh.state("acme"), COLLECTING)
check("still silent", fresh.should_alert("acme"), False)


print("\n2. Both thresholds must be met, not either")
# A busy host still waits out the week…
busy = fed(days=2, per_day=5000)
check("5000 events/day for 2 days is not enough", busy.state("acme"), COLLECTING)
check("…and stays silent", busy.should_alert("acme"), False)
# …and a quiet one still waits for enough events.
quiet = fed(days=8, per_day=10)
check("8 days of near-silence is not enough", quiet.state("acme"), COLLECTING)
check("…and stays silent too", quiet.should_alert("acme"), False)


print("\n3. Enough of both promotes to READY — but not to ARMED")
ready = fed(days=7, per_day=100)
check("becomes ready", ready.state("acme"), READY)
# Arming is a human decision on purpose: going from "silent" to "can page you"
# should not happen because a counter ticked over at 3am.
check("ready is still NOT armed", ready.should_alert("acme"), False)


print("\n4. Arming is an operator action, and is refused early")
early = fed(days=2, per_day=50)
ok, err = early.arm("acme")
check("arming a still-collecting host is refused", ok, False)
truthy("with a reason", err)
check("and it stays silent", early.should_alert("acme"), False)

ok, err = ready.arm("acme")
check("arming a ready host succeeds", (ok, err), (True, None))
check("now it may alert", ready.should_alert("acme"), True)


print("\n5. Progress is reportable while it happens")
p = fed(days=3, per_day=100).progress("acme")
check("state is collecting", p["state"], COLLECTING)
check("days counted", p["days_seen"], 3)
check("events counted", p["events"], 300)
truthy("percent is partial", 0 < p["percent"] < 100)
# The SLOWER axis governs, so a host cannot look nearly-done on volume alone.
fast = fed(days=1, per_day=100000).progress("acme")
truthy("volume alone cannot fake progress", fast["percent"] <= 20)


print("\n6. Tenants are independent")
multi = fed(owner="acme", days=7, per_day=100)
multi.observe("beta", "2026-09-01", n=5)
multi.arm("acme")
check("armed tenant alerts", multi.should_alert("acme"), True)
check("the new tenant does not", multi.should_alert("beta"), False)
check("both are tracked", multi.all_owners(), ["acme", "beta"])


print("\n7. It survives a restart")
path = os.path.join(tempfile.mkdtemp(), "obs.json")
o = fed(days=7, per_day=100, path=path)
o.arm("acme")
o.save()
again = ObservationMode(path=path)
check("armed state persists", again.should_alert("acme"), True)
check("and the counts persist", again.progress("acme")["events"], 700)


print("\n8. Unreadable state fails CLOSED (silent), never open")
bad = os.path.join(tempfile.mkdtemp(), "corrupt.json")
with open(bad, "w") as fh:
    fh.write("{not json at all")
o2 = ObservationMode(path=bad)
check("a corrupt file does not crash", o2.state("acme"), COLLECTING)
check("and nobody gets paged from it", o2.should_alert("acme"), False)
check("a missing file is the same", ObservationMode(path="/nope/x.json").should_alert("a"), False)


print("\n9. A host can be sent back to school")
o3 = fed(days=7, per_day=100)
o3.arm("acme")
check("armed", o3.should_alert("acme"), True)
o3.reset("acme")
check("reset returns it to collecting", o3.state("acme"), COLLECTING)
check("and it goes quiet again", o3.should_alert("acme"), False)
check("with the counters cleared", o3.progress("acme")["events"], 0)

print("\n10. Grandfathering: upgrading must not silence a working install")
# The regression this prevents: deploy observation mode to a host that has
# been alerting for months, and every tenant drops to COLLECTING — a working
# detector goes quiet for a week, presented as a safety feature.
g = ObservationMode()
truthy("a fresh object reports first_run", g.first_run)
done = g.grandfather(["admin", "alexandru", "__manager__"])
check("all three were grandfathered", sorted(done), ["__manager__", "admin", "alexandru"])
check("an existing tenant keeps alerting", g.should_alert("admin"), True)
check("so does the manager bucket", g.should_alert("__manager__"), True)

# …but it must never reach a host that genuinely needs observing.
g.observe("brand_new", "2026-09-26", n=1)
again = g.grandfather(["admin", "brand_new"])
check("nothing already tracked is touched", again, [])
check("and the new tenant is STILL collecting", g.state("brand_new"), COLLECTING)
check("so it is still silent", g.should_alert("brand_new"), False)

print("\n11. …and only on the first run")
path = os.path.join(tempfile.mkdtemp(), "obs.json")
first = ObservationMode(path=path)
truthy("first load is first_run", first.first_run)
first.grandfather(["admin"])
first.save()
second = ObservationMode(path=path)
check("a later load is NOT first_run", second.first_run, False)
check("but the grandfathered state persists", second.should_alert("admin"), True)

print("\n12. Progress is flushed on time, not only on volume")
# A quiet host may take days to reach the event-count flush; a restart before
# then would silently reset its window to day zero.
import observation as _obs
path2 = os.path.join(tempfile.mkdtemp(), "obs2.json")
o = ObservationMode(path=path2)
o._last_save = time.time() - (_obs.SAVE_INTERVAL + 5)   # pretend time passed
o.observe("slowpoke", "2026-09-26", n=1)                # one single event
truthy("the state file exists after one event", os.path.exists(path2))
check("and it survives a restart",
      ObservationMode(path=path2).progress("slowpoke")["events"], 1)
truthy("the interval is short enough to matter", _obs.SAVE_INTERVAL <= 300)

print("\n13. The flush stamp is actually updated")
# _last_save was set in __init__ and nowhere else, so once the process had
# been up for SAVE_INTERVAL the time condition was permanently true and every
# single observed event rewrote the whole JSON file.
path3 = os.path.join(tempfile.mkdtemp(), "obs3.json")
o3 = ObservationMode(path=path3)
o3._last_save = time.time() - (_obs.SAVE_INTERVAL + 5)
o3.observe("chatty", "2026-09-26", n=1)                 # triggers the flush
truthy("save() stamps _last_save",
       (time.time() - o3._last_save) < _obs.SAVE_INTERVAL)
writes_before = os.stat(path3).st_mtime_ns
o3.observe("chatty", "2026-09-26", n=1)                 # must NOT flush again
check("the very next event does not rewrite the file",
      os.stat(path3).st_mtime_ns, writes_before)

print("\n14. The default event bar is the trainable one, not the token one")
truthy("MIN_EVENTS is at least 1500", _obs.MIN_EVENTS >= 1500)
check("and the default is 2000", _obs.MIN_EVENTS, 2000)
check("days unchanged at 7", _obs.MIN_DAYS, 7.0)

print("\n15. start() begins a window and refuses to silently discard one")
st = ObservationMode()
ok, err = st.start("newco")
truthy("a tenant with no window can start one", ok)
check("and it is collecting", st.state("newco"), COLLECTING)
st.observe("newco", "2026-09-26", n=42)
ok, err = st.start("newco")
check("a second start is refused", ok, False)
truthy("with a reason naming the state", "collecting" in (err or ""))
check("and the banked progress is untouched", st.progress("newco")["events"], 42)
ok, err = st.start("newco", force=True)
truthy("force restarts it", ok)
check("which does clear the counters", st.progress("newco")["events"], 0)
# An ARMED host is the dangerous case: restarting silences a live detector.
st.grandfather(["liveco"])
ok, err = st.start("liveco")
check("an armed host is refused too", ok, False)
truthy("and the reason says armed", "armed" in (err or ""))
check("and it keeps alerting", st.should_alert("liveco"), True)

print()
if _fails:
    print(f"{len(_fails)} FAILED: " + ", ".join(_fails))
    sys.exit(1)
print("All observation-mode tests passed.")
