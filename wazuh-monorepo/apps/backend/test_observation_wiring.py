"""Observation mode, wired into the real app.

    ../../services/ai-engine/venv/bin/python test_observation_wiring.py

test_observation.py proves the state machine. This proves the WIRING, which
is where a mode like this actually fails: a gate placed one line too early
starves the measurements that end observation, and a gate placed one line too
late lets the reaction fire before anyone checks. Both look fine in review.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_tmp = tempfile.mkdtemp()
import auth                                        # noqa: E402
auth.DB_PATH = os.path.join(_tmp, "users.db")
os.environ["ADMIN_PASSWORD"] = "bootstrap-admin-pw"
os.environ["AUTH_ENABLED"] = "1"
os.environ["LOG_DIR"] = _tmp

import server                                      # noqa: E402

app = server.app
app.config["TESTING"] = True
server.limiter.enabled = False

# Point observation state at a scratch file, never the real one.
server.OBSERVATION_FILE = os.path.join(_tmp, "observation.json")
server._observation = None

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


def alert(agent="alice__LAPTOP-1", rule_id="5710", day="2026-09-20"):
    return {"timestamp": f"{day}T10:00:00.000+0000",
            "rule": {"id": rule_id, "level": 5, "description": "test",
                     "groups": ["syslog"]},
            "agent": {"id": "001", "name": agent},
            "full_log": "test line", "data": {}}


print("\n1. The module loads and is reachable from the app")
obs = server._get_observation()
truthy("observation singleton loaded", obs is not None)
check("owner is derived from the agent name",
      server._observation_owner(alert("alice__LAPTOP-1")), "alice")
check("an unclaimed host falls to the manager bucket",
      server._observation_owner(alert("MANAGER-HOST")), "__manager__")


print("\n2. A brand-new tenant is silent")
check("unknown tenant is collecting", obs.state("alice"), "collecting")
check("and must not alert", obs.should_alert("alice"), False)


print("\n3. Ingest feeds observation — measurement never waits for arming")
# This is the half that is easy to get wrong: suppress too early and the
# host can never accumulate the evidence that ends its own observation.
before = obs.progress("alice")["events"]
for d in range(3):
    obs.observe("alice", f"2026-09-{20 + d:02d}", n=100)
# Back-date the install. progress() uses min(distinct days, WALL-CLOCK days
# elapsed) on purpose, so replaying a week of old logs cannot fast-forward
# observation — which means a test that writes three day-strings in one
# millisecond legitimately shows 0%.
import time as _t
obs._state["alice"]["started_at"] = _t.time() - 3 * 86400
after = obs.progress("alice")
check("events accumulate while still collecting", after["events"], before + 300)
check("days accumulate too", after["days_seen"], 3)
check("and it is STILL not alerting", obs.should_alert("alice"), False)
truthy("progress is reportable mid-flight", 0 < after["percent"] < 100)


print("\n4. The API answers for the signed-in tenant")
auth.create_user("alice", "password123", email="alice@example.com")
tok, _ = auth.login("alice", "password123", ip="1.1.1.1")
c = app.test_client()
c.set_cookie("session_token", tok)

r = c.get("/api/observation")
check("status is 200", r.status_code, 200)
body = r.get_json()
check("scoped to the caller", body.get("owner"), "alice")
check("reports collecting", body.get("state"), "collecting")
check("reports not alerting", body.get("alerting"), False)
truthy("carries progress for the UI",
       "percent" in body and "days_needed" in body and "events_needed" in body)

r = c.post("/api/observation/arm")
check("arming too early is refused", r.status_code, 409)
truthy("with a reason the UI can show", (r.get_json() or {}).get("error"))
check("still not alerting after a refused arm", obs.should_alert("alice"), False)


print("\n5. Once the evidence is there, the operator can arm it")
import time
obs._state["alice"]["started_at"] = time.time() - 8 * 86400
# Derived from the configured bar rather than hard-coded: this fixture fed a
# flat 100/day, which silently stopped clearing the threshold the day
# MIN_EVENTS was raised from 500 to 2000.
_per_day = obs.min_events // 8 + 1
for d in range(8):
    obs.observe("alice", f"2026-10-{1 + d:02d}", n=_per_day)
check("promoted to ready", obs.state("alice"), "ready")
check("ready is still not alerting", obs.should_alert("alice"), False)

r = c.post("/api/observation/arm")
check("arming now succeeds", r.status_code, 200)
check("and alerting is on", obs.should_alert("alice"), True)


print("\n6. Tenants do not arm each other")
obs.observe("bob", "2026-09-20", n=5)
check("bob is still collecting", obs.should_alert("bob"), False)
check("alice is unaffected", obs.should_alert("alice"), True)

auth.create_user("bob", "password123", email="bob@example.com")
btok, _ = auth.login("bob", "password123", ip="1.1.1.1")
c2 = app.test_client()
c2.set_cookie("session_token", btok)
r = c2.get("/api/observation")
check("bob's view is his own", (r.get_json() or {}).get("owner"), "bob")
r = c2.post("/api/observation/reset", json={"owner": "alice"})
check("a non-admin cannot reset another tenant", r.status_code, 403)
check("alice is still armed", obs.should_alert("alice"), True)


print("\n7. Anonymous callers get nothing")
anon = app.test_client()
check("status needs a session", anon.get("/api/observation").status_code, 401)
check("arm needs a session", anon.post("/api/observation/arm").status_code, 401)
check("reset needs a session", anon.post("/api/observation/reset").status_code, 401)


print("\n8. A missing module must not silence an armed customer")
# Fail-open is correct HERE and only here: if observation cannot load, the
# alternative is a product that quietly stops alerting for everyone.
saved = server._observation
server._observation = False
check("_get_observation reports unavailable", server._get_observation(), None)
r = c.get("/api/observation")
check("the API says so plainly", (r.get_json() or {}).get("available"), False)
check("and reports armed, not suppressed", (r.get_json() or {}).get("state"), "armed")
server._observation = saved

print("\n9. Existing tenants are grandfathered on the upgrade")
# Deployed to a live install, observation must not take a working detector
# and silence it for a week. Verified against the real _get_observation()
# path, because the grandfathering happens there, not in the module.
import observation as _obsmod
fresh_path = os.path.join(tempfile.mkdtemp(), "obs_first.json")
server.OBSERVATION_FILE = fresh_path
server._observation = None
auth.create_user("carol", "password123", email="carol@example.com")

o2 = server._get_observation()
truthy("observation reloaded", o2 is not None)
check("the pre-existing admin keeps alerting", o2.should_alert("admin"), True)
check("so does carol", o2.should_alert("carol"), True)
check("and the manager bucket", o2.should_alert("__manager__"), True)
check("a host enrolled LATER still observes", o2.should_alert("newcomer"), False)

# On the next boot there is a state file, so nothing is grandfathered again.
server._observation = None
o3 = server._get_observation()
check("second load does not re-grandfather", o3.first_run, False)
check("newcomer is still observing", o3.should_alert("newcomer"), False)


print("\n10. Admins see the bucket that is actually gating")
# An admin's own tenant is usually empty — alerts land under the agent owner
# or __manager__. Reporting the admin's own 0/7d while something else holds
# every alert back is worse than silence.
o3.observe("newcomer", "2026-09-26", n=7)
atok, _ = auth.login("admin", "bootstrap-admin-pw", ip="1.1.1.1")
ac = app.test_client()
ac.set_cookie("session_token", atok)
body = ac.get("/api/observation").get_json()
truthy("admins get the full owner list", body.get("all_owners"))
truthy("and a 'gating' pointer", body.get("gating"))
check("which names the unarmed tenant", body["gating"]["owner"], "newcomer")
check("the admin's own tenant is armed", body.get("alerting"), True)

print("\n11. The Start-collecting button")
# o3 is the live singleton at this point; "newcomer" is mid-window and
# "carol" is grandfathered ARMED.
check("anonymous start is refused",
      anon.post("/api/observation/start").status_code, 401)

# A tenant with no window at all can just start one.
nc = app.test_client()
auth.create_user("dave", "password123", email="dave@example.com")
dtok, _ = auth.login("dave", "password123", ip="1.1.1.1")
nc.set_cookie("session_token", dtok)
r = nc.post("/api/observation/start")
check("a tenant with no window starts one", r.status_code, 200)
check("and it is collecting", r.get_json().get("state"), "collecting")

# A second press must NOT silently wipe the window.
o3.observe("dave", "2026-11-01", n=250)
r = nc.post("/api/observation/start")
check("pressing it again is refused", r.status_code, 409)
truthy("with a reason for the prompt", (r.get_json() or {}).get("error"))
check("and the 409 carries what would be lost",
      (r.get_json() or {}).get("events"), 250)
check("nothing was discarded", o3.progress("dave")["events"], 250)

r = nc.post("/api/observation/start", json={"force": True})
check("force restarts it", r.status_code, 200)
check("counters cleared", o3.progress("dave")["events"], 0)
truthy("and the response reports what it threw away",
       (r.get_json() or {}).get("discarded"))

# Cross-tenant: the owner field is admin-only, exactly like arm/reset.
r = nc.post("/api/observation/start", json={"owner": "carol", "force": True})
check("a non-admin naming another owner hits their OWN bucket",
      r.get_json().get("owner"), "dave")
check("carol is untouched and still alerting", o3.should_alert("carol"), True)
r = ac.post("/api/observation/start", json={"owner": "carol", "force": True})
check("an admin may restart another tenant", r.status_code, 200)
check("which does silence that tenant", o3.should_alert("carol"), False)

print()
if _fails:
    print(f"{len(_fails)} FAILED: " + ", ".join(_fails))
    sys.exit(1)
print("All observation wiring tests passed.")
