"""Alert tools must work — and stay tenant-scoped — with no request context.

    ../../services/ai-engine/venv/bin/python test_request_context.py

The bug: the chat stream builds its context in a worker thread and the
reactor's AI triage runs in a daemon, but the alert search reached the caller's
identity through Flask's `request`, which is a thread-local bound to the
request context. In both places that raised

    RuntimeError: Working outside of request context

which build_context swallowed and reported to the user as "Error preparing
context", so every alert-backed answer came back empty.

The fix threads an explicit `viewer` down the chain. These tests pin both
halves: it must not raise, and it must not start showing one tenant another
tenant's machines on the way to not raising.
"""

import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_tmp = tempfile.mkdtemp()
import auth                                        # noqa: E402
auth.DB_PATH = os.path.join(_tmp, "users.db")
os.environ["ADMIN_PASSWORD"] = "bootstrap-admin-pw"
os.environ["AUTH_ENABLED"] = "1"
os.environ["LOG_DIR"] = _tmp

import server                                      # noqa: E402

_fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected {want!r}, got {got!r}")
        _fails.append(label)


def no_raise(label, fn):
    try:
        fn()
        print(f"  PASS  {label}")
    except Exception as e:                          # noqa: BLE001
        print(f"  FAIL  {label}   ({type(e).__name__}: {str(e)[:70]})")
        _fails.append(label)


def alert(agent_name, desc):
    return {"timestamp": "2026-09-17T10:00:00.000+0000",
            "rule": {"id": "5503", "level": 5, "description": desc, "groups": ["pam"]},
            "agent": {"id": "001", "name": agent_name, "ip": "10.0.0.5"},
            "full_log": f"pam_unix(sshd:auth): {desc}", "data": {}}


# Pin the store: _search_wazuh_alerts() calls _check_new_alerts(), which tails
# the real alerts file and would otherwise grow the fixture mid-test and make
# the counts below depend on whatever the host happened to log.
server._check_new_alerts = lambda *a, **k: None
server._load_all_wazuh_alerts = lambda *a, **k: None

# Two tenants' machines plus one unclaimed host, in the real store.
with server._wazuh_alerts_lock:
    server._wazuh_alerts.clear()
    server._wazuh_alerts.extend([
        alert("alice__LAPTOP-1", "failed login alpha"),
        alert("alice__DESKTOP-2", "failed login beta"),
        alert("bob__LAPTOP-9", "failed login gamma"),
        alert("MANAGER-HOST", "failed login delta"),      # unclaimed
    ])
server._wazuh_loaded = True


print("\n1. No request context — the reported crash")
no_raise("_current_username()", lambda: server._current_username())
no_raise("_visible_alerts()", lambda: server._visible_alerts())
no_raise("_search_wazuh_alerts()", lambda: server._search_wazuh_alerts("failed"))
check("and it fails CLOSED, with no identity", server._current_username(), (None, False))
check("so an unscoped call sees nothing", len(server._visible_alerts()), 0)


print("\n2. An explicit viewer is honoured")
admin_n = len(server._visible_alerts(("admin", True)))
alice_n = len(server._visible_alerts(("alice", False)))
bob_n = len(server._visible_alerts(("bob", False)))
check("admin sees every alert", admin_n, 4)
check("alice sees only her two machines", alice_n, 2)
check("bob sees only his one", bob_n, 1)
# The unclaimed host is admin-only — failing open there would hand a stranger's
# machine to whichever tenant asked first.
check("neither tenant sees the unclaimed host", alice_n + bob_n, 3)


print("\n3. Tenancy holds through the search path the agent tool uses")
a_hits = server._search_wazuh_alerts("failed login", viewer=("alice", False))
b_hits = server._search_wazuh_alerts("failed login", viewer=("bob", False))
names_a = {h[1]["agent"]["name"] for h in a_hits}
names_b = {h[1]["agent"]["name"] for h in b_hits}
check("alice's search returns only alice's machines",
      names_a, {"alice__LAPTOP-1", "alice__DESKTOP-2"})
check("bob's search returns only bob's", names_b, {"bob__LAPTOP-9"})
check("no overlap between tenants", bool(names_a & names_b), False)


print("\n4. …and inside a worker thread, the way the chat stream runs")
res = {}


def worker():
    try:
        hits = server._search_wazuh_alerts("failed login", viewer=("alice", False))
        res["names"] = {h[1]["agent"]["name"] for h in hits}
    except Exception as e:                          # noqa: BLE001
        res["err"] = f"{type(e).__name__}: {e}"


t = threading.Thread(target=worker)
t.start()
t.join()
check("the thread did not raise", res.get("err"), None)
check("and scoping survived the thread boundary",
      res.get("names"), {"alice__LAPTOP-1", "alice__DESKTOP-2"})


print("\n5. The reactor runs detached and is explicitly system-wide")
check("reactor viewer is admin-equivalent", server._REACTOR_VIEWER[1], True)
check("so triage can see the whole store",
      len(server._visible_alerts(server._REACTOR_VIEWER)), 4)

print()
if _fails:
    print(f"{len(_fails)} FAILED: " + ", ".join(_fails))
    sys.exit(1)
print("All request-context / tenancy tests passed.")
