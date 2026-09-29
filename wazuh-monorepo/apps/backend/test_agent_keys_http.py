"""HTTP-level tests for Selenne Agents ingestion keys.

Covers the browser side (/api/keys), the container side
(/internal/keys/verify) and the entitlement flag on /api/auth/me.

    ../../services/ai-engine/venv/bin/python test_agent_keys_http.py
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
os.environ["SELENNE_INTERNAL_SECRET"] = "internal-test-secret"
os.environ["AGENTS_OPEN_BETA"] = "0"               # exercise real entitlement
os.environ.pop("SMTP_HOST", None)
os.environ["LOG_DIR"] = _tmp

import server                                      # noqa: E402
import agent_keys                                  # noqa: E402

app = server.app
app.config["TESTING"] = True
server.limiter.enabled = False

_fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected {want!r}, got {got!r}")
        _fails.append(label)


def signed_in(username, password, verified=True):
    auth.create_user(username, password, email=f"{username}@example.com")
    if verified:
        with auth._conn() as conn:
            conn.execute("UPDATE users SET email_verified = 1 WHERE username = ?", (username,))
    c = app.test_client()
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.get_json()
    return c


INTERNAL = {"X-Selenne-Internal": "internal-test-secret"}
anon = app.test_client()


def verify(key, headers=INTERNAL):
    return anon.post("/internal/keys/verify", json={"key": key}, headers=headers)


print("\n1. Key management needs a verified session")
check("list without session is 401", anon.get("/api/keys").status_code, 401)
check("create without session is 401",
      anon.post("/api/keys", json={"project": "bot"}).status_code, 401)
unverified = signed_in("carol", "carol-password-1", verified=False)
r = unverified.post("/api/keys", json={"project": "bot"})
check("unverified email cannot create keys", r.status_code, 403)
check("and is told why", r.get_json().get("action"), "verify_email")

print("\n2. Create, list, and the raw key is shown exactly once")
diana = signed_in("diana", "diana-password-1")
r = diana.post("/api/keys", json={"project": "support-bot"})
check("create is 201", r.status_code, 201)
key = r.get_json()["key"]
rec = r.get_json()["record"]
check("key has the ingest prefix", key.startswith("sk_sel_"), True)
check("key matches the ingest format (sk_sel_ + 16..128 url-safe)",
      16 <= len(key) - 7 <= 128 and all(ch.isalnum() or ch in "_-" for ch in key[7:]), True)
listed = diana.get("/api/keys").get_json()["keys"]
check("listed once", [k["id"] for k in listed], [rec["id"]])
check("list never contains the raw key", key in str(listed), False)
check("hint shows prefix and tail only", listed[0]["hint"], f"{key[:11]}…{key[-4:]}")
with auth._conn() as conn:
    stored = conn.execute("SELECT key_hash FROM agent_api_keys").fetchone()[0]
check("users.db holds only the digest", key in stored or stored == key, False)
for bad in ("", "has space", "../etc", "x" * 65, "-leading"):
    check(f"project {bad[:10]!r} refused",
          diana.post("/api/keys", json={"project": bad}).status_code, 400)
check("non-string project refused",
      diana.post("/api/keys", json={"project": {"a": 1}}).status_code, 400)

print("\n3. /internal/keys/verify: secret, proxy refusal, answers")
check("no secret is 403", verify(key, headers={}).status_code, 403)
check("wrong secret is 403",
      verify(key, headers={"X-Selenne-Internal": "nope"}).status_code, 403)
check("via a proxy (X-Forwarded-For) is 404",
      verify(key, headers={**INTERNAL, "X-Forwarded-For": "1.2.3.4"}).status_code, 404)
r = verify(key)
check("valid key", r.get_json(), {"valid": True, "username": "diana",
                                  "project": "support-bot", "entitled": False,
                                  "key_id": rec["id"]})
check("unknown key is invalid", verify("sk_sel_" + "A" * 43).get_json(), {"valid": False})
check("garbage is invalid", verify(12345).get_json(), {"valid": False})
check("last_used_at recorded",
      diana.get("/api/keys").get_json()["keys"][0]["last_used_at"] is not None, True)

print("\n4. Entitlement: /me and verify agree")
check("/me says not entitled", diana.get("/api/auth/me").get_json()["user"]["agents"], False)
agent_keys.set_entitlement("diana", True, "admin")
check("/me says entitled after grant",
      diana.get("/api/auth/me").get_json()["user"]["agents"], True)
check("verify says entitled after grant", verify(key).get_json()["entitled"], True)
admin = app.test_client()
admin.post("/api/auth/login", json={"username": "admin", "password": "bootstrap-admin-pw"})
check("admins are always entitled", admin.get("/api/auth/me").get_json()["user"]["agents"], True)

print("\n5. Tenancy and revocation")
bob = signed_in("bob", "bob-password-12")
check("bob does not see diana's keys", bob.get("/api/keys").get_json()["keys"], [])
check("bob cannot revoke diana's key",
      bob.delete(f"/api/keys/{rec['id']}").status_code, 404)
check("diana's key still valid", verify(key).get_json()["valid"], True)
check("diana revokes", diana.delete(f"/api/keys/{rec['id']}").status_code, 200)
check("revoked key is invalid", verify(key).get_json(), {"valid": False})
check("revoking twice is 404", diana.delete(f"/api/keys/{rec['id']}").status_code, 404)
check("revoked key stays listed as inactive",
      diana.get("/api/keys").get_json()["keys"][0]["active"], False)

print("\n6. Active-key cap")
for i in range(agent_keys.MAX_ACTIVE_KEYS):
    assert bob.post("/api/keys", json={"project": f"p{i}"}).status_code == 201
check("one over the cap is refused",
      bob.post("/api/keys", json={"project": "extra"}).status_code, 400)

print("\n7. Deleted account kills its keys")
k2 =diana.post("/api/keys", json={"project": "later"}).get_json()["key"]
with auth._conn() as conn:
    conn.execute("DELETE FROM users WHERE username = 'diana'")
check("key of a deleted user is invalid", verify(k2).get_json(), {"valid": False})

print("\n8. Agents activity stays out of the SIEM's Wazuh-collected logs")
# Console-style session probe (marked) vs an ordinary one (unmarked/forged).
anon.get("/api/auth/me", headers={"X-Selenne-Internal": "internal-test-secret"},
         query_string={"probe": "agents-console"})
anon.get("/api/auth/me", headers={"X-Selenne-Internal": "forged"},
         query_string={"probe": "forged-marker"})


def _read(name):
    try:
        with open(os.path.join(_tmp, name), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


audit_log, access_log = _read("selenne-audit.json"), _read("flask_access.log")
agents_log = _read("selenne-agents.json")
for ev in ("agent_key_created", "agent_key_revoked", "internal_verify_denied"):
    check(f"{ev} not in selenne-audit.json", ev in audit_log, False)
    check(f"{ev} in selenne-agents.json", ev in agents_log, True)
check("no /api/keys lines in flask_access.log", "/api/keys" in access_log, False)
check("no /internal/ lines in flask_access.log", "/internal/" in access_log, False)
check("marked console probe not in flask_access.log", "agents-console" in access_log, False)
check("forged marker is still access-logged", "forged-marker" in access_log, True)
check("SIEM traffic still access-logged", "/api/auth/login" in access_log, True)
check("agents records are namespaced selenne_agents, not selenne",
      '"selenne_agents": {' in agents_log and '"selenne": {' not in agents_log, True)

print("\n9. Secret unset -> 503 (retryable for ingest), never an accept")
server.SELENNE_INTERNAL_SECRET = ""
check("unconfigured verify is 503", verify(k2).status_code, 503)

if _fails:
    print(f"\n{len(_fails)} FAILED: {_fails}")
    sys.exit(1)
print("\nAll Selenne Agents key tests passed.")
