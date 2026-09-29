"""HTTP-level tests for registration, verification and the download gate.

Drives the real Flask app through its test client, so route wiring, status
codes and the auth decorators are exercised rather than just the helpers.

    ../../services/ai-engine/venv/bin/python test_registration_http.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Redirect the credential store before server.py imports auth and calls init_db.
_tmp = tempfile.mkdtemp()
import auth                                        # noqa: E402
auth.DB_PATH = os.path.join(_tmp, "users.db")
os.environ["ADMIN_PASSWORD"] = "bootstrap-admin-pw"
os.environ["AUTH_ENABLED"] = "1"
os.environ["WAZUH_REG_PASSWORD"] = "test-enrolment-secret"
os.environ["SELENNE_MANAGER_HOST"] = "agents.example.com"
os.environ["SELENNE_DASHBOARD_HOST"] = "example.com"
os.environ.pop("SMTP_HOST", None)                  # no mail server in tests
os.environ["LOG_DIR"] = _tmp                       # never touch the real logs

import server                                      # noqa: E402

app = server.app
app.config["TESTING"] = True
# The limiter would reject the repeated registrations below.
server.limiter.enabled = False

_fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected {want!r}, got {got!r}")
        _fails.append(label)


c = app.test_client()

print("\n1. Registration rejects the dangerous names over HTTP")
for uname, why in (("аdmin", "Cyrillic homoglyph"),
                   ("bob__test", "tenant separator"),
                   ("root", "reserved"),
                   ("ab", "too short")):
    r = c.post("/api/auth/register",
               json={"username": uname, "password": "password123",
                     "email": "x@example.com"})
    check(f"400 for {why}", r.status_code, 400)

print("\n2. Missing / malformed email")
check("no email -> 400", c.post("/api/auth/register", json={
    "username": "alice", "password": "password123"}).status_code, 400)
check("bad email -> 400", c.post("/api/auth/register", json={
    "username": "alice", "password": "password123",
    "email": "nope"}).status_code, 400)
check("CRLF email -> 400", c.post("/api/auth/register", json={
    "username": "alice", "password": "password123",
    "email": "a@b.com\r\nBcc: v@x.com"}).status_code, 400)

print("\n3. A good registration succeeds")
r = c.post("/api/auth/register", json={
    "username": "alice", "password": "password123", "email": "alice@example.com"})
check("200", r.status_code, 200)
check("no token leaked in the response", "token" in r.get_data(as_text=True), False)
check("warns that SMTP is unconfigured", "warning" in r.get_json(), True)

print("\n4. A duplicate email is reported, and still creates nothing")
# The default flipped on 2026-09-29: telling the user beats hiding the fact.
# What must NOT change is that the collision creates no account.
r = c.post("/api/auth/register", json={
    "username": "someoneelse", "password": "password123",
    "email": "alice@example.com"})
check("duplicate email returns 409", r.status_code, 409)
check("the message names the problem",
      "already registered" in r.get_json().get("error", ""), True)
check("and points at the email field", r.get_json().get("field"), "email")
check("no account was created", auth.get_profile("someoneelse"), None)
r = c.post("/api/auth/register", json={
    "username": "alice", "password": "password123", "email": "new@example.com"})
check("duplicate USERNAME is still reported", r.status_code, 400)

# The old silent behaviour is one env var away, and must still work.
server._REVEAL_EMAIL_COLLISION = False
try:
    r = c.post("/api/auth/register", json={
        "username": "yetanother", "password": "password123",
        "email": "alice@example.com"})
    check("with the flag off it returns 200", r.status_code, 200)
    check("and the generic success body", r.get_json().get("message"),
          server._REGISTER_OK)
    check("still creating nothing", auth.get_profile("yetanother"), None)
finally:
    server._REVEAL_EMAIL_COLLISION = True

print("\n5. Unverified account cannot download a collector")
login = c.post("/api/auth/login", json={"username": "alice", "password": "password123"})
check("login 200", login.status_code, 200)
r = c.get("/api/download/agent/linux")
check("download blocked with 403", r.status_code, 403)
check("response tells the client what to do",
      r.get_json().get("action"), "verify_email")
body = r.get_data(as_text=True)
check("enrolment password not leaked in the denial",
      os.environ["WAZUH_REG_PASSWORD"] in body, False)

print("\n6. Verification unlocks the download")
# Registration already minted a token and stamped verify_sent_at, so asking for
# another one immediately is correctly refused by the per-account cooldown.
_, cooldown_err = auth.issue_verification("alice")
check("resend within the cooldown is refused", bool(cooldown_err), True)
# Clear the stamp to mint a fresh token, standing in for the emailed one.
import sqlite3                                     # noqa: E402
_c = sqlite3.connect(auth.DB_PATH)
_c.execute("UPDATE users SET verify_sent_at='' WHERE username='alice'")
_c.commit(); _c.close()
token, err = auth.issue_verification("alice")
check("token issued after the cooldown", err, None)
check("bad token -> 400", c.get("/api/auth/verify?token=nope").status_code, 400)
check("no token -> 400", c.get("/api/auth/verify").status_code, 400)
r = c.get(f"/api/auth/verify?token={token}")
check("valid token -> 200", r.status_code, 200)
check("verified in the store", auth.is_email_verified("alice"), True)
r = c.get("/api/download/agent/linux")
check("download now allowed", r.status_code, 200)
# This route serves the branded zip, which is what a customer actually gets.
import io, zipfile                                 # noqa: E402
zf = zipfile.ZipFile(io.BytesIO(r.get_data()))
names = zf.namelist()
check("zip contains the installer",
      any(n.endswith("install-selenne-collector.sh") for n in names), True)
script = zf.read(next(n for n in names
                      if n.endswith("install-selenne-collector.sh"))).decode()
check("installer carries the enrolment password",
      os.environ["WAZUH_REG_PASSWORD"] in script, True)
check("installer uses the transport host for agent-auth",
      "MANAGER='agents.example.com'" in script, True)
check("installer uses the dashboard host for https",
      "DASHBOARD='example.com'" in script, True)
check("no placeholder was left unsubstituted",
      "__MANAGER__" in script or "__DASHBOARD__" in script
      or "__REG_PASSWORD__" in script, False)
check("agent name binds the account", "OWNER='alice'" in script, True)

print("\n7. Changing the email revokes verification")
r = c.post("/api/profile", json={"email": "alice2@example.com"})
check("profile update 200", r.status_code, 200)
check("no longer verified", auth.is_email_verified("alice"), False)
check("download blocked again", c.get("/api/download/agent/linux").status_code, 403)
r = c.post("/api/profile", json={"email": "bad-address"})
check("invalid email rejected", r.status_code, 400)

print("\n8. Clicking the link in a browser lands on a page, not JSON")
auth.create_user("dave", "password123", email="dave@example.com")
_c = sqlite3.connect(auth.DB_PATH)
_c.execute("UPDATE users SET verify_sent_at='' WHERE username='dave'")
_c.commit(); _c.close()
tok = auth.issue_verification("dave")[0]
r = c.get(f"/api/auth/verify?token={tok}", headers={"Accept": "text/html"})
check("browser gets a redirect", r.status_code, 302)
check("redirected to the login page with a status",
      "/login.html?verify=ok" in r.headers.get("Location", ""), True)
r = c.get("/api/auth/verify?token=bad", headers={"Accept": "text/html"})
check("failure also redirects", r.status_code, 302)
check("failure carries a reason", "verify=failed" in r.headers.get("Location", ""), True)
r = c.get("/api/auth/verify?token=bad", headers={"Accept": "application/json"})
check("API client still gets JSON 400", r.status_code, 400)

print("\n9. Anonymous access is unchanged")
c2 = app.test_client()
check("anonymous download -> 401", c2.get("/api/download/agent/linux").status_code, 401)
check("anonymous resend -> 401",
      c2.post("/api/auth/verify/resend").status_code, 401)

print("\n10. The verification link works with NO session")
# The bug this pins: /api/auth/verify was missing from _AUTH_EXEMPT_PATHS, so
# the global gate answered 401 before the route ran. A verification link is
# clicked from an email client — on a phone, in another browser, days later —
# where there is by construction no session cookie. Confirmation was therefore
# impossible for anyone who did not happen to open the link in the same browser
# they signed up in. Measured in production: an iPhone hitting the emailed link
# got "401 Authentication required".
anon = app.test_client()                      # no cookies at all

ok, err = auth.create_user("linkuser", "password123", email="link@example.com")
check("fixture account created", (ok, err), (True, None))
tok, terr = auth.issue_verification("linkuser")
check("token issued", terr, None)

r = anon.get(f"/api/auth/verify?token={tok}")
check("an anonymous request is NOT refused by the auth gate", r.status_code == 401, False)
check("and the account is now verified", auth.is_email_verified("linkuser"), True)

# The path must be exempt EXACTLY, never by prefix — /api/auth/verify/resend
# takes its account from the session and must keep requiring one.
check("/api/auth/verify is exempt", "/api/auth/verify" in server._AUTH_EXEMPT_PATHS, True)
check("/api/auth/verify/resend is NOT exempt",
      "/api/auth/verify/resend" in server._AUTH_EXEMPT_PATHS, False)
r = anon.post("/api/auth/verify/resend")
check("anonymous resend still refused", r.status_code, 401)

# A bad token must fail as a TOKEN failure (400), not as an auth failure (401):
# the difference is what tells you whether the link is stale or the gate is
# eating the request.
r = anon.get("/api/auth/verify?token=not-a-real-token")
check("a bad token is a 400, not a 401", r.status_code, 400)
r = anon.get(f"/api/auth/verify?token={tok}")
check("the token is single-use", r.status_code, 400)

print("\n11. Forgot-password: the public half stays blind")
anon2 = app.test_client()
check("/api/auth/password/forgot is exempt from the gate",
      "/api/auth/password/forgot" in server._AUTH_EXEMPT_PATHS, True)
check("/api/auth/password/reset is exempt too",
      "/api/auth/password/reset" in server._AUTH_EXEMPT_PATHS, True)
check("and so is the page it lands on",
      "/reset.html" in server._AUTH_EXEMPT_PATHS, True)

# An address nobody holds and one that exists must be indistinguishable —
# otherwise this endpoint is a bulk checker for "does this person use Selenne".
r_unknown = anon2.post("/api/auth/password/forgot",
                       json={"email": "nobody@example.com"})
r_known = anon2.post("/api/auth/password/forgot",
                     json={"email": "link@example.com"})
check("unknown address -> 200", r_unknown.status_code, 200)
check("known address -> 200", r_known.status_code, 200)
check("identical bodies", r_unknown.get_json().get("message"),
      r_known.get_json().get("message"))
check("and no token is ever in the response",
      "token" in r_known.get_data(as_text=True), False)
check("a malformed address is not an oracle either",
      anon2.post("/api/auth/password/forgot",
                 json={"email": "not-an-email"}).status_code, 200)

print("\n12. Forgot-password: the token half actually resets")
tok2, uname2, err2 = auth.issue_password_reset("link@example.com")
# issue_password_reset was just called by the route above, so the per-account
# cooldown is running — that refusal is itself the behaviour under test.
check("the cooldown refuses a second mint", tok2, None)
check("and names the account for the log", uname2, "linkuser")
import sqlite3                                     # noqa: E402
_c = sqlite3.connect(auth.DB_PATH)
_c.execute("UPDATE users SET reset_sent_at='' WHERE username='linkuser'")
_c.commit(); _c.close()
tok2, uname2, err2 = auth.issue_password_reset("link@example.com")
check("a token is minted after the cooldown", err2, None)

r = anon2.get(f"/api/auth/password/reset?token={tok2}")
check("GET says the link is live", r.get_json().get("valid"), True)
check("and names the account", r.get_json().get("username"), "linkuser")
check("a junk token is a 400", anon2.get(
    "/api/auth/password/reset?token=not-a-real-token").status_code, 400)

# A live session must not survive the reset: the premise is that the account
# may already be in someone else's hands.
login = anon2.post("/api/auth/login",
                   json={"username": "linkuser", "password": "password123"})
check("the old password still works before the reset", login.status_code, 200)

r = anon2.post("/api/auth/password/reset",
               json={"token": tok2, "new_password": "short"})
check("a too-short new password is refused", r.status_code, 400)
r = anon2.post("/api/auth/password/reset",
               json={"token": tok2, "new_password": "brand-new-password"})
check("the reset succeeds", r.status_code, 200)
check("and names the account", r.get_json().get("username"), "linkuser")

check("the token is single-use", anon2.post(
    "/api/auth/password/reset",
    json={"token": tok2, "new_password": "another-password"}).status_code, 400)
fresh = app.test_client()
check("the OLD password no longer works", fresh.post(
    "/api/auth/login",
    json={"username": "linkuser", "password": "password123"}).status_code, 401)
check("the new one does", fresh.post(
    "/api/auth/login",
    json={"username": "linkuser", "password": "brand-new-password"}).status_code, 200)
# anon2 still holds the pre-reset cookie.
check("and the session held from before the reset is dead",
      anon2.get("/api/auth/me").status_code, 401)

print()
if _fails:
    print(f"FAILED ({len(_fails)}): " + ", ".join(_fails[:8]))
    sys.exit(1)
print("All HTTP registration/verification tests passed.")
