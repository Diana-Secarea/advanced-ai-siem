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

print("\n4. Email enumeration is not possible")
r = c.post("/api/auth/register", json={
    "username": "someoneelse", "password": "password123",
    "email": "alice@example.com"})
check("duplicate email returns 200, not 400", r.status_code, 200)
check("body matches the success body", r.get_json().get("message"),
      server._REGISTER_OK)
check("no account was created", auth.get_profile("someoneelse"), None)
r = c.post("/api/auth/register", json={
    "username": "alice", "password": "password123", "email": "new@example.com"})
check("duplicate USERNAME is still reported", r.status_code, 400)

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

print()
if _fails:
    print(f"FAILED ({len(_fails)}): " + ", ".join(_fails[:8]))
    sys.exit(1)
print("All HTTP registration/verification tests passed.")
