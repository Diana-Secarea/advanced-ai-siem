"""End-to-end registration + email-verification tests against a temp database.

Runnable without pytest:
    ../../services/ai-engine/venv/bin/python test_registration_flow.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Point the store at a throwaway file BEFORE auth opens it.
_tmp = tempfile.mkdtemp()
import auth                                       # noqa: E402
auth.DB_PATH = os.path.join(_tmp, "users.db")
os.environ["ADMIN_PASSWORD"] = "bootstrap-admin-pw"
auth.init_db()

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
    return got


print("\n1. Registration validation is enforced at the auth layer")
check("homoglyph username refused",
      auth.create_user("аdmin", "password123", email="a@example.com")[0], False)
check("'__' username refused",
      auth.create_user("bob__test", "password123", email="b@example.com")[0], False)
check("reserved username refused",
      auth.create_user("root", "password123", email="c@example.com")[0], False)
check("short password refused",
      auth.create_user("alice", "short", email="d@example.com")[0], False)
check("over-long password refused",
      auth.create_user("alice", "a" * 200, email="d@example.com")[0], False)
check("missing email refused",
      auth.create_user("alice", "password123")[0], False)
check("malformed email refused",
      auth.create_user("alice", "password123", email="not-an-email")[0], False)
check("CRLF in email refused",
      auth.create_user("alice", "password123",
                       email="a@example.com\r\nBcc: v@x.com")[0], False)

print("\n2. A valid registration succeeds and starts UNVERIFIED")
ok, err = auth.create_user("alice", "password123", email="Alice@Example.COM")
check("created", (ok, err), (True, None))
check("starts unverified", auth.is_email_verified("alice"), False)
check("email normalised to lowercase",
      auth.get_profile("alice")["email"], "alice@example.com")

print("\n3. Duplicate username and duplicate email are both refused")
check("duplicate username", auth.create_user(
    "alice", "password123", email="other@example.com")[1], "Username already exists")
check("duplicate email", auth.create_user(
    "alice2", "password123", email="alice@example.com")[1],
    "That email is already registered")
check("duplicate email is case-insensitive", auth.create_user(
    "alice3", "password123", email="ALICE@EXAMPLE.COM")[1],
    "That email is already registered")

print("\n4. Verification token round-trip")
token = truthy("token issued", auth.issue_verification("alice")[0])
check("still unverified before use", auth.is_email_verified("alice"), False)
check("garbage token rejected", auth.verify_email("garbage")[0], None)
check("empty token rejected", auth.verify_email("")[0], None)
check("None token rejected", auth.verify_email(None)[0], None)
user, err = auth.verify_email(token)
check("valid token verifies the right account", (user, err), ("alice", None))
check("now verified", auth.is_email_verified("alice"), True)
check("token cannot be replayed", auth.verify_email(token)[0], None)

print("\n5. Token is not recoverable from the database")
import sqlite3                                    # noqa: E402
conn = sqlite3.connect(auth.DB_PATH)
stored = conn.execute(
    "SELECT verify_token_hash FROM users WHERE username='alice'").fetchone()[0]
check("digest cleared after use", stored, "")
auth.create_user("bob", "password123", email="bob@example.com")
tok2 = auth.issue_verification("bob")[0]
stored2 = conn.execute(
    "SELECT verify_token_hash FROM users WHERE username='bob'").fetchone()[0]
check("raw token never stored", stored2 == tok2, False)
check("stored value is the digest", stored2, auth._token_digest(tok2))
conn.close()

print("\n6. Resend throttle (anti mail-bombing)")
again, err = auth.issue_verification("bob")
check("second request within the window is refused", again, None)
truthy("throttle message names the wait", err and "wait" in err.lower())

print("\n7. Expired links are refused")
auth.create_user("carol", "password123", email="carol@example.com")
tok3 = auth.issue_verification("carol")[0]
conn = sqlite3.connect(auth.DB_PATH)
conn.execute("UPDATE users SET verify_expires_at = '2020-01-01T00:00:00Z' "
             "WHERE username='carol'")
conn.commit(); conn.close()
user, err = auth.verify_email(tok3)
check("expired token refused", user, None)
truthy("error mentions expiry", err and "expired" in err.lower())
check("carol still unverified", auth.is_email_verified("carol"), False)

print("\n8. Already-verified and unknown accounts")
check("re-issuing for a verified account is refused",
      auth.issue_verification("alice")[0], None)
check("unknown account", auth.issue_verification("nobody-here")[0], None)
check("is_email_verified fails closed for unknown user",
      auth.is_email_verified("nobody-here"), False)
check("is_email_verified fails closed for invalid name",
      auth.is_email_verified("аdmin"), False)

print("\n9. The bootstrap admin is grandfathered, not locked out")
check("admin exists", auth.get_profile("admin") is not None, True)
check("admin is verified", auth.is_email_verified("admin"), True)

print("\n10. Login still works for a verified user")
tok, user = auth.login("alice", "password123", ip="127.0.0.1")
truthy("login returns a session token", tok)
check("login returns the account", user and user["username"], "alice")
check("wrong password still fails", auth.login("alice", "nope", ip="1.2.3.4")[0], None)

print()
if _fails:
    print(f"FAILED ({len(_fails)}): " + ", ".join(_fails[:8]))
    sys.exit(1)
print("All registration/verification flow tests passed.")
