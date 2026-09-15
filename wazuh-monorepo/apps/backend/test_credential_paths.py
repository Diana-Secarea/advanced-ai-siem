"""Regression tests for the credential paths that identity.py did NOT reach.

Runnable without pytest:
    ../../services/ai-engine/venv/bin/python test_credential_paths.py

``identity`` was introduced as the single source of truth for the tenant key,
but login(), change_password() and the lockout map kept an inline
``(username or "").strip().lower()`` and an inline ``len(pw) < 8``. Each case
below pins one half of that gap closed.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_tmp = tempfile.mkdtemp()
import auth                                       # noqa: E402
import identity                                   # noqa: E402
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


PW = "password123"
ok, err = auth.create_user("carol", PW, email="carol@example.com")
check("fixture account created", (ok, err), (True, None))


print("\n1. login() folds a username the way create_user stored it")
# create_user runs NFKC, so "ﬀ" (U+FB00) and "ｃ" (fullwidth) fold to ASCII on
# the way in. login() used .lower(), which does no NFKC — so a user could
# register a name and then be unable to type it at the login box.
ok, err = auth.create_user("ﬀred", PW, email="fred@example.com")
check("NFKC-folding name registers", (ok, err), (True, None))
check("stored as folded ASCII",
      any(u["username"] == "ffred" for u in auth.list_users()), True)
tok, user = auth.login("ﬀred", PW, ip="1.2.3.4")
truthy("can log in with the SAME spelling used to register", tok)
check("resolves to the canonical tenant key", (user or {}).get("username"), "ffred")

tok2, user2 = auth.login("CAROL", PW, ip="1.2.3.4")
truthy("case-insensitive login still works", tok2)
check("canonical username returned", (user2 or {}).get("username"), "carol")


print("\n2. The lockout map keys on the same folding as the lookup")
# If the key folded differently from the lookup, failures would accumulate
# under a spelling the account is never found under, so the lockout could
# never trip and the brute-force guard would be decorative.
check("key matches canonical form",
      auth._lockout_key("ＣＡＲＯＬ", "9.9.9.9"),
      auth._lockout_key("carol", "9.9.9.9"))
for _ in range(auth.MAX_FAILS):
    auth.login("ＣＡＲＯＬ", "wrong-password", ip="9.9.9.9")
truthy("failures under a folded spelling lock the real account",
       auth.lockout_remaining("carol", "9.9.9.9"))
check("a different IP is unaffected", auth.lockout_remaining("carol", "8.8.8.8"), 0)


print("\n3. change_password enforces the SAME policy as registration")
# create_user refuses > PASSWORD_MAX so one request cannot become a PBKDF2
# workout. change_password had only an inline "< 8", so the bound was
# enforced on signup and not on change.
ok, err = auth.change_password("carol", PW, "a" * (identity.PASSWORD_MAX + 1))
check("over-PASSWORD_MAX new password refused", ok, False)
truthy("and says why", err)
check("registration refuses the same value",
      auth.create_user("dave", "a" * (identity.PASSWORD_MAX + 1),
                       email="dave@example.com")[0], False)

check("short new password still refused",
      auth.change_password("carol", PW, "short")[0], False)
check("NUL in new password refused",
      auth.change_password("carol", PW, "abcdefgh\x00")[0], False)
check("unchanged password still refused",
      auth.change_password("carol", PW, PW), (False, "New password must differ from the current one"))

# An over-long CURRENT password must not be hashed, and must not reveal that
# length was the reason it failed.
ok, err = auth.change_password("carol", "a" * 5000, "brand-new-password")
check("over-long current password rejected", ok, False)
check("without confirming the length was the problem", err, "Current password is incorrect")


print("\n4. change_password folds the username, and still works end to end")
ok, err = auth.change_password("ＣＡＲＯＬ", PW, "a-fresh-password-1")
check("folded spelling reaches the real account", (ok, err), (True, None))
truthy("new password works", auth.login("carol", "a-fresh-password-1", ip="4.4.4.4")[0])
check("old password no longer works",
      auth.login("carol", PW, ip="5.5.5.5")[0], None)

ok, err = auth.change_password("no-such-account", PW, "a-fresh-password-2")
check("unknown account refused", ok, False)


print()
if _fails:
    print(f"{len(_fails)} FAILED: " + ", ".join(_fails))
    sys.exit(1)
print("All credential-path tests passed.")
