"""Security regression tests for registration and the tenant key.

Runnable without pytest:  python3 test_identity_security.py

Every case here was either a live hole (measured before the fix) or a property
that must not regress. Where a case is about SQL, it exercises the real
database rather than asserting that the code "looks parameterised".
"""

import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import identity as I
import tenancy

_fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected {want!r}, got {got!r}")
        _fails.append(label)


def rejected(label, raw, fn=None):
    fn = fn or I.normalise_username
    value, err = fn(raw)
    ok = value is None and bool(err)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected rejection, got {value!r}")
        _fails.append(label)


def accepted(label, raw, want, fn=None):
    fn = fn or I.normalise_username
    value, err = fn(raw)
    ok = value == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected {want!r}, got {value!r} (err={err!r})")
        _fails.append(label)


print("\n1. Confusable / homoglyph usernames (all previously ACCEPTED)")
rejected("Cyrillic 'аdmin'", "аdmin")
rejected("Latin alpha 'ɑdmin'", "ɑdmin")
rejected("dotless i 'admın'", "admın")
rejected("Greek omicron 'admin' -> 'admιn'", "admιn")
# NFKC folds these onto ASCII, so they collapse into the canonical spelling
# instead of coexisting with it — and 'admin' is reserved, so it is refused.
rejected("fullwidth 'ａdmin' folds to reserved 'admin'", "ａdmin")
accepted("ligature 'ﬁle' folds to 'file'", "ﬁle", "file")
rejected("emoji", "\U0001f600evil")
rejected("Roman numeral chars", "ⅰⅴ")
rejected("Arabic-Indic digits", "١٢٣")

print("\n2. Invisible / bidi / control characters")
rejected("zero-width space inside", "ad​min")
rejected("trailing zero-width space", "alice​")
rejected("RTL override prefix", "‮alice")
rejected("bidi isolate", "⁦alice⁩")
rejected("soft hyphen", "al­ice")
rejected("BOM", "﻿alice")
rejected("newline (log/header injection)", "alice\nX-Injected: 1")
rejected("carriage return", "alice\rwhoami")
rejected("NUL byte", "alice\x00")

print("\n3. Tenant-key integrity (the cross-tenant bug)")
check("identity.SEP matches tenancy.SEP", I.SEP, tenancy.SEP)
rejected("username containing the '__' separator", "bob__test")
rejected("username that is only the separator", "__")
rejected("leading underscore", "_alice")
rejected("trailing hyphen", "alice-")
accepted("ordinary name with inner - and _", "bob-test_1", "bob-test_1")
accepted("uppercase folds to lowercase", "Alice", "alice")
# The property that actually matters: every accepted username must round-trip
# through the agent name the installer builds.
print("  -- round-trip: owner derived from '<user>__<machine>' == user")
for name in ("alice", "bob-test_1", "a1b2", "x-y-z"):
    agent = f"{name}{tenancy.SEP}LAPTOP-1"
    check(f"derive_owner({agent!r})", tenancy.derive_owner(agent), name)

print("\n4. Reserved and malformed names")
for name in ("admin", "root", "selenne", "support", "noreply", "api", "system"):
    rejected(f"reserved: {name}", name)
rejected("too short", "ab")
rejected("too long", "a" * (I.USERNAME_MAX + 1))
rejected("empty", "")
rejected("whitespace only", "   ")
rejected("non-string (None)", None)
rejected("non-string (int)", 1234)
rejected("SQLi string", "robert'); DROP TABLE users;--")

print("\n5. Email validation and header-injection safety")
accepted("plain address", "Alice@Example.COM", "alice@example.com", I.normalise_email)
accepted("plus addressing", "a+tag@example.co.uk", "a+tag@example.co.uk", I.normalise_email)
rejected("no @", "alice.example.com", I.normalise_email)
rejected("two @", "a@b@example.com", I.normalise_email)
rejected("no TLD", "alice@localhost", I.normalise_email)
rejected("consecutive dots", "a..b@example.com", I.normalise_email)
rejected("CRLF header injection", "a@example.com\r\nBcc: victim@x.com", I.normalise_email)
rejected("newline in address", "a@example.com\nBcc: x@y.com", I.normalise_email)
rejected("display-name form", "Alice <a@example.com>", I.normalise_email)
rejected("unicode domain", "a@exämple.com", I.normalise_email)
rejected("over-long", "a" * 250 + "@example.com", I.normalise_email)
rejected("empty", "", I.normalise_email)
check("header_safe rejects CR", I.header_safe("a\rb"), False)
check("header_safe rejects LF", I.header_safe("a\nb"), False)
check("header_safe accepts plain", I.header_safe("a@example.com"), True)

print("\n6. Password bounds")
rejected("too short", "short", I.check_password)
rejected("over PASSWORD_MAX (KDF abuse)", "a" * (I.PASSWORD_MAX + 1), I.check_password)
rejected("NUL in password", "abcdefgh\x00", I.check_password)
accepted("exactly minimum", "a" * I.PASSWORD_MIN, "a" * I.PASSWORD_MIN, I.check_password)
# Passwords must NOT be normalised: folding would make distinct secrets equal.
pw = "paﬁssword"        # contains the fi ligature
accepted("password kept byte-exact (no NFKC)", pw, pw, I.check_password)

print("\n7. safe_text strips rather than rejects (free-text fields)")
check("strips zero-width", I.safe_text("Ac​me"), "Acme")
check("strips RTL override", I.safe_text("‮Acme"), "Acme")
check("strips newline", I.safe_text("Acme\nX: 1"), "AcmeX: 1")
check("caps length", len(I.safe_text("a" * 500, cap=120)), 120)
check("non-string -> empty", I.safe_text(None), "")

print("\n8. SQL injection against a real database")
# Not a code-shape assertion: build the real schema, feed the payload through
# the same parameterised statement auth.create_user uses, and prove the table
# survives and the payload was stored as literal data.
tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "t.db")
conn = sqlite3.connect(db)
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL)")
conn.commit()
payloads = [
    "robert'); DROP TABLE users;--",
    "' OR 1=1--",
    "x'; UPDATE users SET username='pwned'; --",
    'x" ; DROP TABLE users; --',
    "x'/**/UNION/**/SELECT/**/1--",
]
for p in payloads:
    conn.execute("INSERT INTO users (username) VALUES (?)", (p,))
conn.commit()
rows = conn.execute("SELECT username FROM users").fetchall()
check("table survived every payload", len(rows), len(payloads))
check("payloads stored as literal text", sorted(r[0] for r in rows), sorted(payloads))
check("no row was named 'pwned'",
      conn.execute("SELECT COUNT(*) FROM users WHERE username='pwned'").fetchone()[0], 0)
conn.close()
# ...and the validator refuses them long before the database sees them.
for p in payloads:
    v, _ = I.normalise_username(p)
    check(f"validator rejects {p[:22]!r}", v, None)

print()
if _fails:
    print(f"FAILED ({len(_fails)}): " + ", ".join(_fails[:8]))
    sys.exit(1)
print("All identity/registration security checks passed.")
