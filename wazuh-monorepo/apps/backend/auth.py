"""
Authentication for the Wazuh AI Threat Engine backend.

User accounts live in an SQLite database: backend/users.db
  table users    — id, username, password_hash (PBKDF2 via werkzeug), role, created_at
  table sessions — token, username, created_at, expires_at  (revocable server-side)

Login issues an opaque random token delivered as an HttpOnly cookie, so the
existing frontend fetches and the SSE chat stream work unchanged (same-origin
cookies ride along automatically). Tokens also work as a Bearer header for
API clients:  Authorization: Bearer <token>

On first startup an 'admin' account is created; the password comes from the
ADMIN_PASSWORD env var, or is generated randomly and printed ONCE to stdout.

Disable the whole gate with AUTH_ENABLED=0 (e.g. for local experiments).
"""

import contextlib
import datetime
import hashlib
import logging
import os
import secrets
import sqlite3
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

import identity

# Propagates to the root logger configured by logging_setup. Never print():
# under systemd stdout is a block-buffered pipe, so security events would sit
# in a buffer instead of reaching journald. Logging writes to stderr, unbuffered.
log = logging.getLogger("auth")

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
SESSION_TTL_HOURS = int(os.environ.get("AUTH_SESSION_TTL_HOURS", "72"))

# --- Brute-force lockout -----------------------------------------------------
# After MAX_FAILS consecutive failures for a (username, ip) pair the pair is
# locked out with exponential backoff: 60s, 120s, 240s … capped at 1 hour.
MAX_FAILS = 5
LOCKOUT_BASE_SECONDS = 60
LOCKOUT_CAP_SECONDS = 3600
_failed_logins = {}   # "user|ip" -> {"count": int, "locked_until": epoch}
_failed_lock = threading.Lock()

# A real PBKDF2 hash used to burn the same CPU time when the username does not
# exist — otherwise response timing reveals which usernames are registered.
_DUMMY_HASH = generate_password_hash("timing-equalizer-dummy")

_db_lock = threading.Lock()


def _token_digest(token):
    """Sessions are stored as SHA-256 digests — a stolen users.db file cannot
    be replayed as live session cookies."""
    return hashlib.sha256(token.encode()).hexdigest()


def lockout_remaining(username, ip):
    """Seconds until this (username, ip) may try again; 0 when not locked."""
    key = f"{(username or '').strip().lower()}|{ip}"
    with _failed_lock:
        entry = _failed_logins.get(key)
        if not entry:
            return 0
        remaining = entry.get("locked_until", 0) - time.time()
        return max(0, int(remaining))


def _record_failure(username, ip):
    key = f"{(username or '').strip().lower()}|{ip}"
    now = time.time()
    with _failed_lock:
        entry = _failed_logins.setdefault(key, {"count": 0, "locked_until": 0})
        entry["count"] += 1
        if entry["count"] >= MAX_FAILS:
            backoff = min(LOCKOUT_CAP_SECONDS,
                          LOCKOUT_BASE_SECONDS * (2 ** (entry["count"] - MAX_FAILS)))
            entry["locked_until"] = now + backoff
        # bound the map so it can't be used for memory exhaustion
        if len(_failed_logins) > 10000:
            for k in [k for k, v in _failed_logins.items()
                      if v.get("locked_until", 0) < now and v.get("count", 0) < MAX_FAILS]:
                _failed_logins.pop(k, None)


def record_failure(username, ip):
    """Public hook so non-login flows (e.g. password change) feed the lockout."""
    _record_failure(username, ip)


def _record_success(username, ip):
    with _failed_lock:
        _failed_logins.pop(f"{(username or '').strip().lower()}|{ip}", None)


@contextlib.contextmanager
def _conn():
    """Open users.db, commit-or-rollback, then *close*.

    `with sqlite3.connect(...) as conn` only ends the transaction — it does
    NOT close the connection. Returning a bare connection here leaked one file
    descriptor per call, and validate_token() runs on every authenticated
    request: production hit the 1024-fd soft limit and every route began
    failing with "unable to open database file" (really OSError 24).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        with conn:                      # commit on success, rollback on error
            yield conn
    finally:
        conn.close()


def _now():
    return datetime.datetime.utcnow()


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(text):
    """Inverse of _iso; None for empty or malformed values.

    The stored format is lexicographically sortable, which is why session
    cleanup can compare it as a string. Verification needs the actual delta to
    tell the caller how long to wait, so it parses instead.
    """
    try:
        return datetime.datetime.strptime(text or "", "%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return None


def _restrict_db_permissions():
    """Keep the credential store owner-only (0600).

    Applied on every startup, not just at creation: SQLite's -wal/-shm side
    files are recreated on demand and would otherwise inherit the umask.
    """
    for path in (DB_PATH, DB_PATH + "-wal", DB_PATH + "-shm"):
        try:
            if os.path.exists(path) and (os.stat(path).st_mode & 0o077):
                os.chmod(path, 0o600)
        except OSError as exc:                      # e.g. NFS, foreign owner
            log.warning("Could not restrict %s: %s", path, exc)


def init_db():
    """Create tables and seed the admin account if the DB is fresh."""
    with _db_lock, _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'analyst',
                created_at    TEXT NOT NULL
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )""")
        # Profile fields (added later — ALTER is a no-op when they exist)
        for col, decl in (("email", "TEXT DEFAULT ''"),
                          ("organisation", "TEXT DEFAULT ''"),
                          ("last_login", "TEXT DEFAULT ''"),
                          ("avatar", "TEXT DEFAULT ''"),      # data-URI, capped by API
                          ("email_verified", "INTEGER DEFAULT 0"),
                          ("verify_token_hash", "TEXT DEFAULT ''"),
                          ("verify_expires_at", "TEXT DEFAULT ''"),
                          ("verify_sent_at", "TEXT DEFAULT ''")):
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError:
                pass  # column already exists
            else:
                if col == "email_verified":
                    # Accounts that predate verification are grandfathered in.
                    # ALTER backfills the DEFAULT 0, which would otherwise lock
                    # every existing operator out of the collector downloads.
                    conn.execute("UPDATE users SET email_verified = 1")
        have_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        if not have_users:
            password = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
            # email_verified = 1: the bootstrap admin has no address to confirm,
            # and on a FRESH database the ALTER above ran against an empty table,
            # so the grandfathering UPDATE could not reach this row.
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at, "
                "email_verified) VALUES (?, ?, 'admin', ?, 1)",
                ("admin", generate_password_hash(password), _iso(_now())),
            )
            if os.environ.get("ADMIN_PASSWORD"):
                # Already in the operator's env file — don't copy it into the logs.
                log.info("Created default account 'admin' (password from ADMIN_PASSWORD env)")
            else:
                log.warning("Created default account  admin / %s  "
                            "(GENERATED — SAVE IT NOW, it is not shown again)", password)
    _restrict_db_permissions()


def create_user(username, password, role="analyst", email=None,
                require_email=True):
    """Returns (ok, error_message).

    Validation lives in ``identity`` because the username is the tenant key,
    not a display string — see that module for what the previous check let
    through (Cyrillic look-alikes, the ``__`` separator, invisible characters).

    ``require_email`` is only ever False for internal/admin provisioning; the
    self-service registration route must leave it True.
    """
    username, err = identity.normalise_username(username)
    if err:
        return False, err
    password, err = identity.check_password(password)
    if err:
        return False, err

    if email is None and not require_email:
        email = ""
    else:
        email, err = identity.normalise_email(email)
        if err:
            return False, err

    try:
        with _db_lock, _conn() as conn:
            if email:
                # One account per address. Checked explicitly rather than with a
                # UNIQUE index so the pre-existing rows (empty email) stay legal.
                taken = conn.execute(
                    "SELECT 1 FROM users WHERE email = ? LIMIT 1", (email,)).fetchone()
                if taken:
                    return False, "That email is already registered"
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at, "
                "email, email_verified) VALUES (?, ?, ?, ?, ?, 0)",
                (username, generate_password_hash(password), role, _iso(_now()),
                 email),
            )
        return True, None
    except sqlite3.IntegrityError:
        return False, "Username already exists"


# --------------------------------------------------------------------------- #
#  Email verification
# --------------------------------------------------------------------------- #
#: How long a verification link stays usable.
VERIFY_TTL_HOURS = 24
#: Minimum gap between verification emails for one account (anti mail-bombing).
VERIFY_RESEND_SECONDS = 120


def issue_verification(username):
    """Mint a verification token. Returns (raw_token, error).

    Only the SHA-256 digest is stored, the same way session tokens are: a
    database read must not yield a working link.
    """
    username = identity.canonical_username(username)
    if not username:
        return None, "No such account"
    now = _now()
    with _db_lock, _conn() as conn:
        row = conn.execute(
            "SELECT email, email_verified, verify_sent_at FROM users WHERE username = ?",
            (username,)).fetchone()
        if row is None:
            return None, "No such account"
        if row["email_verified"]:
            return None, "Email is already verified"
        if not row["email"]:
            return None, "No email address on this account"
        last = _parse_iso(row["verify_sent_at"])
        if last and (now - last).total_seconds() < VERIFY_RESEND_SECONDS:
            wait = int(VERIFY_RESEND_SECONDS - (now - last).total_seconds())
            return None, f"Please wait {wait}s before requesting another email"
        token = secrets.token_urlsafe(32)
        conn.execute(
            "UPDATE users SET verify_token_hash = ?, verify_expires_at = ?, "
            "verify_sent_at = ? WHERE username = ?",
            (_token_digest(token),
             _iso(now + datetime.timedelta(hours=VERIFY_TTL_HOURS)),
             _iso(now), username))
    return token, None


def verify_email(raw_token):
    """Consume a verification token. Returns (username, error).

    Looked up by digest, so the comparison is an indexed equality on a hash
    rather than a string compare against a secret.
    """
    if not isinstance(raw_token, str) or not (16 <= len(raw_token) <= 200):
        return None, "Invalid verification link"
    with _db_lock, _conn() as conn:
        row = conn.execute(
            "SELECT username, verify_expires_at FROM users "
            "WHERE verify_token_hash = ? AND verify_token_hash != ''",
            (_token_digest(raw_token),)).fetchone()
        if row is None:
            return None, "Invalid or already-used verification link"
        expires = _parse_iso(row["verify_expires_at"])
        if expires is None or _now() > expires:
            return None, "This verification link has expired — request a new one"
        conn.execute(
            "UPDATE users SET email_verified = 1, verify_token_hash = '', "
            "verify_expires_at = '' WHERE username = ?", (row["username"],))
    log.info("Email verified for '%s'", row["username"])
    return row["username"], None


def is_email_verified(username):
    """True when the account may use verified-only features. Fails closed."""
    username = identity.canonical_username(username)
    if not username:
        return False
    with _db_lock, _conn() as conn:
        row = conn.execute(
            "SELECT email_verified FROM users WHERE username = ?",
            (username,)).fetchone()
    return bool(row and row["email_verified"])


def login(username, password, ip="?"):
    """Verify credentials; returns (token, user_dict) or (None, None).

    Constant-shape: a missing user still pays the PBKDF2 cost (anti user
    enumeration), and every failure feeds the per-(user, ip) lockout.
    """
    username = (username or "").strip().lower()
    with _db_lock, _conn() as conn:
        row = conn.execute(
            "SELECT username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None:
            check_password_hash(_DUMMY_HASH, password or "")  # burn equal time
            _record_failure(username, ip)
            log.warning("Failed login for '%s' from %s (no such user)", username, ip)
            return None, None
        if not check_password_hash(row["password_hash"], password or ""):
            _record_failure(username, ip)
            log.warning("Failed login for '%s' from %s (bad password)", username, ip)
            return None, None
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (_token_digest(token), username, _iso(_now()),
             _iso(_now() + datetime.timedelta(hours=SESSION_TTL_HOURS))),
        )
        conn.execute("UPDATE users SET last_login = ? WHERE username = ?",
                     (_iso(_now()), row["username"]))
        # opportunistic cleanup of expired sessions
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_iso(_now()),))
    _record_success(username, ip)
    return token, {"username": row["username"], "role": row["role"]}


def change_password(username, current_password, new_password, keep_token=None):
    """Change a password after re-verifying the current one.

    Returns (ok, error_message). Every other session of that user is dropped, so
    a stolen cookie stops working the moment the owner changes their password.
    """
    username = (username or "").strip().lower()
    if len(new_password or "") < 8:
        return False, "New password must be at least 8 characters"
    if new_password == current_password:
        return False, "New password must differ from the current one"
    with _db_lock, _conn() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return False, "Account not found"
        if not check_password_hash(row["password_hash"], current_password or ""):
            return False, "Current password is incorrect"
        conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                     (generate_password_hash(new_password), username))
        if keep_token:
            conn.execute("DELETE FROM sessions WHERE username = ? AND token != ?",
                         (username, _token_digest(keep_token)))
        else:
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
    log.info("Password changed for '%s' — other sessions revoked", username)
    return True, None


def validate_token(token):
    """Return {'username', 'role'} for a live session token, else None."""
    if not token or len(token) > 128:
        return None
    with _db_lock, _conn() as conn:
        row = conn.execute(
            "SELECT s.username, s.expires_at, u.role FROM sessions s "
            "JOIN users u ON u.username = s.username WHERE s.token = ?",
            (_token_digest(token),),
        ).fetchone()
    if row is None or row["expires_at"] < _iso(_now()):
        return None
    return {"username": row["username"], "role": row["role"]}


def logout(token):
    if not token:
        return
    with _db_lock, _conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (_token_digest(token),))


def list_users():
    with _db_lock, _conn() as conn:
        rows = conn.execute(
            "SELECT username, role, created_at, email, organisation, email_verified "
            "FROM users ORDER BY created_at"
        ).fetchall()
    return [dict(r) for r in rows]


def admin_accounts():
    """Every account plus the activity a console admin needs to judge it.

    Avatars are deliberately left out — they are data-URIs of up to 300 KB and
    a hundred of them would make this response megabytes wide; the UI draws a
    monogram from the username instead.
    """
    now = _iso(_now())
    with _db_lock, _conn() as conn:
        rows = conn.execute(
            "SELECT u.username, u.role, u.created_at, u.email, u.organisation, "
            "       u.last_login, "
            "       (SELECT COUNT(*) FROM sessions s "
            "         WHERE s.username = u.username AND s.expires_at > ?) AS live_sessions "
            "FROM users u ORDER BY u.created_at DESC",
            (now,),
        ).fetchall()

    accounts = []
    for row in rows:
        acct = dict(row)
        # 'active' = holds a session right now; 'idle' = has signed in before;
        # 'never' = created (by an admin or a signup) but never used.
        acct["status"] = ("active" if acct["live_sessions"]
                          else "idle" if acct["last_login"]
                          else "never")
        accounts.append(acct)
    return accounts


def signup_series(days=30):
    """Accounts created per day over the last `days` days, oldest first.

    Zero-filled so the chart keeps a flat baseline on quiet days.
    """
    days = max(1, min(int(days or 30), 365))
    first = _now().date() - datetime.timedelta(days=days - 1)
    with _db_lock, _conn() as conn:
        rows = conn.execute(
            "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS c FROM users "
            "WHERE substr(created_at, 1, 10) >= ? GROUP BY day",
            (first.isoformat(),),
        ).fetchall()
    counts = {r["day"]: r["c"] for r in rows}
    return [{"date": (first + datetime.timedelta(days=i)).isoformat(),
             "count": counts.get((first + datetime.timedelta(days=i)).isoformat(), 0)}
            for i in range(days)]


def get_profile(username):
    with _db_lock, _conn() as conn:
        row = conn.execute(
            "SELECT username, role, created_at, email, organisation, avatar, "
            "email_verified FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def update_profile(username, email=None, organisation=None, avatar=None):
    """Update profile fields; None leaves a field untouched.

    Returns (profile, error). Changing the address RESETS verification: a
    confirmed flag that survives an arbitrary change to the thing it confirmed
    would let one throwaway confirmation bless every later address.
    """
    username = identity.canonical_username(username)
    sets, params = [], []
    email_changed = False
    if email is not None:
        email, err = identity.normalise_email(email)
        if err:
            return None, err
        with _db_lock, _conn() as conn:
            current = conn.execute(
                "SELECT email FROM users WHERE username = ?", (username,)).fetchone()
            taken = conn.execute(
                "SELECT 1 FROM users WHERE email = ? AND username != ? LIMIT 1",
                (email, username)).fetchone()
        if taken:
            return None, "That email is already registered"
        email_changed = not current or current["email"] != email
        sets.append("email = ?"); params.append(email)
        if email_changed:
            sets.append("email_verified = 0")
            sets.append("verify_token_hash = ''")
            sets.append("verify_expires_at = ''")
    if organisation is not None:
        sets.append("organisation = ?")
        params.append(identity.safe_text(organisation, cap=120))
    if avatar is not None:
        sets.append("avatar = ?"); params.append(avatar)
    if sets:
        params.append(username)
        with _db_lock, _conn() as conn:
            conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE username = ?", params)
        if email_changed:
            log.info("Email changed for '%s' — verification reset", username)
    return get_profile(username), None
