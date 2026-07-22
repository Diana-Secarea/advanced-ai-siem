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

import datetime
import hashlib
import os
import secrets
import sqlite3
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

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


def _record_success(username, ip):
    with _failed_lock:
        _failed_logins.pop(f"{(username or '').strip().lower()}|{ip}", None)


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _now():
    return datetime.datetime.utcnow()


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


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
                          ("avatar", "TEXT DEFAULT ''")):   # data-URI, capped by API
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError:
                pass  # column already exists
        have_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        if not have_users:
            password = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) "
                "VALUES (?, ?, 'admin', ?)",
                ("admin", generate_password_hash(password), _iso(_now())),
            )
            source = "from ADMIN_PASSWORD env" if os.environ.get("ADMIN_PASSWORD") \
                else "GENERATED — SAVE IT NOW, it is not shown again"
            print(f"[auth] Created default account  admin / {password}  ({source})")


def create_user(username, password, role="analyst"):
    """Returns (ok, error_message)."""
    username = (username or "").strip().lower()
    if not username or not username.replace("_", "").replace("-", "").isalnum():
        return False, "Username must be alphanumeric (plus - and _)"
    if len(username) > 40:
        return False, "Username too long"
    if len(password or "") < 8:
        return False, "Password must be at least 8 characters"
    try:
        with _db_lock, _conn() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), role, _iso(_now())),
            )
        return True, None
    except sqlite3.IntegrityError:
        return False, "Username already exists"


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
            return None, None
        if not check_password_hash(row["password_hash"], password or ""):
            _record_failure(username, ip)
            print(f"[auth] Failed login for '{username}' from {ip}")
            return None, None
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (_token_digest(token), username, _iso(_now()),
             _iso(_now() + datetime.timedelta(hours=SESSION_TTL_HOURS))),
        )
        # opportunistic cleanup of expired sessions
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_iso(_now()),))
    _record_success(username, ip)
    return token, {"username": row["username"], "role": row["role"]}


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
            "SELECT username, role, created_at, email, organisation FROM users ORDER BY created_at"
        ).fetchall()
    return [dict(r) for r in rows]


def get_profile(username):
    with _db_lock, _conn() as conn:
        row = conn.execute(
            "SELECT username, role, created_at, email, organisation, avatar "
            "FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def update_profile(username, email=None, organisation=None, avatar=None):
    """Update profile fields; None leaves a field untouched. Returns profile."""
    sets, params = [], []
    if email is not None:
        sets.append("email = ?"); params.append(email.strip()[:120])
    if organisation is not None:
        sets.append("organisation = ?"); params.append(organisation.strip()[:120])
    if avatar is not None:
        sets.append("avatar = ?"); params.append(avatar)
    if sets:
        params.append(username)
        with _db_lock, _conn() as conn:
            conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE username = ?", params)
    return get_profile(username)
