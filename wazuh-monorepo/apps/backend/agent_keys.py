"""
Ingestion keys and the Agents entitlement for Selenne Agents.

Selenne Agents (the AI-agent monitoring product, separate container) shares
these accounts. Its data plane authenticates with per-project API keys that
live here, in users.db, next to the users they belong to:

  table agent_api_keys     — id, username, project, key_hash (SHA-256),
                             hint, created_at, last_used_at, revoked_at
  table agent_entitlements — username, active, source, updated_at
                             (written by the Stripe add-on webhook later;
                             'admin' grants meanwhile)

The Agents service never opens this file. It POSTs each key to
/internal/keys/verify (server.py) and caches the answer for a minute, so
revoking a key here stops ingestion within that window.

Only the SHA-256 digest of a key is stored, like session tokens: a copied
users.db cannot be replayed as live ingestion keys. The raw key is shown to
the user exactly once, at creation.
"""

import logging
import os
import re
import secrets

import auth
from auth import _conn, _db_lock, _iso, _now, _token_digest

log = logging.getLogger("agent_keys")

KEY_PREFIX = "sk_sel_"
MAX_ACTIVE_KEYS = 20
_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# No billing for Agents yet: while this is on, every account is entitled.
# Turn it off once the Stripe add-on writes agent_entitlements.
OPEN_BETA = os.environ.get("AGENTS_OPEN_BETA", "1") == "1"


def init_db():
    with _db_lock, _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_api_keys (
                id           TEXT PRIMARY KEY,
                username     TEXT NOT NULL,
                project      TEXT NOT NULL,
                key_hash     TEXT UNIQUE NOT NULL,
                hint         TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                last_used_at TEXT NOT NULL DEFAULT '',
                revoked_at   TEXT NOT NULL DEFAULT ''
            )""")
        conn.execute("CREATE INDEX IF NOT EXISTS agent_api_keys_user "
                     "ON agent_api_keys (username)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_entitlements (
                username   TEXT PRIMARY KEY,
                active     INTEGER NOT NULL DEFAULT 0,
                source     TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            )""")
    auth._restrict_db_permissions()


def normalise_project(raw):
    """(project, error). Projects name what a key is for — one per agent or
    per environment — and show up as-is in the Agents console."""
    project = str(raw or "").strip()
    if not _PROJECT_RE.match(project):
        return None, ("Project name: 1–64 characters, letters, digits, '.', '_' "
                      "or '-', starting with a letter or digit")
    return project, None


def _public(row):
    return {"id": row["id"], "project": row["project"], "hint": row["hint"],
            "created_at": row["created_at"], "last_used_at": row["last_used_at"] or None,
            "revoked_at": row["revoked_at"] or None, "active": not row["revoked_at"]}


def create_key(username, project):
    """Returns (raw_key, public_record, error)."""
    project, err = normalise_project(project)
    if err:
        return None, None, err
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    key_id = "k_" + secrets.token_hex(6)
    now = _iso(_now())
    with _db_lock, _conn() as conn:
        active = conn.execute(
            "SELECT COUNT(*) FROM agent_api_keys WHERE username = ? AND revoked_at = ''",
            (username,)).fetchone()[0]
        if active >= MAX_ACTIVE_KEYS:
            return None, None, f"Limit of {MAX_ACTIVE_KEYS} active keys reached — revoke one first"
        conn.execute(
            "INSERT INTO agent_api_keys (id, username, project, key_hash, hint, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (key_id, username, project, _token_digest(raw), f"{raw[:11]}…{raw[-4:]}", now))
        row = conn.execute("SELECT * FROM agent_api_keys WHERE id = ?", (key_id,)).fetchone()
    return raw, _public(row), None


def list_keys(username):
    with _db_lock, _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM agent_api_keys WHERE username = ? "
            "ORDER BY revoked_at = '' DESC, created_at DESC", (username,)).fetchall()
    return [_public(r) for r in rows]


def revoke_key(username, key_id):
    """Only the owner can revoke; someone else's id looks like a missing one."""
    with _db_lock, _conn() as conn:
        cur = conn.execute(
            "UPDATE agent_api_keys SET revoked_at = ? "
            "WHERE id = ? AND username = ? AND revoked_at = ''",
            (_iso(_now()), str(key_id), username))
    return cur.rowcount == 1


def is_entitled(username, role=None):
    if OPEN_BETA or role == "admin":
        return True
    with _db_lock, _conn() as conn:
        row = conn.execute("SELECT active FROM agent_entitlements WHERE username = ?",
                           (username,)).fetchone()
    return bool(row and row["active"])


def set_entitlement(username, active, source):
    with _db_lock, _conn() as conn:
        conn.execute(
            "INSERT INTO agent_entitlements (username, active, source, updated_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET "
            "active = excluded.active, source = excluded.source, updated_at = excluded.updated_at",
            (username, 1 if active else 0, str(source), _iso(_now())))


def verify(raw_key):
    """The answer /internal/keys/verify returns for one key.

    A key is valid only while it is unrevoked AND its account still exists —
    a deleted user's keys die with it even if nobody revoked them.
    """
    if not isinstance(raw_key, str) or not raw_key.startswith(KEY_PREFIX) \
            or len(raw_key) > 200:
        return {"valid": False}
    digest = _token_digest(raw_key)
    with _db_lock, _conn() as conn:
        row = conn.execute(
            "SELECT k.id, k.username, k.project, u.role FROM agent_api_keys k "
            "JOIN users u ON u.username = k.username "
            "WHERE k.key_hash = ? AND k.revoked_at = ''", (digest,)).fetchone()
        if row is None:
            return {"valid": False}
        # Ingest caches answers for a minute, so this runs at most about once
        # per key per minute — cheap enough to keep "last used" honest.
        conn.execute("UPDATE agent_api_keys SET last_used_at = ? WHERE id = ?",
                     (_iso(_now()), row["id"]))
    return {"valid": True, "username": row["username"], "project": row["project"],
            "entitled": is_entitled(row["username"], row["role"]), "key_id": row["id"]}
