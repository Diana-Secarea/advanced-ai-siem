"""Per-account endpoint ownership.

Every alert Wazuh produces carries the name of the agent that reported it.
This module answers one question — *which Selenne account owns that endpoint* —
so the alert read paths can show each user only their own machines.

Ownership is resolved in two steps:

1. An explicit row in ``agent_owners`` (set by an admin, or recorded at
   enrolment). Always wins.
2. Otherwise the agent's own name: the Windows installer enrols machines as
   ``<owner>__<COMPUTERNAME>``, so the owner travels with the agent and
   survives a database restore or a manual re-enrolment.

Anything that resolves to no owner (the manager itself, agents enrolled by
hand) is visible to admins only — failing closed rather than leaking.
"""

import datetime
import os
import sqlite3
import threading

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

#: separator between the owner and the machine name in an enrolled agent name
SEP = "__"

_lock = threading.Lock()
_cache = {}          # agent_name -> owner|None
_cache_loaded = False


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock, _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_owners (
                agent_name TEXT PRIMARY KEY,
                owner      TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
    _invalidate()


def _invalidate():
    global _cache_loaded
    _cache.clear()
    _cache_loaded = False


def _load_cache():
    global _cache_loaded
    if _cache_loaded:
        return
    try:
        with _conn() as conn:
            rows = conn.execute("SELECT agent_name, owner FROM agent_owners").fetchall()
        _cache.update({r["agent_name"]: r["owner"] for r in rows})
    except sqlite3.Error:
        pass          # fall back to name-derived ownership
    _cache_loaded = True


def derive_owner(agent_name):
    """Owner encoded in the agent name (``alice__LAPTOP-1`` -> ``alice``)."""
    name = (agent_name or "").strip()
    if SEP not in name:
        return None
    owner = name.split(SEP, 1)[0].strip().lower()
    return owner or None


def machine_name(agent_name):
    """The part a human cares about — ``alice__LAPTOP-1`` -> ``LAPTOP-1``."""
    name = (agent_name or "").strip()
    return name.split(SEP, 1)[1] if SEP in name else name


def owner_of(agent_name):
    """Account owning this endpoint, or None when unclaimed."""
    name = (agent_name or "").strip()
    if not name:
        return None
    with _lock:
        _load_cache()
        if name in _cache:
            return _cache[name]
    owner = derive_owner(name)
    with _lock:
        _cache[name] = owner
    return owner


def visible_to(agent_name, username, is_admin):
    """Admins see everything; everyone else sees only what they own."""
    if is_admin:
        return True
    if not username:
        return False
    return owner_of(agent_name) == username


def assign(agent_name, owner):
    """Explicitly bind an endpoint to an account (admin action)."""
    name = (agent_name or "").strip()
    owner = (owner or "").strip().lower()
    if not name or not owner:
        return False, "agent_name and owner are required"
    with _lock, _conn() as conn:
        conn.execute(
            "INSERT INTO agent_owners (agent_name, owner, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(agent_name) DO UPDATE SET owner = excluded.owner",
            (name, owner, datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")))
    _invalidate()
    return True, None


def unassign(agent_name):
    with _lock, _conn() as conn:
        conn.execute("DELETE FROM agent_owners WHERE agent_name = ?",
                     ((agent_name or "").strip(),))
    _invalidate()
    return True, None


def explicit_assignments():
    with _lock, _conn() as conn:
        rows = conn.execute(
            "SELECT agent_name, owner, created_at FROM agent_owners "
            "ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]
