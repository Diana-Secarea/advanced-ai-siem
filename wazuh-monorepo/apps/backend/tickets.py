"""
Support-ticket service for the Wazuh AI Threat Engine.

Tickets are stored in the same SQLite DB as the users (backend/users.db) and
every new ticket is emailed to the platform owner (TICKET_EMAIL_TO, default
diana.secarea1111@gmail.com) in a background thread.

Email transport is plain SMTP, configured via env:
    SMTP_HOST  (e.g. smtp.gmail.com)     SMTP_USER
    SMTP_PORT  (default 587, STARTTLS)   SMTP_PASS  (Gmail: an App Password)

Without SMTP configuration the ticket is still stored and listed in the UI —
`email_status` records 'unconfigured' / 'sent' / 'failed: …' so nothing is
silently lost.
"""

import datetime
import os
import smtplib
import sqlite3
import threading
from email.mime.text import MIMEText

from auth import DB_PATH, _db_lock  # same DB + lock as the account store

TICKET_EMAIL_TO = os.environ.get("TICKET_EMAIL_TO", "diana.secarea1111@gmail.com")
SEVERITIES = ("low", "medium", "high", "critical")


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db_lock, _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT NOT NULL,
                subject      TEXT NOT NULL,
                body         TEXT NOT NULL,
                severity     TEXT NOT NULL DEFAULT 'medium',
                status       TEXT NOT NULL DEFAULT 'open',
                email_status TEXT NOT NULL DEFAULT 'pending',
                created_at   TEXT NOT NULL
            )""")


def _send_email(ticket_id, username, subject, body, severity):
    """Background: email the ticket to the owner; record the outcome."""
    host = os.environ.get("SMTP_HOST", "").strip()
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASS", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587"))

    if not host:
        status = "unconfigured (set SMTP_HOST/SMTP_USER/SMTP_PASS)"
    else:
        try:
            msg = MIMEText(
                f"Ticket #{ticket_id} — severity {severity.upper()}\n"
                f"Raised by: {username}\n"
                f"At: {datetime.datetime.utcnow().isoformat()}Z\n\n{body}\n",
                "plain", "utf-8")
            msg["Subject"] = f"[Selene] #{ticket_id} {severity.upper()}: {subject}"
            msg["From"] = user or "shield@localhost"
            msg["To"] = TICKET_EMAIL_TO
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.starttls()
                if user:
                    s.login(user, password)
                s.sendmail(msg["From"], [TICKET_EMAIL_TO], msg.as_string())
            status = "sent"
        except Exception as e:
            status = f"failed: {e}"[:200]

    with _db_lock, _conn() as conn:
        conn.execute("UPDATE tickets SET email_status = ? WHERE id = ?", (status, ticket_id))
    print(f"[tickets] #{ticket_id} email → {TICKET_EMAIL_TO}: {status}")


def create(username, subject, body, severity="medium"):
    """Store the ticket and fire the email in the background. Returns dict."""
    subject = (subject or "").strip()[:200]
    body = (body or "").strip()[:5000]
    severity = severity if severity in SEVERITIES else "medium"
    if not subject or not body:
        return None
    created = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    with _db_lock, _conn() as conn:
        cur = conn.execute(
            "INSERT INTO tickets (username, subject, body, severity, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, subject, body, severity, created))
        ticket_id = cur.lastrowid
    threading.Thread(target=_send_email,
                     args=(ticket_id, username, subject, body, severity),
                     daemon=True).start()
    return {"id": ticket_id, "username": username, "subject": subject,
            "severity": severity, "status": "open",
            "email_status": "pending", "created_at": created}


def list_for(username, is_admin=False, limit=50):
    """A user sees their own tickets; admins see everything."""
    with _db_lock, _conn() as conn:
        if is_admin:
            rows = conn.execute(
                "SELECT * FROM tickets ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM tickets WHERE username = ? ORDER BY id DESC LIMIT ?",
                (username, limit)).fetchall()
    return [dict(r) for r in rows]


def set_status(ticket_id, status):
    if status not in ("open", "in_progress", "closed"):
        return False
    with _db_lock, _conn() as conn:
        cur = conn.execute("UPDATE tickets SET status = ? WHERE id = ?", (status, ticket_id))
        return cur.rowcount > 0
