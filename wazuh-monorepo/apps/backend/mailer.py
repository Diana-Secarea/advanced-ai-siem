"""Minimal SMTP sender for transactional mail (email verification).

Separate from tickets.py because that one is bound to the ticket table: it
writes its outcome back to a row and always sends to a fixed operator address.
This sends to an address the *registrant* supplied, which is a different threat
model — the recipient is attacker-controlled, so every header value is checked
before it goes near the message.

Configuration is the same environment already documented for tickets:
    SMTP_HOST, SMTP_PORT (default 587, STARTTLS), SMTP_USER, SMTP_PASS
Unconfigured is not an error: send() reports it, and the caller decides. In
development that keeps registration usable without a mail server.
"""

import logging
import os
import smtplib
from email.message import EmailMessage

import identity

log = logging.getLogger("backend")

#: Public base URL used to build links in outgoing mail. Must not be taken from
#: the request Host header: an attacker-supplied Host would make us mail the
#: victim a verification link pointing at the attacker's server.
PUBLIC_URL_ENV = "SELENNE_PUBLIC_URL"


def public_url():
    return os.environ.get(PUBLIC_URL_ENV, "").strip().rstrip("/")


def is_configured():
    return bool(os.environ.get("SMTP_HOST", "").strip())


def send(to_address, subject, body):
    """Send one plain-text message. Returns (ok, status).

    ``status`` is a short string for logs and audit — never surfaced verbatim
    to the caller of a public endpoint, since it can carry server detail.
    """
    if not (identity.header_safe(to_address) and identity.header_safe(subject)):
        # Reachable only if a caller skipped identity.normalise_email.
        log.warning("refusing to send mail with CR/LF in a header")
        return False, "invalid header"

    host = os.environ.get("SMTP_HOST", "").strip()
    if not host:
        return False, "unconfigured (set SMTP_HOST/SMTP_USER/SMTP_PASS)"

    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASS", "").strip()
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError:
        port = 587

    msg = EmailMessage()
    # EmailMessage rejects embedded newlines in headers on its own; the check
    # above is the belt to this braces, and gives a clean log line instead of
    # an exception from deep in the email package.
    msg["Subject"] = subject
    msg["From"] = user or "no-reply@selenne.app"
    msg["To"] = to_address
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True, "sent"
    except Exception as exc:                       # noqa: BLE001 — reported, not raised
        log.warning("verification mail to %s failed: %s", to_address, exc)
        return False, f"failed: {exc}"[:200]


def send_verification(to_address, username, token):
    """Compose and send the verification mail. Returns (ok, status)."""
    base = public_url()
    link = f"{base}/api/auth/verify?token={token}" if base else None
    body = (
        f"Hi {username},\n\n"
        "Confirm this address to finish setting up your Selenne account.\n\n"
        + (f"{link}\n\n" if link
           else f"Your verification code:\n\n    {token}\n\n")
        + "The link expires in 24 hours. If you did not create this account, "
          "ignore this message — nothing was activated.\n"
    )
    if not base:
        log.warning("%s is unset — verification mail carries a bare token "
                    "instead of a link", PUBLIC_URL_ENV)
    return send(to_address, "Confirm your Selenne account", body)
