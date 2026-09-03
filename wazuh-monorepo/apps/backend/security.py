"""
Registration & profile input hardening for the Selenne AI Threat Engine.

Everything a user can type at sign-up or on their profile (username, email,
organisation) eventually surfaces in three dangerous places:

  * the admin console and the alert-owner columns (rendered as HTML),
  * the LLM copilot's context when it reasons over accounts / tenancy, and
  * SQL statements against users.db.

The database layer already uses parameterised queries, so this module is NOT
the thing standing between a caller and an ``'; DROP TABLE users; --``.  It is
defence-in-depth: it rejects hostile *shapes* of input early, at the trust
boundary, so a value that would be a nuisance downstream never gets stored in
the first place.

Threats screened here
---------------------
  1. SQL-injection shapes      — DROP TABLE / UNION SELECT / stacked queries /
                                 comment sequences, even though the driver is
                                 parameterised.
  2. Prompt injection          — "ignore previous instructions", role/system
                                 spoofing, guardrail-delimiter smuggling; these
                                 strings would otherwise ride into the copilot's
                                 prompt via the account roster.
  3. Emoji / pictographs       — usernames and emails must be plain text, not
                                 emoji, so they can't be spoofed, can't break
                                 log alignment, and stay greppable.
  4. Unicode trickery          — zero-width joiners, BiDi overrides (the
                                 "Trojan Source" class), homoglyph mixing, and
                                 control characters that hide the true value.
  5. Null bytes / control chars — truncation attacks against C libraries and
                                 log-injection via embedded newlines.

No third-party dependencies — standard library only.
"""

import re
import unicodedata

# --- Prompt-injection screens (kept in sync with guardrails.py) --------------
# Registration fields are short identifiers, so we can afford to be stricter
# here than the chat pipeline (which merely flags-and-wraps): anything that
# looks like an instruction to the model is rejected outright.
_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|previous\s+|above\s+|prior\s+)*(instructions|rules|prompts?)",
    r"disregard\s+(the\s+)?(system|previous|above)",
    r"forget\s+(everything|all|your\s+instructions)",
    r"you\s+are\s+now\b",
    r"act\s+as\s+(if\s+you|a\s+different|an?\s+unrestricted)",
    r"(reveal|show|print|repeat|output)\s+(your\s+)?(system\s+)?prompt",
    r"(developer|dan|god|jailbreak)\s+mode",
    r"new\s+(system\s+)?instructions?\s*:",
    r"\[\s*system\s*\]|<\s*system\s*>|^\s*system\s*:",
    r"override\s+(safety|security|previous|your)",
    # Guardrail delimiter tokens must never appear verbatim in stored data,
    # or content could fake-close an UNTRUSTED block in the copilot prompt.
    r"<<<\s*(end_)?(untrusted_context|user_question)\s*>>>",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _INJECTION_PATTERNS]

# --- SQL-injection shapes (belt-and-suspenders behind parameterised SQL) -----
_SQL_PATTERNS = [
    r"\b(drop|truncate|alter)\s+(table|database|schema)\b",
    r"\b(delete|insert|update|select)\b.*\b(from|into|table|where|values)\b",
    r"\bunion\b\s+\bselect\b",
    r"\bexec(\s|\()|\bxp_cmdshell\b",
    r"--\s|/\*|\*/|;\s*\w",              # comment sequences & stacked queries
    r"'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+",  # ' OR 1=1
    r"\bor\b\s+1\s*=\s*1",
]
_SQL_RE = [re.compile(p, re.IGNORECASE) for p in _SQL_PATTERNS]

# --- Emoji / pictographic ranges --------------------------------------------
# Covers the main emoji planes plus dingbats, symbols, flags and the
# variation-selector / zero-width-joiner glue that composes multi-codepoint
# emoji. Deliberately broad: identifiers should be plain text.
_EMOJI_RE = re.compile(
    "["
    "\U0001F1E6-\U0001F1FF"   # regional indicators (flags)
    "\U0001F300-\U0001FAFF"   # symbols, pictographs, supplemental & extended-A
    "\U00002600-\U000027BF"   # misc symbols & dingbats
    "\U0001F000-\U0001F0FF"   # mahjong / dominoes / playing cards
    "\U00002190-\U000021FF"   # arrows
    "\U00002B00-\U00002BFF"   # misc symbols & arrows
    "\U0000FE00-\U0000FE0F"   # variation selectors
    "\U0001F900-\U0001F9FF"   # supplemental symbols & pictographs
    "\U00002700-\U000027BF"   # dingbats
    "‍"                  # zero-width joiner (emoji glue)
    "⃣"                  # combining enclosing keycap
    "]",
    flags=re.UNICODE,
)

# --- Unicode control / invisible / direction-spoofing codepoints -------------
# Zero-width and BiDi controls (the Trojan-Source class) that let a stored
# value render differently from its bytes.
_INVISIBLE_CHARS = {
    "​", "‌", "‍", "‎", "‏",      # zero-width & LRM/RLM
    "‪", "‫", "‬", "‭", "‮",      # BiDi embeddings/overrides
    "⁦", "⁧", "⁨", "⁩",                # BiDi isolates
    "﻿",                                              # zero-width no-break space (BOM)
}

# Usernames that must never be claimable by a self-service signup — they map to
# privileged roles, system paths, or would let an attacker impersonate the app.
RESERVED_USERNAMES = {
    "admin", "administrator", "root", "superuser", "sysadmin", "system",
    "selenne", "wazuh", "support", "security", "postmaster", "hostmaster",
    "webmaster", "operator", "anonymous", "null", "undefined", "me",
    "everyone", "all", "owner", "moderator", "mod", "api", "service",
}

# A short deny-list of the passwords that show up first in every breach corpus.
# Not a replacement for a real HIBP check — just stops the most trivial ones.
_COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "qwerty123", "letmein1", "welcome1", "admin123",
    "changeme", "iloveyou", "superman", "trustno1", "passw0rd",
    "abc12345", "111111111", "000000000", "qwertyuiop", "1q2w3e4r",
}

USERNAME_MAX = 40
EMAIL_MAX = 120
ORG_MAX = 120

# Deliberately conservative email shape: single @, a dotted domain, no spaces,
# no quoting, no comments. We are validating a login identifier, not proving
# RFC 5322 compliance.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


# --- Low-level screens -------------------------------------------------------

def normalize(text):
    """NFKC-normalise so homoglyph/compatibility forms collapse to one shape.

    Prevents 'ADMIN' spelled with fullwidth 'ＡＤＭＩＮ' or a Cyrylic 'а' from
    sneaking past the reserved-name and uniqueness checks.
    """
    return unicodedata.normalize("NFKC", text or "").strip()


def has_control_chars(text):
    """True if the string carries C0/C1 control codes or a NUL byte."""
    return any(ch == "\x00" or unicodedata.category(ch) == "Cc" for ch in text or "")


def has_invisible_chars(text):
    """True if the string carries zero-width or BiDi-override codepoints."""
    return any(ch in _INVISIBLE_CHARS for ch in text or "")


def has_emoji(text):
    """True if the string contains emoji or pictographic symbols."""
    return bool(_EMOJI_RE.search(text or ""))


def looks_like_prompt_injection(text):
    """True if the string matches a known prompt-injection shape."""
    return any(rx.search(text or "") for rx in _INJECTION_RE)


def looks_like_sql_injection(text):
    """True if the string matches a known SQL-injection shape."""
    return any(rx.search(text or "") for rx in _SQL_RE)


def _reject_hostile_shape(text, field="value"):
    """Shared screen for every free-ish field. Returns an error string or None."""
    if has_control_chars(text):
        return f"{field} contains control characters"
    if has_invisible_chars(text):
        return f"{field} contains invisible or direction-overriding characters"
    if has_emoji(text):
        return f"{field} must not contain emoji"
    if looks_like_prompt_injection(text):
        return f"{field} contains disallowed instruction-like text"
    if looks_like_sql_injection(text):
        return f"{field} contains disallowed SQL-like text"
    return None


# --- Field validators --------------------------------------------------------

def validate_username(raw):
    """Return (ok, cleaned_username, error).

    Cleaned value is NFKC-normalised and lower-cased. Enforces the historical
    'alphanumeric plus - and _' rule *after* normalisation, then layers the
    reserved-name and hostile-shape screens on top.
    """
    name = normalize(raw).lower()
    if not name:
        return False, None, "Username is required"
    if len(name) > USERNAME_MAX:
        return False, None, "Username too long"
    if len(name) < 3:
        return False, None, "Username must be at least 3 characters"
    # Emoji / invisible / injection screens run on the raw text so we catch
    # them even where the alnum check below would also fire (clearer errors).
    hostile = _reject_hostile_shape(name, "Username")
    if hostile:
        return False, None, hostile
    if not name.replace("_", "").replace("-", "").isalnum():
        return False, None, "Username must be alphanumeric (plus - and _)"
    # isalnum() is Unicode-aware and accepts letters from any script; pin it to
    # ASCII so 'admın' (dotless i) can't shadow a real account.
    if not name.isascii():
        return False, None, "Username must use ASCII letters and digits only"
    if name in RESERVED_USERNAMES:
        return False, None, "That username is reserved"
    return True, name, None


def validate_email(raw, required=True):
    """Return (ok, cleaned_email, error). Empty is allowed when not required."""
    email = normalize(raw).lower()
    if not email:
        if required:
            return False, None, "Email is required"
        return True, "", None
    if len(email) > EMAIL_MAX:
        return False, None, "Email too long"
    hostile = _reject_hostile_shape(email, "Email")
    if hostile:
        return False, None, hostile
    if not email.isascii():
        return False, None, "Email must use ASCII characters only"
    if not _EMAIL_RE.match(email):
        return False, None, "Enter a valid email address"
    return True, email, None


def validate_organisation(raw):
    """Return (ok, cleaned_org, error). Free text, but screened and length-capped."""
    org = normalize(raw)
    if not org:
        return True, "", None
    if len(org) > ORG_MAX:
        return False, None, "Organisation name too long"
    hostile = _reject_hostile_shape(org, "Organisation")
    if hostile:
        return False, None, hostile
    return True, org, None


def validate_password(password, username=None):
    """Return (ok, error). Length, common-password and username-echo checks."""
    pw = password or ""
    if len(pw) < 8:
        return False, "Password must be at least 8 characters"
    if len(pw) > 200:
        return False, "Password too long"
    if has_control_chars(pw):
        return False, "Password contains control characters"
    if pw.lower() in _COMMON_PASSWORDS:
        return False, "That password is too common — choose a stronger one"
    if username and pw.lower() == normalize(username).lower():
        return False, "Password must not match your username"
    return True, None
