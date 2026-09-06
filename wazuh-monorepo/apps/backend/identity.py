"""Validation for identifiers that cross a trust boundary.

Usernames and emails are not ordinary strings here. A username becomes the
tenant key: the collector installer bakes it into the agent name as
``<owner>__<machine>``, and ``tenancy.derive_owner()`` reads it back to decide
whose alerts a request may see. Anything that lets two accounts resolve to the
same owner — or lets one account's name *look* like another's — is a
cross-tenant issue, not a cosmetic one.

Three classes of problem this closes, all measured against the previous
``username.replace("_","").replace("-","").isalnum()`` check:

1. **Confusables.** ``str.isalnum()`` is Unicode-aware, so ``аdmin`` (Cyrillic
   а), ``ɑdmin`` (Latin alpha), ``admın`` (dotless i) and ``ａdmin`` (fullwidth)
   all passed and render indistinguishably from ``admin`` in the admin panel
   and in ticket emails. NFKC folds the width/ligature variants onto ASCII so
   they collide with the real name (and get rejected as taken); anything still
   non-ASCII after folding is refused outright.
2. **Separator collision.** ``bob__test`` was accepted, and
   ``bob__test__LAPTOP-1`` resolves to owner ``bob`` — so that account could
   never see its own endpoints while ``bob`` saw them all.
3. **Impersonation of system identities.** ``admin``-adjacent and
   service-looking names are reserved.

Emails additionally guard header injection: the verification mail puts the
address in a To: header, so a CR or LF in it would let the registrant append
headers of their own.
"""

import re
import unicodedata

# Tenant separator from tenancy.SEP. Imported lazily to keep this module free
# of app dependencies; asserted in the tests instead.
SEP = "__"

USERNAME_MIN = 3
USERNAME_MAX = 40
EMAIL_MAX = 254            # RFC 5321 upper bound on a forward-path
PASSWORD_MIN = 8
# Bounded so a huge body cannot turn one registration into a KDF workout. The
# global request-body cap already limits the extreme; this makes it explicit.
PASSWORD_MAX = 128

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*[a-z0-9]$")
# Deliberately conservative: one @, no quoting, no comments, no display name,
# ASCII only. A deliverable address that this rejects is rare; an address this
# accepts cannot smuggle anything.
_EMAIL_RE = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
                       r"(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
                       r"@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$")

#: Names that must never belong to a self-registered account: role names, the
#: brand, and the local parts that automated mail comes from.
RESERVED = frozenset("""
    admin administrator root superuser sysadmin system selenne selene wazuh
    support help helpdesk security soc noreply no-reply postmaster webmaster
    abuse hostmaster api service daemon operator manager owner billing
    anonymous guest test null undefined me you all everyone
""".split())

# Characters that are invisible, reorder rendered text, or terminate a C string.
# Rejected rather than stripped: a name that only differs by an invisible
# character is a name chosen to be mistaken for another one.
_FORBIDDEN_CODEPOINTS = re.compile(
    "["
    "\u0000-\u001f\u007f"   # C0 controls + DEL (CR/LF and NUL live here)
    "\u0080-\u009f"          # C1 controls
    "\u00ad"                  # soft hyphen
    "\u200b-\u200f"          # zero-width + bidi marks
    "\u2028\u2029"           # line/paragraph separators
    "\u202a-\u202e"          # bidi embedding/override
    "\u2060-\u2064"          # invisible operators
    "\u2066-\u2069"          # bidi isolates
    "\ufeff"                  # BOM / ZWNBSP
    "\ufff9-\ufffb"          # interlinear annotation
    "]")


def _prescreen(raw, field):
    """Shared first pass: type, invisibles, then NFKC.

    NFKC runs *after* the invisible-character check so that folding cannot
    quietly erase something that should have been a rejection.
    """
    if not isinstance(raw, str):
        return None, f"{field} must be text"
    if _FORBIDDEN_CODEPOINTS.search(raw):
        return None, f"{field} contains a control or invisible character"
    return unicodedata.normalize("NFKC", raw).strip(), None


def canonical_username(raw):
    """Fold a username for *lookup*, applying no policy. "" when unusable.

    Registration policy and identity lookup are different questions. Reserved
    names, length limits and the ``__`` ban all describe what may be CREATED;
    applying them on the read path would make pre-existing and system accounts
    (``admin`` above all) unfindable, which fails closed in the worst way — the
    real admin reads as unverified. Only case/width folding belongs here, so a
    lookup matches exactly what create_user stored.
    """
    if not isinstance(raw, str):
        return ""
    return unicodedata.normalize("NFKC", raw).strip().casefold()


def normalise_username(raw):
    """Return (username, None) or (None, error).

    The returned value is what must be stored and compared: callers must not
    re-derive it from the raw input, or two spellings can diverge again.
    """
    value, err = _prescreen(raw, "Username")
    if err:
        return None, err
    value = value.casefold()

    if not value:
        return None, "Username is required"
    if len(value) < USERNAME_MIN:
        return None, f"Username must be at least {USERNAME_MIN} characters"
    if len(value) > USERNAME_MAX:
        return None, f"Username must be at most {USERNAME_MAX} characters"
    if not value.isascii():
        # Reached only by scripts NFKC does not fold to ASCII — Cyrillic,
        # Greek, emoji. Naming the confusable case makes the 400 actionable.
        return None, ("Username must use ASCII letters, digits, - and _ "
                      "(characters that merely look like ASCII are refused)")
    if not _USERNAME_RE.match(value):
        return None, ("Username must be lowercase letters, digits, - or _, "
                      "and must start and end with a letter or digit")
    if SEP in value:
        # The installer builds "<owner>__<machine>" and tenancy splits on the
        # FIRST separator, so an owner containing it is unresolvable.
        return None, f"Username must not contain '{SEP}'"
    if value in RESERVED:
        return None, "That username is reserved"
    return value, None


def normalise_email(raw):
    """Return (email, None) or (None, error). Lowercased, ASCII, single @."""
    value, err = _prescreen(raw, "Email")
    if err:
        return None, err
    value = value.casefold()

    if not value:
        return None, "Email is required"
    if len(value) > EMAIL_MAX:
        return None, f"Email must be at most {EMAIL_MAX} characters"
    if not value.isascii():
        return None, "Email must use ASCII characters"
    if not _EMAIL_RE.match(value):
        return None, "Enter a valid email address"
    local, _, domain = value.rpartition("@")
    if len(local) > 64:                      # RFC 5321 local-part limit
        return None, "Email local part is too long"
    if ".." in value or domain.startswith("-") or domain.endswith("-"):
        return None, "Enter a valid email address"
    return value, None


def check_password(raw):
    """Return (password, None) or (None, error). Never normalised or trimmed.

    Passwords are deliberately NOT NFKC-folded: the stored hash must match the
    exact bytes the user typed, and folding would make two different passwords
    interchangeable. Only length and control characters are enforced.
    """
    if not isinstance(raw, str):
        return None, "Password must be text"
    if "\x00" in raw:
        return None, "Password must not contain a null byte"
    if len(raw) < PASSWORD_MIN:
        return None, f"Password must be at least {PASSWORD_MIN} characters"
    if len(raw) > PASSWORD_MAX:
        return None, f"Password must be at most {PASSWORD_MAX} characters"
    return raw, None


def safe_text(raw, cap=120):
    """Sanitise a free-text profile field (organisation, ticket subject…).

    Unlike an identifier this is not an equality key, so invisible characters
    are stripped rather than refused — but the result still cannot carry
    control characters into a log line, a mail header, or an LLM prompt.
    """
    if not isinstance(raw, str):
        return ""
    value = _FORBIDDEN_CODEPOINTS.sub("", raw)
    return unicodedata.normalize("NFKC", value).strip()[:cap]


def header_safe(raw):
    """True when a string is safe to place in an email header.

    Guards the To:/Subject: of the verification mail. CR, LF and NUL are the
    injection vectors; everything else is the header encoder's problem.
    """
    return isinstance(raw, str) and not any(c in raw for c in "\r\n\x00")
