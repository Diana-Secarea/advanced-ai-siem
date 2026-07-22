"""
Single source of truth for attack classification used by both
train_isolation_forest.py and evaluate_isolation_forest.py.

Both scripts must classify alerts identically so that the model is
evaluated against the same ground truth it was trained on.
"""

ATTACK_KEYWORDS = {
    # Specific attack-pattern phrases in rule descriptions
    'brute force', 'multiple failed', 'attack', 'exploit',
    'sql injection', 'web attack', 'rootkit', 'trojan',
    'backdoor', 'reverse shell', 'privilege escalation attempt',
    # Auth-specific attack signals
    'non-existent', 'authentication_failed', 'invalid_login', 'authentication_failures',
}

ATTACK_RULE_IDS = {
    '5503',    # PAM: User login failed
    '5710',    # sshd: Attempt to login using a non-existent user
    '5760',    # sshd: authentication failed
    '5758',    # sshd: max auth attempts
    '5712',    # sshd: brute force (non-existent)
    '5720',    # sshd: Multiple failed logins
    '2502',    # User missed password for UID change
    '100001',  # Failed WordPress login (brute force)
    '100002',  # Process execution at unusual time (custom rule — catches reverse shells, C2 beacons)
}

# Union of groups from both scripts — previously inconsistent.
ATTACK_GROUPS = {
    'attack', 'exploit',
    'web_attack', 'sql_injection', 'ids',
    'bruteforce', 'failed-login',
    'authentication_failed', 'invalid_login',
}

# Rule IDs whose description clearly indicates a non-attack event.
# The rule_id alone is not enough — Wazuh occasionally produces alerts
# where the ID does not match the expected description (stale rule cache,
# custom rules, etc.).  We guard against these with description keywords.
SAFE_DESCRIPTION_KEYWORDS = {
    'successful login',      # sshd 5710 sometimes fires with this desc instead of the non-existent-user desc
    'login session opened',  # PAM session-open (informational, not an attack)
    'session opened',        # generic session-open events
    'session closed',        # PAM session-close (rule 5502) — routine, not an attack
    'plugin uninstalled',    # WordPress admin action — level 8 but not an attack
    'connection established',
}

# Rule IDs that are always benign regardless of level — Wazuh assigns level 8
# to routine administrative changes; we do not want those to mask training data.
SAFE_RULE_IDS = {
    '100022',  # WordPress plugin uninstalled (level 8, admin action)
    '31101',   # Web server 400 error code — normal 404s, Wazuh tags group 'attack' but these are benign navigation errors
    '31151',   # Multiple 400 errors from same IP — triggers on our own web activity generation, not a real scan
    # Routine PAM session lifecycle — these fire constantly on any interactive
    # login/sudo and are NOT attacks; without this they score HIGH at inference.
    '5501',    # PAM: Login session opened
    '5502',    # PAM: Login session closed
}

# Wazuh's own control-plane / operational log sources (the `location` or decoder
# name in archives.json). These are the MANAGER'S self-telemetry — scans starting/
# ending, SCA benchmark output, monitord/logcollector status — not host activity,
# so novelty/anomaly scoring must not surface them as threats. Used by log_stream.
OPERATIONAL_SOURCES = {
    "rootcheck", "sca", "wazuh-monitord", "wazuh-logcollector", "logcollector",
    "wazuh-modulesd", "wazuh-remoted", "wazuh-analysisd", "wazuh-db",
    "ossec", "wazuh", "sca-summary",
    # Agent hardware/OS/package inventory: syscollector emits large JSON snapshots
    # with fresh checksums every run, so each looks novel AND structurally odd
    # (long JSON, many hex/number tokens) — but it is pure inventory bookkeeping,
    # never host activity, so it must not surface as an anomaly.
    "syscollector",
}

# Routine content markers: substrings that mark an event as operational noise
# regardless of source (scan lifecycle, SCA policy output, PAM sessions, cron).
OPERATIONAL_MARKERS = (
    "starting rootcheck", "ending rootcheck", "starting syscheck", "ending syscheck",
    "starting sca", "ending sca", '"type":"summary"', '"type":"policies"',
    "session opened", "session closed", "pam_unix(cron", "pam_unix(sudo:session",
    "cis distribution", "sca_distro", "scan interrupted", "scan finished",
    # FIM DB bookkeeping (file/registry counters) — NOT a file-change event, which
    # stays scoreable; this marker matches only the periodic capacity telemetry.
    "fim db:", '"fim_db_table"',
)


def is_routine_safe(alert, benign_rule_ids=frozenset()):
    """True for events EXPLICITLY known to be routine/benign — safe rule IDs,
    safe descriptions, or user-flagged benign IDs.

    Distinct from `not is_attack_alert(...)`: that is True for anything that
    merely isn't a known attack (which the anomaly models must still be free to
    score). This is the narrower "definitely routine, cap the score" signal used
    as an inference override so PAM sessions / admin events don't read as HIGH.
    """
    rule = alert.get('rule', {}) or {}
    rule_id = str(rule.get('id', ''))
    description = str(rule.get('description', '')).lower()
    if rule_id in benign_rule_ids:
        return True
    if rule_id in SAFE_RULE_IDS:
        return True
    if any(kw in description for kw in SAFE_DESCRIPTION_KEYWORDS):
        return True
    return False


def is_operational_log(event):
    """True for Wazuh control-plane / routine operational log events (rootcheck,
    SCA, monitord, PAM sessions…). Keyed on the collector source and content, so
    it works on raw archive events that have no rule. Used to suppress novelty."""
    loc = str(event.get('location', '') or (event.get('decoder') or {}).get('name', '')).lower()
    if loc in OPERATIONAL_SOURCES:
        return True
    blob = str(event.get('full_log', '')).lower()
    return any(m in blob for m in OPERATIONAL_MARKERS)


def is_attack_alert(alert, benign_rule_ids=frozenset()):
    """Return True if the alert describes an attack, False if it is benign.

    benign_rule_ids: set of rule IDs the user has explicitly marked as benign
                     via the UI — these always override all other signals.

    NOTE: MITRE tags are intentionally NOT used as an attack signal. Wazuh
    attaches MITRE technique IDs to many routine events (PAM logins, sudo
    sessions) to indicate "this is the technique IF done maliciously" — not
    that the specific event is an attack. Using MITRE presence as a signal
    causes normal login/session events to be mislabelled as attacks, which
    removes them from clean training data and causes the model to flag them
    as 100/100 anomalies at inference time.
    """
    rule = alert.get('rule', {})
    rule_id = str(rule.get('id', ''))
    description = rule.get('description', '').lower()
    groups = set(rule.get('groups', []))
    level = rule.get('level', 0)

    # User-defined UI exceptions always win
    if rule_id in benign_rule_ids:
        return False

    # Hard-coded safe rule IDs — routine admin actions Wazuh assigns level 8
    if rule_id in SAFE_RULE_IDS:
        return False

    # Description-level safe override: if the description clearly says it is a
    # normal/successful event, do not label as attack even if the rule_id or
    # level would otherwise match (guards against stale rule ID / custom rules).
    if any(kw in description for kw in SAFE_DESCRIPTION_KEYWORDS):
        return False

    if rule_id in ATTACK_RULE_IDS:
        return True

    if level >= 8:
        return True

    if any(kw in description for kw in ATTACK_KEYWORDS):
        return True

    if groups & ATTACK_GROUPS:
        return True

    return False
