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
    'plugin uninstalled',    # WordPress admin action — level 8 but not an attack
    'connection established',
}

# Rule IDs that are always benign regardless of level — Wazuh assigns level 8
# to routine administrative changes; we do not want those to mask training data.
SAFE_RULE_IDS = {
    '100022',  # WordPress plugin uninstalled (level 8, admin action)
}


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
