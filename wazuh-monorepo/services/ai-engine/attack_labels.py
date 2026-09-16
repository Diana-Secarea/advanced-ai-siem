"""
Single source of truth for attack classification used by both
train_isolation_forest.py and evaluate_isolation_forest.py.

Both scripts must classify alerts identically so that the model is
evaluated against the same ground truth it was trained on.

OUTCOME vs VERDICT
------------------
This module answers two different questions, and conflating them is what
saturated the autoencoder.

  * an OUTCOME is what happened — a login failed, a sudo was denied.
  * a VERDICT is what it means — this was hostile.

A single failed login is an outcome. It is the most ordinary event on a host
with a human on it: people mistype passwords, keys get offered before the right
one, sudo timestamps expire. Treating it as a verdict had a specific and
measurable cost. `is_attack_alert()` decides what is EXCLUDED from one-class
training, so labelling every failure an attack meant the clean training set was
defined as "the set where failed_count is 0". Measured 2026-09-16 over 2,149
alerts, the clean subset collapsed on exactly the features that discriminate:

    feature           sd (all)   sd (clean)
    failed_count         0.469        0.088
    off_hours            0.330        0.000
    unknown_user         0.343        0.000
    port_count           0.218        0.084

StandardScaler then turned a single failed login into z ~ 11-37, the
reconstruction error saturated, and 98% of production incidents came back
CRITICAL. More clean data made it strictly worse, because it tightened those
standard deviations toward zero.

So failure markers now live in the FAILURE_* sets and feed `failure_outcome()`.
They no longer make something an attack on their own. What still does: rules and
phrases that describe a BURST ("multiple failed", "brute force", max auth
attempts) or a technique (sql injection, rootkit, reverse shell). Those are
verdicts — one is genuinely evidence of an attack.
"""

ATTACK_KEYWORDS = {
    # Attack-pattern phrases. Every one of these describes a BURST or a
    # TECHNIQUE, never a single ordinary failure.
    'brute force', 'multiple failed', 'attack', 'exploit',
    'sql injection', 'web attack', 'rootkit', 'trojan',
    'backdoor', 'reverse shell', 'privilege escalation attempt',
    # Plural / burst phrasing. Wazuh reuses ONE rule id (5503) for both
    # "PAM: User login failed." (level 5, one miss) and "Multiple
    # authentication failures." (level 10, a burst), so the description is the
    # only thing that separates them — a rule-id split cannot do it.
    'authentication_failures', 'multiple authentication', 'multiple failures',
    # Putting an interface into promiscuous mode is a technique, not an
    # outcome: nothing routine on this host sniffs the wire.
    'promiscuous',
}

#: Phrases that mark a FAILURE OUTCOME. Present in perfectly ordinary events.
#: These must never, alone, make something an attack — see the module docstring.
FAILURE_KEYWORDS = {
    'authentication_failed', 'invalid_login', 'non-existent',
    'login failed', 'password check failed', 'authentication failure',
    'user login failed', 'missed the password',
}

ATTACK_RULE_IDS = {
    # Each of these fires on REPEATED failures or on a technique, not on one
    # ordinary miss. That is the whole difference from FAILURE_RULE_IDS.
    '5758',    # sshd: max auth attempts (a burst, by definition)
    '5712',    # sshd: brute force (non-existent user)
    '5720',    # sshd: Multiple failed logins
    '100001',  # Failed WordPress login (brute force)
    '100002',  # Process execution at unusual time (reverse shells, C2 beacons)
}

#: Rules that record a SINGLE failure. Ordinary on any host with a human on it:
#: a mistyped password, a key offered before the right one, an expired sudo
#: timestamp. Excluding these from training is what produced failed_count
#: sd = 0.088 and the z ~ 37 that saturated the autoencoder.
FAILURE_RULE_IDS = {
    '5503',    # PAM: User login failed  (but see 'multiple authentication'
               # in ATTACK_KEYWORDS — the same id also carries the burst)
    '5710',    # sshd: attempt to login using a non-existent user
    '5760',    # sshd: authentication failed
    '5557',    # unix_chkpwd: password check failed
    '5301',    # User missed the password to change UID
    '5300',    # Telnet authentication failure
    '2502',    # User missed the password for a UID change (legacy id)
}

# Union of groups from both scripts — previously inconsistent.
ATTACK_GROUPS = {
    'attack', 'exploit',
    'web_attack', 'sql_injection', 'ids',
    'bruteforce',
}

#: Groups that mark a failure outcome. Wazuh tags every single failed login
#: with these, which is why they cannot be treated as an attack verdict.
FAILURE_GROUPS = {
    'authentication_failed', 'invalid_login', 'failed-login',
}

#: Wazuh rule level at which severity alone is taken as a verdict.
#: Was 8, which swept in routine administrative events (Wazuh assigns 8 freely)
#: and pushed them out of the clean training set. 12 is Wazuh's own "high
#: importance" boundary and is the level at which severity is worth trusting
#: on its own.
SEVERE_LEVEL = 12

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

    if any(kw in description for kw in ATTACK_KEYWORDS):
        return True

    if groups & ATTACK_GROUPS:
        return True

    # Severity alone, but only at Wazuh's "high importance" boundary. The old
    # `level >= 8` swept in routine administrative events — Wazuh assigns 8
    # liberally — and every one of those left the clean training set.
    if level >= SEVERE_LEVEL:
        return True

    # Note what is NOT here: FAILURE_RULE_IDS / FAILURE_KEYWORDS /
    # FAILURE_GROUPS. A single failed login is an outcome, not a verdict, and
    # it belongs IN the clean baseline so the model learns that failures are a
    # normal part of a working host. Ask failure_outcome() for that signal.
    return False


def failure_outcome(alert):
    """True when the event records a failure or denial. Descriptive, not a verdict.

    Separated from is_attack_alert() so the two can be used for what each is
    actually good for: this one to build a feature, stratify a training sample
    or drive burst detection, that one to label an attack.

    A host that never emits this is not a secure host, it is an unused one.
    """
    rule = alert.get('rule', {}) or {}
    rule_id = str(rule.get('id', ''))
    description = str(rule.get('description', '')).lower()
    groups = set(rule.get('groups', []) or [])

    if rule_id in FAILURE_RULE_IDS:
        return True
    if any(kw in description for kw in FAILURE_KEYWORDS):
        return True
    if groups & FAILURE_GROUPS:
        return True
    # A burst of failures is both an outcome and a verdict.
    return rule_id in ATTACK_RULE_IDS and 'fail' in description
